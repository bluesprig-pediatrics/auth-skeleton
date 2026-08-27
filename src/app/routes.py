# ABOUTME: Authentication routes: login, callback, logout, and the current user.
# ABOUTME: Gates SPEC checklist items 1 and 8.

import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlmodel import Session, col, select

from app.config import Settings
from app.deps import AppSettings, CurrentUser, DbSession, Entra
from app.entra import Identity, TokenExchangeError, TokenValidationError, new_pkce_pair
from app.models import AuthTransaction, User
from app.session import create_session, revoke_session

router = APIRouter(prefix="/auth", tags=["auth"])

STATE_BYTES = 32


class MeResponse(BaseModel):
    """Explicit, so no table column can leak by being added to a model."""

    oid: str
    email: str | None
    display_name: str | None
    roles: list[str]


def _validated_next(candidate: str | None, settings: Settings) -> str:
    """The allowlist is the open-redirect guard, so membership is exact.

    Rejecting rather than falling back: a request carrying an unexpected
    target is a sign of either an attack or a misconfiguration, and silently
    redirecting elsewhere hides both.
    """
    if candidate is None:
        return settings.post_login_allowlist[0]
    if candidate not in settings.post_login_allowlist:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "next is not an allowed destination")
    return candidate


def _upsert_user(db: Session, identity: Identity) -> User:
    """Keyed on (tid, oid). Email and display name are refreshed but never
    used for lookup: they are reassignable, the object id is not."""
    user = db.exec(
        select(User).where(col(User.tid) == identity.tid, col(User.oid) == identity.oid)
    ).one_or_none()
    if user is None:
        user = User(tid=identity.tid, oid=identity.oid)
    user.email = identity.email
    user.display_name = identity.display_name
    db.add(user)
    db.flush()
    return user


def _set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    # `__Host-` requires Secure, Path=/, and no Domain. All three hold here.
    response.set_cookie(
        settings.cookie_name,
        token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
        max_age=settings.session_absolute_ttl_seconds,
    )


@router.get("/login")
def login(
    db: DbSession,
    settings: AppSettings,
    entra: Entra,
    next: str | None = Query(default=None),
) -> RedirectResponse:
    target = _validated_next(next, settings)
    state = secrets.token_urlsafe(STATE_BYTES)
    nonce = secrets.token_urlsafe(STATE_BYTES)
    verifier, challenge = new_pkce_pair()

    db.add(
        AuthTransaction(
            state=state,
            nonce=nonce,
            code_verifier=verifier,
            next_path=target,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=settings.auth_transaction_ttl_seconds),
        )
    )
    db.commit()
    return RedirectResponse(
        entra.authorization_url(state, nonce, challenge), status_code=status.HTTP_302_FOUND
    )


@router.get("/callback")
def callback(
    db: DbSession,
    settings: AppSettings,
    entra: Entra,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
) -> RedirectResponse:
    if error or not code or not state:
        # The identity provider refused, or the request is malformed. Neither
        # is our internal error, and neither detail is echoed back.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "authentication failed")

    # Single-use, and consumed before anything else is trusted: this is what
    # makes a replayed callback fail.
    transaction = AuthTransaction.consume(db, state)
    if transaction is None:
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "authentication failed")

    nonce, verifier, target = transaction.nonce, transaction.code_verifier, transaction.next_path
    db.commit()

    try:
        id_token = entra.exchange_code(code, verifier)
        identity = entra.validate_id_token(id_token, expected_nonce=nonce)
    except (TokenExchangeError, TokenValidationError) as failure:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "authentication failed") from failure

    user = _upsert_user(db, identity)
    token = create_session(
        db,
        user,
        roles=identity.roles,
        idle=settings.session_idle_ttl_seconds,
        absolute=settings.session_absolute_ttl_seconds,
    )
    db.commit()

    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(response, token, settings)
    return response


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, db: DbSession, settings: AppSettings) -> Response:
    token = request.cookies.get(settings.cookie_name)
    if token:
        revoke_session(db, token)
        db.commit()

    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(
        settings.cookie_name, path="/", httponly=True, secure=settings.cookie_secure, samesite="lax"
    )
    return response


@router.get("/me", response_model=MeResponse)
def me(user: CurrentUser) -> MeResponse:
    return MeResponse(
        oid=user.oid, email=user.email, display_name=user.display_name, roles=user.roles
    )
