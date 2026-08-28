# ABOUTME: Authentication routes: login, callback, logout, and the current user.
# ABOUTME: Gates the README security checklist items 1 and 8.

import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlmodel import Session, col, delete

from app.config import Settings
from app.deps import AppSettings, CurrentUser, DbSession, Entra
from app.entra import Identity, TokenExchangeError, TokenValidationError, new_pkce_pair
from app.models import AuthTransaction, User, UserSession
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
    statement = (
        pg_insert(User)
        .values(
            id=uuid.uuid4(),
            tid=identity.tid,
            oid=identity.oid,
            email=identity.email,
            display_name=identity.display_name,
            created_at=datetime.now(UTC),
        )
        # One statement: a check-then-insert loses the race when the same user
        # signs in twice concurrently for the first time, and the loser gets a
        # 500 on the last leg of a valid login.
        .on_conflict_do_update(
            constraint="uq_app_user_tid_oid",
            set_={"email": identity.email, "display_name": identity.display_name},
        )
        .returning(User)
    )
    user: User = db.execute(statement).scalars().one()
    db.flush()
    return user


def _sweep_expired(db: Session) -> None:
    """Login is an unauthenticated write path, so it is where the tables grow.

    AuthTransaction.consume only reaps rows for logins that come back, and an
    expired session is only deleted when its token is presented again. Neither
    covers the user who never returns.
    """
    now = datetime.now(UTC)
    db.execute(delete(AuthTransaction).where(col(AuthTransaction.expires_at) <= now))
    db.execute(delete(UserSession).where(col(UserSession.expires_at) <= now))


def _set_login_cookie(response: Response, state: str, settings: Settings) -> None:
    # SameSite=lax, not strict: the callback arrives as a top-level navigation
    # from the identity provider, and strict would withhold the cookie there.
    response.set_cookie(
        settings.login_cookie_name,
        state,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
        max_age=settings.auth_transaction_ttl_seconds,
    )


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
    _sweep_expired(db)
    db.commit()

    response = RedirectResponse(
        entra.authorization_url(state, nonce, challenge), status_code=status.HTTP_302_FOUND
    )
    _set_login_cookie(response, state, settings)
    return response


@router.get("/callback")
def callback(
    request: Request,
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

    # Storing state server-side only proves it was issued, not that it was
    # issued to *this* browser. Without this check an attacker starts a login,
    # then lures a victim to the callback with the attacker's code and state,
    # and the victim ends up signed in as the attacker.
    bound_state = request.cookies.get(settings.login_cookie_name)
    if not bound_state or not secrets.compare_digest(bound_state.encode(), state.encode()):
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
        absolute=settings.session_absolute_ttl_seconds,
    )
    db.commit()

    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(response, token, settings)
    response.delete_cookie(settings.login_cookie_name, path="/")
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
