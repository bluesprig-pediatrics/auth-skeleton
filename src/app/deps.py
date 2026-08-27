# ABOUTME: FastAPI dependencies for the current user and role checks.
# ABOUTME: Resolves the session cookie; never exposes a table model to a route.

import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlmodel import Session

from app.config import Settings
from app.entra import EntraClient
from app.models import User
from app.session import session_for_token


@dataclass(frozen=True)
class AuthenticatedUser:
    """What a route is allowed to see. Deliberately not a table model."""

    id: uuid.UUID
    tid: str
    oid: str
    email: str | None
    display_name: str | None
    roles: list[str]


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_entra(request: Request) -> EntraClient:
    client: EntraClient = request.app.state.entra
    return client


def get_db(request: Request) -> Iterator[Session]:
    with Session(request.app.state.engine) as session:
        yield session


DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings)]
Entra = Annotated[EntraClient, Depends(get_entra)]


def current_user(
    request: Request,
    db: DbSession,
    settings: AppSettings,
) -> AuthenticatedUser:
    token = request.cookies.get(settings.cookie_name)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")

    user_session = session_for_token(db, token, idle=settings.session_idle_ttl_seconds)
    if user_session is None:
        db.commit()  # session_for_token deletes expired rows
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")

    user = db.get(User, user_session.user_id)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")

    # Roles come from the snapshot taken at login, not a live directory call.
    identity = AuthenticatedUser(
        id=user.id,
        tid=user.tid,
        oid=user.oid,
        email=user.email,
        display_name=user.display_name,
        roles=list(user_session.roles),
    )
    db.commit()
    return identity


CurrentUser = Annotated[AuthenticatedUser, Depends(current_user)]


def require_roles(*required: str) -> Callable[..., AuthenticatedUser]:
    """Dependency factory. Denies unless the session holds one of these roles."""

    def check(user: CurrentUser) -> AuthenticatedUser:
        if not set(required) & set(user.roles):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return user

    return check
