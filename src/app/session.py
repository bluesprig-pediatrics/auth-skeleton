# ABOUTME: Browser session lifecycle: create, look up, revoke.
# ABOUTME: Tokens are stored only as hashes; gates SPEC checklist items 6 and 7.

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, col, select

from app.models import User, UserSession

# 256 bits. Guessing is not a threat model at this size, which is why lookup
# can go straight through the hash index.
TOKEN_BYTES = 32


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(session: Session, user: User, *, roles: list[str], absolute: int) -> str:
    """Create a session and return the token. The token is returned once and
    never stored; only its digest is persisted."""
    token = secrets.token_urlsafe(TOKEN_BYTES)
    now = datetime.now(UTC)
    session.add(
        UserSession(
            user_id=user.id,
            token_hash=_hash(token),
            roles=roles,
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(seconds=absolute),
        )
    )
    session.flush()
    return token


def session_for_token(session: Session, token: str, *, idle: int) -> UserSession | None:
    """Return the live session for this token, refreshing its idle clock.

    Lookup is by digest, so the comparison happens in the index on a 256-bit
    value; a separate constant-time compare would add nothing.
    """
    found = session.exec(
        select(UserSession).where(col(UserSession.token_hash) == _hash(token))
    ).one_or_none()
    if found is None:
        return None

    now = datetime.now(UTC)
    if found.expires_at <= now or found.last_seen_at + timedelta(seconds=idle) <= now:
        # Both bounds matter: idle alone lets a session live forever under
        # steady use, absolute alone lets an abandoned one stay valid all day.
        session.delete(found)
        session.flush()
        return None

    # Throttled: this runs on every authenticated request, and writing a row
    # each time buys nothing when the idle window is measured in minutes.
    if now - found.last_seen_at > timedelta(seconds=idle // 10):
        found.last_seen_at = now
        session.add(found)
    return found


def revoke_session(session: Session, token: str) -> None:
    found = session.exec(
        select(UserSession).where(col(UserSession.token_hash) == _hash(token))
    ).one_or_none()
    if found is not None:
        session.delete(found)
        session.flush()
