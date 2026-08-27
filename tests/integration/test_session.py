# ABOUTME: Tests for session creation, lookup, expiry, and revocation.
# ABOUTME: Gates SPEC checklist items 6 and 7.

from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from app.models import User, UserSession
from app.session import create_session, revoke_session, session_for_token

IDLE = 1800
ABSOLUTE = 28800


def a_user(session: Session) -> User:
    user = User(tid="t", oid="o")
    session.add(user)
    session.flush()
    return user


def test_create_returns_a_token_and_persists_a_row(session: Session):
    user = a_user(session)
    token = create_session(session, user, roles=["Clinician"], absolute=ABSOLUTE)
    assert token
    assert session.exec(select(UserSession)).one().user_id == user.id


def test_raw_token_is_never_stored(session: Session):
    """A database leak must not be enough to impersonate anyone."""
    user = a_user(session)
    token = create_session(session, user, roles=[], absolute=ABSOLUTE)
    stored = session.exec(select(UserSession)).one()
    assert token not in (stored.token_hash, str(stored.id))
    row = session.exec(select(UserSession)).one()
    assert token not in " ".join(str(value) for value in row.model_dump().values())


def test_tokens_are_not_reused(session: Session):
    user = a_user(session)
    first = create_session(session, user, roles=[], absolute=ABSOLUTE)
    second = create_session(session, user, roles=[], absolute=ABSOLUTE)
    assert first != second


def test_lookup_returns_the_session(session: Session):
    user = a_user(session)
    token = create_session(session, user, roles=["Admin"], absolute=ABSOLUTE)
    found = session_for_token(session, token, idle=IDLE)
    assert found is not None
    assert found.roles == ["Admin"]


def test_lookup_of_an_unknown_token_returns_none(session: Session):
    assert session_for_token(session, "not-a-real-token", idle=IDLE) is None


def test_idle_timeout_expires_an_untouched_session(session: Session):
    user = a_user(session)
    token = create_session(session, user, roles=[], absolute=ABSOLUTE)
    stored = session.exec(select(UserSession)).one()
    stored.last_seen_at = datetime.now(UTC) - timedelta(seconds=IDLE + 1)
    session.flush()
    assert session_for_token(session, token, idle=IDLE) is None


def test_absolute_timeout_expires_an_actively_used_session(session: Session):
    """Idle timeout alone would let a session live forever under steady use."""
    user = a_user(session)
    token = create_session(session, user, roles=[], absolute=ABSOLUTE)
    stored = session.exec(select(UserSession)).one()
    stored.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    stored.last_seen_at = datetime.now(UTC)
    session.flush()
    assert session_for_token(session, token, idle=IDLE) is None


def test_lookup_refreshes_last_seen(session: Session):
    user = a_user(session)
    token = create_session(session, user, roles=[], absolute=ABSOLUTE)
    stored = session.exec(select(UserSession)).one()
    stored.last_seen_at = datetime.now(UTC) - timedelta(seconds=IDLE // 2)
    session.flush()
    before = stored.last_seen_at

    session_for_token(session, token, idle=IDLE)
    session.flush()
    assert session.exec(select(UserSession)).one().last_seen_at > before


def test_revoke_takes_effect_immediately(session: Session):
    user = a_user(session)
    token = create_session(session, user, roles=[], absolute=ABSOLUTE)
    revoke_session(session, token)
    assert session_for_token(session, token, idle=IDLE) is None
    assert session.exec(select(UserSession)).all() == []


def test_revoking_an_unknown_token_is_not_an_error(session: Session):
    revoke_session(session, "never-existed")
