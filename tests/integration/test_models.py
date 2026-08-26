# ABOUTME: Tests for table constraints and AuthTransaction consumption.
# ABOUTME: Covers the single-use and expiry rules the callback depends on.

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.models import AuthTransaction, User, UserSession


def make_user(session: Session, *, tid="t1", oid="o1") -> User:
    user = User(tid=tid, oid=oid)
    session.add(user)
    session.flush()
    return user


def make_transaction(session: Session, *, state="s1", ttl_seconds=300) -> AuthTransaction:
    transaction = AuthTransaction(
        state=state,
        nonce="n",
        code_verifier="v",
        expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
    )
    session.add(transaction)
    session.flush()
    return transaction


def test_same_tid_and_oid_cannot_be_inserted_twice(session: Session):
    make_user(session)
    session.add(User(tid="t1", oid="o1"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_same_oid_in_a_different_tenant_is_allowed(session: Session):
    make_user(session, tid="t1", oid="shared")
    make_user(session, tid="t2", oid="shared")


def test_consume_returns_the_transaction_and_deletes_it(session: Session):
    make_transaction(session, state="live")
    assert AuthTransaction.consume(session, "live") is not None
    assert session.get(AuthTransaction, "live") is None


def test_consume_is_single_use(session: Session):
    """A replayed `state` must find nothing, which is what makes the callback
    resistant to replay."""
    make_transaction(session, state="once")
    AuthTransaction.consume(session, "once")
    assert AuthTransaction.consume(session, "once") is None


def test_expired_transaction_is_rejected_without_a_sweeper(session: Session):
    """Correctness must not depend on scheduled cleanup running."""
    make_transaction(session, state="stale", ttl_seconds=-1)
    assert AuthTransaction.consume(session, "stale") is None


def test_expired_transaction_is_still_deleted(session: Session):
    make_transaction(session, state="stale", ttl_seconds=-1)
    AuthTransaction.consume(session, "stale")
    assert session.get(AuthTransaction, "stale") is None


def test_consume_of_unknown_state_returns_none(session: Session):
    assert AuthTransaction.consume(session, "never-existed") is None


def test_session_token_hash_is_unique(session: Session):
    user = make_user(session)
    expires = datetime.now(UTC) + timedelta(hours=1)
    session.add(UserSession(user_id=user.id, token_hash="dup", expires_at=expires))
    session.flush()
    session.add(UserSession(user_id=user.id, token_hash="dup", expires_at=expires))
    with pytest.raises(IntegrityError):
        session.flush()


def test_roles_round_trip_as_a_list(session: Session):
    user = make_user(session)
    session.add(
        UserSession(
            user_id=user.id,
            token_hash="h",
            roles=["Admin", "Clinician"],
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    session.flush()
    session.expire_all()
    stored = session.exec(select(UserSession).where(UserSession.token_hash == "h")).one()
    assert stored.roles == ["Admin", "Clinician"]


def test_consume_sweeps_other_expired_transactions(session: Session):
    """A login the user abandons leaves a row nothing else would ever remove;
    SPEC claims the consuming delete clears them, so it must."""
    make_transaction(session, state="abandoned", ttl_seconds=-1)
    make_transaction(session, state="live")
    AuthTransaction.consume(session, "live")
    assert session.get(AuthTransaction, "abandoned") is None


def test_consume_does_not_sweep_unexpired_transactions(session: Session):
    make_transaction(session, state="other")
    make_transaction(session, state="live")
    AuthTransaction.consume(session, "live")
    assert session.get(AuthTransaction, "other") is not None


def test_roles_mutation_on_a_loaded_session_is_persisted(session: Session):
    """Without MutableList an in-place append is invisible to the unit of work
    and silently persists nothing, which is the worst way for a roles snapshot
    to fail."""
    user = make_user(session)
    session.add(
        UserSession(
            user_id=user.id,
            token_hash="mut",
            roles=["Clinician"],
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    session.flush()
    session.expire_all()

    loaded = session.exec(select(UserSession).where(UserSession.token_hash == "mut")).one()
    loaded.roles.append("Admin")
    session.flush()
    session.expire_all()

    stored = session.exec(select(UserSession).where(UserSession.token_hash == "mut")).one()
    assert stored.roles == ["Clinician", "Admin"]
