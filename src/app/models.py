# ABOUTME: Database tables for users, sessions, and in-flight auth transactions.
# ABOUTME: No table here is ever serialized to a client; see SPEC model layer rules.

import uuid
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, Session, SQLModel


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _timestamp_column() -> Column:  # type: ignore[type-arg]
    """Timezone-aware timestamps. Naive columns silently compare wrong the
    first time a deployment is not on UTC."""
    return Column(DateTime(timezone=True), nullable=False)


class User(SQLModel, table=True):
    # `user` is reserved in Postgres; naming it explicitly avoids quoting it
    # in every hand-written query forever.
    __tablename__ = "app_user"
    __table_args__ = (UniqueConstraint("tid", "oid", name="uq_app_user_tid_oid"),)

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)

    # Entra's immutable object id, scoped to its tenant. `sub` is pairwise per
    # application and email is reassignable, so neither identifies a user.
    tid: str
    oid: str

    # Non-authoritative: refreshed from the ID token on each login, never
    # trusted for identity or lookup.
    email: str | None = None
    display_name: str | None = None

    created_at: datetime = Field(default_factory=_utcnow, sa_column=_timestamp_column())


class UserSession(SQLModel, table=True):
    """A browser session. Named UserSession because `Session` is sqlmodel's
    database session, and the collision is a footgun in every file using both."""

    __tablename__ = "user_session"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="app_user.id", index=True)

    # SHA-256 of the token handed to the browser. A database leak must not be
    # enough to impersonate anyone.
    token_hash: str = Field(unique=True, index=True)

    # Snapshot of the Entra `roles` claim at login. Authorization must not
    # depend on a live directory lookup on every request.
    roles: list[str] = Field(default_factory=list, sa_column=Column(JSONB, nullable=False))

    created_at: datetime = Field(default_factory=_utcnow, sa_column=_timestamp_column())
    # Idle timeout is measured from here; absolute timeout from expires_at.
    last_seen_at: datetime = Field(default_factory=_utcnow, sa_column=_timestamp_column())
    expires_at: datetime = Field(sa_column=_timestamp_column())


class AuthTransaction(SQLModel, table=True):
    """One in-flight login, from the redirect to Entra until the callback."""

    __tablename__ = "auth_transaction"

    state: str = Field(primary_key=True)
    nonce: str
    code_verifier: str
    next_path: str = "/"
    expires_at: datetime = Field(sa_column=_timestamp_column())

    @classmethod
    def consume(cls, session: Session, state: str) -> AuthTransaction | None:
        """Delete the transaction and return it only if it was still valid.

        Deletion is unconditional: a transaction is single-use whether or not
        the callback succeeds, so a replayed `state` finds nothing.
        """
        transaction = session.get(cls, state)
        if transaction is None:
            return None
        expired = transaction.expires_at <= _utcnow()
        session.delete(transaction)
        session.flush()
        return None if expired else transaction
