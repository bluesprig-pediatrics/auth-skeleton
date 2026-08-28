# ABOUTME: Database tables for users, sessions, and in-flight auth transactions.
# ABOUTME: No table here is ever serialized to a client; routes declare explicit schemas.

import uuid
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, UniqueConstraint, delete, or_
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.mutable import MutableList
from sqlmodel import Field, Session, SQLModel, col


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _timestamp_column(*, index: bool = False) -> Column:  # type: ignore[type-arg]
    """Timezone-aware timestamps. Naive columns silently compare wrong the
    first time a deployment is not on UTC."""
    return Column(DateTime(timezone=True), nullable=False, index=index)


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
    # MutableList: without it an in-place `roles.append(...)` is invisible to
    # the unit of work and silently persists nothing. Tracking begins when the
    # attribute is loaded by SQLAlchemy; on an instance just constructed in
    # Python, pydantic holds a plain list, so assign a whole list there.
    roles: list[str] = Field(
        default_factory=list,
        sa_column=Column(MutableList.as_mutable(JSONB), nullable=False),
    )

    created_at: datetime = Field(default_factory=_utcnow, sa_column=_timestamp_column())
    # Idle timeout is measured from here; absolute timeout from expires_at.
    last_seen_at: datetime = Field(default_factory=_utcnow, sa_column=_timestamp_column())
    # Indexed: login sweeps expired sessions, since a user who never returns
    # leaves a row nothing else removes.
    expires_at: datetime = Field(sa_column=_timestamp_column(index=True))


class AuthTransaction(SQLModel, table=True):
    """One in-flight login, from the redirect to Entra until the callback."""

    __tablename__ = "auth_transaction"

    state: str = Field(primary_key=True)
    nonce: str
    code_verifier: str
    next_path: str = "/"
    # Indexed: consume() sweeps expired rows on every callback.
    expires_at: datetime = Field(sa_column=_timestamp_column(index=True))

    @classmethod
    def consume(cls, session: Session, state: str) -> AuthTransaction | None:
        """Delete the transaction and return it only if it was still valid.

        Deletion is unconditional: a transaction is single-use whether or not
        the callback succeeds, so a replayed `state` finds nothing.
        """
        now = _utcnow()
        # One statement, so two concurrent callbacks cannot both be handed the
        # same nonce and verifier. The `or` clause also sweeps abandoned rows:
        # a login the user never returns from would otherwise live forever.
        statement = (
            delete(cls)
            .where(or_(col(cls.state) == state, col(cls.expires_at) <= now))
            .returning(cls)
        )
        deleted = session.execute(statement).all()
        for row in deleted:
            transaction = row[0]
            if transaction.state == state:
                return None if transaction.expires_at <= now else transaction
        return None
