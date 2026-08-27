"""index user_session expiry for sweeping

Revision ID: dd7fcc45038b
Revises: 072ed7f067d7
Create Date: 2026-08-27 09:40:54.197903

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
import sqlmodel.sql.sqltypes


# revision identifiers, used by Alembic.
revision: str = 'dd7fcc45038b'
down_revision: str | Sequence[str] | None = '072ed7f067d7'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Fail fast rather than hold a lock: an unbounded ALTER on a large table
    # blocks every reader behind it. Raise it deliberately if a migration
    # genuinely needs longer.
    op.execute("SET statement_timeout = '5s'")
    op.execute("SET lock_timeout = '3s'")
    op.create_index(op.f('ix_user_session_expires_at'), 'user_session', ['expires_at'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    # DROP TABLE and DROP INDEX both take ACCESS EXCLUSIVE. A rollback against
    # a live database blocks every reader, which is what these bound.
    op.execute("SET statement_timeout = '5s'")
    op.execute("SET lock_timeout = '3s'")
    op.drop_index(op.f('ix_user_session_expires_at'), table_name='user_session')
