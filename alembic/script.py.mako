"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
import sqlmodel.sql.sqltypes
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision: str = ${repr(up_revision)}
down_revision: str | Sequence[str] | None = ${repr(down_revision)}
branch_labels: str | Sequence[str] | None = ${repr(branch_labels)}
depends_on: str | Sequence[str] | None = ${repr(depends_on)}


def upgrade() -> None:
    """Upgrade schema."""
    # Fail fast rather than hold a lock: an unbounded ALTER on a large table
    # blocks every reader behind it. Raise it deliberately if a migration
    # genuinely needs longer.
    op.execute("SET statement_timeout = '5s'")
    op.execute("SET lock_timeout = '3s'")
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    """Downgrade schema."""
    # DROP TABLE and DROP INDEX both take ACCESS EXCLUSIVE. A rollback against
    # a live database blocks every reader, which is what these bound.
    op.execute("SET statement_timeout = '5s'")
    op.execute("SET lock_timeout = '3s'")
    ${downgrades if downgrades else "pass"}
