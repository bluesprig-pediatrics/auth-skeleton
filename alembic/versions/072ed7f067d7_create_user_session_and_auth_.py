"""create user, session, and auth transaction tables

Revision ID: 072ed7f067d7
Revises: 
Create Date: 2026-08-26 18:52:13.128759

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '072ed7f067d7'
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Fail fast rather than hold a lock: an unbounded ALTER on a large table
    # blocks every reader behind it. Raise it deliberately if a migration
    # genuinely needs longer.
    op.execute("SET statement_timeout = '5s'")
    op.execute("SET lock_timeout = '3s'")
    op.create_table('app_user',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('tid', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
    sa.Column('oid', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
    sa.Column('email', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    sa.Column('display_name', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tid', 'oid', name='uq_app_user_tid_oid')
    )
    op.create_table('auth_transaction',
    sa.Column('state', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
    sa.Column('nonce', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
    sa.Column('code_verifier', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
    sa.Column('next_path', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('state')
    )
    op.create_index(op.f('ix_auth_transaction_expires_at'), 'auth_transaction', ['expires_at'], unique=False)
    op.create_table('user_session',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('token_hash', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
    sa.Column('roles', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['app_user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_session_token_hash'), 'user_session', ['token_hash'], unique=True)
    op.create_index(op.f('ix_user_session_user_id'), 'user_session', ['user_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    # DROP TABLE and DROP INDEX both take ACCESS EXCLUSIVE. A rollback against
    # a live database blocks every reader, which is what these bound.
    op.execute("SET statement_timeout = '5s'")
    op.execute("SET lock_timeout = '3s'")
    op.drop_index(op.f('ix_user_session_user_id'), table_name='user_session')
    op.drop_index(op.f('ix_user_session_token_hash'), table_name='user_session')
    op.drop_table('user_session')
    op.drop_index(op.f('ix_auth_transaction_expires_at'), table_name='auth_transaction')
    op.drop_table('auth_transaction')
    op.drop_table('app_user')
