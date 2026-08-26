# ABOUTME: Tests that migrations apply, reverse, and match the models.
# ABOUTME: Drift between SQLModel classes and revisions is the failure this catches.

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import Engine
from sqlmodel import SQLModel

from app import models  # noqa: F401  registers tables on SQLModel.metadata


def test_upgrade_and_downgrade_round_trip(alembic_config: Config, engine: Engine):
    command.downgrade(alembic_config, "base")
    command.upgrade(alembic_config, "head")


def test_migrations_match_models(alembic_config: Config, engine: Engine):
    """Autogenerate against a migrated database must find nothing to do.

    Autogenerate is a draft, not an oracle, so this does not prove a revision
    is correct -- but it does catch a model edited without a migration.
    """
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        assert compare_metadata(context, SQLModel.metadata) == []
