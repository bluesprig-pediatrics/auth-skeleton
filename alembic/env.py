# ABOUTME: Alembic environment wiring for SQLModel metadata.
# ABOUTME: Online mode reads DATABASE_URL from settings; offline mode renders SQL only.

import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import create_engine, pool
from sqlmodel import SQLModel

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from app import models  # noqa: E402,F401  imported for its side effect: table registration
from app.config import Settings  # noqa: E402

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Autogenerate diffs against this. Without the models import above it is empty
# and every generated revision is a no-op.
target_metadata = SQLModel.metadata

# SQLModel maps `str` to its own AutoString. Alembic writes that type into
# revisions; this prefix makes the reference resolvable there.
USER_MODULE_PREFIX = "sqlmodel.sql.sqltypes."


def run_migrations_offline() -> None:
    """Render SQL without a database. Used by CI to feed Squawk."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        user_module_prefix=USER_MODULE_PREFIX,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # Built directly rather than via config.set_main_option: the ini is a
    # ConfigParser and interpolates `%`, so a password containing a
    # percent-encoded character (`%40` for `@`) raises before connecting.
    connectable = create_engine(Settings().database_url, poolclass=pool.NullPool)
    try:
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                user_module_prefix=USER_MODULE_PREFIX,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        # Migrations run in-process during tests; an undisposed engine leaks
        # its connection and surfaces as a ResourceWarning.
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
