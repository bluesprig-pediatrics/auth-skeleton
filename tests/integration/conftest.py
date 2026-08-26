# ABOUTME: Fixtures for tests that need a real Postgres.
# ABOUTME: Applies migrations once, then isolates each test in a rolled-back transaction.

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine
from sqlmodel import Session, create_engine

ROOT = Path(__file__).resolve().parents[2]

DATABASE_URL = os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://auth:auth@localhost:5432/auth"
)
# alembic/env.py builds Settings, which needs the full environment.
os.environ.setdefault("ENV", "test")
os.environ.setdefault("ENTRA_TENANT_ID", "11111111-1111-1111-1111-111111111111")
os.environ.setdefault("ENTRA_CLIENT_ID", "22222222-2222-2222-2222-222222222222")
os.environ.setdefault("ENTRA_CLIENT_SECRET", "test")
os.environ.setdefault("REDIRECT_URI", "http://localhost:57005/auth/callback")


@pytest.fixture(scope="session")
def alembic_config() -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "alembic"))
    return config


@pytest.fixture(scope="session")
def engine(alembic_config: Config) -> Iterator[Engine]:
    command.upgrade(alembic_config, "head")
    engine = create_engine(DATABASE_URL)
    yield engine
    engine.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    """One transaction per test, rolled back, so tests cannot see each other."""
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    try:
        yield session
    finally:
        # Order matters: a test that provokes an IntegrityError leaves the
        # session needing a rollback, and closing out of order strands the
        # underlying psycopg connection.
        session.close()
        if transaction.is_active:
            transaction.rollback()
        connection.close()
