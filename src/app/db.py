# ABOUTME: Database engine and the request-scoped session dependency.
# ABOUTME: Sync sessions; httpx is the only async surface in this app.

from collections.abc import Iterator

from sqlalchemy import Engine
from sqlmodel import Session, create_engine

from app.config import Settings


def make_engine(settings: Settings) -> Engine:
    return create_engine(settings.database_url, pool_pre_ping=True)


def session_factory(engine: Engine) -> Iterator[Session]:
    with Session(engine) as session:
        yield session
