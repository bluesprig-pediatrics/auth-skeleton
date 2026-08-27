# ABOUTME: Database engine and the request-scoped session dependency.
# ABOUTME: Sync sessions; httpx is the only async surface in this app.

from sqlalchemy import Engine
from sqlmodel import create_engine

from app.config import Settings


def make_engine(settings: Settings) -> Engine:
    return create_engine(settings.database_url, pool_pre_ping=True)

