# ABOUTME: FastAPI application factory.
# ABOUTME: Wires settings, logging, the Entra client, the engine, and the auth routes.

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import Settings
from app.db import make_engine
from app.entra import EntraClient
from app.logging import configure_logging
from app.routes import router


def create_app() -> FastAPI:
    configure_logging()
    settings = Settings()
    engine = make_engine(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        # Without this the pool outlives the app and leaks its connections.
        engine.dispose()

    app = FastAPI(title="auth-skeleton", lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = engine
    # One per process. EntraClient holds the JWKS cache and the refresh
    # throttle; building it per request would restore the unbounded refetch.
    app.state.entra = EntraClient(settings)
    app.include_router(router)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
