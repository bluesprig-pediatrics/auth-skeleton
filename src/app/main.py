# ABOUTME: FastAPI application factory.
# ABOUTME: Wires settings and logging; exposes the health endpoint.

from fastapi import FastAPI

from app.config import Settings
from app.entra import EntraClient
from app.logging import configure_logging


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(title="auth-skeleton")
    settings = Settings()
    app.state.settings = settings
    # One per process. EntraClient holds the JWKS cache and the refresh
    # throttle; building it per request would restore the unbounded refetch.
    app.state.entra = EntraClient(settings)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
