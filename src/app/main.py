# ABOUTME: FastAPI application factory.
# ABOUTME: Wires settings and logging; exposes the health endpoint.

from fastapi import FastAPI

from app.config import Settings
from app.logging import configure_logging


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(title="auth-skeleton")
    app.state.settings = Settings()

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
