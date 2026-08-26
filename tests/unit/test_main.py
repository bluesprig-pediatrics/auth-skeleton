# ABOUTME: Tests the app factory and health endpoint.
# ABOUTME: Verifies the app boots with valid settings.

from fastapi.testclient import TestClient

from app.main import create_app


def test_healthz_returns_ok(env):
    with TestClient(create_app()) as client:
        response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
