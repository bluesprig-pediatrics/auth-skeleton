# ABOUTME: Shared pytest fixtures.
# ABOUTME: Provides a minimal valid environment so settings can be constructed.

import pytest

MINIMAL_ENV = {
    "ENV": "production",
    "DATABASE_URL": "postgresql+psycopg://u:p@localhost/db",
    "ENTRA_TENANT_ID": "11111111-1111-1111-1111-111111111111",
    "ENTRA_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
    "ENTRA_CLIENT_SECRET": "shhh",
    "REDIRECT_URI": "https://app.example/auth/callback",
}


@pytest.fixture
def env(monkeypatch):
    """Set the minimal valid environment; return a mutator for overrides."""
    for key in list(MINIMAL_ENV) + ["DEV_INSECURE_COOKIES", "POST_LOGIN_ALLOWLIST"]:
        monkeypatch.delenv(key, raising=False)
    for key, value in MINIMAL_ENV.items():
        monkeypatch.setenv(key, value)
    return monkeypatch
