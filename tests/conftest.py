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
def env(monkeypatch, tmp_path):
    """Set the minimal valid environment; return a mutator for overrides.

    Runs from an empty directory: Settings reads `.env`, so a developer's real
    dotenv would otherwise supply the very values these tests remove.
    """
    monkeypatch.chdir(tmp_path)
    optional = ["DEV_INSECURE_COOKIES", "POST_LOGIN_ALLOWLIST", "ENTRA_AUTHORITY"]
    for key in list(MINIMAL_ENV) + optional:
        monkeypatch.delenv(key, raising=False)
    for key, value in MINIMAL_ENV.items():
        monkeypatch.setenv(key, value)
    return monkeypatch
