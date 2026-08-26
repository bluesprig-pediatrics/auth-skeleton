# ABOUTME: Tests for settings validation.
# ABOUTME: Covers required fields and the production guard on insecure cookies.

import pytest
from pydantic import ValidationError

from app.config import Settings


def test_missing_required_field_raises(env):
    env.delenv("ENTRA_CLIENT_SECRET")
    with pytest.raises(ValidationError):
        Settings()


def test_defaults_to_host_prefixed_secure_cookie(env):
    settings = Settings()
    assert settings.cookie_name == "__Host-session"
    assert settings.cookie_secure is True


def test_dev_insecure_cookies_rejected_in_production(env):
    env.setenv("DEV_INSECURE_COOKIES", "true")
    with pytest.raises(ValidationError, match="DEV_INSECURE_COOKIES"):
        Settings()


def test_dev_insecure_cookies_drops_prefix_outside_production(env):
    env.setenv("ENV", "dev")
    env.setenv("DEV_INSECURE_COOKIES", "true")
    settings = Settings()
    assert settings.cookie_name == "session"
    assert settings.cookie_secure is False


def test_post_login_allowlist_defaults_to_root(env):
    assert Settings().post_login_allowlist == ["/"]


def test_post_login_allowlist_accepts_comma_separated(env):
    env.setenv("POST_LOGIN_ALLOWLIST", "/home, /dashboard")
    assert Settings().post_login_allowlist == ["/home", "/dashboard"]
