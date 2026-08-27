# ABOUTME: Application settings loaded from the environment.
# ABOUTME: Cookie name and Secure flag derive from one dev-only escape hatch.

from typing import Annotated, Literal, Self

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: Literal["dev", "test", "production"] = "production"
    database_url: str
    port: int = 57005

    # Overridable for sovereign clouds (US Gov, China) and for tests, which
    # point it at a local issuer.
    entra_authority: str = "https://login.microsoftonline.com"
    entra_tenant_id: str
    entra_client_id: str
    entra_client_secret: str
    redirect_uri: str

    # NoDecode: without it the settings source JSON-decodes this before any
    # validator runs, and a comma-separated value dies as a decode error.
    post_login_allowlist: Annotated[list[str], NoDecode] = ["/"]

    @field_validator("post_login_allowlist", mode="before")
    @classmethod
    def _split_comma_separated(cls, value: object) -> object:
        """Comma-separated, not JSON: shell and container env vars mangle the
        quotes a JSON array needs, and the failure is a startup crash."""
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("post_login_allowlist", mode="after")
    @classmethod
    def _require_relative_paths(cls, value: list[str]) -> list[str]:
        """This list is the open-redirect guard. An absolute or
        protocol-relative entry turns the guard into the vulnerability."""
        for item in value:
            if not item.startswith("/") or item.startswith("//"):
                raise ValueError(f"post_login_allowlist entry {item!r} must be a relative path")
        return value

    session_idle_ttl_seconds: int = 60 * 30
    session_absolute_ttl_seconds: int = 60 * 60 * 8
    auth_transaction_ttl_seconds: int = 60 * 5

    # `__Host-` requires Secure, which requires HTTPS. Browsers permit it on
    # http://localhost but silently drop the cookie on any other plain-HTTP
    # host, so dev setups off localhost need the prefix gone.
    dev_insecure_cookies: bool = False

    @model_validator(mode="after")
    def _forbid_insecure_cookies_in_production(self) -> Self:
        if self.dev_insecure_cookies and self.env == "production":
            raise ValueError("DEV_INSECURE_COOKIES must not be set when ENV=production")
        return self

    @property
    def cookie_secure(self) -> bool:
        return not self.dev_insecure_cookies

    @property
    def cookie_name(self) -> str:
        return "session" if self.dev_insecure_cookies else "__Host-session"

