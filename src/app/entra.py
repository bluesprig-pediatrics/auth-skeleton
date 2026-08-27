# ABOUTME: Microsoft Entra ID OIDC client: PKCE, code exchange, ID token validation.
# ABOUTME: Endpoints are templated from the tenant id; no discovery document is fetched.

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWKClient

from app.config import Settings

SIGNING_ALGORITHMS = ["RS256"]

# PyJWKClient caches the key set, but on an unknown `kid` it refetches every
# time -- measured, not assumed. Unbounded, that is one outbound request per
# forged token. Refreshes are throttled to this interval instead.
JWKS_REFRESH_INTERVAL_SECONDS = 300

# Without `aud` and `iss` here, a token missing the claim entirely skips the
# corresponding check instead of failing it.
REQUIRED_CLAIMS = ["exp", "nbf", "iss", "aud", "sub", "oid", "tid", "nonce"]


class TokenExchangeError(Exception):
    """The authorization code could not be exchanged."""


class TokenValidationError(Exception):
    """The ID token is not one we will accept."""


@dataclass(frozen=True)
class Endpoints:
    authorize: str
    token: str
    jwks: str
    issuer: str


@dataclass(frozen=True)
class Identity:
    """The subset of an ID token we trust and store."""

    tid: str
    oid: str
    email: str | None
    display_name: str | None
    roles: list[str]


def endpoints_for(authority: str, tenant_id: str) -> Endpoints:
    base = f"{authority.rstrip('/')}/{tenant_id}"
    return Endpoints(
        authorize=f"{base}/oauth2/v2.0/authorize",
        token=f"{base}/oauth2/v2.0/token",
        jwks=f"{base}/discovery/v2.0/keys",
        issuer=f"{base}/v2.0",
    )


def new_pkce_pair() -> tuple[str, str]:
    """Return (verifier, S256 challenge), per RFC 7636."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class EntraClient:
    """Holds the JWKS cache and the refresh throttle.

    Must live for the process, not per request: both bounds are instance
    state, and rebuilding this per request restores the unbounded refetch it
    exists to prevent. The app factory stores one on `app.state`.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.endpoints = endpoints_for(settings.entra_authority, settings.entra_tenant_id)
        # `lifespan` bounds how long a *known* key set is reused. It does not
        # bound refetching on an unknown kid -- see _signing_key.
        self._jwks = PyJWKClient(
            self.endpoints.jwks,
            cache_jwk_set=True,
            lifespan=JWKS_REFRESH_INTERVAL_SECONDS,
            max_cached_keys=16,
            timeout=10,
        )
        # -inf, not 0.0: monotonic() is uptime on Linux and macOS, so a
        # process starting within the interval of boot would skip its first
        # refresh and reject a genuine key rotation.
        self._last_jwks_refresh = float("-inf")

    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        query = urlencode(
            {
                "client_id": self._settings.entra_client_id,
                "response_type": "code",
                "redirect_uri": self._settings.redirect_uri,
                "response_mode": "query",
                "scope": "openid profile email",
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{self.endpoints.authorize}?{query}"

    def exchange_code(self, code: str, code_verifier: str) -> str:
        """Trade the authorization code for an ID token. Confidential client:
        the secret goes with it, and PKCE is used regardless."""
        try:
            response = httpx.post(
                self.endpoints.token,
                data={
                    "client_id": self._settings.entra_client_id,
                    "client_secret": self._settings.entra_client_secret,
                    "grant_type": "authorization_code",
                    "code": code,
                    # Same source as authorization_url: RFC 6749 requires the
                    # two to be identical, and a mismatch surfaces only as an
                    # opaque invalid_grant.
                    "redirect_uri": self._settings.redirect_uri,
                    "code_verifier": code_verifier,
                },
                timeout=10,
            )
        except httpx.HTTPError as error:
            raise TokenExchangeError("token endpoint unreachable") from error

        if response.status_code != 200:
            # The body echoes the code; keep it out of the message.
            raise TokenExchangeError(f"token endpoint returned {response.status_code}")

        try:
            body = response.json()
        except ValueError as error:
            # A captive portal or WAF answering 200 with HTML is not an HTTPError.
            raise TokenExchangeError("token endpoint returned a non-JSON body") from error
        if not isinstance(body, dict):
            raise TokenExchangeError("token endpoint returned an unexpected body")

        id_token = body.get("id_token")
        if not id_token:
            raise TokenExchangeError("token response carried no id_token")
        return str(id_token)

    def _signing_key(self, id_token: str) -> Any:
        """Resolve the signing key, refreshing at most once per interval.

        Deliberately not `get_signing_key_from_jwt`: that refetches the key set
        on every unrecognised `kid`, so a stream of forged tokens becomes a
        stream of outbound requests.
        """
        kid = jwt.get_unverified_header(id_token).get("kid")
        if not kid:
            raise TokenValidationError("id token rejected: no kid in header")

        for key in self._jwks.get_jwk_set().keys:
            if key.key_id == kid:
                return key

        now = time.monotonic()
        if now - self._last_jwks_refresh < JWKS_REFRESH_INTERVAL_SECONDS:
            raise TokenValidationError("id token rejected: unknown kid")
        self._last_jwks_refresh = now

        for key in self._jwks.get_jwk_set(refresh=True).keys:
            if key.key_id == kid:
                return key
        raise TokenValidationError("id token rejected: unknown kid")

    def validate_id_token(self, id_token: str, *, expected_nonce: str) -> Identity:
        if not expected_nonce:
            # Fail closed. An empty expected nonce would otherwise match an
            # empty claim and silently disable the replay guard.
            raise TokenValidationError("id token rejected: no nonce to compare against")

        try:
            signing_key = self._signing_key(id_token)
            claims: dict[str, Any] = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=SIGNING_ALGORITHMS,
                audience=self._settings.entra_client_id,
                issuer=self.endpoints.issuer,
                options={"require": REQUIRED_CLAIMS},
            )
        except TokenValidationError:
            raise
        except Exception as error:
            # Includes PyJWKClientError for an unknown kid. The token is not
            # logged: it is a bearer credential.
            raise TokenValidationError(f"id token rejected: {type(error).__name__}") from error

        # PyJWT has no notion of nonce; this is what binds the token to the
        # login we started, so a token captured elsewhere cannot be replayed.
        # Compared as bytes: compare_digest raises TypeError on a non-ASCII
        # str, and the claim is attacker-influenced.
        if not secrets.compare_digest(str(claims["nonce"]).encode(), expected_nonce.encode()):
            raise TokenValidationError("id token rejected: nonce mismatch")

        # Defence in depth. Exact issuer matching already pins the tenant, but
        # Identity.tid is stored and used downstream, so verify what we keep.
        if claims["tid"] != self._settings.entra_tenant_id:
            raise TokenValidationError("id token rejected: unexpected tenant")

        return Identity(
            tid=str(claims["tid"]),
            oid=str(claims["oid"]),
            email=claims.get("email"),
            display_name=claims.get("name"),
            roles=list(claims.get("roles") or []),
        )
