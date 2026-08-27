# ABOUTME: Tests for Entra endpoint templating, PKCE, code exchange, and ID token validation.
# ABOUTME: The negative cases are the deliverable; they gate SPEC checklist items 2-5.

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from tests.idp import KID, FakeIdP

from app.config import Settings
from app.entra import EntraClient, TokenExchangeError, TokenValidationError, new_pkce_pair

TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT = "22222222-2222-2222-2222-222222222222"
NONCE = "nonce-value"


@pytest.fixture
def idp():
    server = FakeIdP()
    yield server
    server.stop()


@pytest.fixture
def client(idp, env):
    env.setenv("ENTRA_AUTHORITY", idp.base_url)
    env.setenv("ENTRA_TENANT_ID", TENANT)
    env.setenv("ENTRA_CLIENT_ID", CLIENT)
    return EntraClient(Settings())


def claims(idp, **overrides):
    now = datetime.now(UTC)
    base = {
        "iss": f"{idp.base_url}/{TENANT}/v2.0",
        "aud": CLIENT,
        "exp": now + timedelta(minutes=5),
        "nbf": now,
        "iat": now,
        "sub": "pairwise-subject",
        "oid": "object-id",
        "tid": TENANT,
        "nonce": NONCE,
        "roles": ["Clinician"],
        "email": "someone@example.com",
        "name": "Someone",
    }
    return {**base, **overrides}


# --- endpoints and PKCE -------------------------------------------------


def test_endpoints_are_templated_from_the_tenant(client):
    assert client.endpoints.issuer.endswith(f"/{TENANT}/v2.0")
    assert client.endpoints.jwks.endswith("/discovery/v2.0/keys")
    assert TENANT in client.endpoints.token


def test_pkce_challenge_is_the_s256_of_the_verifier():
    import base64
    import hashlib

    verifier, challenge = new_pkce_pair()
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    assert challenge == expected.decode()


def test_pkce_verifiers_are_not_reused():
    assert new_pkce_pair()[0] != new_pkce_pair()[0]


def test_authorization_url_carries_state_nonce_and_challenge(client):
    _, challenge = new_pkce_pair()
    query = parse_qs(urlparse(client.authorization_url("st", NONCE, challenge)).query)
    assert query["state"] == ["st"]
    assert query["nonce"] == [NONCE]
    assert query["code_challenge"] == [challenge]
    assert query["code_challenge_method"] == ["S256"]
    assert query["response_type"] == ["code"]


# --- ID token validation: the happy path --------------------------------


def test_valid_token_yields_the_identity(client, idp):
    identity = client.validate_id_token(idp.sign(claims(idp)), expected_nonce=NONCE)
    assert (identity.tid, identity.oid) == (TENANT, "object-id")
    assert identity.roles == ["Clinician"]


def test_roles_default_to_empty_when_the_claim_is_absent(client, idp):
    token = idp.sign(claims(idp, roles=None))
    assert client.validate_id_token(token, expected_nonce=NONCE).roles == []


# --- ID token validation: the negative cases ----------------------------


def test_rejects_a_token_signed_by_another_key(client, idp):
    other = FakeIdP(use_other_key=True)
    try:
        token = other.sign(claims(idp))
    finally:
        other.stop()
    with pytest.raises(TokenValidationError):
        client.validate_id_token(token, expected_nonce=NONCE)


def test_rejects_issuer_prefix_attack(client, idp):
    """`iss` must match exactly. A prefix comparison would accept this."""
    token = idp.sign(claims(idp, iss=f"{idp.base_url}/{TENANT}/v2.0.evil.example"))
    with pytest.raises(TokenValidationError):
        client.validate_id_token(token, expected_nonce=NONCE)


def test_rejects_another_tenants_issuer(client, idp):
    other_tenant = "99999999-9999-9999-9999-999999999999"
    token = idp.sign(claims(idp, iss=f"{idp.base_url}/{other_tenant}/v2.0"))
    with pytest.raises(TokenValidationError):
        client.validate_id_token(token, expected_nonce=NONCE)


def test_rejects_a_token_for_another_audience(client, idp):
    with pytest.raises(TokenValidationError):
        client.validate_id_token(idp.sign(claims(idp, aud="someone-else")), expected_nonce=NONCE)


def test_rejects_an_expired_token(client, idp):
    token = idp.sign(claims(idp, exp=datetime.now(UTC) - timedelta(seconds=1)))
    with pytest.raises(TokenValidationError):
        client.validate_id_token(token, expected_nonce=NONCE)


def test_rejects_a_token_not_yet_valid(client, idp):
    token = idp.sign(claims(idp, nbf=datetime.now(UTC) + timedelta(minutes=10)))
    with pytest.raises(TokenValidationError):
        client.validate_id_token(token, expected_nonce=NONCE)


def test_rejects_a_mismatched_nonce(client, idp):
    """Binds the token to this login. Without it a token captured elsewhere
    replays into our callback."""
    with pytest.raises(TokenValidationError):
        client.validate_id_token(idp.sign(claims(idp)), expected_nonce="a-different-nonce")


def test_rejects_a_missing_nonce(client, idp):
    token = idp.sign(claims(idp, nonce=None))
    with pytest.raises(TokenValidationError):
        client.validate_id_token(token, expected_nonce=NONCE)


def test_rejects_alg_none(client, idp):
    token = idp.sign(claims(idp), algorithm="none")
    with pytest.raises(TokenValidationError):
        client.validate_id_token(token, expected_nonce=NONCE)


def test_rejects_hs256_signed_with_the_public_key(client, idp):
    """The classic key-confusion attack: sign with the public key as an HMAC
    secret and hope the verifier picks the algorithm from the header."""
    import base64
    import hashlib
    import hmac
    import json

    from cryptography.hazmat.primitives import serialization

    public_pem = idp.key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    def b64(raw: bytes) -> bytes:
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    payload = claims(idp)
    for field in ("exp", "nbf", "iat"):
        payload[field] = int(payload[field].timestamp())

    # Forged by hand: PyJWT refuses to encode with an asymmetric key as an
    # HMAC secret, but an attacker is under no such constraint.
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode())
    body = b64(json.dumps(payload).encode())
    signing_input = header + b"." + body
    signature = b64(hmac.new(public_pem, signing_input, hashlib.sha256).digest())
    token = (signing_input + b"." + signature).decode()

    with pytest.raises(TokenValidationError):
        client.validate_id_token(token, expected_nonce=NONCE)


def test_rejects_a_token_missing_required_claims(client, idp):
    token = idp.sign({k: v for k, v in claims(idp).items() if k != "oid"})
    with pytest.raises(TokenValidationError):
        client.validate_id_token(token, expected_nonce=NONCE)


# --- JWKS fetching ------------------------------------------------------


def test_jwks_is_cached_across_validations(client, idp):
    for _ in range(5):
        client.validate_id_token(idp.sign(claims(idp)), expected_nonce=NONCE)
    assert idp.jwks_fetches == 1


def test_unknown_kid_does_not_refetch_without_bound(client, idp):
    """An attacker sending random `kid` values must not drive one outbound
    request per token."""
    client.validate_id_token(idp.sign(claims(idp)), expected_nonce=NONCE)
    baseline = idp.jwks_fetches
    for index in range(25):
        with pytest.raises(TokenValidationError):
            client.validate_id_token(
                idp.sign(claims(idp), kid=f"unknown-{index}"), expected_nonce=NONCE
            )
    assert idp.jwks_fetches - baseline <= 1


# --- code exchange ------------------------------------------------------


def test_code_exchange_sends_pkce_verifier_and_secret(client, idp):
    idp.token_response = {"id_token": "x", "access_token": "y"}
    client.exchange_code("the-code", "the-verifier")
    sent = idp.last_token_request
    assert sent["code"] == "the-code"
    assert sent["code_verifier"] == "the-verifier"
    assert sent["grant_type"] == "authorization_code"
    assert "client_secret" in sent


def test_code_exchange_returns_the_id_token(client, idp):
    idp.token_response = {"id_token": "the-id-token"}
    assert client.exchange_code("c", "v") == "the-id-token"


def test_code_exchange_raises_on_error_response(client, idp):
    idp.token_status = 400
    idp.token_response = {"error": "invalid_grant"}
    with pytest.raises(TokenExchangeError):
        client.exchange_code("c", "v")


def test_code_exchange_raises_when_id_token_is_absent(client, idp):
    idp.token_response = {"access_token": "only-this"}
    with pytest.raises(TokenExchangeError):
        client.exchange_code("c", "v")


# --- regressions from review --------------------------------------------


def test_non_ascii_nonce_is_rejected_not_crashed(client, idp):
    """`secrets.compare_digest` raises TypeError on non-ASCII str. The claim is
    attacker-influenced, so that would be an uncaught 500 on an unauthenticated
    path rather than a rejection."""
    token = idp.sign(claims(idp, nonce="n\u00f6nce"))
    with pytest.raises(TokenValidationError):
        client.validate_id_token(token, expected_nonce=NONCE)


def test_empty_expected_nonce_is_refused(client, idp):
    """Fails closed: an empty expected nonce must not match anything."""
    with pytest.raises(TokenValidationError):
        client.validate_id_token(idp.sign(claims(idp)), expected_nonce="")


def test_rejects_a_token_for_another_tenant(client, idp):
    token = idp.sign(claims(idp, tid="99999999-9999-9999-9999-999999999999"))
    with pytest.raises(TokenValidationError):
        client.validate_id_token(token, expected_nonce=NONCE)


def test_redirect_uri_comes_from_settings(client, idp):
    """RFC 6749 requires the token request to echo the authorize request's
    redirect_uri exactly; two sources invite a silent invalid_grant."""
    from urllib.parse import parse_qs, unquote, urlparse

    idp.token_response = {"id_token": "x"}
    client.exchange_code("c", "v")
    authorized = parse_qs(urlparse(client.authorization_url("s", NONCE, "ch")).query)
    assert unquote(idp.last_token_request["redirect_uri"]) == authorized["redirect_uri"][0]


def test_non_json_token_response_raises_exchange_error(client, idp):
    idp.serve_html_token_response = True
    with pytest.raises(TokenExchangeError):
        client.exchange_code("c", "v")


def test_refresh_throttle_starts_unset(client):
    """A monotonic() baseline of 0.0 would skip the first refresh on a host
    that booted less than the interval ago."""
    assert client._last_jwks_refresh == float("-inf")
