# ABOUTME: End-to-end route tests against a real database and a real OIDC issuer.
# ABOUTME: Gates SPEC checklist items 1 and 8.

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlmodel import Session, delete, select
from tests.idp import FakeIdP

from app.deps import require_roles
from app.main import create_app
from app.models import AuthTransaction, User, UserSession

TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"


@pytest.fixture
def idp():
    server = FakeIdP()
    yield server
    server.stop()


@pytest.fixture
def app_client(idp, engine, monkeypatch):
    monkeypatch.setenv("ENTRA_AUTHORITY", idp.base_url)
    monkeypatch.setenv("ENTRA_TENANT_ID", TENANT)
    monkeypatch.setenv("ENTRA_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("ENTRA_CLIENT_SECRET", "secret")
    monkeypatch.setenv("REDIRECT_URI", "https://app.example/auth/callback")
    monkeypatch.setenv("POST_LOGIN_ALLOWLIST", "/,/dashboard")
    monkeypatch.setenv("ENV", "test")
    app = create_app()

    # Mounted here rather than shipped: require_roles needs a protected route
    # to exercise, but the scaffold should not carry a demo endpoint.
    @app.get("/auth/admin-only", dependencies=[Depends(require_roles("Admin"))])
    def admin_only() -> dict[str, str]:
        return {"ok": "yes"}

    # https, not the default http: the session cookie is Secure, and a client
    # on http silently declines to store it -- the same failure a plain-HTTP
    # dev host hits.
    with TestClient(app, base_url="https://testserver", follow_redirects=False) as client:
        yield client
    with Session(engine) as cleanup:
        for model in (UserSession, AuthTransaction, User):
            cleanup.execute(delete(model))
        cleanup.commit()


def id_token_claims(idp, nonce, **overrides):
    now = datetime.now(UTC)
    return {
        "iss": f"{idp.base_url}/{TENANT}/v2.0",
        "aud": CLIENT_ID,
        "exp": now + timedelta(minutes=5),
        "nbf": now,
        "sub": "subject",
        "oid": "user-object-id",
        "tid": TENANT,
        "nonce": nonce,
        "roles": ["Clinician"],
        "email": "someone@example.com",
        "name": "Someone",
        **overrides,
    }


def start_login(client, engine, next_path=None):
    """Drive /auth/login and return (state, nonce) from the stored transaction."""
    url = "/auth/login" + (f"?next={next_path}" if next_path else "")
    response = client.get(url)
    assert response.status_code == 302
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    with Session(engine) as db:
        row = db.exec(select(AuthTransaction).where(AuthTransaction.state == state)).one()
        return state, row.nonce


# --- login --------------------------------------------------------------


def test_login_redirects_to_the_issuer_with_pkce(app_client, engine, idp):
    response = app_client.get("/auth/login")
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert response.status_code == 302
    assert query["code_challenge_method"] == ["S256"]
    assert query["client_id"] == [CLIENT_ID]


def test_login_persists_the_transaction(app_client, engine):
    start_login(app_client, engine)
    with Session(engine) as db:
        assert len(db.exec(select(AuthTransaction)).all()) == 1


def test_login_rejects_an_absolute_next(app_client):
    """The allowlist is the open-redirect guard."""
    assert app_client.get("/auth/login?next=https://evil.example").status_code == 400


def test_login_rejects_a_protocol_relative_next(app_client):
    assert app_client.get("/auth/login?next=//evil.example").status_code == 400


def test_login_rejects_a_path_outside_the_allowlist(app_client):
    assert app_client.get("/auth/login?next=/secret-admin").status_code == 400


def test_login_accepts_an_allowlisted_next(app_client):
    assert app_client.get("/auth/login?next=/dashboard").status_code == 302


# --- callback -----------------------------------------------------------


def test_callback_signs_the_user_in(app_client, engine, idp):
    state, nonce = start_login(app_client, engine, next_path="/dashboard")
    idp.token_response = {"id_token": idp.sign(id_token_claims(idp, nonce))}

    response = app_client.get(f"/auth/callback?code=the-code&state={state}")
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert "__Host-session" in response.headers["set-cookie"]

    with Session(engine) as db:
        user = db.exec(select(User)).one()
        assert (user.tid, user.oid) == (TENANT, "user-object-id")
        assert db.exec(select(UserSession)).one().roles == ["Clinician"]


def test_callback_sets_a_hardened_cookie(app_client, engine, idp):
    state, nonce = start_login(app_client, engine)
    idp.token_response = {"id_token": idp.sign(id_token_claims(idp, nonce))}
    cookie = app_client.get(f"/auth/callback?code=c&state={state}").headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=lax" in cookie.replace("samesite", "SameSite")
    assert "Path=/" in cookie


def test_callback_rejects_an_unknown_state(app_client, engine, idp):
    assert app_client.get("/auth/callback?code=c&state=never-issued").status_code == 400


def test_callback_rejects_a_replayed_state(app_client, engine, idp):
    """Single-use: the second presentation of a state must fail."""
    state, nonce = start_login(app_client, engine)
    idp.token_response = {"id_token": idp.sign(id_token_claims(idp, nonce))}
    assert app_client.get(f"/auth/callback?code=c&state={state}").status_code == 303
    assert app_client.get(f"/auth/callback?code=c&state={state}").status_code == 400


def test_callback_rejects_an_expired_transaction(app_client, engine, idp):
    state, nonce = start_login(app_client, engine)
    with Session(engine) as db:
        row = db.exec(select(AuthTransaction).where(AuthTransaction.state == state)).one()
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.add(row)
        db.commit()
    assert app_client.get(f"/auth/callback?code=c&state={state}").status_code == 400


def test_callback_rejects_a_mismatched_nonce(app_client, engine, idp):
    state, _ = start_login(app_client, engine)
    idp.token_response = {"id_token": idp.sign(id_token_claims(idp, "someone-elses-nonce"))}
    assert app_client.get(f"/auth/callback?code=c&state={state}").status_code == 400


def test_callback_surfaces_a_token_endpoint_failure_as_400(app_client, engine, idp):
    """An upstream refusal is not our internal error."""
    state, _ = start_login(app_client, engine)
    idp.token_status = 400
    idp.token_response = {"error": "invalid_grant"}
    assert app_client.get(f"/auth/callback?code=c&state={state}").status_code == 400


def test_callback_passes_through_an_identity_provider_error(app_client):
    assert app_client.get("/auth/callback?error=access_denied&state=x").status_code == 400


def test_repeat_login_updates_rather_than_duplicates_the_user(app_client, engine, idp):
    for _ in range(2):
        state, nonce = start_login(app_client, engine)
        idp.token_response = {"id_token": idp.sign(id_token_claims(idp, nonce))}
        app_client.get(f"/auth/callback?code=c&state={state}")
    with Session(engine) as db:
        assert len(db.exec(select(User)).all()) == 1


# --- me, logout, roles --------------------------------------------------


def sign_in(client, engine, idp, roles=("Clinician",)):
    state, nonce = start_login(client, engine)
    idp.token_response = {"id_token": idp.sign(id_token_claims(idp, nonce, roles=list(roles)))}
    client.get(f"/auth/callback?code=c&state={state}")


def test_me_requires_a_session(app_client):
    assert app_client.get("/auth/me").status_code == 401


def test_me_returns_only_the_declared_fields(app_client, engine, idp):
    sign_in(app_client, engine, idp)
    body = app_client.get("/auth/me").json()
    assert set(body) == {"oid", "email", "display_name", "roles"}
    assert body["oid"] == "user-object-id"


def test_me_rejects_a_forged_cookie(app_client):
    app_client.cookies.set("__Host-session", "made-up-token")
    assert app_client.get("/auth/me").status_code == 401


def test_logout_revokes_the_session(app_client, engine, idp):
    sign_in(app_client, engine, idp)
    assert app_client.post("/auth/logout").status_code == 204
    assert app_client.get("/auth/me").status_code == 401
    with Session(engine) as db:
        assert db.exec(select(UserSession)).all() == []


def test_logout_without_a_session_is_not_an_error(app_client):
    assert app_client.post("/auth/logout").status_code == 204


def test_require_roles_allows_a_matching_role(app_client, engine, idp):
    sign_in(app_client, engine, idp, roles=("Admin",))
    assert app_client.get("/auth/admin-only").status_code == 200


def test_require_roles_denies_a_missing_role(app_client, engine, idp):
    sign_in(app_client, engine, idp, roles=("Clinician",))
    assert app_client.get("/auth/admin-only").status_code == 403


def test_require_roles_denies_an_anonymous_caller(app_client):
    assert app_client.get("/auth/admin-only").status_code == 401


def test_dev_insecure_cookies_drop_the_host_prefix(idp, engine, monkeypatch):
    """The escape hatch for plain-HTTP dev hosts. `__Host-` requires Secure,
    and a browser silently drops such a cookie over http, so login appears to
    succeed and then fails with nothing in the logs."""
    monkeypatch.setenv("ENTRA_AUTHORITY", idp.base_url)
    monkeypatch.setenv("ENTRA_TENANT_ID", TENANT)
    monkeypatch.setenv("ENTRA_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("ENTRA_CLIENT_SECRET", "secret")
    monkeypatch.setenv("REDIRECT_URI", "http://localhost:57005/auth/callback")
    monkeypatch.setenv("ENV", "dev")
    monkeypatch.setenv("DEV_INSECURE_COOKIES", "true")

    with TestClient(create_app(), follow_redirects=False) as client:
        state, nonce = start_login(client, engine)
        idp.token_response = {"id_token": idp.sign(id_token_claims(idp, nonce))}
        cookie = client.get(f"/auth/callback?code=c&state={state}").headers["set-cookie"]
        assert cookie.startswith("session=")
        assert "Secure" not in cookie
        # Still hardened in every way that does not require HTTPS.
        assert "HttpOnly" in cookie

        assert client.get("/auth/me").status_code == 200

    with Session(engine) as cleanup:
        for model in (UserSession, AuthTransaction, User):
            cleanup.execute(delete(model))
        cleanup.commit()
