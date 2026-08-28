# auth-skeleton

A FastAPI service skeleton with Microsoft Entra ID sign-in already working.

**Fork it, don't install it.** This is a starting point for a new service, not a
library. Clone it, rename it, delete what you don't need, and build on top.

Sign-in is OIDC authorization code + PKCE against Entra, using the
[BFF pattern](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps-26):
the backend runs the flow and the browser only ever holds an opaque session
cookie. No token reaches JavaScript. There are no passwords to store.

## What you get

```
GET  /auth/login    -> redirects to Entra; accepts ?next= from an allowlist
GET  /auth/callback -> completes sign-in, sets the session cookie
POST /auth/logout   -> revokes the session
GET  /auth/me       -> the current user
GET  /healthz
```

Protecting your own routes:

```python
from fastapi import APIRouter, Depends

from app.deps import CurrentUser, require_roles

router = APIRouter()


@router.get("/reports")
def reports(user: CurrentUser) -> dict[str, str]:
    return {"for": user.oid}


@router.get("/admin", dependencies=[Depends(require_roles("Admin"))])
def admin() -> dict[str, str]:
    return {"ok": "yes"}
```

Register it in `create_app()` with `app.include_router(router)`.

`require_roles` reads the Entra **app roles** captured at login. Roles are a
snapshot, not a live directory lookup, so a role change takes effect at the
user's next sign-in.

## Running it

Requires [uv](https://docs.astral.sh/uv/) and Docker.

```bash
cp .env.example .env      # fill in the Entra values
docker compose up -d --wait db   # --wait, or migrations race the database
uv sync
uv run alembic upgrade head
uv run uvicorn --app-dir src --factory app.main:create_app --port 57005
```

Tests need the database running:

```bash
uv run pytest              # unit + integration
uv run ruff check .
uv run mypy src
```

The integration suite runs `downgrade base`, so it refuses to point anywhere
but a local host. It reads `TEST_DATABASE_URL`, never `DATABASE_URL`.

## Container image

```bash
docker build -t my-service .
docker compose --profile app run --rm app alembic upgrade head
docker compose --profile app up
```

Runs as a non-root user on port 57005. **Migrations are not run on boot** — a
container that migrates as it starts races every other replica. Run
`alembic upgrade head` as a deploy step.

## Entra app registration

In the Entra admin centre, register an application and configure:

| Setting | Value |
|---|---|
| Supported account types | Single tenant |
| Redirect URI | Web -> `https://your-host/auth/callback` |
| Client secret | Create one; it goes in `ENTRA_CLIENT_SECRET` |
| App roles | Define the roles your service checks, then assign users |

Copy the directory (tenant) ID and application (client) ID into `.env`.

Roles come from **app roles**, not group claims. Groups hit an overage claim
past 200 memberships, where the token omits them and you have to call Microsoft
Graph to find out what they were.

### If `roles` comes back empty

Defining a role and assigning it are two separate blades, and the failure mode
between them is silent.

1. **App registrations -> App roles** defines the role. *Allowed member types*
   must be **Users/Groups** — set to *Applications*, it cannot be assigned to a
   person, and it will not appear in the picker in step 2.
2. **Enterprise applications -> Users and groups** assigns it. If the role is
   not selectable here, Azure assigns **Default Access** instead, which emits
   no `roles` claim at all. Check the Role column actually reads your role name.

An unassigned user gets no `roles` claim — not an empty array, the claim is
absent entirely. Nothing in the portal warns you, and the app cannot tell the
difference between "no roles" and "misconfigured".

Roles are snapshotted into the session at sign-in, so after fixing an
assignment you must sign in again; refreshing keeps the old snapshot.

## Configuration

Everything is environment variables, read once at startup. The listening
port is not among them — it comes from `--port` on the uvicorn command.

| Variable | Default | Notes |
|---|---|---|
| `ENV` | `production` | `dev`, `test`, or `production` |
| `DATABASE_URL` | — | `postgresql+psycopg://...` |
| `ENTRA_TENANT_ID` | — | Directory (tenant) ID |
| `ENTRA_CLIENT_ID` | — | Application (client) ID |
| `ENTRA_CLIENT_SECRET` | — | |
| `REDIRECT_URI` | — | Must match the app registration exactly |
| `ENTRA_AUTHORITY` | `https://login.microsoftonline.com` | Change for sovereign clouds |
| `POST_LOGIN_ALLOWLIST` | `/` | Comma-separated paths `?next=` may target |
| `SESSION_IDLE_TTL_SECONDS` | `1800` | |
| `SESSION_ABSOLUTE_TTL_SECONDS` | `28800` | Caps session life under steady use |
| `AUTH_TRANSACTION_TTL_SECONDS` | `300` | How long a login may take |
| `DEV_INSECURE_COOKIES` | `false` | See below. Refused when `ENV=production` |

`POST_LOGIN_ALLOWLIST` is the open-redirect guard: a `?next=` outside it is
rejected rather than quietly redirected. Entries must be relative paths, and
**the first entry is where login lands when no `?next=` is given** — so order
matters, and putting `/admin` first makes it everyone's landing page.

### `DEV_INSECURE_COOKIES`

Session cookies use the `__Host-` prefix, which requires `Secure`, which
requires HTTPS. Chrome (89+) and Firefox (75+) make an exception for
`http://localhost`, so local development works untouched in those.

**Safari does not.** WebKit declines to store a `Secure` cookie over plain HTTP
even on localhost, so Safari needs the flag below for local development.

The failure is silent: the browser discards the cookie, sign-in appears to
succeed, the redirect happens, and the next request is anonymous with nothing
in the logs. Set `DEV_INSECURE_COOKIES=true` for Safari, and for any plain-HTTP
host that is not localhost. Startup refuses it when `ENV=production`.

## Security checklist

- [x] `state` verified on callback **and bound to the originating browser**
      via a short-lived `__Host-login` cookie. Server-side storage alone proves
      only that the state was issued, not that it was issued to this browser —
      without the binding, an attacker can sign a victim into the attacker's
      account.
- [x] `nonce` bound and verified (token replay)
- [x] PKCE used even though this is a confidential client
- [x] JWKS refetch bounded on unknown `kid` (no unbounded fetch = DoS vector) —
      **not** given by `PyJWKClient` alone; throttled in `entra.py` and asserted
      with a fetch counter against a real JWKS server
- [x] Issuer compared by exact string, never prefix match
- [x] Session id hashed at rest — DB leak must not equal session takeover
- [x] Both idle *and* absolute session timeouts
- [x] Post-login `next` param validated against an allowlist (open redirect)
- [x] Tokens never logged

Each line is gated by a named test. If you change the auth flow, keep them
gated or delete the line honestly — a ticked box that is not enforced is worse
than no box, because it buys confidence nothing is earning.

## Forking checklist

1. Rename the project in `pyproject.toml`; the package stays `app`.
2. Point `.env` at your own Entra app registration.
3. Set `POST_LOGIN_ALLOWLIST` to the paths your UI actually lands on.
4. Add your tables to `src/app/models.py`, then
   `uv run alembic revision --autogenerate -m "..."`. **Read what it generates** —
   autogenerate misses server defaults, type changes, and constraint renames.
5. Add your routes, protecting them with `CurrentUser` or `require_roles`.
6. Before going live, sign in once against your real tenant and confirm
   `/auth/me` returns the roles you expect. The test suite uses a local issuer,
   which is real OIDC but not real Entra — and `roles` is the claim most likely
   to differ.

## Things worth knowing before you change them

**Users are keyed on `(tid, oid)`, not email.** Entra's `sub` is per-application
and email addresses get reassigned; the object ID is the stable identifier.

**Session tokens are stored as SHA-256 hashes.** A database leak should not be
enough to impersonate anyone. `create_session` returns the raw token exactly
once.

**Log redaction is a filter, not a convention.** `app/logging.py` strips
credentials from messages, arguments, and tracebacks, including uvicorn's access
log, where query strings carry the authorization code. If you add a handler, it
needs the filter.

**`EntraClient` must live for the process.** It holds the JWKS cache and the
refresh throttle. Building one per request restores the unbounded refetch those
exist to prevent. It is created once in the app factory.

**Migrations set `statement_timeout` and `lock_timeout`.** The revision template
adds them so a migration fails fast instead of blocking every reader. CI lints
rendered migration SQL with [Squawk](https://squawkhq.com/).
