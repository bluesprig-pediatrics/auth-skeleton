# auth-skeleton

A FastAPI service skeleton with Microsoft Entra ID sign-in already working.

**Fork it, don't install it.** This is a starting point for a new service, not a
library. Clone it, rename it, delete what you don't need, and build on top.

Sign-in is OIDC authorization code + PKCE against Entra, using the
[BFF pattern](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps-26):
the backend runs the flow and the browser only ever holds an opaque session
cookie. No token reaches JavaScript. There are no passwords to store.

See [docs/SPEC.md](docs/SPEC.md) for the design and the reasoning behind it.

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
from app.deps import CurrentUser, require_roles

@app.get("/reports")
def reports(user: CurrentUser) -> ...:
    return ...

@app.get("/admin", dependencies=[Depends(require_roles("Admin"))])
def admin() -> ...:
    return ...
```

`require_roles` reads the Entra **app roles** captured at login. Roles are a
snapshot, not a live directory lookup, so a role change takes effect at the
user's next sign-in.

## Running it

Requires [uv](https://docs.astral.sh/uv/) and Docker.

```bash
cp .env.example .env      # fill in the Entra values
docker compose up -d db
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

## Configuration

Everything is environment variables, read once at startup.

| Variable | Default | Notes |
|---|---|---|
| `ENV` | `production` | `dev`, `test`, or `production` |
| `DATABASE_URL` | — | `postgresql+psycopg://...` |
| `PORT` | `57005` | |
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
rejected rather than quietly redirected. Entries must be relative paths.

### `DEV_INSECURE_COOKIES`

Session cookies use the `__Host-` prefix, which requires `Secure`, which
requires HTTPS. Browsers make an exception for `http://localhost`, so normal
local development works untouched.

On any *other* plain-HTTP host the browser silently discards the cookie: sign-in
appears to succeed, the redirect happens, and the next request is anonymous,
with nothing in the logs. Set `DEV_INSECURE_COOKIES=true` there. Startup refuses
it when `ENV=production`.

## Forking checklist

1. Rename the project in `pyproject.toml`; the package stays `app`.
2. Point `.env` at your own Entra app registration.
3. Set `POST_LOGIN_ALLOWLIST` to the paths your UI actually lands on.
4. Add your tables to `src/app/models.py`, then
   `uv run alembic revision --autogenerate -m "..."`. **Read what it generates** —
   autogenerate misses server defaults, type changes, and constraint renames.
5. Add your routes, protecting them with `CurrentUser` or `require_roles`.
6. Before going live, sign in once against your real tenant. The test suite uses
   a local issuer, which is real OIDC but not real Entra.

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
