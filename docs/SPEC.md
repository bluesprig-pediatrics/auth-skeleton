# auth-skeleton — Specification

A reusable FastAPI auth scaffold. Forked per service, not installed as a 
package.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Delivery | Template repo, forked per service | No packaging work; no propagation of fixes to existing forks (accepted) |
| Identity provider | Microsoft Entra ID, single tenant | Issuer validation is an exact string match |
| Flow | OIDC Authorization Code + PKCE, confidential client | BFF pattern per `draft-ietf-oauth-browser-based-apps-26` (BCP, in RFC Editor queue) |
| Browser session | Opaque session id in `__Host-` cookie, server-side session table | Tokens never reach the browser |
| Authorization | Entra **app roles** (`roles` claim) | App-scoped; no Graph call; no group-overage footgun |
| Local credentials | **None** | No password table, no `pwdlib`, no Argon2 |
| DB driver | `psycopg[binary]`, sync sessions | Matches `full-stack-fastapi-template`; SQLModel's async path is less exercised. `httpx` stays the only async surface. |
| Port | **57005** (`0xDEAD`) | Thematic, memorable |
| ORM / models | `sqlmodel` | FastAPI-native idiom, consistent across BlueSprig services. Accepted trade: pins `SQLAlchemy<2.1.0`, so SQLAlchemy upgrades follow SQLModel's schedule. |
| Migrations | `alembic` | Actively maintained (1.19.1, Aug 2026); pure Python, no extra binary. Atlas is stronger for large/polyglot schemas but adds a Go binary to every fork for a three-table schema. |
| Migration linting | `squawk-cli` in CI | Catches locking/unsafe DDL before it reaches production. Ships as a PyPI wheel, so no extra toolchain. |
| JWT library | `PyJWT[crypto]` | `python-jose` is unmaintained with vulnerable deps; FastAPI moved to PyJWT |
| OIDC client | `httpx` + `PyJWT` directly, **not MSAL** | MSAL's value is token caching for Graph calls; app roles mean no Graph. Reversible if Graph access is ever needed. |
| JWKS handling | `jwt.PyJWKClient`, with our own refresh throttle | PyJWT ships fetch, `kid` lookup, and caching. It does **not** bound refetching: measured, an unknown `kid` triggers a fetch every time, so a stream of forged tokens is a stream of outbound requests. We resolve the key against the cached set and refresh at most once per interval. |
| Authority | `entra_authority` setting, default `login.microsoftonline.com` | Sovereign clouds (US Gov, China) use different hosts, and tests point it at a local issuer. |
| Endpoint discovery | **Skipped.** URLs derived from tenant id | Entra's v2.0 endpoints are stable and templated on `{tid}`. Fetching the discovery document adds a network call, a cache, and failure modes to learn three known strings. |

## Layout

```
src/app/
  main.py            # app factory
  config.py          # pydantic-settings; tenant id, client id/secret, cookie flags
  db.py              # engine + session (sync)
  models.py          # User, UserSession, AuthTransaction
  entra.py           # code exchange + ID token validation (JWKS via PyJWKClient)
  session.py         # create / look up / revoke
  routes.py          # /auth/login, /auth/callback, /auth/logout, /auth/me
  deps.py            # current_user, require_roles(...)
tests/{unit,integration,e2e}/
alembic/
```

## Flow

1. `GET /auth/login` — generate `state`, `nonce`, PKCE verifier; persist as an
   `AuthTransaction` row with a short TTL; set `state` in a short-lived
   `__Host-login` cookie (`SameSite=Lax`, so it survives the top-level
   navigation back); 302 to Entra `/authorize`. Also sweeps expired rows.
2. `GET /auth/callback` — require the `__Host-login` cookie to match the
   `state` query parameter, then look up the `AuthTransaction` and consume it
   (single-use); exchange `code` + verifier + client secret at `/token`.
3. Validate ID token — JWKS signature (kid lookup), `iss` exact match on `https://login.microsoftonline.com/{tid}/v2.0`, `aud == client_id`, `exp`/`nbf`, `nonce` match.
4. Upsert `User` keyed on `(tid, oid)`. Email/display name stored as non-authoritative cache.
5. Create `UserSession`: 256-bit random id, **SHA-256 hashed at rest**, idle + absolute timeouts, roles snapshot from `roles` claim. Set `__Host-session` cookie: HttpOnly, Secure, SameSite=Lax.
6. `current_user` dependency resolves cookie -> session -> user; `require_roles` checks the snapshot.
7. `POST /auth/logout` — delete session row, clear cookie.

No session rotation: a session is created at login and revoked at logout, and
there is no pre-authentication session to fix. Absolute expiry bounds its life.

## Security checklist (the things scaffolds get wrong)

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

## Migrations

Alembic, standard versioned scripts, autogenerated from the SQLModel `table=True`
models. `alembic/env.py` must `import` the models module and set
`target_metadata = SQLModel.metadata`, or autogenerate produces empty revisions.

**Required SQLModel wiring** (otherwise the first revision fails with
`NameError: name 'sqlmodel' is not defined`): SQLModel maps `str` to its own
`AutoString`, which Alembic writes into revisions without importing.

- `alembic/script.py.mako` -> add `import sqlmodel.sql.sqltypes`
- `alembic/env.py` -> `context.configure(..., user_module_prefix="sqlmodel.sql.sqltypes.")`

Pairing confirmed against `fastapi/full-stack-fastapi-template`, which uses
`sqlmodel` + `alembic` (and independently confirms `pyjwt`).

### Linting

Squawk lints SQL; Alembic revisions are Python. CI renders them first:

```
alembic upgrade <base>:<head> --sql | squawk
```

Fails the build on locking or otherwise unsafe DDL — the failure mode that
matters once a forked service is carrying real data.

**Autogenerate is a draft, not an oracle.** It misses server defaults, some type
changes, constraint renames, and enum alterations. Every generated revision gets
read before it is committed.

## Model layer rules (SQLModel)

Because `table=True` classes are also Pydantic models, they are trivially
serializable — which is the risk, not the feature.

- **No `table=True` model is ever returned from a route.** Every endpoint
  declares an explicit `response_model` built from a non-table schema class.
- `UserSession` in particular holds the hashed session id and roles snapshot;
  serializing it is a security bug, not a style issue.
- Table classes live in `models.py`; API schemas live beside their routes.

## Why `UserSession`, not `Session`

`Session` is sqlmodel's database session. Every module that touches both would
need an alias, and the one that forgets picks up a confusing error. Tables are
`app_user`, `user_session`, and `auth_transaction` — `user` is reserved in
Postgres and would need quoting in every hand-written query.

## The `AuthTransaction` table

`state`, `nonce`, and the PKCE verifier must survive the redirect to Entra and
back. They are stored server-side rather than in a signed cookie, so the browser
holds nothing but an opaque `state` value — consistent with the BFF posture that
keeps all authentication material off the client.

- Single-use: consumed on callback, deleted whether validation succeeds or fails.
- Short TTL (minutes, not hours), enforced on lookup.
- The consuming `DELETE` clears expired rows, and `/auth/login` sweeps both
  this table and `user_session`. Consumption alone is not enough: it only ever
  reaps logins that come back, and `/auth/login` is unauthenticated and writes
  a row per request. Both `expires_at` columns are indexed.

## Key on `oid`, not `email`

Entra `sub` is pairwise per-application; `oid` is the stable user id within the tenant. Emails are reassignable. Primary key is `(tid, oid)`.

## Dependencies

`fastapi`, `uvicorn`, `sqlmodel`, `pyjwt[crypto]`, `httpx`, `psycopg[binary]`, `alembic`, `pydantic-settings`

(`sqlmodel` brings `sqlalchemy` and `pydantic` transitively. Sync `Session`, not `AsyncSession`.)
Dev: `pytest`, `ruff`, `mypy`, `squawk-cli`

Note: the PyPI package `squawk` is an unrelated project. The linter is `squawk-cli`.

Managed with `uv`.

## Testing

TDD throughout. Three layers required:

- **Unit** — token validation, JWKS cache/rotation, session lifecycle, role checks. Fixtures mint Entra-shaped JWTs with a locally generated RSA keypair.
- **Integration** — routes against a real Postgres.
- **E2E** — full login round trip against a **Keycloak** container (26.7.x) in
  docker compose. Real OIDC provider, real JWKS, real crypto. A protocol mapper
  shapes tokens to Entra's claim set (`oid`, `tid`, `roles`); the realm is
  exported to JSON and version-controlled.

**Fidelity gap, accepted:** Keycloak is not Entra. It will not catch
Entra-specific behavior — exact `roles` claim shape, v2.0 issuer format, or
conditional access. Mitigation is a manual smoke test against a real tenant
before each forked service goes live, not a CI dependency.

## Considered and rejected

Recorded so this is not re-litigated later.

- **pgroll** (v0.16.x) — zero-downtime expand/contract via versioned views.
  Genuinely novel, but migrations are hand-authored JSON/YAML ops, which
  discards SQLModel autogenerate and creates a second source of truth against
  the `table=True` models. Pre-1.0, plus a Go binary in every fork. The
  zero-downtime benefit is worth ~nothing on a three-table schema. Revisit per
  service if one ever grows real zero-downtime requirements — nothing here
  blocks that.
- **Atlas** (v1.3.0) — mature and a reasonable declarative choice; rejected on
  fit, not quality. Costs a Go binary in every fork's CI for a three-table
  schema. Worth revisiting if BlueSprig ever wants one declarative schema story
  across many services.

## Deferred (not built)

**Machine-to-machine callers.** YAGNI. Adding a bearer-validation dependency
later is ~40 lines and purely additive; it does not conflict with the BFF design.
