# auth-skeleton — Implementation Plan

Build order from [SPEC.md](./SPEC.md). Five PRs. TDD: failing test, minimal
code, refactor.

## Resolved

**`__Host-` cookies in dev.** Cookie name and `Secure` derive from
`DEV_INSECURE_COOKIES`, which startup refuses when `ENV=production`. Both paths
are tested, and the failure mode is real: a client on plain HTTP silently
declines to store a `Secure` cookie, so the route tests run over https.

## PR 1 — Skeleton

`uv init`, `pyproject.toml`, ruff + mypy config, `.env.example`,
`docker-compose.yml` (Postgres), CI workflow, `config.py`, `main.py` with
`/healthz`.

Logging redaction ships here, not later — a filter scrubbing `code`,
`id_token`, `access_token`, `Authorization`. Retrofitting after tokens flow is
how they end up in log archives.

- Tests: missing required settings raise at import; `DEV_INSECURE_COOKIES`
  rejected in production; redaction filter emits no token substring.
- Gates **checklist item 9**. Boots on 57005, CI green.

## PR 2 — Models and migrations

`models.py` (`User`, `Session`, `AuthTransaction`), `db.py`, Alembic with the
SQLModel wiring from SPEC.md, first revision, Squawk in CI.

`User` takes a surrogate PK with a unique constraint on `(tid, oid)` — `Session`
needs a single-column FK. The spec's `(tid, oid)` rule survives as the
uniqueness constraint.

- Tests: `upgrade head` / `downgrade base` round-trips on real Postgres;
  `(tid, oid)` uniqueness enforced; expired `AuthTransaction` rejected on lookup.
- Autogenerate must produce a non-empty revision — that proves the
  `target_metadata` wiring. `alembic upgrade --sql | squawk` clean.

## PR 3 — Entra client

`auth/entra.py`. Endpoint URLs templated from tenant id, JWKS via
`PyJWKClient(cache_jwk_set=True, lifespan=300)`, code exchange over `httpx`, and
`validate_id_token` checking signature, issuer, audience, `exp`/`nbf`, `nonce`.

No routes. A library and its tests, built first because everything downstream
trusts it.

Tests mint Entra-shaped tokens with a local RSA keypair. The negative cases are
the deliverable:

- signature from a non-matching key → reject
- issuer prefix attack (`.../{tid}/v2.0.evil.example`) → reject
- wrong `aud` → reject
- expired, and `nbf` in the future → reject
- `nonce` mismatch → reject
- unknown `kid` → bounded refetch, asserted with a fetch counter
- `alg: none` → reject
- `alg: HS256` signed with the RSA public key as HMAC secret → reject

- Gates **checklist items 2, 3, 4, 5**.

## PR 4 — Session, routes, dependencies

`auth/session.py`, `auth/routes.py`, `auth/deps.py`. The full flow lands
together because the pieces are meaningless apart.

Session token is `secrets.token_urlsafe(32)`; only its SHA-256 persists;
constant-time compare on lookup. Idle and absolute timeouts are separate fields,
both enforced.

- Tests: idle timeout expires an untouched session, absolute expires an active
  one, revoke is immediate, raw token appears in no column. State mismatch →
  400; replayed state → 400; `next=https://evil.example` and `next=//evil.example`
  both rejected. No cookie → 401; `require_roles` denies a missing role;
  `/auth/me` returns exactly its declared fields.
- Gates **checklist items 1, 6, 7, 8**.

## PR 5 — End-to-end and README

Keycloak 26.7.x in compose, realm JSON version-controlled, protocol mappers
emitting `oid`, `tid`, `roles`. Full login round trip. README covering what the
scaffold is, how to fork it, and the Entra app registration it expects.

- e2e green from a cold `docker compose up`.

## Gates

Every checklist item maps to a named test. `ruff`, `mypy`, `squawk` clean. Test
output pristine — expected errors are captured and asserted, not printed.

~1,400 LOC including tests.
