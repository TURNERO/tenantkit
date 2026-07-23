# identity/local/sqlite design

## Overview

`identity/local` ([spec](2026-07-22-identity-local-design.md)) ships three
storage interfaces — `CredentialStore`, `SessionStore`, `EphemeralStore` —
plus an in-memory reference implementation (`identity/local/memstore`) for
tests only. Without a persistent backend, `identity/local` has no
production-usable store, the same gap `store/sqlite` closed for
`TenantStore`/`UserStore`/`APIKeyStore`/`ClientCertStore` after the
Foundation plan ([issue #4](https://github.com/TURNERO/tenantkit/issues/4)).

This plan adds that backend: a new `identity/local/sqlite` package,
following the same pattern as `store/sqlite` — pure-Go
`modernc.org/sqlite` driver, `Open(dsn)`/`Close()`, a `CREATE TABLE IF NOT
EXISTS` schema list — plus a shared conformance test suite
(`identity/local/storetest`) that both `memstore` and the new `sqlite`
package run against, mirroring `tenantkit/storetest`'s role for the
original four store interfaces.

## Scope

In scope:
- `identity/local/sqlite`: a `Store` implementing `CredentialStore`,
  `SessionStore`, and `EphemeralStore` against a SQLite database.
- `identity/local/storetest`: exported conformance test functions for
  each of the three interfaces, covering the scenarios already exercised
  ad hoc in `memstore_test.go`.
- Refactoring `memstore_test.go` to call `storetest` instead of
  duplicating its assertions inline.

Out of scope:
- Active/background expiry cleanup. Expiry stays lazy (checked on read),
  matching `memstore`'s existing behavior — see Behavior below.
- Merging with `store/sqlite`. Kept as a separate package; see
  Alternatives Considered.
- Any change to the `identity/local` package itself (interfaces, auth
  logic) — this plan only adds a backend.

## Package layout

```
tenantkit/identity/local/
  sqlite/
    sqlite.go       // Store, Open, Close, schema
    sqlite_test.go  // storetest conformance calls + sqlite-specific tests
  storetest/
    storetest.go    // TestCredentialStore, TestSessionStore, TestEphemeralStore
```

## Schema

Four tables, none of which overlap with `store/sqlite`'s
tenants/users/api_keys/client_certs:

```sql
CREATE TABLE IF NOT EXISTS password_hashes (
    tenant_id TEXT NOT NULL,
    user_id   TEXT NOT NULL,
    hash      TEXT NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
)
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id TEXT PRIMARY KEY,   -- base64 of Credential.ID
    tenant_id     TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    data          TEXT NOT NULL       -- full Credential, JSON-encoded
)
CREATE INDEX IF NOT EXISTS webauthn_credentials_user
    ON webauthn_credentials (tenant_id, user_id)
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    expires_at INTEGER NOT NULL   -- unix seconds
)
CREATE TABLE IF NOT EXISTS ephemeral_tokens (
    token      TEXT PRIMARY KEY,
    payload    BLOB NOT NULL,
    expires_at INTEGER NOT NULL
)
```

`webauthn_credentials.credential_id` is the natural unique key
(`Credential.ID` is already unique per the WebAuthn spec); it is not
folded into a `(tenant_id, user_id)` primary key because a user can
register multiple credentials, and lookups need both "by credential ID"
(implicit, via the primary key) and "all credentials for a user" (via the
index).

## Behavior

- `Store` implements all three interfaces, following `memstore.Store`
  and `store/sqlite.Store`'s existing single-type convention.
- `CreateSession` generates its token with `store.GenerateSecret()`, the
  same helper `memstore.CreateSession` and `store/sqlite`'s API-key
  issuance already use.
- Expiry is lazy: `GetSession` and `Take` compare `expires_at` against
  `time.Now()` and return `local.ErrExpired` if past. No row is
  proactively deleted on a timer or background sweep — expired rows sit
  in the table until read, identical to `memstore`'s behavior. A
  consumer running this at scale can add their own periodic
  `DELETE FROM sessions WHERE expires_at < ?` outside this package if
  row growth becomes a concern; that's explicitly not this plan's job.
- `Take` deletes its row unconditionally before evaluating expiry (in
  the same statement), preserving "single-use regardless of outcome" —
  a replayed token fails on the second attempt whether or not the first
  attempt was itself expired, matching `memstore.Take`.
- WebAuthn credentials are stored as a JSON blob in the `data` column,
  round-tripped with `encoding/json` — the same approach
  `memstore.cloneCredential` already uses for its deep-copy, so there's
  no hand-maintained column-per-field mapping to keep in sync as
  `webauthn.Credential` evolves upstream.
- Errors: `local.ErrNotFound`/`local.ErrExpired` for the documented
  not-found/expired cases; every other failure (driver errors, JSON
  marshal/unmarshal failures) is wrapped with `fmt.Errorf("...: %w",
  err)`, matching `store/sqlite`'s convention. Unlike `store/sqlite`,
  no unique-violation detection (`isUniqueViolation`) is needed: none of
  `CredentialStore`, `SessionStore`, or `EphemeralStore` expose a
  create-fails-if-exists method — `SetPasswordHash` and `Put` are both
  upsert-shaped by their existing contract, so a primary-key collision
  is handled with `INSERT ... ON CONFLICT DO UPDATE` rather than
  surfaced as an error.

## Testing

- `identity/local/storetest` exports one test function per interface
  (`TestCredentialStore`, `TestSessionStore`, `TestEphemeralStore`),
  each taking `*testing.T` and a store value, covering: tenant isolation
  (same `userID` in two tenants doesn't collide), overwrite semantics
  (`SetPasswordHash` replaces, not appends), not-found and expired
  returns, and single-use consumption (`Take` / a replayed ceremony or
  reset token fails on the second attempt) — i.e., the scenarios
  `memstore_test.go` already covers today, made runnable against any
  implementation.
- `memstore_test.go` is refactored to call these `storetest` functions
  instead of asserting inline; `memstore`-specific behavior that isn't
  part of the interface contract (e.g. that `GetWebAuthnCredentials`
  returns independent copies on each call, so mutating one returned
  slice can't corrupt the store's internal state) stays as its own test
  in that file, since `storetest` only asserts what every conforming
  implementation must guarantee.
- `identity/local/sqlite/sqlite_test.go` runs the same three `storetest`
  functions against a `sqlite.Open(":memory:")` instance, plus
  sqlite-specific tests: `Open` run twice against the same file-backed
  dsn is idempotent (schema migration doesn't error on existing tables),
  and data written before a `Close` is still readable after a fresh
  `Open` on the same file-backed dsn (durability, which `memstore` can't
  demonstrate since it never persists anything).

## Alternatives Considered

**Fold into `tenantkit/store/sqlite` instead of a new package.** Rejected:
`store/sqlite` currently has no dependency on `go-webauthn`, and mixing
tenant/user/api-key/cert tables with password/session/webauthn tables in
one file conflates two independent concerns that `identity/local` and
`tenantkit/store` already keep separate as Go packages. A new
`identity/local/sqlite` package mirrors that existing split (`store/sqlite`
next to `store/memstore`; `identity/local/sqlite` next to
`identity/local/memstore`) rather than breaking it for this one backend.

**Active expiry cleanup (background sweep or delete-on-write).**
Rejected for this plan: it adds a goroutine/lifecycle concern (who starts
it, who stops it, what interval) that has no equivalent in `memstore` and
isn't needed for `identity/local`'s stores to function correctly — lazy
expiry is sufficient for correctness, and unbounded row growth is a
production operability concern a consumer can address themselves (see
Behavior above) without this package needing an opinion on sweep
frequency.
