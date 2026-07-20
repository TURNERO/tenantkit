# tenantkit: a store-agnostic multi-tenancy library for Go

## Problem

otel-ingestor's multi-tenancy design (`otel-ingestor/docs/superpowers/specs/2026-07-20-clickhouse-multi-tenancy-design.md`)
solves tenant isolation for that project specifically, and leans hard on
ClickHouse-specific mechanisms (Row Policies, `CREATE ROLE`, a
`currentRoles()`-based write `CONSTRAINT`) plus a SQLite-specific tenant/user
schema. None of that is reusable in a future project that uses Postgres, a
different OTLP-adjacent service, or no ClickHouse at all.

The recurring shape underneath -- resolve which tenant a request belongs to,
authenticate whoever's making it, look up tenant/user/API-key records, and
make that available to request handlers -- is the same problem every
multi-tenant Go service ends up solving from scratch. tenantkit extracts that
shape into a standalone library so future projects (and eventually
otel-ingestor itself) don't re-derive it.

## Goal

A Go library that:

- Is **store-agnostic**: it defines interfaces for tenant/user/API-key
  storage; it never talks to a database itself. Actual data isolation inside
  a specific store (e.g. ClickHouse Row Policies) stays the consumer's job,
  since that's inherently store-specific and out of reach of a generic
  library.
- Handles **user management** for a tenant: both human users (via a
  pluggable `IdentityProvider`) and API keys (service/ingestion credentials),
  with keys supported at both the tenant level and the user level.
- Lets identity be **abstracted to an external system**: the same
  `IdentityProvider` interface that a built-in local (WebAuthn/bcrypt +
  session) implementation satisfies is also satisfied by an OIDC adapter, so
  a consumer can point at Auth0/Okta/Clerk/Keycloak/Zitadel/etc. without
  tenantkit needing per-vendor integrations.
- Ships as a **middleware** for both HTTP and gRPC, since a real consumer
  (otel-ingestor) receives traffic both ways.

## Non-goals (v1)

- Authorization/RBAC/permissions *within* a tenant (who can do what) --
  `Identity.Roles` is carried as opaque strings; interpreting them is the
  consumer's job. A policy engine (e.g. casbin) could layer on top later.
- Any store-specific enforcement (ClickHouse Row Policies, Postgres RLS,
  etc.) -- stays entirely in the consumer.
- Multi-tenant-per-user (a user belonging to more than one tenant, with an
  "active tenant" concept) -- `Identity` carries exactly one `TenantID`.
- Kubernetes/Secret-management integration of any kind.

## Package layout

One Go module, `github.com/TURNERO/tenantkit`, split by responsibility:

- **`tenantkit`** (root) -- core types (`Tenant`, `Identity`, `APIKey`) and
  request-context helpers (`TenantFromContext`, `IdentityFromContext`,
  `WithTenant`, `WithIdentity`).
- **`tenantkit/store`** -- storage interfaces only: `TenantStore`,
  `UserStore`, `APIKeyStore`. No implementation. Consumers implement these
  against whatever database they use.
- **`tenantkit/storetest`** -- exported interface-conformance test helpers
  (e.g. `storetest.TestTenantStore(t, store)`) that any consumer's real
  backend can run against its own implementation to prove it satisfies the
  documented interface behavior (not-found errors, uniqueness constraints,
  etc.).
- **`tenantkit/identity`** -- the `IdentityProvider` interface.
  - **`tenantkit/identity/local`** -- built-in implementation composing
    `go-webauthn/webauthn` (passwordless) and/or `golang.org/x/crypto/bcrypt`
    (password fallback) plus an opaque-token session store.
  - **`tenantkit/identity/oidc`** -- built-in implementation wrapping any
    external OIDC-compliant IdP via `github.com/coreos/go-oidc/v3` and
    `golang.org/x/oauth2`.
- **`tenantkit/resolve`** -- the `TenantResolver` interface plus built-in
  strategies: API-key resolver, session/identity-claim resolver, header
  resolver, subdomain resolver. Composable as an explicitly ordered chain.
- **`tenantkit/httpmw`** -- `net/http` middleware wiring a resolver chain +
  an `IdentityProvider` + the store interfaces together, populating request
  context.
- **`tenantkit/grpcmw`** -- unary and stream gRPC interceptors doing the
  same job for gRPC services.
- **`tenantkit/admin`** -- the operations behind the CLI (create/list/
  deactivate tenant, create/revoke API key, create user), as a plain Go API
  working purely against the `store` interfaces. Exists as its own package,
  separate from `cmd/tenantkit-admin`, so a consumer with extra provisioning
  steps outside tenantkit's scope can import these operations directly and
  compose them with their own steps, rather than being limited to shelling
  out to the binary.
- **`cmd/tenantkit-admin`** -- a production-usable admin CLI, a thin wrapper
  around `tenantkit/admin`. Supported for direct use, not just a reference
  to fork. See "Management plane" below.

## Core types and interfaces

```go
// tenantkit
type Tenant struct {
    ID          string
    DisplayName string
    Active      bool
}

type Identity struct {
    UserID   string
    TenantID string
    Roles    []string // opaque; tenantkit does not interpret these
}

type APIKey struct {
    Hash     string // SHA-256 hex; tenantkit hashes, store just persists/looks up
    TenantID string
    UserID   string // empty = tenant-level key, non-empty = user-level key
}
```

```go
// tenantkit/store
type TenantStore interface {
    GetTenant(ctx context.Context, tenantID string) (*Tenant, error)
    CreateTenant(ctx context.Context, t *Tenant) error
    ListTenants(ctx context.Context) ([]*Tenant, error)
    DeactivateTenant(ctx context.Context, tenantID string) error
}

type UserStore interface {
    GetUser(ctx context.Context, userID string) (*Identity, error)
    GetUserByUsername(ctx context.Context, tenantID, username string) (*Identity, error)
    CreateUser(ctx context.Context, u *Identity) error
}

type APIKeyStore interface {
    GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error)
    CreateAPIKey(ctx context.Context, k *APIKey) error
    RevokeAPIKey(ctx context.Context, hash string) error
}
```

```go
// tenantkit/identity
type IdentityProvider interface {
    Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}
```

```go
// tenantkit/resolve
type TenantResolver interface {
    // ok=false means "found no credential material of this kind" -- distinct
    // from an error, which means "found something, but it's invalid."
    ResolveTenant(ctx context.Context, r *http.Request) (tenantID string, ok bool, err error)
}
```

A resolver chain runs in explicit configured order. The first resolver that
finds credential material handles the request; if that material is invalid,
the chain fails immediately rather than falling through to the next
strategy. Falling through on bad credentials is a real vulnerability (e.g. a
rejected API key silently retried as a spoofable header) -- only genuine
absence of that credential type (`ok=false`) allows the chain to continue.

Pure helper functions (no interface, just functions any admin tool needs)
live alongside `store`: generating a random high-entropy secret, hashing it
(SHA-256) for storage, validating a tenant-key charset (`^[a-z0-9-]+$`), and
rotating an API key (issue new + revoke old, in that order, so there's no
window with zero valid keys... actually a brief window with two valid keys,
which is the safe direction to err in).

## Request flow (httpmw / grpcmw)

```
Request -> TenantResolver chain -> tenantID
        -> TenantStore.GetTenant(tenantID) -> reject if not found or !Active
        -> IdentityProvider.Authenticate(r) -> *Identity (nil for pure API-key/service traffic)
        -> if Identity != nil: Identity.TenantID must equal resolved tenantID, else reject
        -> context populated: TenantFromContext(ctx), IdentityFromContext(ctx)
        -> next handler / interceptor
```

Errors map to HTTP `401` (no/invalid credentials) vs `403` (valid
credentials, wrong tenant or inactive tenant); gRPC interceptors map the
same distinction to `codes.Unauthenticated` vs `codes.PermissionDenied`.

tenantkit never touches tenant-scoped *application* data. Scoping actual
queries (`WHERE tenant_id = ?`, or store-specific mechanisms like ClickHouse
Row Policies) is the consumer's responsibility every time.

## Management plane

`cmd/tenantkit-admin` is a supported, production-usable CLI -- not merely a
reference to fork. tenantkit still ships no opinionated admin *HTTP* API;
the CLI is the supported management surface, and it stays store-agnostic
since it's built entirely against the `store` interfaces (never a specific
database driver).

- **Subcommands**, noun-verb style: `tenantkit-admin tenant create|list|
  deactivate`, `tenantkit-admin key create|revoke`, `tenantkit-admin user
  create`. Scales cleanly as operations grow, matches the convention of
  `git`/`gh`/`kubectl`.
- **Destructive operations require confirmation** (`tenant deactivate`,
  `key revoke`): an interactive `[y/N]` prompt by default, skippable with
  `--yes`/`-f` so the same commands work unattended in scripts/CI.
- **`--dry-run` on every mutating command**: prints what the operation
  would do (which record(s) it would create/modify/deactivate) without
  making the change, independent of the confirmation prompt -- lets an
  operator preview an operation's effect before committing to it, the same
  shape as `terraform plan`/`kubectl --dry-run`.
- **`--json` on read/list commands** (`tenant list`, etc.): human-readable
  text by default, structured JSON output behind the flag so the CLI can be
  wrapped by other automation, matching `gh`/`kubectl` conventions.
- All of the above is implemented once, in `tenantkit/admin`, and the CLI
  is a thin flag-parsing/prompting/output-formatting layer on top -- so a
  consumer with extra provisioning needs (e.g. a database-specific RBAC
  step outside tenantkit's scope) can import `tenantkit/admin` directly and
  compose its operations with their own, rather than being limited to
  shelling out to the binary or forking it.

## Testing strategy

- **Unit tests, no external services**: resolvers, the `identity/local`
  provider (WebAuthn ceremony + bcrypt are pure Go, no DB), and middleware
  wiring are tested against hand-written in-memory `TenantStore`/
  `UserStore`/`APIKeyStore` fakes.
- **Interface conformance suite** (`tenantkit/storetest`): any consumer's
  real backend runs this against its own implementation to prove it
  satisfies the documented contract (not-found errors, uniqueness, etc.).
  This is what otel-ingestor's SQLite-backed store would run to prove it's a
  valid `tenantkit.TenantStore`.
- **`identity/oidc` tests**: run against a mocked/test OIDC provider (no
  network dependency), not a real Auth0/Okta account.
- **No testcontainers, no Docker/Podman requirement** for tenantkit's own
  CI -- that dependency is specific to consumers that need a real database
  (like otel-ingestor's ClickHouse-backed tests), not to tenantkit itself.
- No Kubernetes-flavored test belongs in tenantkit: it has no Kubernetes
  dependency in this design. That stays in otel-ingestor's own end-to-end
  smoke test (provision a tenant, send data, log in, verify isolation),
  which already exists in its own multi-tenancy plan.

## How otel-ingestor adopts this (future work, not part of this spec)

Not designed here in detail, but the shape: otel-ingestor's existing SQLite
`tenants`/`users` tables (already built in
`services/query/internal/store/tenant.go`) get wrapped in an adapter
satisfying tenantkit's `store` interfaces, verified via `storetest`.
otel-ingestor keeps its ClickHouse-specific Row Policy / `CONSTRAINT` /
per-tenant-connection-pool work exactly as already spec'd -- none of that
moves into tenantkit. Its `addtenant` CLI becomes a wrapper around
`cmd/tenantkit-admin`'s logic plus its own ClickHouse RBAC provisioning
step. This adoption is deliberately left as a separate future design/plan,
not bundled into tenantkit's own v1.

## Open questions (flagged, not blocking)

- Exact session-token format for `identity/local` (opaque random token vs.
  signed JWT) -- affects whether session validation needs a store round-trip
  or can be done statelessly. Leaning opaque token + store lookup, matching
  otel-ingestor's existing `sessions` table pattern, but not settled here.
- Whether `cmd/tenantkit-admin` ships as part of the main module or as a
  separate `tools/` submodule to avoid pulling CLI-only dependencies (flag
  parsing, prompting, JSON output, etc.) into every consumer's `go.mod` --
  still open now that the CLI is a supported production tool, not just a
  reference (tracked as issue #2).
