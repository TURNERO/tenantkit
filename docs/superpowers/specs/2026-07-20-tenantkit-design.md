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
  pluggable `IdentityProvider`) and service credentials (API keys or
  mTLS client certs -- a tenant can support either or both), with API
  keys supported at both the tenant level and the user level.
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
- **`tenantkit/identity`** -- the `IdentityProvider` interface only, in
  this plan. `identity/local` and `identity/oidc` (concrete
  implementations) are a separate future plan; this plan gives
  `httpmw`/`grpcmw` something concrete to depend on without waiting on
  those implementations.
  - **`tenantkit/identity/local`** -- (future plan) built-in
    implementation composing `go-webauthn/webauthn` (passwordless)
    and/or `golang.org/x/crypto/bcrypt` (password fallback) plus an
    opaque-token session store.
  - **`tenantkit/identity/oidc`** -- (future plan) built-in
    implementation wrapping any external OIDC-compliant IdP via
    `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2`.
- **`tenantkit/resolve`** -- the `Source` and `TenantResolver`
  interfaces, plus four built-in strategies: API-key resolver,
  client-cert (mTLS) resolver, header resolver, subdomain resolver.
  Composable as an explicitly ordered chain. A fifth strategy --
  session/identity-claim resolution -- is deferred to the Identity plan,
  since it needs the session-token format decided there first (see
  "Open questions").
- **`tenantkit/httpmw`** -- `net/http` middleware wiring a resolver chain
  + an optional `IdentityProvider` (nil skips identity resolution
  entirely, for consumers with no human users) + the store interfaces
  together, populating request context. A pluggable `ErrorHandler`
  controls the response body on rejection; a plain-text default ships if
  none is configured.
- **`tenantkit/grpcmw`** -- unary and stream gRPC interceptors doing the
  same job for gRPC services, sharing the same resolvers via the
  transport-agnostic `Source` interface.
- **`tenantkit/store/sqlite`** -- an implementation of all four `store`
  interfaces backed by SQLite (`modernc.org/sqlite`, pure Go, no cgo --
  an embedded library reading/writing one file, no server process),
  verified against `storetest` exactly like `memstore`. Unlike
  `memstore`, this one is meant for real use: it's `cmd/tenantkit-admin`'s
  default backend, and usable standalone by any consumer who wants a
  persistent store without writing their own. Lives in the main module
  (not `tools/`, see below) since Go only compiles what's actually
  imported -- a consumer who never imports `store/sqlite` never pulls in
  the SQLite driver, so keeping it in the main module costs nothing for
  everyone else while making it importable without depending on `tools/`.
- **`tenantkit/admin`** -- the operations behind the CLI (create/list/
  deactivate tenant, create/revoke/rotate API key, create user,
  register/revoke client cert), as a plain Go API working purely against
  the `store` interfaces. Exists as its own package, separate from
  `cmd/tenantkit-admin`, so a consumer with extra provisioning steps
  outside tenantkit's scope can import these operations directly and
  compose them with their own steps, rather than being limited to
  shelling out to the binary.
- **`cmd/tenantkit-admin`** -- a production-usable admin CLI (built on
  `spf13/cobra`, matching `kubectl`/`gh`'s own subcommand convention), a
  thin wrapper around `tenantkit/admin` plus `store/sqlite` as its
  default backend. Supported for direct use, not just a reference to
  fork. Lives in a separate `tools/` Go submodule (its own `go.mod`,
  depending on the main module) so its CLI-only dependencies (cobra,
  prompting) stay out of the main module's dependency graph -- resolved
  from the open question in a prior draft of this spec (issue #2). See
  "Management plane" below.

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
    Username string // matches store.UserStore.GetUserByUsername's lookup key
    Roles    []string // opaque; tenantkit does not interpret these
}

type APIKey struct {
    Hash     string // SHA-256 hex; tenantkit hashes, store just persists/looks up
    TenantID string
    UserID   string // empty = tenant-level key, non-empty = user-level key
}

type ClientCert struct {
    Fingerprint string // SHA-256 hex of the DER-encoded cert; not a secret, just an identifier
    TenantID    string
    UserID      string // empty = tenant-level cert, non-empty = user-level cert
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

type ClientCertStore interface {
    GetClientCertByFingerprint(ctx context.Context, fingerprint string) (*ClientCert, error)
    CreateClientCert(ctx context.Context, c *ClientCert) error
    RevokeClientCert(ctx context.Context, fingerprint string) error
}
```

```go
// tenantkit/resolve
//
// Source abstracts over the transport (HTTP or gRPC) so the same
// TenantResolver/IdentityProvider implementations work against both --
// httpmw wraps *http.Request, grpcmw wraps incoming metadata + peer info.
type Source interface {
    Header(key string) string
    TLSPeerCertificates() []*x509.Certificate
    Host() string
}

type TenantResolver interface {
    // ok=false means "found no credential material of this kind" -- distinct
    // from an error, which means "found something, but it's invalid."
    ResolveTenant(ctx context.Context, src Source) (tenantID string, ok bool, err error)
}
```

```go
// tenantkit/identity
type IdentityProvider interface {
    Authenticate(ctx context.Context, src resolve.Source) (*Identity, error)
}
```

A resolver chain runs in explicit configured order. The first resolver that
finds credential material handles the request; if that material is invalid,
the chain fails immediately rather than falling through to the next
strategy. Falling through on bad credentials is a real vulnerability (e.g. a
rejected API key silently retried as a spoofable header) -- only genuine
absence of that credential type (`ok=false`) allows the chain to continue.

The four built-in resolvers:

- **API-key** (`NewAPIKeyResolver(store.APIKeyStore)`) reads
  the standard bearer-token form of the `Authorization` header via `Source.Header`. No/non-bearer header
  -- `ok=false`. A Bearer token present but not found (after hashing with
  `store.HashSecret`, same as everywhere else API keys are compared) --
  an error, not `ok=false`: the credential material was present, just
  invalid.
- **Client-cert** (`NewClientCertResolver(store.ClientCertStore)`) reads
  the already-TLS-verified peer certificate off the connection via
  `Source.TLSPeerCertificates()` and looks up its SHA-256 fingerprint via
  `ClientCertStore` -- tenantkit only resolves identity from a cert that
  TLS has already verified against *some* CA pool; it never issues
  certs, runs a CA, or manages rotation. That's the consumer's
  infrastructure, same as it already owns TLS termination. This also
  means the resolver only works when the request actually reaches
  tenantkit's process over mTLS-terminated TLS -- if a load balancer or
  edge proxy terminates TLS before the app, no peer certificates will be
  available there, and either the LB needs to forward cert details some
  other way or this resolver isn't usable for that deployment. The
  fingerprint is computed directly (SHA-256 of the DER-encoded cert),
  not via `store.HashSecret` -- a cert fingerprint isn't a secret being
  hashed for storage, it's already a public identifier, so reusing that
  helper would be a semantic mismatch even though the underlying
  operation is identical. This computation is exported as
  `resolve.CertFingerprint(cert *x509.Certificate) string` (the resolver
  itself calls it too, one implementation) so `tenantkit/admin`'s
  cert-registration operation can compute the same fingerprint an
  incoming mTLS connection would produce, without duplicating the logic.
- **Header** (`NewHeaderResolver(headerName string)`) reads a
  configurable header directly as the tenant ID via `Source.Header` --
  no store lookup at all. For trusted-proxy deployments where something
  upstream (a gateway, a sidecar) already resolved the tenant and just
  needs to pass it through. Tenant existence/active-checking still
  happens downstream in `httpmw`/`grpcmw` via `TenantStore.GetTenant`
  regardless of which resolver produced the ID, so this isn't a
  vector for spoofing a nonexistent tenant into existing.
- **Subdomain** (`NewSubdomainResolver()`) takes the first
  dot-separated label of `Source.Host()` as the tenant ID. No dot in the
  host (e.g. bare `localhost`) -- `ok=false`.

Pure helper functions (no interface, just functions any admin tool needs)
live alongside `store`: generating a random high-entropy secret, hashing it
(SHA-256) for storage, validating a tenant-key charset (`^[a-z0-9-]+$`),
generating a tenant ID that already satisfies that charset
(`GenerateTenantID`, lowercase hex -- `GenerateSecret`'s base64 output
doesn't qualify, it can contain uppercase and underscores), and rotating
an API key (issue new + revoke old, in that order, so there's no window
with zero valid keys... actually a brief window with two valid keys,
which is the safe direction to err in).

## Request flow (httpmw / grpcmw)

```
Request -> TenantResolver chain -> tenantID
        -> TenantStore.GetTenant(tenantID) -> reject if not found or !Active
        -> if IdentityProvider configured: Authenticate(src) -> *Identity
           (nil for pure API-key/service traffic even when configured;
           this step is skipped entirely when IdentityProvider is nil)
        -> if Identity != nil: Identity.TenantID must equal resolved tenantID, else reject
        -> context populated: TenantFromContext(ctx), IdentityFromContext(ctx)
        -> next handler / interceptor
```

`IdentityProvider` is optional per `httpmw`/`grpcmw` instance -- a
consumer with no human users (e.g. an OTLP ingestor authenticating only
service credentials) configures `nil` and skips this step entirely,
rather than being forced to wire up an identity provider it will never
use.

Errors map to HTTP `401` (no/invalid credentials) vs `403` (valid
credentials, wrong tenant or inactive tenant); gRPC interceptors map the
same distinction to `codes.Unauthenticated` vs `codes.PermissionDenied`.
The response body on rejection goes through a pluggable `ErrorHandler`
(`func(w http.ResponseWriter, r *http.Request, status int, err error)`)
so a consumer can return JSON or another format; `httpmw` ships a
minimal plain-text default (`http.Error`-style) if none is configured.

tenantkit never touches tenant-scoped *application* data. Scoping actual
queries (`WHERE tenant_id = ?`, or store-specific mechanisms like ClickHouse
Row Policies) is the consumer's responsibility every time.

## Management plane

`cmd/tenantkit-admin` is a supported, production-usable CLI -- not merely a
reference to fork. tenantkit still ships no opinionated admin *HTTP* API;
the CLI is the supported management surface. Its business logic
(`tenantkit/admin`) stays store-agnostic, built entirely against the
`store` interfaces; the CLI binary itself uses `store/sqlite` as a
concrete, persistent, zero-server-process default backend (see "Package
layout" above), which is what makes it genuinely runnable out of the box
rather than only usable by consumers who bring their own store.

- **Subcommands**, noun-verb style, built on `spf13/cobra`:
  - `tenant create --id <id> | --generate-id --name <name>`,
    `tenant list [--json]`, `tenant deactivate --id <id>`
  - `key create --tenant <id> [--user <id>]`, `key revoke --key <secret>`,
    `key rotate --key <old-secret>`
  - `user create (--user-id <id> | --generate-user-id) --tenant <id>
    --username <name> [--roles a,b,c]`
  - `cert register --cert-file <path> --tenant <id> [--user <id>]`,
    `cert revoke --fingerprint <hex>`
  
  Every revoke/rotate operation is keyed by a string the operator already
  has -- the plaintext secret they were shown once at creation, or the
  fingerprint printed at registration (not a secret, safe to paste back)
  -- rather than needing a `ListAPIKeys`/`ListClientCerts` capability
  that doesn't exist on `APIKeyStore`/`ClientCertStore`. `tenantkit/admin`
  hashes/fingerprints the input and calls the store, so the caller never
  handles a hash directly. `key rotate` looks up the old key's own
  `TenantID`/`UserID` first, so the operator doesn't have to repeat them.
  Both ID-bearing create commands (`tenant create`, `user create`) accept
  either an explicit ID or a `--generate-*` flag, matching each other.
- **Destructive operations require confirmation** (`tenant deactivate`,
  `key revoke`, `cert revoke`): an interactive `[y/N]` prompt by default,
  skippable with `--yes`/`-f` so the same commands work unattended in
  scripts/CI.
- **`--dry-run` on every mutating command**: prints what the operation
  would do (which record(s) it would create/modify/deactivate/revoke)
  without making the change, independent of the confirmation prompt --
  lets an operator preview an operation's effect before committing to it,
  the same shape as `terraform plan`/`kubectl --dry-run`.
- **`--json` on read/list commands** (`tenant list`, the only one in this
  scope): human-readable text by default, structured JSON output behind
  the flag so the CLI can be wrapped by other automation, matching
  `gh`/`kubectl` conventions.
- All of the above is implemented once, in `tenantkit/admin`, and the CLI
  is a thin flag-parsing/prompting/output-formatting layer on top -- so a
  consumer with extra provisioning needs (e.g. a database-specific RBAC
  step outside tenantkit's scope) can import `tenantkit/admin` directly
  (against `store/sqlite`, or their own store implementation) and compose
  its operations with their own, rather than being limited to shelling
  out to the binary or forking it.

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
- **`store/sqlite` tests**: run `storetest`'s conformance suite against a
  real `modernc.org/sqlite` connection opened on `:memory:` (SQLite's
  own in-process, non-persistent mode) -- no temp files, no
  testcontainers, still zero network/Docker dependency, but exercising
  real SQL rather than a map.
- **`identity/oidc` tests**: run against a mocked/test OIDC provider (no
  network dependency), not a real Auth0/Okta account.
- **Client-cert resolver tests**: use Go's `crypto/x509`/`crypto/tls` to
  generate a self-signed test CA and leaf cert in-process (`httptest`
  supports serving/dialing with a custom `tls.Config`) -- no external CA
  or real certs needed, same no-network-dependency bar as the rest of
  this list.
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
  This also blocks the session/identity-claim `TenantResolver` strategy
  (see `tenantkit/resolve`'s package layout entry), which is deferred to
  the Identity plan for the same reason (tracked as issue #1).
- ~~Whether `cmd/tenantkit-admin` ships as part of the main module or as a
  separate `tools/` submodule~~ -- **resolved**: `tools/` submodule (see
  "Package layout" above). `store/sqlite` stays in the main module, since
  Go's per-package import compilation means a consumer who never imports
  it never pulls in the SQLite driver either way -- the only thing a
  separate module would have bought was keeping it out of the main
  module's own `go.mod` bookkeeping, not out of anyone's build. (issue #2)
