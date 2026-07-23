# store.OIDCProviderStore design

## Overview

[Issue #5](https://github.com/TURNERO/tenantkit/issues/5) asks for
`identity/oidc`, a built-in `identity.IdentityProvider` implementation
wrapping an external OIDC-compliant IdP (Auth0, Okta, Clerk, Keycloak,
Zitadel, etc.), the second of the two `IdentityProvider` implementations
the main design spec (`docs/superpowers/specs/2026-07-20-tenantkit-design.md`)
calls for.

Brainstorming that issue surfaced a prerequisite: for OIDC to be usable
by real consumers, IdP configuration (issuer, client ID/secret) can't be
one fixed value for the whole service -- it has to be registered **per
tenant**, the same way a tenant already gets its own API keys and client
certs. This plan scopes that prerequisite as its own unit: a new
`store.OIDCProviderStore` interface plus `memstore`/`sqlite`
implementations, `storetest` conformance coverage, `tenantkit/admin`
operations, and `tenantkit-admin` CLI verbs -- mirroring the existing
`store`/`admin`/CLI trio's shape exactly (`APIKeyStore`/`ClientCertStore`
already follow this same pattern).

`identity/oidc` itself (the login ceremony, token verification, claims
mapping, session issuance) is **out of scope for this plan** -- it's a
separate follow-up plan that consumes this store to look up a tenant's
provider at login time. This mirrors how `identity/local`'s persistent
store (`identity/local/sqlite`, issue #4) was sequenced as its own plan
after the interfaces it implements existed.

## Scope

In scope:
- `tenantkit.OIDCProvider`, a new root-package type.
- `store.OIDCProviderStore`, a new storage interface, plus
  `store.ErrDomainTaken`, a new sentinel error.
- `store/memstore` and `store/sqlite` implementations.
- `storetest.TestOIDCProviderStore`, run against both.
- `tenantkit/admin` operations: `RegisterOIDCProvider`,
  `GetOIDCProvider`, `ListOIDCProviders`, `UpdateOIDCProvider`,
  `RemoveOIDCProvider`.
- `tenantkit-admin oidc` CLI subcommand: `register`, `list`, `show`,
  `update`, `remove`.

Out of scope, deferred to the `identity/oidc` follow-up plan:
- Anything OIDC-protocol-related: discovery, the authorization-code
  ceremony, ID-token verification, claims-to-`Identity` mapping, session
  issuance. This plan only stores and retrieves the config
  `identity/oidc` will need to reach a tenant's IdP -- it has no
  dependency on `go-oidc`/`oauth2` at all.
- Anything under `identity/` -- this plan touches only `tenantkit`
  (root), `tenantkit/store`, `tenantkit/storetest`, `tenantkit/admin`,
  and `tools/cmd/tenantkit-admin`.

## Design decisions

**One provider per (tenant, provider ID), not one per tenant.** A tenant
can register more than one IdP (e.g. both an Okta connection for
employees and a Google connection for external users) -- `ProviderID` is
a caller-chosen slug (`"okta"`, `"google"`), unique within a tenant, not
a single fixed slot. A consumer's login page shows a picker whenever
`ListOIDCProviders` returns more than one entry for a tenant.

**Domain-based lookup for identifier-first login.** Real-world SSO
almost always routes by email domain, not by asking the user to already
know their tenant/provider: a generic "enter your email" login page
extracts the domain, looks up which provider claims it, and redirects
there (this is the standard "Home Realm Discovery" pattern). Each
`OIDCProvider` therefore carries a `Domains []string`, and the store
exposes `GetOIDCProviderByDomain`. Domains must be **globally unique
across all tenants** (two tenants can't both claim `acme.com`) --
`CreateOIDCProvider`/`UpdateOIDCProvider` return the new
`store.ErrDomainTaken` sentinel if a domain collides with a different
tenant/provider's registration. This is a distinct error from
`ErrAlreadyExists` (which still means "this exact `(tenant_id,
provider_id)` already exists") so a caller -- ultimately the CLI's error
message -- can tell the two failure modes apart.

**Redirect URL is not stored here.** It's one fixed value for the whole
service (registered identically with every tenant's IdP registration)
and belongs in `identity/oidc.Config`, not per-tenant data.

**Claims mapping IS stored per registration**, revising an earlier
direction from this same brainstorm: different tenants' IdPs are
administered by different customers, who may each choose their own
custom claim names (especially for roles, which almost never has a
standard claim). A single service-wide mapping can't necessarily cover
every registered provider once more than one tenant brings its own IdP,
so `ClaimsMapping` -- which claim holds tenant ID, user ID, username,
and roles -- travels with the provider registration itself, not with
`identity/oidc.Config`.

**Client secret is stored as plain text**, consistent with how tenantkit
already handles everything else it persists: password hashes are
one-way hashes (not reversible, so "encryption" doesn't apply), and
nothing else in `tenantkit/store` does column-level encryption. Whether
to encrypt this column at rest is the consumer's database/infrastructure
decision, same as it already is for every other column in `store/sqlite`
-- but `ClientSecret`'s doc comment calls this out explicitly, since it's
more sensitive than anything else currently in this store (a real
long-lived secret, not a hash or a public fingerprint).

## Types and interfaces

```go
// tenantkit (root package, types.go)
type OIDCProvider struct {
    TenantID      string
    ProviderID    string   // slug, unique within a tenant, e.g. "okta", "google"
    Name          string   // display label for a login picker, e.g. "Acme Corp Okta"
    IssuerURL     string
    ClientID      string
    ClientSecret  string   // plain text -- see "Client secret" design decision above
    Scopes        []string // e.g. []string{"openid", "email"}
    Domains       []string // e.g. []string{"acme.com", "acme.co.uk"} -- globally unique across all tenants
    ClaimsMapping ClaimsMapping
}

// ClaimsMapping says which of a verified ID token's claims identity/oidc
// reads to build a tenantkit.Identity. TenantIDClaim is required (no
// standard claim holds a tenant ID); the rest default when empty:
// UserIDClaim to "sub", UsernameClaim to "email", RolesClaim to "roles"
// (its claim value must be a JSON array of strings).
type ClaimsMapping struct {
    TenantIDClaim string
    UserIDClaim   string
    UsernameClaim string
    RolesClaim    string
}
```

```go
// tenantkit/store (store.go)

// ErrDomainTaken is returned by CreateOIDCProvider/UpdateOIDCProvider
// when one of the given Domains is already claimed by a different
// tenant/provider. Distinct from ErrAlreadyExists, which means the
// (tenant_id, provider_id) pair itself already exists.
var ErrDomainTaken = errors.New("tenantkit/store: domain already claimed by another provider")

// OIDCProviderStore stores and retrieves per-tenant OIDC IdP
// registrations. A tenant may register more than one provider (distinct
// ProviderIDs); Domains must be globally unique across every tenant and
// provider.
type OIDCProviderStore interface {
    // GetOIDCProvider returns the tenant's provider with the given ID,
    // or ErrNotFound.
    GetOIDCProvider(ctx context.Context, tenantID, providerID string) (*tenantkit.OIDCProvider, error)
    // GetOIDCProviderByDomain returns the provider that claims domain,
    // or ErrNotFound if no provider claims it.
    GetOIDCProviderByDomain(ctx context.Context, domain string) (*tenantkit.OIDCProvider, error)
    // ListOIDCProviders returns all providers registered for tenantID,
    // or an empty slice (not an error) if none are.
    ListOIDCProviders(ctx context.Context, tenantID string) ([]*tenantkit.OIDCProvider, error)
    // CreateOIDCProvider inserts p, or returns ErrAlreadyExists if
    // (p.TenantID, p.ProviderID) already exists, or ErrDomainTaken if
    // any of p.Domains is already claimed elsewhere.
    CreateOIDCProvider(ctx context.Context, p *tenantkit.OIDCProvider) error
    // UpdateOIDCProvider replaces the stored record for (p.TenantID,
    // p.ProviderID) with p, or returns ErrNotFound if it doesn't exist,
    // or ErrDomainTaken if any of p.Domains is now claimed by a
    // different tenant/provider.
    UpdateOIDCProvider(ctx context.Context, p *tenantkit.OIDCProvider) error
    // DeleteOIDCProvider removes the tenant's provider with the given
    // ID (and frees its claimed domains), or returns ErrNotFound if it
    // doesn't exist.
    DeleteOIDCProvider(ctx context.Context, tenantID, providerID string) error
}
```

## store/sqlite schema

Domains need their own table: SQLite can't enforce uniqueness on
individual elements of a JSON array column, so the domain index is a
separate table with `domain` as its primary key, kept in sync with
`oidc_providers.domains` (a denormalized copy used only by
`Get`/`List`, never used to check uniqueness) by every
`Create`/`Update`/`Delete`, in one transaction:

```sql
CREATE TABLE IF NOT EXISTS oidc_providers (
    tenant_id       TEXT NOT NULL,
    provider_id     TEXT NOT NULL,
    name            TEXT NOT NULL,
    issuer_url      TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    client_secret   TEXT NOT NULL,
    scopes          TEXT NOT NULL,   -- JSON array, same encoding as users.roles
    domains         TEXT NOT NULL,   -- JSON array, denormalized; oidc_provider_domains is the source of truth for uniqueness
    tenant_id_claim TEXT NOT NULL,
    user_id_claim   TEXT NOT NULL DEFAULT '',
    username_claim  TEXT NOT NULL DEFAULT '',
    roles_claim     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, provider_id)
)
CREATE TABLE IF NOT EXISTS oidc_provider_domains (
    domain      TEXT PRIMARY KEY, -- enforces global uniqueness; the lookup index for GetOIDCProviderByDomain
    tenant_id   TEXT NOT NULL,
    provider_id TEXT NOT NULL
)
```

`CreateOIDCProvider`: in one transaction, insert the `oidc_providers` row
(`isUniqueViolation` on the primary key -> `ErrAlreadyExists`, matching
`store/sqlite`'s existing convention), then insert one
`oidc_provider_domains` row per domain (`isUniqueViolation` on any of
them -> roll back and return `ErrDomainTaken`).

`UpdateOIDCProvider`: in one transaction, `UPDATE` the `oidc_providers`
row (0 rows affected -> `ErrNotFound`), `DELETE` this provider's existing
`oidc_provider_domains` rows, then re-`INSERT` the new set (a domain
collision here also means a *different* tenant/provider still holds it,
since this provider's own old rows were just cleared -> `ErrDomainTaken`).

`DeleteOIDCProvider`: in one transaction, `DELETE` from both tables (0
rows affected on `oidc_providers` -> `ErrNotFound`).

## admin and CLI

`tenantkit/admin` (thin wrappers over the store interface, matching the
existing functions' shape -- e.g. `CreateAPIKey`, `RegisterClientCert` --
no logic beyond what's already in those):

```go
func RegisterOIDCProvider(ctx context.Context, s store.OIDCProviderStore, p *tenantkit.OIDCProvider) error
func GetOIDCProvider(ctx context.Context, s store.OIDCProviderStore, tenantID, providerID string) (*tenantkit.OIDCProvider, error)
func ListOIDCProviders(ctx context.Context, s store.OIDCProviderStore, tenantID string) ([]*tenantkit.OIDCProvider, error)
func UpdateOIDCProvider(ctx context.Context, s store.OIDCProviderStore, p *tenantkit.OIDCProvider) error
func RemoveOIDCProvider(ctx context.Context, s store.OIDCProviderStore, tenantID, providerID string) error
```

`tools/cmd/tenantkit-admin`: new `oidc` subcommand (noun-then-verb,
matching `cert register/revoke` and `tenant create/list/deactivate`'s
existing convention), with `--json`/`--dry-run` support matching the
other subcommands:

- `oidc register --tenant --provider-id --name --issuer --client-id --client-secret --tenant-id-claim [--scope ... --domain ... --user-id-claim --username-claim --roles-claim]`
- `oidc list --tenant`
- `oidc show --tenant --provider-id`
- `oidc update --tenant --provider-id [--name --issuer --client-id --client-secret --scope ... --domain ... --tenant-id-claim --user-id-claim --username-claim --roles-claim]` (full replace, same as `UpdateOIDCProvider`)
- `oidc remove --tenant --provider-id`

`--scope`/`--domain` are repeatable flags (one value each), matching how
multi-value input is already handled elsewhere in this CLI.
`--tenant-id-claim` is required on `register` (no default); the other
three claim flags are optional and fall back to `ClaimsMapping`'s
documented defaults when omitted.

## Testing

`storetest.TestOIDCProviderStore(t, s store.OIDCProviderStore)`, run by
both `store/memstore` and `store/sqlite`, covering:
- not-found (`GetOIDCProvider`, `GetOIDCProviderByDomain` on an unknown
  domain)
- create/get round-trip, including `Domains`/`Scopes`/`ClaimsMapping`
  surviving the round-trip
- `ListOIDCProviders` returns an empty slice for a tenant with none, and
  all registered providers for one that has several
- duplicate `(tenant_id, provider_id)` create fails `ErrAlreadyExists`
- a domain already claimed by a different tenant/provider fails
  `ErrDomainTaken` on both `Create` and `Update`
- `Update` replaces (including changing `Domains` -- the old domain
  becomes free, claimable by a different registration afterward)
- `Delete` removes the provider and frees its domains (a subsequent
  `GetOIDCProviderByDomain` for a freed domain returns `ErrNotFound`,
  and a different tenant/provider can now claim it)
- tenant isolation: the same `ProviderID` in two different tenants
  doesn't collide (composite key, not the whole point of `ErrDomainTaken`
  which is specifically about `Domains`, a separate uniqueness axis)

## Alternatives considered

**One provider per tenant (`TenantID` alone as the key).** Simpler
schema and CLI, and was the initial direction during brainstorming, but
rejected: real consumers need to support more than one simultaneous SSO
option per tenant (e.g. Okta for employees, Google for external
collaborators), and retrofitting a composite key later would be a
breaking change to every layer (store, admin, CLI) built on top.

**No domain-based lookup (consumer resolves tenant/provider before
calling anything in this store).** Simpler store surface, but pushes
every consumer wanting an identifier-first login page ("enter your
email") into building and maintaining their own separate
domain-to-tenant mapping -- duplicate data sitting right next to this
store's own `Domains` field, which would otherwise go unused for this
purpose. Rejected in favor of `GetOIDCProviderByDomain`.
