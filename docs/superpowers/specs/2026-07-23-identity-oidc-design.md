# identity/oidc design

## Overview

[Issue #5](https://github.com/TURNERO/tenantkit/issues/5) asks for
`identity/oidc`, the second of the two `identity.IdentityProvider`
implementations the main design spec
(`docs/superpowers/specs/2026-07-20-tenantkit-design.md`) calls for: a
built-in adapter wrapping any external OIDC-compliant IdP (Auth0, Okta,
Clerk, Keycloak, Zitadel, etc.) via `github.com/coreos/go-oidc/v3` and
`golang.org/x/oauth2`.

This plan builds on
`docs/superpowers/specs/2026-07-23-oidc-provider-store-design.md`
(`store.OIDCProviderStore`, already spec'd separately): each tenant can
register one or more IdPs there, and this plan is the adapter that
actually performs the OAuth2 Authorization Code ceremony against a
looked-up registration, verifies the resulting ID token, and issues
tenantkit's own session -- mirroring `identity/local`'s WebAuthn
Begin/Finish ceremony pattern and session-backed `Authenticate`.

Per the issue's own framing, `identity/oidc` shares only the
`identity.IdentityProvider` interface with `identity/local` and has no
other dependency on it -- it does not use `store.UserStore`, and its
session/ephemeral storage interfaces are independently declared (not
imported from `identity/local`), even though a couple of them are
structurally similar.

## Scope

In scope:
- `identity/oidc.Config`, `identity/oidc.OIDC`, `New` -- construction,
  and a lazily-built, per-`(tenantID, providerID)` cache of each
  registered provider's `oauth2.Config` + `*oidc.IDTokenVerifier`.
- `BeginLogin`, `BeginLoginByDomain`, `FinishLogin` -- the OAuth2
  Authorization Code ceremony.
- `Authenticate` -- satisfies `identity.IdentityProvider`, session-cookie
  based, no per-request IdP round-trip.
- `SessionStore`, `EphemeralStore` -- new interfaces, own to this
  package.
- `identity/oidc/memstore` -- in-memory reference implementation, tests
  only (same role as `identity/local/memstore`).
- `identity/oidc/storetest` -- conformance suite for the two interfaces
  above, run against `memstore` (same role as `identity/local/storetest`
  after issue #4).
- Claims-to-`Identity` mapping, applying the per-provider
  `tenantkit.ClaimsMapping` (from the `OIDCProviderStore` plan)
  including its documented defaults.

Out of scope:
- A persistent (SQLite) `SessionStore`/`EphemeralStore` backend --
  deferred to its own follow-up plan, the same sequencing
  `identity/local/sqlite` followed after `identity/local`.
- Token refresh, RP-initiated logout, back-channel logout.
- Any HTTP routes. Like `identity/local`, `BeginLogin`/`FinishLogin` are
  plain Go functions a consumer wires into their own `/login` and
  `/callback` handlers -- no framework, matching tenantkit's existing
  "middleware, not a framework" positioning.
- Anything already covered by
  `docs/superpowers/specs/2026-07-23-oidc-provider-store-design.md`
  (the store, admin ops, CLI).

## Package layout

```
tenantkit/identity/oidc/
  oidc.go        // Config, OIDC, New, per-(tenant,provider) cache
  login.go       // BeginLogin, BeginLoginByDomain, FinishLogin
  session.go     // Authenticate, SetSessionCookie/ClearSessionCookie, SessionCookieName
  claims.go       // claims -> tenantkit.Identity mapping, applying ClaimsMapping defaults
  store.go       // SessionStore, EphemeralStore interfaces
  errors.go      // sentinel errors
  memstore/      // in-memory reference implementation
  storetest/     // conformance suite for SessionStore/EphemeralStore
```

## Design decisions

**No dependency on `identity/local` or `store.UserStore`.** The verified
ID token's claims *are* the Identity -- there's nothing to look up in a
local user table, which is the whole point of delegating to an external
IdP rather than duplicating user management in two places. This is why
`SessionStore` here has a different shape than `identity/local`'s (next
section): there's no `userID` to re-fetch from later, so the session has
to carry the full mapped `Identity`.

**Provider client caching, no invalidation (v1).** `oidc.NewProvider`
performs discovery (fetches `/.well-known/openid-configuration`) and
sets up JWKS fetching -- a real network round-trip that shouldn't happen
on every single login. `*OIDC` holds a mutex-guarded
`map[tenantProviderKey]*providerClient`, built lazily on first use of a
given `(tenantID, providerID)`. Trade-off accepted explicitly: if an
admin updates a tenant's provider registration via the CLI (rotate a
client secret, change issuer), a running process keeps using the stale
cached config until restart. Documented on `New`, not solved with more
machinery (a TTL, a watch on the store, etc.) for v1.

**Tenant-claim verification is a required, explicit check in
`FinishLogin`.** `httpmw`/`grpcmw` both reject a request if
`Identity.TenantID` doesn't match the tenant already resolved for that
request via the resolver chain (see `httpmw.go`'s `errTenantMismatch`).
`FinishLogin` additionally checks the token's mapped `TenantID` against
the `tenantID` the ceremony was *started* for, before ever creating a
session -- defense in depth against a misconfigured IdP or a token
crafted/replayed for the wrong tenant, same spirit as
`identity/local.Authenticate`'s session/user tenant-mismatch guard.

**One error bucket for token/claims failures.** `ErrInvalidToken` covers
signature/issuer/audience/expiry failures, a nonce mismatch, a
tenant-claim mismatch, and a missing/malformed mapped claim -- all
"this token is not acceptable," deliberately not split into finer
sentinel errors, mirroring how `identity/local.ErrInvalidCredentials`
doesn't distinguish "wrong password" from "no such user" (a caller
shouldn't be able to use error type to enumerate *why* a login failed).

## Types and interfaces

```go
// identity/oidc (oidc.go)
type Config struct {
    // RedirectURL is fixed for the whole service -- registered
    // identically with every tenant's IdP (a callback route your
    // service's own router serves, e.g. "https://app.example.com/auth/callback").
    RedirectURL string
    // SessionTTL is how long a session issued by FinishLogin stays valid.
    SessionTTL time.Duration
}

// OIDC satisfies identity.IdentityProvider via Authenticate.
type OIDC struct {
    cfg       Config
    providers store.OIDCProviderStore
    sessions  SessionStore
    ephemeral EphemeralStore

    mu      sync.Mutex
    clients map[tenantProviderKey]*providerClient // lazily populated, never evicted (see design decisions)
}

type tenantProviderKey struct {
    tenantID   string
    providerID string
}

// providerClient is what New (lazily) builds from a tenantkit.OIDCProvider
// registration: everything needed to run the OAuth2/OIDC ceremony for
// that one (tenant, provider) pair without hitting the store again.
type providerClient struct {
    oauth2Config *oauth2.Config
    verifier     *oidc.IDTokenVerifier
    mapping      tenantkit.ClaimsMapping
}

// New returns an OIDC identity provider. It returns an error if
// cfg.RedirectURL is empty.
func New(cfg Config, providers store.OIDCProviderStore, sessions SessionStore, ephemeral EphemeralStore) (*OIDC, error)
```

```go
// identity/oidc (store.go)

// SessionStore holds active OIDC-backed login sessions. Unlike
// identity/local's SessionStore, this stores the full Identity, not
// just (tenantID, userID) -- there is no UserStore to re-fetch it from
// later.
type SessionStore interface {
    CreateSession(ctx context.Context, id *tenantkit.Identity, ttl time.Duration) (token string, err error)
    // GetSession returns ErrNotFound (no such token) or ErrExpired
    // (existed, past ttl).
    GetSession(ctx context.Context, token string) (*tenantkit.Identity, error)
    DeleteSession(ctx context.Context, token string) error
}

// EphemeralStore holds short-lived, single-use opaque tokens: OAuth2
// state/nonce ceremony data between BeginLogin and FinishLogin. Same
// 2-method shape as identity/local's EphemeralStore, independently
// declared per this package's no-dependency-on-identity/local rule.
type EphemeralStore interface {
    Put(ctx context.Context, token string, payload []byte, ttl time.Duration) error
    // Take fetches and deletes atomically, so a replayed callback
    // (or a replayed/expired ceremony) always fails on a second attempt.
    Take(ctx context.Context, token string) ([]byte, error) // ErrNotFound / ErrExpired
}
```

```go
// identity/oidc (errors.go)
var (
    ErrNotFound       = errors.New("tenantkit/identity/oidc: not found")
    ErrExpired        = errors.New("tenantkit/identity/oidc: expired")
    // ErrUnknownProvider wraps store.ErrNotFound from a provider lookup
    // (BeginLogin/BeginLoginByDomain/FinishLogin given a (tenantID,
    // providerID) or domain with no matching registration).
    ErrUnknownProvider = errors.New("tenantkit/identity/oidc: unknown provider")
    // ErrInvalidToken covers every token/claims verification failure --
    // see "One error bucket for token/claims failures" above.
    ErrInvalidToken = errors.New("tenantkit/identity/oidc: invalid token")
)
```

## Login ceremony

**`BeginLogin(ctx, tenantID, providerID string) (redirectURL string, err error)`**
1. Resolve the `(tenantID, providerID)`'s `*providerClient` from the
   cache; on a miss, `providers.GetOIDCProvider(ctx, tenantID,
   providerID)` (→ `ErrUnknownProvider` if `store.ErrNotFound`), then
   `oidc.NewProvider(ctx, p.IssuerURL)`, build the `oauth2.Config`
   (`Scopes: append([]string{oidc.ScopeOpenID}, p.Scopes...)`) and
   `provider.Verifier(&oidc.Config{ClientID: p.ClientID})`, cache all
   three plus `p.ClaimsMapping`.
2. Generate `state` and `nonce` via `store.GenerateSecret()` (the same
   helper `identity/local`'s session creation and `store/sqlite`'s
   API-key issuance already use).
3. JSON-encode `{tenantID, providerID, nonce}` and `ephemeral.Put(ctx,
   state, payload, loginCeremonyTTL)` -- a short, unexported constant
   (5 minutes, matching `identity/local`'s `webauthnCeremonyTTL`
   precedent: comfortably covers a real browser/IdP redirect round-trip,
   no evidence any consumer needs it tunable).
4. Return `oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))`. The
   consumer's login handler redirects the browser there.

**`BeginLoginByDomain(ctx, domain string) (redirectURL string, err error)`**
Looks up `(tenantID, providerID)` via `providers.GetOIDCProviderByDomain`
(→ `ErrUnknownProvider` if `store.ErrNotFound`), then calls `BeginLogin`.
Pure convenience for an identifier-first ("enter your email") login
page -- saves every such consumer writing the same two-line glue, since
`*OIDC` already holds the store handle `BeginLogin` needs anyway.

**`FinishLogin(ctx, state, code string) (identity *tenantkit.Identity, sessionToken string, err error)`**
1. `ephemeral.Take(ctx, state)` -- single-use; a replayed callback (or
   one for an expired ceremony) fails here (`ErrNotFound`/`ErrExpired`).
   Decode `{tenantID, providerID, nonce}`.
2. Resolve the `(tenantID, providerID)`'s cached `*providerClient` (same
   lazy-build path as step 1 of `BeginLogin` -- a different process
   handling the callback than the one that handled `BeginLogin` just
   costs a cache miss, not a correctness problem, since the ceremony
   state itself travels via `EphemeralStore`, not in-memory).
3. `oauth2Config.Exchange(ctx, code)` to get the token response.
4. Pull the raw ID token from `token.Extra("id_token").(string)` --
   `ErrInvalidToken` if absent or not a string.
5. `verifier.Verify(ctx, rawIDToken)` -- checks signature, issuer,
   audience, and expiry; wrap any failure as `ErrInvalidToken`.
6. Compare the verified token's `Nonce` field against the ceremony's
   stored `nonce` -- mismatch is `ErrInvalidToken`.
7. Decode the token's claims into `map[string]any` and map them to a
   `*tenantkit.Identity` via `mapping` (see Claims mapping below) --
   any missing/malformed required claim is `ErrInvalidToken`.
8. Verify `identity.TenantID == tenantID` (the tenant this ceremony was
   started for) -- mismatch is `ErrInvalidToken` (see "Tenant-claim
   verification" design decision above).
9. `sessions.CreateSession(ctx, identity, cfg.SessionTTL)`. Return
   `identity` (e.g. for the consumer to render a welcome page) and the
   session token (for the consumer to set via `SetSessionCookie`).

**`Authenticate(ctx, src) (*tenantkit.Identity, error)`** -- satisfies
`identity.IdentityProvider`. Reads the session cookie from `src`
(same `SessionCookieName`/cookie-parsing approach as
`identity/local.Authenticate`, independently implemented in this
package). Absent cookie → `(nil, nil)` (not an error -- degrade to
anonymous, identical contract to `identity/local`). Present-but-invalid
or expired → a real error. No IdP round-trip on this path at all --
that's the entire reason `FinishLogin` created a local session in the
first place.

## Claims mapping

Applied once, in `FinishLogin` step 7, using the `tenantkit.ClaimsMapping`
cached alongside that `(tenantID, providerID)`'s `providerClient`:

```go
func mapClaims(claims map[string]any, m tenantkit.ClaimsMapping) (*tenantkit.Identity, error) {
    userIDClaim := m.UserIDClaim
    if userIDClaim == "" {
        userIDClaim = "sub"
    }
    usernameClaim := m.UsernameClaim
    if usernameClaim == "" {
        usernameClaim = "email"
    }
    rolesClaim := m.RolesClaim
    if rolesClaim == "" {
        rolesClaim = "roles"
    }

    tenantID, ok := claims[m.TenantIDClaim].(string)
    if !ok || tenantID == "" {
        return nil, fmt.Errorf("tenantkit/identity/oidc: missing/invalid %q claim: %w", m.TenantIDClaim, ErrInvalidToken)
    }
    userID, ok := claims[userIDClaim].(string)
    if !ok || userID == "" {
        return nil, fmt.Errorf("tenantkit/identity/oidc: missing/invalid %q claim: %w", userIDClaim, ErrInvalidToken)
    }
    username, _ := claims[usernameClaim].(string) // optional: falls back to "" rather than failing

    var roles []string
    if raw, ok := claims[rolesClaim]; ok {
        arr, ok := raw.([]any)
        if !ok {
            return nil, fmt.Errorf("tenantkit/identity/oidc: %q claim is not an array: %w", rolesClaim, ErrInvalidToken)
        }
        for _, v := range arr {
            s, ok := v.(string)
            if !ok {
                return nil, fmt.Errorf("tenantkit/identity/oidc: %q claim contains a non-string element: %w", rolesClaim, ErrInvalidToken)
            }
            roles = append(roles, s)
        }
    }

    return &tenantkit.Identity{TenantID: tenantID, UserID: userID, Username: username, Roles: roles}, nil
}
```

`TenantIDClaim` and the mapped user-ID claim are required (a missing or
wrong-type value is `ErrInvalidToken`); `Username`/`Roles` degrade
gracefully (empty string / nil slice) if their claim is simply absent,
since not every IdP or scope grants them, but a *present-and-malformed*
roles claim (not a JSON array of strings) is still rejected rather than
silently ignored.

## Testing

No real IdP in CI, matching the main design spec's stated bar
("`identity/oidc` tests: run against a mocked/test OIDC provider, no
network dependency"):

- An `httptest.Server` serves a fake `/.well-known/openid-configuration`
  discovery document, a JWKS endpoint, and a token endpoint.
- Test ID tokens are signed in-process with `github.com/go-jose/go-jose/v4`
  against a throwaway RSA key whose public half is exposed via the fake
  JWKS endpoint -- the standard way to exercise `go-oidc`'s verifier
  without network access.
- Coverage: a full `BeginLogin` → (simulated redirect/consent) →
  `FinishLogin` round-trip against the fake IdP, including: correct
  claims mapping (with and without optional claims present, exercising
  every default), state/nonce correctness, a replayed `state` failing
  (single-use), an expired ceremony failing, a tenant-claim mismatch
  being rejected, a malformed roles claim being rejected,
  `BeginLoginByDomain` resolving through `store.OIDCProviderStore`
  (`store/memstore`, which already exists), `ErrUnknownProvider` for an
  unregistered `(tenantID, providerID)`/domain, and `Authenticate`
  against a present/absent/expired session.
- `identity/oidc/storetest.TestSessionStore`/`TestEphemeralStore`, run
  against `identity/oidc/memstore`, covering the same not-found/expired/
  single-use/overwrite scenarios `identity/local/storetest` already
  established for its own two interfaces.

## Alternatives considered

**Bearer/resource-server-only mode (no ceremony, no session; verify an
already-issued token on every request).** Considered first during
brainstorming and rejected: the issue's own stated dependency on
`golang.org/x/oauth2` (not just `go-oidc`) pointed at the fuller
Authorization Code flow, and a session-backed `Authenticate` avoids an
IdP/JWKS round-trip on every single request, matching
`identity/local`'s existing shape and giving `httpmw`/`grpcmw` a
consistent, cheap `Authenticate` call regardless of which provider is
configured.

**Deriving `Identity` from a local `store.UserStore` record instead of
token claims.** Rejected: would require provisioning a local user record
before anyone could log in via OIDC, duplicating user/role management in
two places and defeating the stated reason to support an external IdP
at all (see main design spec's stated goal). Confirmed during
brainstorming.

**No provider-client caching (always call `oidc.NewProvider` fresh).**
Simpler, always reflects the latest registered config with no restart
needed, but adds a discovery-plus-JWKS network round-trip to every
single login attempt. Rejected in favor of the lazy, non-invalidating
cache described above.
