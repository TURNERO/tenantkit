# identity/oidc follow-up fixes (#13, #14) design

## Overview

Two small, independent follow-ups filed during the identity/oidc final
whole-branch review (`docs/superpowers/plans/2026-07-29-identity-oidc.md`).
Neither changes the package's public API surface beyond one new sentinel
error.

## #14 -- missing test coverage for forged signature / wrong audience / wrong issuer

Pure test-coverage gap, no production code change. `identity/oidc`'s
verification pipeline (`go-oidc`'s `IDTokenVerifier`) already rejects all
three cases correctly -- the existing `TestFinishLogin_ExpiredTokenRejected`
proves the verifier is genuinely wired in and its failures become
`ErrInvalidToken`, and `TestFinishLogin`'s happy path exercises real
signature verification positively. This closes coverage completeness, not
a wiring risk.

Add to `identity/oidc/finish_test.go`, reusing the existing `fakeIdP`
harness (`newFakeIdP`, `newTestOIDCWithIdP`, `beginAndExtractState`):

- `TestFinishLogin_ForeignKeySignatureRejected` -- sign the ID token with a
  second `rsa.GenerateKey` never published in the fake IdP's JWKS
  response. Requires `fakeIdP` to gain a way to sign one response with an
  alternate key (its `handleToken`/`signIDToken` currently always use
  `f.key`) -- add a `foreignKey *rsa.PrivateKey` field the test sets
  before calling `FinishLogin`; when set, `signIDToken` uses it instead of
  `f.key` for that one token, while the JWKS endpoint keeps serving only
  the real `f.key`'s public key.
- `TestFinishLogin_WrongAudienceRejected` -- `nextClaims["aud"]` set to a
  client ID other than the registered provider's `ClientID`
  (`"test-client"`), everything else valid.
- `TestFinishLogin_WrongIssuerRejected` -- `nextClaims["iss"]` set to a
  URL other than the fake IdP's own `idp.server.URL`.

All three assert `errors.Is(err, oidc.ErrInvalidToken)`, matching every
existing rejection test in the file (e.g.
`TestFinishLogin_ExpiredTokenRejected`,
`TestFinishLogin_TenantClaimMismatchRejected`).

## #13 -- empty TenantIDClaim fails opaquely and is cached forever

`mapClaims` (`identity/oidc/claims.go`) looks up
`claims[m.TenantIDClaim]` with no default -- an empty `TenantIDClaim`
produces `missing/invalid "" claim` on every single login for that
provider, an unhelpful error that doesn't name the real cause
(misconfiguration, not a bad token). Worse: `resolveProviderClient`
(`identity/oidc/oidc.go`) caches the built `*providerClient` forever
(`New`'s documented, deliberate v1 trade-off -- no eviction), so once a
`providerClient` is built and cached, this persists until process restart
even after an admin fixes the registration.

`admin.RegisterOIDCProvider`/`UpdateOIDCProvider` already validate
`TenantIDClaim` is non-empty before writing to the store, so this only
bites a consumer implementing `store.OIDCProviderStore` directly and
bypassing the admin package -- which the README explicitly says is
supported.

**Fix:** validate in `resolveProviderClient`, immediately after fetching
`p` from `o.providers.GetOIDCProvider` and before doing OIDC discovery or
writing to `o.clients`:

```go
if p.ClaimsMapping.TenantIDClaim == "" {
	return nil, fmt.Errorf("tenantkit/identity/oidc: provider %s/%s: claims mapping TenantIDClaim is required: %w", tenantID, providerID, ErrInvalidProviderConfig)
}
```

Because this check runs before the cache write, a fixed registration
(via the CLI/admin package, or a direct store update) is picked up on the
very next `BeginLogin`/`FinishLogin` call for that provider -- no restart
needed. No network round-trip (discovery) happens for an already-known-bad
registration either, matching the package's existing "fail fast, minimal
cost" precedent (`identity/local`'s `SetPassword` doc comment, cited in
the login-limiter design).

**New sentinel**, added to `identity/oidc/errors.go`'s existing `var (...)`
block, parallel to `ErrUnknownProvider` ("found but not usable" vs. "not
found"), not folded into `ErrInvalidToken` (which the package's own docs
scope specifically to token/claims *verification* failures, not
registration validity -- a `ClaimsMapping.TenantIDClaim` gap is caught
before any token exists to verify):

```go
// ErrInvalidProviderConfig wraps a provider registration that was found
// but isn't usable to build an OAuth2/OIDC client from -- currently
// just an empty ClaimsMapping.TenantIDClaim. admin.RegisterOIDCProvider
// and admin.UpdateOIDCProvider already reject this before it reaches
// the store; this only bites a consumer implementing
// store.OIDCProviderStore directly.
ErrInvalidProviderConfig = errors.New("tenantkit/identity/oidc: invalid provider config")
```

**Scope note:** this fix only validates `TenantIDClaim`, matching the
issue's exact scope -- not a general validation pass over every
`providerClient` field (`ClientID`, `IssuerURL`, etc. already fail loudly
via `goidc.NewProvider`'s discovery round-trip or a rejected OAuth2
exchange, they don't silently misbehave the way an empty claim name
does).

## Testing (#13)

Add `TestResolveProviderClient_EmptyTenantIDClaimRejected` (or as a
`FinishLogin`-level test, following this file's existing pattern of
driving behavior through the public API rather than an unexported
function) to `identity/oidc/oidc_test.go` or `finish_test.go` (whichever
already has the right fixtures -- prefer reusing `newTestOIDCWithIdP` if
it's easy to parameterize the registered provider's `ClaimsMapping`,
otherwise register a second provider inline in the test): register a
provider with `ClaimsMapping{TenantIDClaim: ""}`, call `BeginLogin` (or
`FinishLogin`, whichever reaches `resolveProviderClient`) for it, assert
`errors.Is(err, oidc.ErrInvalidProviderConfig)`. Then call again and
assert the same error each time (proving it isn't cached as a
`*providerClient` that would instead produce a different failure on the
second call).

## Open questions

None blocking.
