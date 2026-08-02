# identity/oidc follow-up fixes (#13, #14) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two follow-ups from the identity/oidc final review: missing rejection-path test coverage (#14) and an opaque, forever-cached failure for a misconfigured provider registration (#13).

**Architecture:** Two fully independent tasks touching disjoint files -- #14 is test-only (extends the existing `fakeIdP` harness in `finish_test.go`), #13 adds one validation check plus one new sentinel error to `identity/oidc/oidc.go`/`errors.go`, tested via the existing `newTestOIDC`/`newFakeDiscoveryServer` harness in `oidc_test.go`.

**Tech Stack:** No new dependencies -- `crypto/rsa`/`crypto/rand` (already imported in `finish_test.go`) for #14's second signing key.

Design spec: `docs/superpowers/specs/2026-08-02-identity-oidc-followups-design.md`.

## Global Constraints

- Error wrapping follows this package's existing convention throughout: `fmt.Errorf("tenantkit/identity/oidc: <action>: %w", err)`.
- #13's new sentinel is `ErrInvalidProviderConfig`, distinct from `ErrUnknownProvider` (not found) and `ErrInvalidToken` (scoped specifically to token/claims verification failures, not registration validity).
- #13's validation runs in `resolveProviderClient`, after `GetOIDCProvider` succeeds and before `goidc.NewProvider` (discovery) or writing to `o.clients` -- a misconfigured registration must never be cached, and must not cost a network round-trip.
- #13's fix only validates `ClaimsMapping.TenantIDClaim` -- no broader validation pass over other `providerClient` fields.
- #14 makes no production code changes -- the verifier already rejects all three cases correctly; this closes test coverage only.
- Every new/changed test file must remain `package oidc_test` (black-box), matching every existing test in both files.

---

### Task 1: Test coverage for forged signature / wrong audience / wrong issuer (#14)

**Files:**
- Modify: `identity/oidc/finish_test.go`

**Interfaces:**
- Consumes: existing `fakeIdP` type, `newFakeIdP`, `newTestOIDCWithIdP`, `beginAndExtractState` helpers (all already defined in this file); `oidc.ErrInvalidToken` (already exported).
- Produces: `fakeIdP.foreignKey *rsa.PrivateKey` field and `signIDToken`'s new second parameter -- both `finish_test.go`-local, nothing outside this file depends on them.

- [ ] **Step 1: Give `fakeIdP` a way to sign with a key its JWKS never publishes**

In `identity/oidc/finish_test.go`, add a `foreignKey` field to the `fakeIdP` struct:

```go
type fakeIdP struct {
	server      *httptest.Server
	key         *rsa.PrivateKey
	kid         string
	nextClaims  map[string]any // set by the test before calling FinishLogin
	omitIDToken bool           // set by the test to make the token endpoint omit id_token
	foreignKey  *rsa.PrivateKey // set by a test to sign the next ID token with a key this IdP's JWKS never publishes
}
```

Change `signIDToken` to take the signing key as a parameter instead of always using `f.key`:

```go
func (f *fakeIdP) signIDToken(claims map[string]any, key *rsa.PrivateKey) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"kid": f.kid},
	})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return sig.CompactSerialize()
}
```

Update `handleToken` to pass `f.foreignKey` when set, else `f.key`:

```go
func (f *fakeIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp := map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
	}
	if !f.omitIDToken {
		if f.nextClaims == nil {
			http.Error(w, "no claims configured for this test", http.StatusInternalServerError)
			return
		}
		signingKey := f.key
		if f.foreignKey != nil {
			signingKey = f.foreignKey
		}
		idToken, err := f.signIDToken(f.nextClaims, signingKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp["id_token"] = idToken
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
```

Note: `f.kid` (`"test-key-1"`) stays the same in the token header regardless of which key signs it -- the JWKS endpoint (`handleJWKS`) always publishes only `f.key`'s public key under that `kid`, so a token signed with `foreignKey` fails signature verification against the published key even though the `kid` matches. That mismatch (claimed key ID vs. actual signing key) is exactly the forged-signature scenario.

- [ ] **Step 2: Write the three failing tests**

Append to `identity/oidc/finish_test.go`:

```go
func TestFinishLogin_ForeignKeySignatureRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, nonce := beginAndExtractState(t, o)

	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss": idp.server.URL, "sub": "user-123", "aud": "test-client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"nonce": nonce, "tenant": "acme",
	}
	foreignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	idp.foreignKey = foreignKey

	if _, _, err := o.FinishLogin(ctx, state, state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestFinishLogin_WrongAudienceRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, nonce := beginAndExtractState(t, o)

	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss": idp.server.URL, "sub": "user-123", "aud": "some-other-client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"nonce": nonce, "tenant": "acme",
	}

	if _, _, err := o.FinishLogin(ctx, state, state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestFinishLogin_WrongIssuerRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, nonce := beginAndExtractState(t, o)

	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss": "https://not-the-real-idp.example.com", "sub": "user-123", "aud": "test-client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"nonce": nonce, "tenant": "acme",
	}

	if _, _, err := o.FinishLogin(ctx, state, state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./identity/oidc/... -run 'TestFinishLogin_ForeignKeySignatureRejected|TestFinishLogin_WrongAudienceRejected|TestFinishLogin_WrongIssuerRejected' -v`
Expected: FAIL to compile -- `too many arguments in call to f.signIDToken` (from the OLD single-argument call site still in `handleToken` before Step 1's edit) if Step 1 and Step 2 are applied out of order, or (if Step 1 is already applied) the tests should actually PASS immediately since no production code changed and the verifier already does the right thing. **This task has no true RED step in production code** -- Step 1's harness change is what makes these tests expressible at all; treat "compiles and all three pass" as the success criterion, and confirm each test would fail if you temporarily comment out its distinguishing claim (e.g. temporarily set `idp.foreignKey = nil` in the first test and confirm it then fails to get `ErrInvalidToken` -- proving the test genuinely exercises the forged-signature path -- then restore it).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./identity/oidc/... -v`
Expected: PASS, all tests in the package (existing + 3 new).

- [ ] **Step 5: Run `go vet`, `gofmt`, and commit**

```bash
go build ./...
go vet ./...
gofmt -l identity/oidc/
git add identity/oidc/finish_test.go
git commit -m "test: cover forged-signature/wrong-audience/wrong-issuer rejection (#14)"
```

---

### Task 2: Reject an empty TenantIDClaim before caching (#13)

**Files:**
- Modify: `identity/oidc/errors.go`
- Modify: `identity/oidc/oidc.go`
- Modify: `identity/oidc/oidc_test.go`

**Interfaces:**
- Consumes: `resolveProviderClient(ctx, tenantID, providerID) (*providerClient, error)` (existing, unexported), called by `BeginLogin` (`begin.go:36`) and `FinishLogin` (`finish.go:40`) -- both already propagate its error unchanged, so no caller-side changes are needed.
- Produces: `oidc.ErrInvalidProviderConfig` (new exported sentinel).

- [ ] **Step 1: Write the failing test**

Append to `identity/oidc/oidc_test.go`:

```go
func TestBeginLogin_EmptyTenantIDClaimRejectedAndNotCached(t *testing.T) {
	ctx := context.Background()
	o, providers, _ := newTestOIDC(t)
	issuerURL := newFakeDiscoveryServer(t)

	if err := providers.CreateOIDCProvider(ctx, &tenantkit.OIDCProvider{
		TenantID:      "acme",
		ProviderID:    "okta",
		IssuerURL:     issuerURL,
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		ClaimsMapping: tenantkit.ClaimsMapping{TenantIDClaim: ""}, // misconfigured
	}); err != nil {
		t.Fatalf("CreateOIDCProvider: %v", err)
	}

	if _, _, err := o.BeginLogin(ctx, "acme", "okta"); !errors.Is(err, oidc.ErrInvalidProviderConfig) {
		t.Fatalf("first BeginLogin: got %v, want ErrInvalidProviderConfig", err)
	}

	// A second call against the same bad registration must fail the
	// same way -- proves nothing was cached from the first (failed)
	// resolution attempt.
	if _, _, err := o.BeginLogin(ctx, "acme", "okta"); !errors.Is(err, oidc.ErrInvalidProviderConfig) {
		t.Fatalf("second BeginLogin: got %v, want ErrInvalidProviderConfig", err)
	}

	// Fixing the registration (e.g. via admin.UpdateOIDCProvider in a
	// real deployment) must take effect on the very next call -- no
	// process restart needed, since nothing bad was ever cached.
	if err := providers.UpdateOIDCProvider(ctx, &tenantkit.OIDCProvider{
		TenantID:      "acme",
		ProviderID:    "okta",
		IssuerURL:     issuerURL,
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		ClaimsMapping: tenantkit.ClaimsMapping{TenantIDClaim: "tenant"},
	}); err != nil {
		t.Fatalf("UpdateOIDCProvider: %v", err)
	}
	if _, _, err := o.BeginLogin(ctx, "acme", "okta"); err != nil {
		t.Fatalf("third BeginLogin after fixing registration: %v", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./identity/oidc/... -run TestBeginLogin_EmptyTenantIDClaimRejectedAndNotCached -v`
Expected: FAIL to compile -- `undefined: oidc.ErrInvalidProviderConfig`.

- [ ] **Step 3: Add `ErrInvalidProviderConfig`**

In `identity/oidc/errors.go`, add inside the existing `var (...)` block, after `ErrUnknownProvider`:

```go
	// ErrInvalidProviderConfig wraps a provider registration that was
	// found but isn't usable to build an OAuth2/OIDC client from --
	// currently just an empty ClaimsMapping.TenantIDClaim.
	// admin.RegisterOIDCProvider and admin.UpdateOIDCProvider already
	// reject this before it reaches the store; this only bites a
	// consumer implementing store.OIDCProviderStore directly.
	ErrInvalidProviderConfig = errors.New("tenantkit/identity/oidc: invalid provider config")
```

- [ ] **Step 4: Validate in `resolveProviderClient` before discovery/caching**

In `identity/oidc/oidc.go`, in `resolveProviderClient`, insert a check immediately after the `GetOIDCProvider` error-handling block and before the `goidc.NewProvider` call:

```go
	p, err := o.providers.GetOIDCProvider(ctx, tenantID, providerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("tenantkit/identity/oidc: look up provider: %w", ErrUnknownProvider)
		}
		return nil, fmt.Errorf("tenantkit/identity/oidc: look up provider: %w", err)
	}
	if p.ClaimsMapping.TenantIDClaim == "" {
		return nil, fmt.Errorf("tenantkit/identity/oidc: provider %s/%s: claims mapping TenantIDClaim is required: %w", tenantID, providerID, ErrInvalidProviderConfig)
	}

	provider, err := goidc.NewProvider(ctx, p.IssuerURL)
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./identity/oidc/... -run TestBeginLogin_EmptyTenantIDClaimRejectedAndNotCached -v`
Expected: PASS.

- [ ] **Step 6: Run the full package test suite, `go vet`, `gofmt`, and commit**

```bash
go build ./...
go vet ./...
gofmt -l identity/oidc/
go test ./identity/oidc/... -v
git add identity/oidc/errors.go identity/oidc/oidc.go identity/oidc/oidc_test.go
git commit -m "fix: reject empty TenantIDClaim before caching a provider client (#13)"
```

Expected: all commands clean, all existing `identity/oidc` tests still pass.

---

## Final Verification

After both tasks:

```bash
go build ./...
go vet ./...
gofmt -l .
go test ./... -v
```

Expected: everything clean, every test passing, no gofmt diffs. This closes [issue #13](https://github.com/TURNERO/tenantkit/issues/13) and [issue #14](https://github.com/TURNERO/tenantkit/issues/14).
