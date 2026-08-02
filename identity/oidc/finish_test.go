package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity/oidc"
	oidcmem "github.com/TURNERO/tenantkit/identity/oidc/memstore"
	"github.com/TURNERO/tenantkit/store/memstore"
	"github.com/go-jose/go-jose/v4"
)

// fakeIdP serves a minimal OIDC discovery document, JWKS endpoint, and
// token endpoint, and signs ID tokens in-process -- so FinishLogin's
// tests never hit a real IdP over the network.
type fakeIdP struct {
	server      *httptest.Server
	key         *rsa.PrivateKey
	kid         string
	nextClaims  map[string]any  // set by the test before calling FinishLogin
	omitIDToken bool            // set by the test to make the token endpoint omit id_token
	foreignKey  *rsa.PrivateKey // set by a test to sign the next ID token with a key this IdP's JWKS never publishes
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	f := &fakeIdP{key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/jwks", f.handleJWKS)
	mux.HandleFunc("/token", f.handleToken)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIdP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                f.server.URL,
		"authorization_endpoint":                f.server.URL + "/authorize",
		"token_endpoint":                        f.server.URL + "/token",
		"jwks_uri":                              f.server.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (f *fakeIdP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := jose.JSONWebKey{Key: &f.key.PublicKey, KeyID: f.kid, Algorithm: "RS256", Use: "sig"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

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

// newTestOIDCWithIdP wires an OIDC instance to idp and registers a
// single (acme, okta) provider pointing at it.
func newTestOIDCWithIdP(t *testing.T, idp *fakeIdP) *oidc.OIDC {
	t.Helper()
	providers := memstore.New()
	oidcStore := oidcmem.New()
	o, err := oidc.New(oidc.Config{
		RedirectURL: "https://app.example.com/callback",
		SessionTTL:  time.Hour,
	}, providers, oidcStore, oidcStore)
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	if err := providers.CreateOIDCProvider(context.Background(), &tenantkit.OIDCProvider{
		TenantID:      "acme",
		ProviderID:    "okta",
		IssuerURL:     idp.server.URL,
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		ClaimsMapping: tenantkit.ClaimsMapping{TenantIDClaim: "tenant"},
	}); err != nil {
		t.Fatalf("CreateOIDCProvider: %v", err)
	}
	return o
}

// beginAndExtractState runs BeginLogin and pulls state/nonce back out
// of the redirect URL it returns, so the test can configure the fake
// IdP's next ID token to use the matching nonce before simulating the
// callback.
func beginAndExtractState(t *testing.T, o *oidc.OIDC) (state, nonce string) {
	t.Helper()
	redirectURL, state, err := o.BeginLogin(context.Background(), "acme", "okta")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}
	return state, parsed.Query().Get("nonce")
}

func TestFinishLogin(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, nonce := beginAndExtractState(t, o)

	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss":    idp.server.URL,
		"sub":    "user-123",
		"aud":    "test-client",
		"exp":    now.Add(time.Hour).Unix(),
		"iat":    now.Unix(),
		"nonce":  nonce,
		"email":  "alice@acme.com",
		"tenant": "acme",
		"roles":  []string{"admin", "member"},
	}

	identity, sessionToken, err := o.FinishLogin(ctx, state, state, "fake-auth-code")
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if identity.TenantID != "acme" || identity.UserID != "user-123" || identity.Username != "alice@acme.com" {
		t.Fatalf("got %+v", identity)
	}
	if len(identity.Roles) != 2 || identity.Roles[0] != "admin" || identity.Roles[1] != "member" {
		t.Fatalf("roles = %v", identity.Roles)
	}
	if sessionToken == "" {
		t.Fatal("expected non-empty session token")
	}
}

func TestFinishLogin_ReplayedStateFails(t *testing.T) {
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

	if _, _, err := o.FinishLogin(ctx, state, state, "fake-auth-code"); err != nil {
		t.Fatalf("first FinishLogin: %v", err)
	}
	if _, _, err := o.FinishLogin(ctx, state, state, "fake-auth-code"); !errors.Is(err, oidc.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound on replayed state", err)
	}
}

func TestFinishLogin_NonceMismatchRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, _ := beginAndExtractState(t, o)
	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss": idp.server.URL, "sub": "user-123", "aud": "test-client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"nonce": "wrong-nonce", "tenant": "acme",
	}

	if _, _, err := o.FinishLogin(ctx, state, state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestFinishLogin_TenantClaimMismatchRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, nonce := beginAndExtractState(t, o)
	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss": idp.server.URL, "sub": "user-123", "aud": "test-client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"nonce": nonce, "tenant": "some-other-tenant", // ceremony was started for "acme"
	}

	if _, _, err := o.FinishLogin(ctx, state, state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestFinishLogin_MalformedRolesClaimRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, nonce := beginAndExtractState(t, o)
	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss": idp.server.URL, "sub": "user-123", "aud": "test-client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"nonce": nonce, "tenant": "acme", "roles": "not-an-array",
	}

	if _, _, err := o.FinishLogin(ctx, state, state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestFinishLogin_ExpiredTokenRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, nonce := beginAndExtractState(t, o)
	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss": idp.server.URL, "sub": "user-123", "aud": "test-client",
		"exp": now.Add(-time.Hour).Unix(), "iat": now.Add(-2 * time.Hour).Unix(), // already expired
		"nonce": nonce, "tenant": "acme",
	}

	if _, _, err := o.FinishLogin(ctx, state, state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestFinishLogin_UnknownStateFails(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	if _, _, err := o.FinishLogin(ctx, "bogus-state", "bogus-state", "fake-auth-code"); !errors.Is(err, oidc.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestFinishLogin_MissingIDTokenRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	idp.omitIDToken = true
	o := newTestOIDCWithIdP(t, idp)

	state, _ := beginAndExtractState(t, o)

	if _, _, err := o.FinishLogin(ctx, state, state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

// TestFinishLogin_StateCookieMismatchRejected proves the state-cookie
// binding (RFC 9700 §4.7 login-CSRF protection) actually rejects a
// mismatched cookieState, and that doing so does NOT consume the real
// ceremony via ephemeral.Take -- an attacker's mismatched attempt must
// not burn the legitimate ceremony a victim's browser could still
// complete. Proven by immediately following the rejected attempt with
// the correct (cookieState == state) call and confirming it succeeds.
func TestFinishLogin_StateCookieMismatchRejected(t *testing.T) {
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

	if _, _, err := o.FinishLogin(ctx, "wrong-cookie-value", state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}

	// The mismatched attempt above must not have consumed the ceremony
	// via ephemeral.Take -- the legitimate call (matching cookieState)
	// must still succeed.
	if _, _, err := o.FinishLogin(ctx, state, state, "fake-auth-code"); err != nil {
		t.Fatalf("legitimate FinishLogin after mismatched attempt: %v", err)
	}
}

// TestFinishLogin_EmptyStateCookieRejected proves an empty/absent state
// cookie is rejected rather than treated as an unconditional match.
func TestFinishLogin_EmptyStateCookieRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, _ := beginAndExtractState(t, o)

	if _, _, err := o.FinishLogin(ctx, "", state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

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
