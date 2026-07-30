package oidc_test

import (
	"context"
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
	"github.com/TURNERO/tenantkit/store"
	"github.com/TURNERO/tenantkit/store/memstore"
)

// newTestOIDC returns an OIDC instance wired to fresh in-memory stores,
// plus the OIDCProviderStore (for registering providers) and the
// identity/oidc memstore.Store (for seeding sessions/ephemeral data
// directly, bypassing the full login ceremony). Reused by Tasks 4-5's
// tests.
func newTestOIDC(t *testing.T) (o *oidc.OIDC, providers store.OIDCProviderStore, oidcStore *oidcmem.Store) {
	t.Helper()
	providers = memstore.New()
	oidcStore = oidcmem.New()
	o, err := oidc.New(oidc.Config{
		RedirectURL: "https://app.example.com/callback",
		SessionTTL:  time.Hour,
	}, providers, oidcStore, oidcStore)
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	return o, providers, oidcStore
}

// newFakeDiscoveryServer serves just enough of an OIDC discovery
// document and an empty JWKS for oidc.NewProvider to succeed. It never
// issues or verifies tokens -- BeginLogin/BeginLoginByDomain only need
// discovery to succeed to build a provider client, they never exchange
// a code or verify anything (that's Task 4's FinishLogin, which uses
// its own more complete fake IdP in finish_test.go).
func newFakeDiscoveryServer(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	var issuerURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":                                issuerURL,
			"authorization_endpoint":                issuerURL + "/authorize",
			"token_endpoint":                        issuerURL + "/token",
			"jwks_uri":                              issuerURL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	issuerURL = server.URL
	return issuerURL
}

func TestNew_RequiresRedirectURL(t *testing.T) {
	providers := memstore.New()
	oidcStore := oidcmem.New()
	if _, err := oidc.New(oidc.Config{}, providers, oidcStore, oidcStore); err == nil {
		t.Fatal("expected error for empty RedirectURL")
	}
}

func TestBeginLogin(t *testing.T) {
	ctx := context.Background()
	o, providers, _ := newTestOIDC(t)
	issuerURL := newFakeDiscoveryServer(t)

	if err := providers.CreateOIDCProvider(ctx, &tenantkit.OIDCProvider{
		TenantID:      "acme",
		ProviderID:    "okta",
		Name:          "Acme Okta",
		IssuerURL:     issuerURL,
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		Scopes:        []string{"email"},
		ClaimsMapping: tenantkit.ClaimsMapping{TenantIDClaim: "tenant"},
	}); err != nil {
		t.Fatalf("CreateOIDCProvider: %v", err)
	}

	redirectURL, err := o.BeginLogin(ctx, "acme", "okta")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}
	q := parsed.Query()
	if got := q.Get("client_id"); got != "test-client" {
		t.Errorf("client_id = %q", got)
	}
	if q.Get("state") == "" {
		t.Error("expected non-empty state")
	}
	if q.Get("nonce") == "" {
		t.Error("expected non-empty nonce")
	}
	if got := q.Get("redirect_uri"); got != "https://app.example.com/callback" {
		t.Errorf("redirect_uri = %q", got)
	}
}

func TestBeginLogin_UnknownProvider(t *testing.T) {
	ctx := context.Background()
	o, _, _ := newTestOIDC(t)
	if _, err := o.BeginLogin(ctx, "acme", "nonexistent"); !errors.Is(err, oidc.ErrUnknownProvider) {
		t.Fatalf("got %v, want ErrUnknownProvider", err)
	}
}

func TestBeginLoginByDomain(t *testing.T) {
	ctx := context.Background()
	o, providers, _ := newTestOIDC(t)
	issuerURL := newFakeDiscoveryServer(t)

	if err := providers.CreateOIDCProvider(ctx, &tenantkit.OIDCProvider{
		TenantID:      "acme",
		ProviderID:    "okta",
		Name:          "Acme Okta",
		IssuerURL:     issuerURL,
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		Domains:       []string{"acme.com"},
		ClaimsMapping: tenantkit.ClaimsMapping{TenantIDClaim: "tenant"},
	}); err != nil {
		t.Fatalf("CreateOIDCProvider: %v", err)
	}

	redirectURL, err := o.BeginLoginByDomain(ctx, "acme.com")
	if err != nil {
		t.Fatalf("BeginLoginByDomain: %v", err)
	}
	if redirectURL == "" {
		t.Fatal("expected non-empty redirect URL")
	}
}

func TestBeginLoginByDomain_UnknownDomain(t *testing.T) {
	ctx := context.Background()
	o, _, _ := newTestOIDC(t)
	if _, err := o.BeginLoginByDomain(ctx, "nonexistent.com"); !errors.Is(err, oidc.ErrUnknownProvider) {
		t.Fatalf("got %v, want ErrUnknownProvider", err)
	}
}

func TestBeginLogin_CachesProviderClient(t *testing.T) {
	ctx := context.Background()
	o, providers, _ := newTestOIDC(t)
	issuerURL := newFakeDiscoveryServer(t)

	if err := providers.CreateOIDCProvider(ctx, &tenantkit.OIDCProvider{
		TenantID:      "acme",
		ProviderID:    "okta",
		IssuerURL:     issuerURL,
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		ClaimsMapping: tenantkit.ClaimsMapping{TenantIDClaim: "tenant"},
	}); err != nil {
		t.Fatalf("CreateOIDCProvider: %v", err)
	}

	// First call builds and caches the provider client (a real
	// discovery round trip against the fake server). Deleting the
	// registration afterward and confirming a second BeginLogin call
	// still succeeds proves the second call used the cached client
	// rather than re-resolving from the store -- an incorrect
	// (non-caching, or wrongly-evicting) implementation would fail
	// this with ErrUnknownProvider.
	if _, err := o.BeginLogin(ctx, "acme", "okta"); err != nil {
		t.Fatalf("first BeginLogin: %v", err)
	}
	if err := providers.DeleteOIDCProvider(ctx, "acme", "okta"); err != nil {
		t.Fatalf("DeleteOIDCProvider: %v", err)
	}
	if _, err := o.BeginLogin(ctx, "acme", "okta"); err != nil {
		t.Fatalf("second BeginLogin (should use cache, provider was deleted): %v", err)
	}
}
