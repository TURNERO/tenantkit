package resolve_test

import (
	"context"
	"testing"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
	"github.com/TURNERO/tenantkit/store/memstore"
)

func TestAPIKeyResolver_ResolvesValidKey(t *testing.T) {
	ks := memstore.New()
	ctx := context.Background()
	secret, err := store.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if err := ks.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: store.HashSecret(secret), TenantID: "acme"}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	r := resolve.NewAPIKeyResolver(ks)
	src := fakeSource{headers: map[string]string{"Authorization": "Bearer " + secret}}

	tenantID, ok, err := r.ResolveTenant(ctx, src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true for a present Authorization header")
	}
	if tenantID != "acme" {
		t.Errorf("ResolveTenant tenantID = %q, want acme", tenantID)
	}
}

func TestAPIKeyResolver_NoAuthorizationHeader(t *testing.T) {
	r := resolve.NewAPIKeyResolver(memstore.New())
	tenantID, ok, err := r.ResolveTenant(context.Background(), fakeSource{})
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false when no Authorization header is present")
	}
	if tenantID != "" {
		t.Errorf("ResolveTenant tenantID = %q, want empty", tenantID)
	}
}

func TestAPIKeyResolver_NonBearerAuthorizationHeader(t *testing.T) {
	r := resolve.NewAPIKeyResolver(memstore.New())
	src := fakeSource{headers: map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}}
	_, ok, err := r.ResolveTenant(context.Background(), src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false for a non-Bearer Authorization header")
	}
}

func TestAPIKeyResolver_UnknownKeyFailsChain(t *testing.T) {
	r := resolve.NewAPIKeyResolver(memstore.New())
	src := fakeSource{headers: map[string]string{"Authorization": "Bearer unknown-token"}}
	_, ok, err := r.ResolveTenant(context.Background(), src)
	if err == nil {
		t.Fatal("expected an error for an unrecognized API key, got nil")
	}
	if !ok {
		t.Error("expected ok=true when credential material was present but invalid, so the chain does not fall through")
	}
}
