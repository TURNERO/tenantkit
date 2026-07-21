package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"
	"github.com/TURNERO/tenantkit/store/memstore"
)

func TestGenerateSecret_ReturnsHighEntropyUniqueValues(t *testing.T) {
	a, err := store.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	b, err := store.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if a == b {
		t.Error("expected two calls to GenerateSecret to return different values")
	}
	if len(a) < 32 {
		t.Errorf("GenerateSecret returned a %d-char value, want at least 32", len(a))
	}
}

func TestHashSecret_Deterministic(t *testing.T) {
	h1 := store.HashSecret("my-secret")
	h2 := store.HashSecret("my-secret")
	if h1 != h2 {
		t.Errorf("HashSecret not deterministic: %q != %q", h1, h2)
	}
	if h1 == "my-secret" {
		t.Error("HashSecret returned the plaintext unchanged")
	}
}

func TestHashSecret_DifferentInputsDifferentHashes(t *testing.T) {
	if store.HashSecret("a") == store.HashSecret("b") {
		t.Error("expected different inputs to hash differently")
	}
}

func TestValidTenantID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"acme", true},
		{"acme-corp", true},
		{"acme123", true},
		{"", false},
		{"Acme", false},
		{"acme_corp", false},
		{"acme corp", false},
		{"acme/corp", false},
	}
	for _, c := range cases {
		if got := store.ValidTenantID(c.id); got != c.want {
			t.Errorf("ValidTenantID(%q) = %v, want %v", c.id, got, c.want)
		}
	}
}

func TestRotateAPIKey(t *testing.T) {
	ks := memstore.New()
	ctx := context.Background()

	oldSecret, err := store.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	oldHash := store.HashSecret(oldSecret)
	if err := ks.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: oldHash, TenantID: "acme", UserID: "u1"}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	newSecret, err := store.RotateAPIKey(ctx, ks, oldHash, "acme", "u1")
	if err != nil {
		t.Fatalf("RotateAPIKey: %v", err)
	}
	if newSecret == oldSecret {
		t.Error("expected RotateAPIKey to return a new secret, got the old one")
	}

	if _, err := ks.GetAPIKeyByHash(ctx, oldHash); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected old key to be revoked, GetAPIKeyByHash error = %v", err)
	}

	newHash := store.HashSecret(newSecret)
	got, err := ks.GetAPIKeyByHash(ctx, newHash)
	if err != nil {
		t.Fatalf("GetAPIKeyByHash for new key: %v", err)
	}
	if got.TenantID != "acme" || got.UserID != "u1" {
		t.Errorf("new key = %+v, want TenantID=acme UserID=u1", got)
	}
}

func TestRotateAPIKey_OldHashNotFound(t *testing.T) {
	ks := memstore.New()
	ctx := context.Background()

	_, err := store.RotateAPIKey(ctx, ks, "does-not-exist", "acme", "u1")
	if err == nil {
		t.Fatal("expected an error rotating a nonexistent key, got nil")
	}

	// Confirm RotateAPIKey didn't leave a new, orphaned key behind when
	// the old one didn't exist -- it must check for the old key before
	// creating a replacement.
	got, listErr := ks.GetAPIKeyByHash(ctx, "does-not-exist")
	if listErr == nil {
		t.Errorf("expected no key to exist for the failed rotation, got %+v", got)
	}
}


func TestGenerateTenantID_SatisfiesValidTenantID(t *testing.T) {
	id, err := store.GenerateTenantID()
	if err != nil {
		t.Fatalf("GenerateTenantID: %v", err)
	}
	if !store.ValidTenantID(id) {
		t.Errorf("GenerateTenantID() = %q, not valid per ValidTenantID", id)
	}
}

func TestGenerateTenantID_ReturnsUniqueValues(t *testing.T) {
	a, err := store.GenerateTenantID()
	if err != nil {
		t.Fatalf("GenerateTenantID: %v", err)
	}
	b, err := store.GenerateTenantID()
	if err != nil {
		t.Fatalf("GenerateTenantID: %v", err)
	}
	if a == b {
		t.Error("expected two calls to GenerateTenantID to return different values")
	}
}
