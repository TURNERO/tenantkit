package resolve_test

import (
	"context"
	"testing"

	"github.com/TURNERO/tenantkit/resolve"
)

func TestSubdomainResolver_ResolvesFirstLabel(t *testing.T) {
	r := resolve.NewSubdomainResolver()
	src := fakeSource{host: "acme.example.com"}

	tenantID, ok, err := r.ResolveTenant(context.Background(), src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true for a host with a subdomain")
	}
	if tenantID != "acme" {
		t.Errorf("ResolveTenant tenantID = %q, want acme", tenantID)
	}
}

func TestSubdomainResolver_NoDotInHost(t *testing.T) {
	r := resolve.NewSubdomainResolver()
	src := fakeSource{host: "localhost"}

	tenantID, ok, err := r.ResolveTenant(context.Background(), src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false for a host with no subdomain")
	}
	if tenantID != "" {
		t.Errorf("ResolveTenant tenantID = %q, want empty", tenantID)
	}
}

func TestSubdomainResolver_EmptyHost(t *testing.T) {
	r := resolve.NewSubdomainResolver()
	_, ok, err := r.ResolveTenant(context.Background(), fakeSource{})
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false for an empty host")
	}
}
