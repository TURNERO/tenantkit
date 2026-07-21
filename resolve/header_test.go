package resolve_test

import (
	"context"
	"testing"

	"github.com/TURNERO/tenantkit/resolve"
)

func TestHeaderResolver_ResolvesFromHeader(t *testing.T) {
	r := resolve.NewHeaderResolver("X-Tenant-ID")
	src := fakeSource{headers: map[string]string{"X-Tenant-ID": "acme"}}

	tenantID, ok, err := r.ResolveTenant(context.Background(), src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true when the header is present")
	}
	if tenantID != "acme" {
		t.Errorf("ResolveTenant tenantID = %q, want acme", tenantID)
	}
}

func TestHeaderResolver_MissingHeader(t *testing.T) {
	r := resolve.NewHeaderResolver("X-Tenant-ID")
	tenantID, ok, err := r.ResolveTenant(context.Background(), fakeSource{})
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false when the header is absent")
	}
	if tenantID != "" {
		t.Errorf("ResolveTenant tenantID = %q, want empty", tenantID)
	}
}

func TestHeaderResolver_UsesConfiguredHeaderName(t *testing.T) {
	r := resolve.NewHeaderResolver("X-Custom-Tenant")
	src := fakeSource{headers: map[string]string{"X-Tenant-ID": "acme"}}

	_, ok, err := r.ResolveTenant(context.Background(), src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false when only a differently-named header is present")
	}
}
