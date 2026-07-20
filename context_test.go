package tenantkit_test

import (
	"context"
	"testing"

	"github.com/TURNERO/tenantkit"
)

func TestWithTenant_TenantFromContext(t *testing.T) {
	tenant := &tenantkit.Tenant{ID: "acme", DisplayName: "Acme Corp", Active: true}
	ctx := tenantkit.WithTenant(context.Background(), tenant)

	got, ok := tenantkit.TenantFromContext(ctx)
	if !ok {
		t.Fatal("expected TenantFromContext to return ok=true")
	}
	if got != tenant {
		t.Errorf("TenantFromContext returned %+v, want %+v", got, tenant)
	}
}

func TestTenantFromContext_Missing(t *testing.T) {
	_, ok := tenantkit.TenantFromContext(context.Background())
	if ok {
		t.Error("expected ok=false when no tenant is in context")
	}
}

func TestWithIdentity_IdentityFromContext(t *testing.T) {
	id := &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice", Roles: []string{"admin"}}
	ctx := tenantkit.WithIdentity(context.Background(), id)

	got, ok := tenantkit.IdentityFromContext(ctx)
	if !ok {
		t.Fatal("expected IdentityFromContext to return ok=true")
	}
	if got != id {
		t.Errorf("IdentityFromContext returned %+v, want %+v", got, id)
	}
}

func TestIdentityFromContext_Missing(t *testing.T) {
	_, ok := tenantkit.IdentityFromContext(context.Background())
	if ok {
		t.Error("expected ok=false when no identity is in context")
	}
}
