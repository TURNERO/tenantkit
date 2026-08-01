package oidc

import (
	"errors"
	"testing"

	"github.com/TURNERO/tenantkit"
)

func TestMapClaims_AllDefaults(t *testing.T) {
	claims := map[string]any{
		"tenant": "acme",
		"sub":    "user-123",
		"email":  "alice@acme.com",
		"roles":  []any{"admin", "member"},
	}
	id, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"})
	if err != nil {
		t.Fatalf("mapClaims: %v", err)
	}
	if id.TenantID != "acme" || id.UserID != "user-123" || id.Username != "alice@acme.com" {
		t.Fatalf("got %+v", id)
	}
	if len(id.Roles) != 2 || id.Roles[0] != "admin" || id.Roles[1] != "member" {
		t.Fatalf("roles = %v", id.Roles)
	}
}

func TestMapClaims_CustomClaimNames(t *testing.T) {
	claims := map[string]any{
		"org_id":       "acme",
		"user_uuid":    "u-999",
		"preferred_un": "alice",
	}
	id, err := mapClaims(claims, tenantkit.ClaimsMapping{
		TenantIDClaim: "org_id",
		UserIDClaim:   "user_uuid",
		UsernameClaim: "preferred_un",
	})
	if err != nil {
		t.Fatalf("mapClaims: %v", err)
	}
	if id.TenantID != "acme" || id.UserID != "u-999" || id.Username != "alice" {
		t.Fatalf("got %+v", id)
	}
	if id.Roles != nil {
		t.Fatalf("roles = %v, want nil (claim absent)", id.Roles)
	}
}

func TestMapClaims_MissingTenantClaim(t *testing.T) {
	claims := map[string]any{"sub": "user-123"}
	if _, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestMapClaims_MissingUserIDClaim(t *testing.T) {
	claims := map[string]any{"tenant": "acme"}
	if _, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestMapClaims_MissingUsernameAndRolesClaimsOK(t *testing.T) {
	claims := map[string]any{"tenant": "acme", "sub": "user-123"}
	id, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"})
	if err != nil {
		t.Fatalf("mapClaims: %v", err)
	}
	if id.Username != "" {
		t.Fatalf("Username = %q, want empty", id.Username)
	}
	if id.Roles != nil {
		t.Fatalf("Roles = %v, want nil", id.Roles)
	}
}

func TestMapClaims_MalformedRolesClaimRejected(t *testing.T) {
	claims := map[string]any{"tenant": "acme", "sub": "user-123", "roles": "not-an-array"}
	if _, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestMapClaims_RolesArrayWithNonStringElementRejected(t *testing.T) {
	claims := map[string]any{"tenant": "acme", "sub": "user-123", "roles": []any{"admin", 42}}
	if _, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestMapClaims_TenantIDWrongTypeRejected(t *testing.T) {
	claims := map[string]any{"tenant": 12345, "sub": "user-123"}
	if _, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}
