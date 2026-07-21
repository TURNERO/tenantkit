package memstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"
	"github.com/TURNERO/tenantkit/store/memstore"
)

func TestStore_CreateAndGetTenant(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()

	want := &tenantkit.Tenant{ID: "acme", DisplayName: "Acme Corp", Active: true}
	if err := s.CreateTenant(ctx, want); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	got, err := s.GetTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if *got != *want {
		t.Errorf("GetTenant = %+v, want %+v", got, want)
	}
}

func TestStore_GetTenant_NotFound(t *testing.T) {
	s := memstore.New()
	_, err := s.GetTenant(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetTenant error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_CreateTenant_DuplicateFails(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	t1 := &tenantkit.Tenant{ID: "acme", DisplayName: "Acme Corp", Active: true}
	if err := s.CreateTenant(ctx, t1); err != nil {
		t.Fatalf("first CreateTenant: %v", err)
	}
	err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: "acme", DisplayName: "Dup", Active: true})
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("CreateTenant error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
	}
}

func TestStore_ListTenants(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: "beta", DisplayName: "Beta", Active: true}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: "acme", DisplayName: "Acme", Active: true}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	got, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(got) != 2 || got[0].ID != "acme" || got[1].ID != "beta" {
		t.Errorf("ListTenants = %+v, want [acme, beta] in order", got)
	}
}

func TestStore_DeactivateTenant(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: "acme", DisplayName: "Acme", Active: true}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	if err := s.DeactivateTenant(ctx, "acme"); err != nil {
		t.Fatalf("DeactivateTenant: %v", err)
	}
	got, err := s.GetTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Active {
		t.Error("expected tenant to be inactive after DeactivateTenant")
	}
}

func TestStore_DeactivateTenant_NotFound(t *testing.T) {
	s := memstore.New()
	err := s.DeactivateTenant(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("DeactivateTenant error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_CreateAndGetUser(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	want := &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice", Roles: []string{"admin"}}
	if err := s.CreateUser(ctx, want); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetUser(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.UserID != want.UserID || got.TenantID != want.TenantID || got.Username != want.Username {
		t.Errorf("GetUser = %+v, want %+v", got, want)
	}
}

func TestStore_GetUser_MutatingResultDoesNotCorruptStore(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice", Roles: []string{"member"}}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetUser(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	got.Roles[0] = "admin"

	again, err := s.GetUser(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUser (second fetch): %v", err)
	}
	if again.Roles[0] != "member" {
		t.Errorf("GetUser Roles[0] = %q after caller mutated a previous result, want %q (store's own copy was corrupted)", again.Roles[0], "member")
	}
}

func TestStore_GetUser_NotFound(t *testing.T) {
	s := memstore.New()
	_, err := s.GetUser(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetUser error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_GetUserByUsername(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetUserByUsername(ctx, "acme", "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.UserID != "u1" {
		t.Errorf("GetUserByUsername returned UserID %q, want u1", got.UserID)
	}
}

func TestStore_GetUserByUsername_MutatingResultDoesNotCorruptStore(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice", Roles: []string{"member"}}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetUserByUsername(ctx, "acme", "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	got.Roles[0] = "admin"

	again, err := s.GetUserByUsername(ctx, "acme", "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername (second fetch): %v", err)
	}
	if again.Roles[0] != "member" {
		t.Errorf("GetUserByUsername Roles[0] = %q after caller mutated a previous result, want %q (store's own copy was corrupted)", again.Roles[0], "member")
	}
}

func TestStore_GetUserByUsername_ScopedToTenant(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err := s.GetUserByUsername(ctx, "globex", "alice")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetUserByUsername in wrong tenant error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_CreateUser_DuplicateUserIDFails(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "someoneelse"})
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("CreateUser duplicate UserID error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
	}
}

func TestStore_CreateUser_DuplicateUsernameInTenantFails(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u2", TenantID: "acme", Username: "alice"})
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("CreateUser duplicate username error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
	}
}

func TestStore_CreateAndGetAPIKey(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	want := &tenantkit.APIKey{Hash: "deadbeef", TenantID: "acme"}
	if err := s.CreateAPIKey(ctx, want); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	got, err := s.GetAPIKeyByHash(ctx, "deadbeef")
	if err != nil {
		t.Fatalf("GetAPIKeyByHash: %v", err)
	}
	if *got != *want {
		t.Errorf("GetAPIKeyByHash = %+v, want %+v", got, want)
	}
}

func TestStore_GetAPIKeyByHash_NotFound(t *testing.T) {
	s := memstore.New()
	_, err := s.GetAPIKeyByHash(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetAPIKeyByHash error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_CreateAPIKey_DuplicateFails(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: "deadbeef", TenantID: "acme"}); err != nil {
		t.Fatalf("first CreateAPIKey: %v", err)
	}
	err := s.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: "deadbeef", TenantID: "globex"})
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("CreateAPIKey duplicate error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
	}
}

func TestStore_RevokeAPIKey(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: "deadbeef", TenantID: "acme"}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	if err := s.RevokeAPIKey(ctx, "deadbeef"); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	_, err := s.GetAPIKeyByHash(ctx, "deadbeef")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetAPIKeyByHash after revoke error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_RevokeAPIKey_NotFound(t *testing.T) {
	s := memstore.New()
	err := s.RevokeAPIKey(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RevokeAPIKey error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_CreateAndGetClientCert(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	want := &tenantkit.ClientCert{Fingerprint: "cafef00d", TenantID: "acme"}
	if err := s.CreateClientCert(ctx, want); err != nil {
		t.Fatalf("CreateClientCert: %v", err)
	}
	got, err := s.GetClientCertByFingerprint(ctx, "cafef00d")
	if err != nil {
		t.Fatalf("GetClientCertByFingerprint: %v", err)
	}
	if *got != *want {
		t.Errorf("GetClientCertByFingerprint = %+v, want %+v", got, want)
	}
}

func TestStore_GetClientCertByFingerprint_NotFound(t *testing.T) {
	s := memstore.New()
	_, err := s.GetClientCertByFingerprint(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetClientCertByFingerprint error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_CreateClientCert_DuplicateFails(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: "cafef00d", TenantID: "acme"}); err != nil {
		t.Fatalf("first CreateClientCert: %v", err)
	}
	err := s.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: "cafef00d", TenantID: "globex"})
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("CreateClientCert duplicate error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
	}
}

func TestStore_RevokeClientCert(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: "cafef00d", TenantID: "acme"}); err != nil {
		t.Fatalf("CreateClientCert: %v", err)
	}

	if err := s.RevokeClientCert(ctx, "cafef00d"); err != nil {
		t.Fatalf("RevokeClientCert: %v", err)
	}
	_, err := s.GetClientCertByFingerprint(ctx, "cafef00d")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetClientCertByFingerprint after revoke error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_RevokeClientCert_NotFound(t *testing.T) {
	s := memstore.New()
	err := s.RevokeClientCert(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RevokeClientCert error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}
