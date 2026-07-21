// Package storetest provides interface-conformance test helpers for
// tenantkit's store interfaces. A consumer's own store implementation
// (SQL, NoSQL, or otherwise) can run these against a fresh instance to
// prove it satisfies the documented behavior of store.TenantStore,
// store.UserStore, store.APIKeyStore, and store.ClientCertStore -- not
// just that it compiles against the interface.
package storetest

import (
	"context"
	"errors"
	"testing"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"
)

// TestTenantStore runs a battery of subtests against s. Pass a fresh,
// empty store -- these subtests create tenants and do not clean up
// after themselves.
func TestTenantStore(t *testing.T, s store.TenantStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateAndGet", func(t *testing.T) {
		want := &tenantkit.Tenant{ID: "conformance-acme", DisplayName: "Acme Corp", Active: true}
		if err := s.CreateTenant(ctx, want); err != nil {
			t.Fatalf("CreateTenant: %v", err)
		}
		got, err := s.GetTenant(ctx, "conformance-acme")
		if err != nil {
			t.Fatalf("GetTenant: %v", err)
		}
		if got.ID != want.ID || got.DisplayName != want.DisplayName || got.Active != want.Active {
			t.Errorf("GetTenant = %+v, want %+v", got, want)
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		_, err := s.GetTenant(ctx, "conformance-does-not-exist")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetTenant error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("CreateDuplicateFails", func(t *testing.T) {
		id := "conformance-dupe"
		if err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: id, DisplayName: "First", Active: true}); err != nil {
			t.Fatalf("first CreateTenant: %v", err)
		}
		err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: id, DisplayName: "Second", Active: true})
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Errorf("CreateTenant duplicate error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
		}
	})

	t.Run("ListIncludesCreated", func(t *testing.T) {
		id := "conformance-listed"
		if err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: id, DisplayName: "Listed", Active: true}); err != nil {
			t.Fatalf("CreateTenant: %v", err)
		}
		got, err := s.ListTenants(ctx)
		if err != nil {
			t.Fatalf("ListTenants: %v", err)
		}
		found := false
		for _, tn := range got {
			if tn.ID == id {
				found = true
			}
		}
		if !found {
			t.Errorf("ListTenants did not include tenant %q", id)
		}
	})

	t.Run("GetMutatingResultDoesNotCorruptStore", func(t *testing.T) {
		id := "conformance-get-mutate"
		if err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: id, DisplayName: "Original Name", Active: true}); err != nil {
			t.Fatalf("CreateTenant: %v", err)
		}
		got, err := s.GetTenant(ctx, id)
		if err != nil {
			t.Fatalf("GetTenant: %v", err)
		}
		got.DisplayName = "Mutated Name"
		got.Active = false

		again, err := s.GetTenant(ctx, id)
		if err != nil {
			t.Fatalf("GetTenant (second fetch): %v", err)
		}
		if again.DisplayName != "Original Name" || !again.Active {
			t.Errorf("GetTenant = %+v after caller mutated a previous result, want DisplayName %q and Active %v (store's own copy was corrupted)", again, "Original Name", true)
		}
	})

	t.Run("Deactivate", func(t *testing.T) {
		id := "conformance-deactivate"
		if err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: id, DisplayName: "Deactivate Me", Active: true}); err != nil {
			t.Fatalf("CreateTenant: %v", err)
		}
		if err := s.DeactivateTenant(ctx, id); err != nil {
			t.Fatalf("DeactivateTenant: %v", err)
		}
		got, err := s.GetTenant(ctx, id)
		if err != nil {
			t.Fatalf("GetTenant: %v", err)
		}
		if got.Active {
			t.Error("expected tenant to be inactive after DeactivateTenant")
		}
	})

	t.Run("DeactivateNotFound", func(t *testing.T) {
		err := s.DeactivateTenant(ctx, "conformance-does-not-exist-either")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeactivateTenant error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})
}

// TestUserStore runs a battery of subtests against s. Pass a fresh,
// empty store.
func TestUserStore(t *testing.T, s store.UserStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateAndGet", func(t *testing.T) {
		want := &tenantkit.Identity{UserID: "conformance-u1", TenantID: "conformance-tenant", Username: "alice", Roles: []string{"admin"}}
		if err := s.CreateUser(ctx, want); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		got, err := s.GetUser(ctx, "conformance-u1")
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if got.UserID != want.UserID || got.TenantID != want.TenantID || got.Username != want.Username {
			t.Errorf("GetUser = %+v, want %+v", got, want)
		}
	})

	t.Run("GetByUsername", func(t *testing.T) {
		if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "conformance-u2", TenantID: "conformance-tenant", Username: "bob"}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		got, err := s.GetUserByUsername(ctx, "conformance-tenant", "bob")
		if err != nil {
			t.Fatalf("GetUserByUsername: %v", err)
		}
		if got.UserID != "conformance-u2" {
			t.Errorf("GetUserByUsername returned UserID %q, want conformance-u2", got.UserID)
		}
	})

	t.Run("GetByUsernameScopedToTenant", func(t *testing.T) {
		if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "conformance-u3", TenantID: "conformance-tenant-a", Username: "carol"}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		_, err := s.GetUserByUsername(ctx, "conformance-tenant-b", "carol")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetUserByUsername in wrong tenant error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		_, err := s.GetUser(ctx, "conformance-does-not-exist")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetUser error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("CreateDuplicateUserIDFails", func(t *testing.T) {
		id := "conformance-dupe-user"
		if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: id, TenantID: "conformance-tenant", Username: "dupe-a"}); err != nil {
			t.Fatalf("first CreateUser: %v", err)
		}
		err := s.CreateUser(ctx, &tenantkit.Identity{UserID: id, TenantID: "conformance-tenant", Username: "dupe-b"})
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Errorf("CreateUser duplicate UserID error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
		}
	})

	t.Run("GetMutatingResultDoesNotCorruptStore", func(t *testing.T) {
		if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "conformance-u4", TenantID: "conformance-tenant", Username: "dave", Roles: []string{"member"}}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		got, err := s.GetUser(ctx, "conformance-u4")
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		got.Roles[0] = "admin"

		again, err := s.GetUser(ctx, "conformance-u4")
		if err != nil {
			t.Fatalf("GetUser (second fetch): %v", err)
		}
		if again.Roles[0] != "member" {
			t.Errorf("GetUser Roles[0] = %q after caller mutated a previous result, want %q (store's own copy was corrupted)", again.Roles[0], "member")
		}
	})
}

// TestAPIKeyStore runs a battery of subtests against s. Pass a fresh,
// empty store.
func TestAPIKeyStore(t *testing.T, s store.APIKeyStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateAndGet", func(t *testing.T) {
		want := &tenantkit.APIKey{Hash: "conformance-hash-1", TenantID: "conformance-tenant"}
		if err := s.CreateAPIKey(ctx, want); err != nil {
			t.Fatalf("CreateAPIKey: %v", err)
		}
		got, err := s.GetAPIKeyByHash(ctx, "conformance-hash-1")
		if err != nil {
			t.Fatalf("GetAPIKeyByHash: %v", err)
		}
		if got.Hash != want.Hash || got.TenantID != want.TenantID {
			t.Errorf("GetAPIKeyByHash = %+v, want %+v", got, want)
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		_, err := s.GetAPIKeyByHash(ctx, "conformance-does-not-exist")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetAPIKeyByHash error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("CreateDuplicateFails", func(t *testing.T) {
		hash := "conformance-hash-dupe"
		if err := s.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: hash, TenantID: "conformance-tenant"}); err != nil {
			t.Fatalf("first CreateAPIKey: %v", err)
		}
		err := s.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: hash, TenantID: "conformance-tenant-2"})
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Errorf("CreateAPIKey duplicate error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		hash := "conformance-hash-revoke"
		if err := s.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: hash, TenantID: "conformance-tenant"}); err != nil {
			t.Fatalf("CreateAPIKey: %v", err)
		}
		if err := s.RevokeAPIKey(ctx, hash); err != nil {
			t.Fatalf("RevokeAPIKey: %v", err)
		}
		_, err := s.GetAPIKeyByHash(ctx, hash)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetAPIKeyByHash after revoke error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("RevokeNotFound", func(t *testing.T) {
		err := s.RevokeAPIKey(ctx, "conformance-does-not-exist-2")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RevokeAPIKey error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})
}

// TestClientCertStore runs a battery of subtests against s. Pass a
// fresh, empty store.
func TestClientCertStore(t *testing.T, s store.ClientCertStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateAndGet", func(t *testing.T) {
		want := &tenantkit.ClientCert{Fingerprint: "conformance-fp-1", TenantID: "conformance-tenant"}
		if err := s.CreateClientCert(ctx, want); err != nil {
			t.Fatalf("CreateClientCert: %v", err)
		}
		got, err := s.GetClientCertByFingerprint(ctx, "conformance-fp-1")
		if err != nil {
			t.Fatalf("GetClientCertByFingerprint: %v", err)
		}
		if got.Fingerprint != want.Fingerprint || got.TenantID != want.TenantID {
			t.Errorf("GetClientCertByFingerprint = %+v, want %+v", got, want)
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		_, err := s.GetClientCertByFingerprint(ctx, "conformance-does-not-exist")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetClientCertByFingerprint error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("CreateDuplicateFails", func(t *testing.T) {
		fp := "conformance-fp-dupe"
		if err := s.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: fp, TenantID: "conformance-tenant"}); err != nil {
			t.Fatalf("first CreateClientCert: %v", err)
		}
		err := s.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: fp, TenantID: "conformance-tenant-2"})
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Errorf("CreateClientCert duplicate error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		fp := "conformance-fp-revoke"
		if err := s.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: fp, TenantID: "conformance-tenant"}); err != nil {
			t.Fatalf("CreateClientCert: %v", err)
		}
		if err := s.RevokeClientCert(ctx, fp); err != nil {
			t.Fatalf("RevokeClientCert: %v", err)
		}
		_, err := s.GetClientCertByFingerprint(ctx, fp)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetClientCertByFingerprint after revoke error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("RevokeNotFound", func(t *testing.T) {
		err := s.RevokeClientCert(ctx, "conformance-does-not-exist-2")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RevokeClientCert error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})
}
