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
	"slices"
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

// TestOIDCProviderStore runs a battery of subtests against s. Pass a
// fresh, empty store -- these subtests create providers and do not
// clean up after themselves.
func TestOIDCProviderStore(t *testing.T, s store.OIDCProviderStore) {
	t.Helper()
	ctx := context.Background()

	newProvider := func(tenantID, providerID string, domains ...string) *tenantkit.OIDCProvider {
		return &tenantkit.OIDCProvider{
			TenantID:     tenantID,
			ProviderID:   providerID,
			Name:         "Test Provider",
			IssuerURL:    "https://idp.example/" + tenantID + "/" + providerID,
			ClientID:     "client-" + providerID,
			ClientSecret: "secret-" + providerID,
			Scopes:       []string{"openid", "email"},
			Domains:      domains,
			ClaimsMapping: tenantkit.ClaimsMapping{
				TenantIDClaim: "https://example/tenant_id",
				UserIDClaim:   "sub",
				UsernameClaim: "email",
				RolesClaim:    "roles",
			},
		}
	}

	t.Run("CreateAndGet", func(t *testing.T) {
		want := newProvider("conformance-acme", "okta", "conformance-acme-okta.example")
		if err := s.CreateOIDCProvider(ctx, want); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		got, err := s.GetOIDCProvider(ctx, "conformance-acme", "okta")
		if err != nil {
			t.Fatalf("GetOIDCProvider: %v", err)
		}
		if got.TenantID != want.TenantID || got.ProviderID != want.ProviderID || got.Name != want.Name ||
			got.IssuerURL != want.IssuerURL || got.ClientID != want.ClientID || got.ClientSecret != want.ClientSecret {
			t.Errorf("GetOIDCProvider = %+v, want %+v", got, want)
		}
		if !slices.Equal(got.Scopes, want.Scopes) {
			t.Errorf("GetOIDCProvider Scopes = %v, want %v", got.Scopes, want.Scopes)
		}
		if !slices.Equal(got.Domains, want.Domains) {
			t.Errorf("GetOIDCProvider Domains = %v, want %v", got.Domains, want.Domains)
		}
		if got.ClaimsMapping != want.ClaimsMapping {
			t.Errorf("GetOIDCProvider ClaimsMapping = %+v, want %+v", got.ClaimsMapping, want.ClaimsMapping)
		}
	})

	t.Run("GetMutatingResultDoesNotCorruptStore", func(t *testing.T) {
		p := newProvider("conformance-mutate-tenant", "okta", "conformance-mutate.example")
		if err := s.CreateOIDCProvider(ctx, p); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		got, err := s.GetOIDCProvider(ctx, "conformance-mutate-tenant", "okta")
		if err != nil {
			t.Fatalf("GetOIDCProvider: %v", err)
		}
		got.Domains[0] = "mutated.example"
		got.Scopes[0] = "mutated-scope"

		again, err := s.GetOIDCProvider(ctx, "conformance-mutate-tenant", "okta")
		if err != nil {
			t.Fatalf("GetOIDCProvider (second fetch): %v", err)
		}
		if again.Domains[0] != "conformance-mutate.example" {
			t.Errorf("GetOIDCProvider Domains[0] = %q after caller mutated a previous result, want %q (store's own copy was corrupted)", again.Domains[0], "conformance-mutate.example")
		}
		if again.Scopes[0] != "openid" {
			t.Errorf("GetOIDCProvider Scopes[0] = %q after caller mutated a previous result, want %q (store's own copy was corrupted)", again.Scopes[0], "openid")
		}
	})
	t.Run("GetNotFound", func(t *testing.T) {
		_, err := s.GetOIDCProvider(ctx, "conformance-acme", "conformance-does-not-exist")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetOIDCProvider error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("GetByDomain", func(t *testing.T) {
		p := newProvider("conformance-globex", "google", "conformance-globex-google.example")
		if err := s.CreateOIDCProvider(ctx, p); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		got, err := s.GetOIDCProviderByDomain(ctx, "conformance-globex-google.example")
		if err != nil {
			t.Fatalf("GetOIDCProviderByDomain: %v", err)
		}
		if got.TenantID != "conformance-globex" || got.ProviderID != "google" {
			t.Errorf("GetOIDCProviderByDomain = %+v, want tenant conformance-globex provider google", got)
		}
	})

	t.Run("GetByDomainNotFound", func(t *testing.T) {
		_, err := s.GetOIDCProviderByDomain(ctx, "conformance-unclaimed.example")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetOIDCProviderByDomain error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("ListEmpty", func(t *testing.T) {
		got, err := s.ListOIDCProviders(ctx, "conformance-no-providers-tenant")
		if err != nil {
			t.Fatalf("ListOIDCProviders: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("ListOIDCProviders = %+v, want empty", got)
		}
	})

	t.Run("ListIncludesCreated", func(t *testing.T) {
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-multi", "okta")); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-multi", "google")); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		got, err := s.ListOIDCProviders(ctx, "conformance-multi")
		if err != nil {
			t.Fatalf("ListOIDCProviders: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("ListOIDCProviders = %+v, want 2 entries", got)
		}
	})

	t.Run("CreateDuplicateProviderIDFails", func(t *testing.T) {
		p := newProvider("conformance-dupe-tenant", "okta")
		if err := s.CreateOIDCProvider(ctx, p); err != nil {
			t.Fatalf("first CreateOIDCProvider: %v", err)
		}
		err := s.CreateOIDCProvider(ctx, newProvider("conformance-dupe-tenant", "okta"))
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Errorf("CreateOIDCProvider duplicate error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
		}
	})

	t.Run("CreateDomainTakenFails", func(t *testing.T) {
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-domain-a", "okta", "conformance-shared.example")); err != nil {
			t.Fatalf("first CreateOIDCProvider: %v", err)
		}
		err := s.CreateOIDCProvider(ctx, newProvider("conformance-domain-b", "okta", "conformance-shared.example"))
		if !errors.Is(err, store.ErrDomainTaken) {
			t.Errorf("CreateOIDCProvider domain-taken error = %v, want errors.Is(err, store.ErrDomainTaken)", err)
		}
	})

	t.Run("Update", func(t *testing.T) {
		p := newProvider("conformance-update-tenant", "okta", "conformance-update-old.example")
		if err := s.CreateOIDCProvider(ctx, p); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		p.Name = "Updated Name"
		p.Domains = []string{"conformance-update-new.example"}
		if err := s.UpdateOIDCProvider(ctx, p); err != nil {
			t.Fatalf("UpdateOIDCProvider: %v", err)
		}
		got, err := s.GetOIDCProvider(ctx, "conformance-update-tenant", "okta")
		if err != nil {
			t.Fatalf("GetOIDCProvider: %v", err)
		}
		if got.Name != "Updated Name" || !slices.Equal(got.Domains, []string{"conformance-update-new.example"}) {
			t.Errorf("GetOIDCProvider after update = %+v, want Name %q Domains %v", got, "Updated Name", []string{"conformance-update-new.example"})
		}
		// The old domain must be freed.
		_, err = s.GetOIDCProviderByDomain(ctx, "conformance-update-old.example")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetOIDCProviderByDomain for freed domain error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("UpdateNotFound", func(t *testing.T) {
		err := s.UpdateOIDCProvider(ctx, newProvider("conformance-update-missing", "okta"))
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdateOIDCProvider error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("UpdateDomainTakenFails", func(t *testing.T) {
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-ud-a", "okta", "conformance-ud-taken.example")); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		p := newProvider("conformance-ud-b", "okta")
		if err := s.CreateOIDCProvider(ctx, p); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		p.Domains = []string{"conformance-ud-taken.example"}
		err := s.UpdateOIDCProvider(ctx, p)
		if !errors.Is(err, store.ErrDomainTaken) {
			t.Errorf("UpdateOIDCProvider domain-taken error = %v, want errors.Is(err, store.ErrDomainTaken)", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		p := newProvider("conformance-delete-tenant", "okta", "conformance-delete.example")
		if err := s.CreateOIDCProvider(ctx, p); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		if err := s.DeleteOIDCProvider(ctx, "conformance-delete-tenant", "okta"); err != nil {
			t.Fatalf("DeleteOIDCProvider: %v", err)
		}
		_, err := s.GetOIDCProvider(ctx, "conformance-delete-tenant", "okta")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetOIDCProvider after delete error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
		_, err = s.GetOIDCProviderByDomain(ctx, "conformance-delete.example")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetOIDCProviderByDomain after delete error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
		// The freed domain must be claimable again.
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-delete-tenant-2", "google", "conformance-delete.example")); err != nil {
			t.Errorf("CreateOIDCProvider re-claiming freed domain: %v", err)
		}
	})

	t.Run("DeleteNotFound", func(t *testing.T) {
		err := s.DeleteOIDCProvider(ctx, "conformance-delete-missing", "okta")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteOIDCProvider error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-iso-a", "shared-id")); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		// Same ProviderID, different tenant -- must not collide.
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-iso-b", "shared-id")); err != nil {
			t.Errorf("CreateOIDCProvider in different tenant with same ProviderID: %v", err)
		}
	})
}
