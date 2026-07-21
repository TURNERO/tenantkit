// Package admin implements tenantkit's tenant/user/key/cert provisioning
// operations, working purely against the store interfaces -- the same
// operations cmd/tenantkit-admin's CLI wraps. A consumer with extra
// provisioning steps outside tenantkit's scope can import this package
// directly and compose its operations with their own, rather than being
// limited to shelling out to the binary.
package admin

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
)

// CreateTenant validates id (see store.ValidTenantID) and inserts a new,
// active tenant record.
func CreateTenant(ctx context.Context, ts store.TenantStore, id, displayName string) (*tenantkit.Tenant, error) {
	if !store.ValidTenantID(id) {
		return nil, fmt.Errorf("invalid tenant id %q: must match ^[a-z0-9-]+$", id)
	}
	t := &tenantkit.Tenant{ID: id, DisplayName: displayName, Active: true}
	if err := ts.CreateTenant(ctx, t); err != nil {
		return nil, fmt.Errorf("create tenant: %w", err)
	}
	return t, nil
}

// ListTenants returns every tenant.
func ListTenants(ctx context.Context, ts store.TenantStore) ([]*tenantkit.Tenant, error) {
	tenants, err := ts.ListTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	return tenants, nil
}

// DeactivateTenant marks the tenant with the given ID inactive.
func DeactivateTenant(ctx context.Context, ts store.TenantStore, id string) error {
	if err := ts.DeactivateTenant(ctx, id); err != nil {
		return fmt.Errorf("deactivate tenant: %w", err)
	}
	return nil
}

// CreateAPIKey generates a new high-entropy secret, hashes it, and
// creates the record. Returns the plaintext secret -- the only time
// it's ever available; the caller must show/store it now. userID may be
// empty for a tenant-level key.
func CreateAPIKey(ctx context.Context, ks store.APIKeyStore, tenantID, userID string) (string, error) {
	secret, err := store.GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("generate api key: %w", err)
	}
	k := &tenantkit.APIKey{Hash: store.HashSecret(secret), TenantID: tenantID, UserID: userID}
	if err := ks.CreateAPIKey(ctx, k); err != nil {
		return "", fmt.Errorf("create api key: %w", err)
	}
	return secret, nil
}

// RevokeAPIKey hashes secret and revokes the matching record.
func RevokeAPIKey(ctx context.Context, ks store.APIKeyStore, secret string) error {
	if err := ks.RevokeAPIKey(ctx, store.HashSecret(secret)); err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	return nil
}

// RotateAPIKey looks up the key identified by oldSecret to find its own
// TenantID/UserID, then rotates it via store.RotateAPIKey -- the caller
// doesn't need to already know or repeat the tenant/user the old key
// belonged to.
func RotateAPIKey(ctx context.Context, ks store.APIKeyStore, oldSecret string) (string, error) {
	oldHash := store.HashSecret(oldSecret)
	existing, err := ks.GetAPIKeyByHash(ctx, oldHash)
	if err != nil {
		return "", fmt.Errorf("look up existing api key: %w", err)
	}
	newSecret, err := store.RotateAPIKey(ctx, ks, oldHash, existing.TenantID, existing.UserID)
	if err != nil {
		return "", fmt.Errorf("rotate api key: %w", err)
	}
	return newSecret, nil
}

// CreateUser inserts a new user identity record with the given roles.
func CreateUser(ctx context.Context, us store.UserStore, userID, tenantID, username string, roles []string) (*tenantkit.Identity, error) {
	u := &tenantkit.Identity{UserID: userID, TenantID: tenantID, Username: username, Roles: roles}
	if err := us.CreateUser(ctx, u); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// RegisterClientCert computes cert's fingerprint (see
// resolve.CertFingerprint) and creates the record. userID may be empty
// for a tenant-level cert.
func RegisterClientCert(ctx context.Context, cs store.ClientCertStore, cert *x509.Certificate, tenantID, userID string) (*tenantkit.ClientCert, error) {
	c := &tenantkit.ClientCert{Fingerprint: resolve.CertFingerprint(cert), TenantID: tenantID, UserID: userID}
	if err := cs.CreateClientCert(ctx, c); err != nil {
		return nil, fmt.Errorf("register client cert: %w", err)
	}
	return c, nil
}

// RevokeClientCert revokes the client cert record identified by
// fingerprint (as printed by RegisterClientCert -- not a secret, safe
// to paste back).
func RevokeClientCert(ctx context.Context, cs store.ClientCertStore, fingerprint string) error {
	if err := cs.RevokeClientCert(ctx, fingerprint); err != nil {
		return fmt.Errorf("revoke client cert: %w", err)
	}
	return nil
}
