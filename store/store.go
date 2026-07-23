// Package store defines tenantkit's storage interfaces. tenantkit never
// implements these against a real database itself -- a consumer
// implements them against whatever store it already uses. See package
// storetest for a conformance-test suite any implementation can run
// against itself, and package memstore for an in-memory implementation
// used by tenantkit's own tests (and reusable in a consumer's tests too).
package store

import (
	"context"
	"errors"

	"github.com/TURNERO/tenantkit"
)

// ErrNotFound is returned by a Get*/lookup method when no matching
// record exists.
var ErrNotFound = errors.New("tenantkit/store: not found")

// ErrAlreadyExists is returned by a Create* method when the record would
// violate a uniqueness constraint (a duplicate tenant ID, user ID,
// (tenant, username) pair, or API key hash).
var ErrAlreadyExists = errors.New("tenantkit/store: already exists")

// TenantStore stores and retrieves tenant records.
type TenantStore interface {
	// GetTenant returns the tenant with the given ID, or ErrNotFound.
	GetTenant(ctx context.Context, tenantID string) (*tenantkit.Tenant, error)
	// CreateTenant inserts t, or returns ErrAlreadyExists if a tenant
	// with the same ID already exists.
	CreateTenant(ctx context.Context, t *tenantkit.Tenant) error
	// ListTenants returns every tenant.
	ListTenants(ctx context.Context) ([]*tenantkit.Tenant, error)
	// DeactivateTenant marks the tenant with the given ID inactive, or
	// returns ErrNotFound if it doesn't exist.
	DeactivateTenant(ctx context.Context, tenantID string) error
}

// UserStore stores and retrieves user identity records.
type UserStore interface {
	// GetUser returns the user with the given ID, or ErrNotFound.
	GetUser(ctx context.Context, userID string) (*tenantkit.Identity, error)
	// GetUserByUsername returns the user with the given username within
	// tenantID, or ErrNotFound -- including when the username exists
	// but under a different tenant.
	GetUserByUsername(ctx context.Context, tenantID, username string) (*tenantkit.Identity, error)
	// CreateUser inserts u, or returns ErrAlreadyExists if a user with
	// the same UserID, or the same (TenantID, Username) pair, already
	// exists.
	CreateUser(ctx context.Context, u *tenantkit.Identity) error
}

// APIKeyStore stores and retrieves API key records, keyed by the
// SHA-256 hash of the plaintext secret -- never the plaintext itself.
type APIKeyStore interface {
	// GetAPIKeyByHash returns the key with the given hash, or ErrNotFound.
	GetAPIKeyByHash(ctx context.Context, hash string) (*tenantkit.APIKey, error)
	// CreateAPIKey inserts k, or returns ErrAlreadyExists if a key with
	// the same hash already exists.
	CreateAPIKey(ctx context.Context, k *tenantkit.APIKey) error
	// RevokeAPIKey removes the key with the given hash, or returns
	// ErrNotFound if it doesn't exist.
	RevokeAPIKey(ctx context.Context, hash string) error
}

// ClientCertStore stores and retrieves mTLS client-certificate
// records, keyed by the SHA-256 hex fingerprint of the DER-encoded
// cert -- not a secret, just an identifier; the trust decision (is
// this cert signed by a CA we trust) happens in TLS itself, before
// tenantkit ever sees the request.
type ClientCertStore interface {
	// GetClientCertByFingerprint returns the cert with the given
	// fingerprint, or ErrNotFound.
	GetClientCertByFingerprint(ctx context.Context, fingerprint string) (*tenantkit.ClientCert, error)
	// CreateClientCert inserts c, or returns ErrAlreadyExists if a cert
	// with the same fingerprint already exists.
	CreateClientCert(ctx context.Context, c *tenantkit.ClientCert) error
	// RevokeClientCert removes the cert with the given fingerprint, or
	// returns ErrNotFound if it doesn't exist.
	RevokeClientCert(ctx context.Context, fingerprint string) error
}

// ErrDomainTaken is returned by CreateOIDCProvider/UpdateOIDCProvider
// when one of the given Domains is already claimed by a different
// tenant/provider. Distinct from ErrAlreadyExists, which means the
// (tenant_id, provider_id) pair itself already exists.
var ErrDomainTaken = errors.New("tenantkit/store: domain already claimed by another provider")

// OIDCProviderStore stores and retrieves per-tenant OIDC IdP
// registrations. A tenant may register more than one provider (distinct
// ProviderIDs); Domains must be globally unique across every tenant and
// provider.
type OIDCProviderStore interface {
	// GetOIDCProvider returns the tenant's provider with the given ID,
	// or ErrNotFound.
	GetOIDCProvider(ctx context.Context, tenantID, providerID string) (*tenantkit.OIDCProvider, error)
	// GetOIDCProviderByDomain returns the provider that claims domain,
	// or ErrNotFound if no provider claims it.
	GetOIDCProviderByDomain(ctx context.Context, domain string) (*tenantkit.OIDCProvider, error)
	// ListOIDCProviders returns all providers registered for tenantID,
	// or an empty slice (not an error) if none are.
	ListOIDCProviders(ctx context.Context, tenantID string) ([]*tenantkit.OIDCProvider, error)
	// CreateOIDCProvider inserts p, or returns ErrAlreadyExists if
	// (p.TenantID, p.ProviderID) already exists, or ErrDomainTaken if
	// any of p.Domains is already claimed elsewhere.
	CreateOIDCProvider(ctx context.Context, p *tenantkit.OIDCProvider) error
	// UpdateOIDCProvider replaces the stored record for (p.TenantID,
	// p.ProviderID) with p, or returns ErrNotFound if it doesn't exist,
	// or ErrDomainTaken if any of p.Domains is now claimed by a
	// different tenant/provider.
	UpdateOIDCProvider(ctx context.Context, p *tenantkit.OIDCProvider) error
	// DeleteOIDCProvider removes the tenant's provider with the given
	// ID (and frees its claimed domains), or returns ErrNotFound if it
	// doesn't exist.
	DeleteOIDCProvider(ctx context.Context, tenantID, providerID string) error
}
