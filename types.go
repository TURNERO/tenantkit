package tenantkit

// Tenant is a single tenant's record as tenantkit understands it. A
// consumer's store implementation may track additional fields of its
// own; tenantkit only needs these three.
type Tenant struct {
	ID          string
	DisplayName string
	Active      bool
}

// Identity is an authenticated user: the result of an IdentityProvider
// authenticating a request, or a record looked up directly via
// store.UserStore.
type Identity struct {
	UserID   string
	TenantID string
	Username string
	// Roles is opaque to tenantkit -- it's carried through for a
	// consumer's own authorization logic to interpret, never read or
	// written by tenantkit itself.
	Roles []string
}

// APIKey is a service or user credential used for tenant-scoped access.
// UserID is empty for a tenant-level key (e.g. a service ingestion
// credential not tied to any one person) and non-empty for a
// user-level key.
type APIKey struct {
	Hash     string
	TenantID string
	UserID   string
}

// ClientCert is an mTLS client-certificate credential used for
// tenant-scoped access, an alternative (or complement) to APIKey.
// Fingerprint is the SHA-256 hex digest of the DER-encoded cert -- not
// a secret, just an identifier; TLS itself already verified the cert
// against a CA before tenantkit ever sees the request. UserID is empty
// for a tenant-level cert, non-empty for a user-level cert.
type ClientCert struct {
	Fingerprint string
	TenantID    string
	UserID      string
}
