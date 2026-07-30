package oidc

import "errors"

var (
	// ErrNotFound is returned by the storage interfaces (SessionStore,
	// EphemeralStore) for a missing row.
	ErrNotFound = errors.New("tenantkit/identity/oidc: not found")
	// ErrExpired is returned by SessionStore and EphemeralStore for a
	// row that existed but is past its TTL.
	ErrExpired = errors.New("tenantkit/identity/oidc: expired")
	// ErrUnknownProvider wraps store.ErrNotFound from a provider lookup
	// (BeginLogin/BeginLoginByDomain/FinishLogin given a (tenantID,
	// providerID) or domain with no matching registration).
	ErrUnknownProvider = errors.New("tenantkit/identity/oidc: unknown provider")
	// ErrInvalidToken covers every token/claims verification failure --
	// signature/issuer/audience/expiry, a nonce mismatch, a
	// tenant-claim mismatch, and a missing/malformed mapped claim --
	// deliberately one bucket, not split into finer sentinel errors, so
	// a caller can't use error type to enumerate why a login failed.
	ErrInvalidToken = errors.New("tenantkit/identity/oidc: invalid token")
)
