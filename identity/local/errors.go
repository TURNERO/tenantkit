package local

import "errors"

var (
	// ErrNotFound is returned by the storage interfaces (CredentialStore,
	// SessionStore, EphemeralStore) for a missing row.
	ErrNotFound = errors.New("tenantkit/identity/local: not found")
	// ErrExpired is returned by SessionStore and EphemeralStore for a row
	// that existed but is past its TTL.
	ErrExpired = errors.New("tenantkit/identity/local: expired")
	// ErrInvalidCredentials is returned by LoginWithPassword and the
	// WebAuthn login ceremony on a failed login -- deliberately not
	// ErrNotFound, so a caller can't distinguish "no such user" from
	// "wrong credential" even if it wanted to.
	ErrInvalidCredentials = errors.New("tenantkit/identity/local: invalid credentials")
	// ErrTooManyAttempts is returned by LoginWithPassword and
	// BeginWebAuthnLogin when a configured LoginLimiter reports the
	// account is currently locked out.
	ErrTooManyAttempts = errors.New("tenantkit/identity/local: too many attempts")
)
