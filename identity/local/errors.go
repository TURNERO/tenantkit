package local

import "errors"

var (
	// ErrNotFound is returned by the storage interfaces (CredentialStore,
	// SessionStore, EphemeralStore) for a missing row.
	ErrNotFound = errors.New("tenantkit/identity/local: not found")
	// ErrExpired is returned by SessionStore and EphemeralStore for a row
	// that existed but is past its TTL.
	ErrExpired = errors.New("tenantkit/identity/local: expired")
	// ErrInvalidCredentials is returned by LoginWithPassword on a failed
	// login (unknown username, no password set, or wrong password
	// alike) -- deliberately not ErrNotFound, so a caller can't
	// distinguish "no such user" from "wrong credential" even if it
	// wanted to. The WebAuthn login ceremony also returns
	// ErrInvalidCredentials for a user with no registered passkeys, but
	// (unlike LoginWithPassword) an unknown username there is
	// distinguishable via a wrapped store.ErrNotFound -- WebAuthn's own
	// response shape (a real vs. absent allowCredentials list) is an
	// inherent enumeration signal no error-shaping can hide, so
	// matching LoginWithPassword's non-enumerable guarantee isn't
	// possible here regardless of which error type is returned.
	ErrInvalidCredentials = errors.New("tenantkit/identity/local: invalid credentials")
	// ErrTooManyAttempts is returned by LoginWithPassword and
	// BeginWebAuthnLogin when a configured LoginLimiter reports the
	// account is currently locked out. The rate-limit gate is enforced
	// at BeginWebAuthnLogin only, not at FinishWebAuthnLogin -- a
	// ceremony token obtained before lockout engaged can still be
	// redeemed after the account locks. This is a known, accepted
	// property, not an oversight: ceremonies expire after
	// webauthnCeremonyTTL (5 minutes) and still require a valid
	// signature to redeem.
	ErrTooManyAttempts = errors.New("tenantkit/identity/local: too many attempts")
)
