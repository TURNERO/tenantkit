// Package local is tenantkit's built-in identity.IdentityProvider
// implementation: password (bcrypt) and WebAuthn (passkey)
// authentication, opaque-token sessions, and a password-reset token
// flow.
package local

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// CredentialStore holds password hashes and WebAuthn credentials.
// Implementations key both by (tenantID, userID) -- usernames are only
// unique within a tenant, matching store.UserStore's existing scoping.
type CredentialStore interface {
	SetPasswordHash(ctx context.Context, tenantID, userID, hash string) error
	// GetPasswordHash returns ErrNotFound if the user has no password set
	// (e.g. a WebAuthn-only account).
	GetPasswordHash(ctx context.Context, tenantID, userID string) (string, error)
	AddWebAuthnCredential(ctx context.Context, tenantID, userID string, cred webauthn.Credential) error
	// GetWebAuthnCredentials returns an empty slice (not an error) for a
	// user with no registered credentials.
	GetWebAuthnCredentials(ctx context.Context, tenantID, userID string) ([]webauthn.Credential, error)
}

// SessionStore holds active login sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, tenantID, userID string, ttl time.Duration) (token string, err error)
	// GetSession returns ErrNotFound (no such token) or ErrExpired
	// (existed, past ttl).
	GetSession(ctx context.Context, token string) (tenantID, userID string, err error)
	DeleteSession(ctx context.Context, token string) error
}

// EphemeralStore holds short-lived, single-use opaque tokens: WebAuthn
// ceremony state and password-reset tokens both use this -- structurally
// identical (opaque token -> payload blob, TTL, consumed exactly once).
type EphemeralStore interface {
	Put(ctx context.Context, token string, payload []byte, ttl time.Duration) error
	// Take fetches and deletes atomically, so single-use is a property
	// of the interface -- a replayed ceremony-finish or reset request
	// always fails on the second attempt.
	Take(ctx context.Context, token string) ([]byte, error) // ErrNotFound / ErrExpired
}
