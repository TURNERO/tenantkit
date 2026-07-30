// Package oidc is tenantkit's built-in identity.IdentityProvider
// implementation wrapping an external OIDC-compliant identity
// provider: the OAuth2 Authorization Code ceremony
// (BeginLogin/BeginLoginByDomain/FinishLogin), verified-ID token claims
// mapped to a tenantkit.Identity, and opaque-token sessions. It shares
// only the identity.IdentityProvider interface with identity/local and
// has no other dependency on it.
package oidc

import (
	"context"
	"time"

	"github.com/TURNERO/tenantkit"
)

// SessionStore holds active OIDC-backed login sessions. Unlike
// identity/local's SessionStore, this stores the full Identity, not
// just (tenantID, userID) -- there is no UserStore to re-fetch it from
// later; the verified ID token's claims are the Identity.
type SessionStore interface {
	CreateSession(ctx context.Context, id *tenantkit.Identity, ttl time.Duration) (token string, err error)
	// GetSession returns ErrNotFound (no such token) or ErrExpired
	// (existed, past ttl).
	GetSession(ctx context.Context, token string) (*tenantkit.Identity, error)
	DeleteSession(ctx context.Context, token string) error
}

// EphemeralStore holds short-lived, single-use opaque tokens: OAuth2
// state/nonce ceremony data between BeginLogin and FinishLogin.
type EphemeralStore interface {
	Put(ctx context.Context, token string, payload []byte, ttl time.Duration) error
	// Take fetches and deletes atomically, so a replayed callback (or a
	// replayed/expired ceremony) always fails on a second attempt.
	Take(ctx context.Context, token string) ([]byte, error) // ErrNotFound / ErrExpired
}
