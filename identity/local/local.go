package local

import (
	"fmt"
	"time"

	"github.com/TURNERO/tenantkit/store"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config configures a Local identity provider.
type Config struct {
	// RPID is the WebAuthn relying-party ID: your service's effective
	// domain (e.g. "example.com"), without scheme or port.
	RPID string
	// RPOrigins is the list of origins WebAuthn ceremonies are permitted
	// from (e.g. "https://example.com").
	RPOrigins []string
	// RPDisplayName is a human-readable name shown by browser/OS WebAuthn
	// UI during registration and login.
	RPDisplayName string
	// SessionTTL is how long a session (password or WebAuthn login) stays
	// valid.
	SessionTTL time.Duration
	// ResetTokenTTL is how long a password-reset token stays valid.
	ResetTokenTTL time.Duration
}

// Local is tenantkit's built-in password + WebAuthn identity provider.
// It satisfies identity.IdentityProvider via Authenticate.
type Local struct {
	cfg       Config
	users     store.UserStore
	creds     CredentialStore
	sessions  SessionStore
	ephemeral EphemeralStore
	wa        *webauthn.WebAuthn
}

// New returns a Local identity provider. It returns an error if cfg is
// invalid (e.g. missing RPID) -- see github.com/go-webauthn/webauthn's
// Config validation.
func New(cfg Config, users store.UserStore, creds CredentialStore, sessions SessionStore, ephemeral EphemeralStore) (*Local, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("tenantkit/identity/local: configure webauthn: %w", err)
	}
	return &Local{
		cfg:       cfg,
		users:     users,
		creds:     creds,
		sessions:  sessions,
		ephemeral: ephemeral,
		wa:        wa,
	}, nil
}
