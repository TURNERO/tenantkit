package local

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// webauthnCeremonyTTL bounds how long a WebAuthn ceremony (registration
// or login) has to complete before its EphemeralStore entry expires.
// Not exposed via Config -- 5 minutes comfortably covers a real
// browser/authenticator interaction, and there's no evidence yet that
// any consumer needs this tunable.
const webauthnCeremonyTTL = 5 * time.Minute

// webauthnUser bridges an Identity + its stored WebAuthn credentials to
// go-webauthn's webauthn.User interface.
type webauthnUser struct {
	identity *tenantkit.Identity
	creds    []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte {
	// Must be unique per Relying Party -- i.e. across the whole
	// deployment, not just within a tenant. Bare UserID isn't safe
	// (UserStore's uniqueness guarantee only spans tenantID+username),
	// and a raw tenantID+userID string composite doesn't fit WebAuthn's
	// 64-byte user-handle limit with tenantkit's default ID generators
	// (32-char tenant ID + 43-char user ID = 76 bytes combined). SHA-256
	// gives a fixed 32-byte opaque handle that's both collision-resistant
	// and safely under the limit.
	sum := sha256.Sum256([]byte(u.identity.TenantID + ":" + u.identity.UserID))
	return sum[:]
}
func (u *webauthnUser) WebAuthnName() string                       { return u.identity.Username }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.identity.Username }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// webauthnCeremony is the payload saved in EphemeralStore between a
// ceremony's Begin and Finish calls -- go-webauthn's SessionData plus
// which user this ceremony belongs to (FinishWebAuthnLogin doesn't take
// tenantID/userID again; this is where that comes from).
type webauthnCeremony struct {
	TenantID    string               `json:"tenant_id"`
	UserID      string               `json:"user_id"`
	SessionData webauthn.SessionData `json:"session_data"`
}

func (l *Local) loadUserForWebAuthn(ctx context.Context, tenantID, userID string) (*webauthnUser, error) {
	ident, err := l.users.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("tenantkit/identity/local: look up user: %w", err)
	}
	if ident.TenantID != tenantID {
		return nil, fmt.Errorf("tenantkit/identity/local: user does not belong to tenant: %w", ErrNotFound)
	}
	creds, err := l.creds.GetWebAuthnCredentials(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("tenantkit/identity/local: get webauthn credentials: %w", err)
	}
	return &webauthnUser{identity: ident, creds: creds}, nil
}

// BeginWebAuthnRegistration starts adding a passkey to an already-known
// user. It returns the challenge to send the browser as JSON, and a
// ceremonyToken the consumer's handler must round-trip back to
// FinishWebAuthnRegistration (a hidden form field or short-lived
// cookie, consumer's choice).
func (l *Local) BeginWebAuthnRegistration(ctx context.Context, tenantID, userID string) (*protocol.CredentialCreation, string, error) {
	user, err := l.loadUserForWebAuthn(ctx, tenantID, userID)
	if err != nil {
		return nil, "", err
	}

	creation, sessionData, err := l.wa.BeginRegistration(user)
	if err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/local: begin webauthn registration: %w", err)
	}

	ceremonyToken, err := l.saveCeremony(ctx, tenantID, userID, *sessionData)
	if err != nil {
		return nil, "", err
	}
	return creation, ceremonyToken, nil
}

// FinishWebAuthnRegistration completes a registration ceremony started
// by BeginWebAuthnRegistration, storing the resulting credential.
// ceremonyToken is single-use: a replayed finish request fails.
func (l *Local) FinishWebAuthnRegistration(ctx context.Context, tenantID, userID, ceremonyToken string, r *http.Request) error {
	ceremony, err := l.takeCeremony(ctx, ceremonyToken)
	if err != nil {
		return err
	}
	if ceremony.TenantID != tenantID || ceremony.UserID != userID {
		return fmt.Errorf("tenantkit/identity/local: ceremony token does not match tenant/user: %w", ErrNotFound)
	}

	user, err := l.loadUserForWebAuthn(ctx, tenantID, userID)
	if err != nil {
		return err
	}

	cred, err := l.wa.FinishRegistration(user, ceremony.SessionData, r)
	if err != nil {
		return fmt.Errorf("tenantkit/identity/local: finish webauthn registration: %w", err)
	}

	if err := l.creds.AddWebAuthnCredential(ctx, tenantID, userID, *cred); err != nil {
		return fmt.Errorf("tenantkit/identity/local: store webauthn credential: %w", err)
	}
	return nil
}

// BeginWebAuthnLogin starts a passkey login for username within
// tenantID. It returns the challenge to send the browser as JSON, and a
// ceremonyToken the consumer's handler must round-trip back to
// FinishWebAuthnLogin.
func (l *Local) BeginWebAuthnLogin(ctx context.Context, tenantID, username string) (*protocol.CredentialAssertion, string, error) {
	ident, err := l.users.GetUserByUsername(ctx, tenantID, username)
	if err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/local: look up user: %w", err)
	}
	user, err := l.loadUserForWebAuthn(ctx, tenantID, ident.UserID)
	if err != nil {
		return nil, "", err
	}

	assertion, sessionData, err := l.wa.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/local: begin webauthn login: %w", err)
	}

	ceremonyToken, err := l.saveCeremony(ctx, tenantID, ident.UserID, *sessionData)
	if err != nil {
		return nil, "", err
	}
	return assertion, ceremonyToken, nil
}

// FinishWebAuthnLogin completes a login ceremony started by
// BeginWebAuthnLogin and, on success, issues a session token.
// ceremonyToken is single-use.
func (l *Local) FinishWebAuthnLogin(ctx context.Context, ceremonyToken string, r *http.Request) (string, error) {
	ceremony, err := l.takeCeremony(ctx, ceremonyToken)
	if err != nil {
		return "", err
	}

	user, err := l.loadUserForWebAuthn(ctx, ceremony.TenantID, ceremony.UserID)
	if err != nil {
		return "", err
	}

	if _, err := l.wa.FinishLogin(user, ceremony.SessionData, r); err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: finish webauthn login: %w", err)
	}

	token, err := l.sessions.CreateSession(ctx, ceremony.TenantID, ceremony.UserID, l.cfg.SessionTTL)
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: create session: %w", err)
	}
	return token, nil
}

func (l *Local) saveCeremony(ctx context.Context, tenantID, userID string, sessionData webauthn.SessionData) (string, error) {
	token, err := store.GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: generate ceremony token: %w", err)
	}
	payload, err := json.Marshal(webauthnCeremony{TenantID: tenantID, UserID: userID, SessionData: sessionData})
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: encode webauthn ceremony: %w", err)
	}
	if err := l.ephemeral.Put(ctx, token, payload, webauthnCeremonyTTL); err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: save webauthn ceremony: %w", err)
	}
	return token, nil
}

func (l *Local) takeCeremony(ctx context.Context, ceremonyToken string) (*webauthnCeremony, error) {
	payload, err := l.ephemeral.Take(ctx, ceremonyToken)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
			return nil, err
		}
		return nil, fmt.Errorf("tenantkit/identity/local: load webauthn ceremony: %w", err)
	}
	var ceremony webauthnCeremony
	if err := json.Unmarshal(payload, &ceremony); err != nil {
		return nil, fmt.Errorf("tenantkit/identity/local: decode webauthn ceremony: %w", err)
	}
	return &ceremony, nil
}
