package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TURNERO/tenantkit/store"
)

type resetPayload struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
}

// RequestPasswordReset generates a single-use reset token for username
// within tenantID and returns it -- delivering it (e.g. via email) is
// entirely the consumer's responsibility. If username doesn't exist,
// this still returns a syntactically valid token and no error, rather
// than a distinguishable error a caller could use to probe for valid
// usernames -- same anti-enumeration reasoning as LoginWithPassword.
func (l *Local) RequestPasswordReset(ctx context.Context, tenantID, username string) (string, error) {
	ident, err := l.users.GetUserByUsername(ctx, tenantID, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return randomLookingToken()
		}
		return "", fmt.Errorf("tenantkit/identity/local: look up user: %w", err)
	}

	token, err := store.GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: generate reset token: %w", err)
	}
	payload, err := json.Marshal(resetPayload{TenantID: tenantID, UserID: ident.UserID})
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: encode reset token: %w", err)
	}
	if err := l.ephemeral.Put(ctx, token, payload, l.cfg.ResetTokenTTL); err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: save reset token: %w", err)
	}
	return token, nil
}

// ResetPassword validates resetToken (single-use) and sets newPassword
// for the user it was issued to.
func (l *Local) ResetPassword(ctx context.Context, resetToken, newPassword string) error {
	payload, err := l.ephemeral.Take(ctx, resetToken)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
			return err
		}
		return fmt.Errorf("tenantkit/identity/local: load reset token: %w", err)
	}
	var reset resetPayload
	if err := json.Unmarshal(payload, &reset); err != nil {
		return fmt.Errorf("tenantkit/identity/local: decode reset token: %w", err)
	}
	return l.SetPassword(ctx, reset.TenantID, reset.UserID, newPassword)
}

// randomLookingToken returns a token indistinguishable in shape from a
// real one issued by RequestPasswordReset, for the unknown-username
// path -- the caller can't tell "no such user" from "reset issued" by
// looking at the return value alone.
func randomLookingToken() (string, error) {
	token, err := store.GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: generate reset token: %w", err)
	}
	return token, nil
}
