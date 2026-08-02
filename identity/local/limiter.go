package local

import (
	"context"
	"fmt"
)

// recordLoginFailure calls RecordFailure (if a limiter is configured)
// and returns wantErr on success, or a wrapped error if RecordFailure
// itself fails -- a rate-limiter backend outage becomes a visible
// error rather than silently not counting toward lockout. Shared by
// LoginWithPassword and the WebAuthn login ceremony (BeginWebAuthnLogin,
// FinishWebAuthnLogin) so both methods record failures identically --
// any failed authentication attempt, regardless of method, counts
// against the same lockout.
func (l *Local) recordLoginFailure(ctx context.Context, tenantID, username string, wantErr error) error {
	if l.cfg.LoginLimiter == nil {
		return wantErr
	}
	if err := l.cfg.LoginLimiter.RecordFailure(ctx, tenantID, username); err != nil {
		return fmt.Errorf("tenantkit/identity/local: record login failure: %w", err)
	}
	return wantErr
}

// recordLoginSuccess calls RecordSuccess (if a limiter is configured),
// resetting any failure count for (tenantID, username), and returns a
// wrapped error if RecordSuccess itself fails. Shared by
// LoginWithPassword and FinishWebAuthnLogin.
func (l *Local) recordLoginSuccess(ctx context.Context, tenantID, username string) error {
	if l.cfg.LoginLimiter == nil {
		return nil
	}
	if err := l.cfg.LoginLimiter.RecordSuccess(ctx, tenantID, username); err != nil {
		return fmt.Errorf("tenantkit/identity/local: record login success: %w", err)
	}
	return nil
}
