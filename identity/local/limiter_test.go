package local_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity/local"
	localmem "github.com/TURNERO/tenantkit/identity/local/memstore"
	"github.com/TURNERO/tenantkit/store/memstore"
)

// fakeLimiter is a minimal local.LoginLimiter used only to prove the
// interface and Config field compile and wire together correctly,
// before any real implementation (memstore.LoginLimiter, Task 2)
// exists.
type fakeLimiter struct{}

func (fakeLimiter) Allow(ctx context.Context, tenantID, username string) (bool, error) {
	return true, nil
}
func (fakeLimiter) RecordFailure(ctx context.Context, tenantID, username string) error { return nil }
func (fakeLimiter) RecordSuccess(ctx context.Context, tenantID, username string) error { return nil }

var _ local.LoginLimiter = fakeLimiter{}

// errBoom is the sentinel error erroringLimiter returns, so tests can
// assert the exact error survives being wrapped on its way back out of
// LoginWithPassword/BeginWebAuthnLogin/FinishWebAuthnLogin.
var errBoom = errors.New("erroringLimiter: boom")

// erroringLimiter is a local.LoginLimiter test double that fails on a
// configurable method, used to prove a LoginLimiter backend error
// propagates as a visible, wrapped error -- fail-closed -- rather than
// being silently swallowed or mistaken for a normal auth outcome.
// fakeLimiter above never errors, so it can't exercise this path.
type erroringLimiter struct {
	allowErr         error
	recordFailureErr error
	recordSuccessErr error
}

func (e erroringLimiter) Allow(ctx context.Context, tenantID, username string) (bool, error) {
	if e.allowErr != nil {
		return false, e.allowErr
	}
	return true, nil
}
func (e erroringLimiter) RecordFailure(ctx context.Context, tenantID, username string) error {
	return e.recordFailureErr
}
func (e erroringLimiter) RecordSuccess(ctx context.Context, tenantID, username string) error {
	return e.recordSuccessErr
}

var _ local.LoginLimiter = erroringLimiter{}

func newTestLocalWithLimiter(t *testing.T, limiter local.LoginLimiter) (*local.Local, *memstore.Store) {
	t.Helper()
	users := memstore.New()
	ls := localmem.New()
	l, err := local.New(local.Config{
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		RPDisplayName: "Test",
		SessionTTL:    time.Hour,
		ResetTokenTTL: time.Hour,
		LoginLimiter:  limiter,
	}, users, ls, ls, ls)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	return l, users
}

// TestLoginWithPassword_LimiterErrorsPropagate proves the "failures
// propagate as errors, not silently swallowed" design decision at all
// three LoginLimiter call sites LoginWithPassword has: Allow (checked
// up front), RecordFailure (wrong password), and RecordSuccess
// (correct password). In every case the limiter's error, not a
// generic auth outcome, must come back out.
func TestLoginWithPassword_LimiterErrorsPropagate(t *testing.T) {
	tests := []struct {
		name     string
		limiter  erroringLimiter
		password string // password to attempt; "wrong" unless overridden
	}{
		{name: "Allow", limiter: erroringLimiter{allowErr: errBoom}},
		{name: "RecordFailure", limiter: erroringLimiter{recordFailureErr: errBoom}},
		{name: "RecordSuccess", limiter: erroringLimiter{recordSuccessErr: errBoom}, password: "correct horse battery staple"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			l, users := newTestLocalWithLimiter(t, tt.limiter)
			if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			if err := l.SetPassword(ctx, "acme", "u1", "correct horse battery staple"); err != nil {
				t.Fatalf("SetPassword: %v", err)
			}

			password := tt.password
			if password == "" {
				password = "wrong"
			}
			if _, err := l.LoginWithPassword(ctx, "acme", "alice", password); !errors.Is(err, errBoom) {
				t.Fatalf("got %v, want an error wrapping errBoom", err)
			}
		})
	}
}

// TestBeginWebAuthnLogin_LimiterAllowErrorPropagates mirrors the
// LoginWithPassword Allow-error case for the WebAuthn side: a
// LoginLimiter backend outage must surface as a visible error from
// BeginWebAuthnLogin too, not be treated as "allowed" or as an
// unrelated lookup failure.
func TestBeginWebAuthnLogin_LimiterAllowErrorPropagates(t *testing.T) {
	ctx := context.Background()
	l, _ := newTestLocalWithLimiter(t, erroringLimiter{allowErr: errBoom})
	if _, _, err := l.BeginWebAuthnLogin(ctx, "acme", "alice"); !errors.Is(err, errBoom) {
		t.Fatalf("got %v, want an error wrapping errBoom", err)
	}
}

func TestErrTooManyAttempts_IsDistinctFromOtherErrors(t *testing.T) {
	if errors.Is(local.ErrTooManyAttempts, local.ErrInvalidCredentials) {
		t.Fatal("ErrTooManyAttempts must be distinct from ErrInvalidCredentials")
	}
	if errors.Is(local.ErrTooManyAttempts, local.ErrNotFound) {
		t.Fatal("ErrTooManyAttempts must be distinct from ErrNotFound")
	}
}

func TestConfig_LoginLimiterDefaultsToNil(t *testing.T) {
	cfg := local.Config{}
	if cfg.LoginLimiter != nil {
		t.Fatal("zero-value Config.LoginLimiter must be nil -- rate limiting is opt-in")
	}
	cfg.LoginLimiter = fakeLimiter{}
	if cfg.LoginLimiter == nil {
		t.Fatal("Config.LoginLimiter must be settable to a LoginLimiter implementation")
	}
}
