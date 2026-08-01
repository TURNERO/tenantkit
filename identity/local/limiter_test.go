package local_test

import (
	"context"
	"errors"
	"testing"

	"github.com/TURNERO/tenantkit/identity/local"
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
