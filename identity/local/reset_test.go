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

func TestRequestAndResetPassword(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "old-password"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	token, err := l.RequestPasswordReset(ctx, "acme", "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	if err := l.ResetPassword(ctx, token, "new-password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	if _, err := l.LoginWithPassword(ctx, "acme", "alice", "old-password"); !errors.Is(err, local.ErrInvalidCredentials) {
		t.Fatalf("old password should no longer work, got %v", err)
	}
	if _, err := l.LoginWithPassword(ctx, "acme", "alice", "new-password"); err != nil {
		t.Fatalf("new password should work: %v", err)
	}
}

func TestRequestPasswordReset_UnknownUsername(t *testing.T) {
	ctx := context.Background()
	l, _ := newTestLocal(t)
	// Anti-enumeration: an unknown username still gets a normal-looking
	// token and no error, so a caller can't use the response shape to
	// probe for valid usernames.
	token, err := l.RequestPasswordReset(ctx, "acme", "nobody")
	if err != nil {
		t.Fatalf("expected no error for unknown username, got %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token even for unknown username")
	}
}

func TestResetPassword_TokenIsSingleUse(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "old"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	token, err := l.RequestPasswordReset(ctx, "acme", "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := l.ResetPassword(ctx, token, "new1"); err != nil {
		t.Fatalf("first ResetPassword: %v", err)
	}
	if err := l.ResetPassword(ctx, token, "new2"); err == nil {
		t.Fatal("expected error on replayed reset token")
	}
}

func TestResetPassword_UnknownToken(t *testing.T) {
	ctx := context.Background()
	l, _ := newTestLocal(t)
	if err := l.ResetPassword(ctx, "bogus-token", "whatever"); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	users := memstore.New()
	ls := localmem.New()
	// A negative ResetTokenTTL means the token RequestPasswordReset
	// issues is already expired the instant it's created -- exercises
	// the ErrExpired path through ResetPassword itself, not just
	// EphemeralStore.Take directly (already covered by Task 1's
	// memstore tests).
	l, err := local.New(local.Config{
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		RPDisplayName: "Test",
		SessionTTL:    time.Hour,
		ResetTokenTTL: -time.Second,
	}, users, ls, ls, ls)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "old"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	token, err := l.RequestPasswordReset(ctx, "acme", "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := l.ResetPassword(ctx, token, "new"); !errors.Is(err, local.ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}
