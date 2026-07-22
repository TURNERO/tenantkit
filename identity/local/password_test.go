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

// newTestLocal returns a Local wired to fresh in-memory stores, plus the
// UserStore so tests can create users. Reused by Tasks 3-5's tests.
func newTestLocal(t *testing.T) (*local.Local, *memstore.Store) {
	t.Helper()
	users := memstore.New()
	ls := localmem.New()
	l, err := local.New(local.Config{
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		RPDisplayName: "Test",
		SessionTTL:    time.Hour,
		ResetTokenTTL: time.Hour,
	}, users, ls, ls, ls)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	return l, users
}

func TestSetPasswordAndLoginWithPassword(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)

	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	token, err := l.LoginWithPassword(ctx, "acme", "alice", "correct horse battery staple")
	if err != nil {
		t.Fatalf("LoginWithPassword: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty session token")
	}
}

func TestLoginWithPassword_WrongPassword(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if _, err := l.LoginWithPassword(ctx, "acme", "alice", "wrong"); !errors.Is(err, local.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginWithPassword_UnknownUsername(t *testing.T) {
	ctx := context.Background()
	l, _ := newTestLocal(t)
	if _, err := l.LoginWithPassword(ctx, "acme", "nobody", "whatever"); !errors.Is(err, local.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginWithPassword_NoPasswordSet(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := l.LoginWithPassword(ctx, "acme", "alice", "whatever"); !errors.Is(err, local.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

func TestSetPassword_Overwrites(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "old-password"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "new-password"); err != nil {
		t.Fatalf("SetPassword overwrite: %v", err)
	}
	if _, err := l.LoginWithPassword(ctx, "acme", "alice", "old-password"); !errors.Is(err, local.ErrInvalidCredentials) {
		t.Fatalf("old password should no longer work, got %v", err)
	}
	if _, err := l.LoginWithPassword(ctx, "acme", "alice", "new-password"); err != nil {
		t.Fatalf("new password should work: %v", err)
	}
}

func TestLogout(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "pw"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	token, err := l.LoginWithPassword(ctx, "acme", "alice", "pw")
	if err != nil {
		t.Fatalf("LoginWithPassword: %v", err)
	}
	if err := l.Logout(ctx, token); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	// Logout is idempotent -- deleting an already-deleted session is not
	// an error (the end state is the same either way).
	if err := l.Logout(ctx, token); err != nil {
		t.Fatalf("second Logout: %v", err)
	}
}
