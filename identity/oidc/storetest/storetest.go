// Package storetest provides interface-conformance test helpers for
// identity/oidc's storage interfaces. A consumer's own store
// implementation can run these against a fresh instance to prove it
// satisfies the documented behavior of oidc.SessionStore and
// oidc.EphemeralStore -- not just that it compiles against the
// interface.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity/oidc"
)

// TestSessionStore runs a battery of subtests against s. Pass a fresh,
// empty store.
func TestSessionStore(t *testing.T, s oidc.SessionStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateGetDelete", func(t *testing.T) {
		if _, err := s.GetSession(ctx, "bogus"); !errors.Is(err, oidc.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}

		id := &tenantkit.Identity{TenantID: "acme", UserID: "u1", Username: "alice", Roles: []string{"admin"}}
		token, err := s.CreateSession(ctx, id, time.Hour)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if token == "" {
			t.Fatal("expected non-empty token")
		}

		got, err := s.GetSession(ctx, token)
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if got.TenantID != "acme" || got.UserID != "u1" || got.Username != "alice" {
			t.Fatalf("got %+v", got)
		}
		if len(got.Roles) != 1 || got.Roles[0] != "admin" {
			t.Fatalf("roles = %v", got.Roles)
		}

		if err := s.DeleteSession(ctx, token); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		if _, err := s.GetSession(ctx, token); !errors.Is(err, oidc.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound after delete", err)
		}

		// Deleting an already-deleted/unknown token is not an error.
		if err := s.DeleteSession(ctx, token); err != nil {
			t.Fatalf("DeleteSession on already-deleted token: %v", err)
		}
	})

	t.Run("Expiry", func(t *testing.T) {
		id := &tenantkit.Identity{TenantID: "acme", UserID: "u1"}
		token, err := s.CreateSession(ctx, id, -time.Second) // already expired
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if _, err := s.GetSession(ctx, token); !errors.Is(err, oidc.ErrExpired) {
			t.Fatalf("got %v, want ErrExpired", err)
		}
	})

	t.Run("StoredIdentityIsIsolatedFromCaller", func(t *testing.T) {
		id := &tenantkit.Identity{TenantID: "acme", UserID: "u2", Roles: []string{"member"}}
		token, err := s.CreateSession(ctx, id, time.Hour)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		// Mutating the caller's Identity (and its Roles backing array)
		// after CreateSession must not affect the stored copy.
		id.Username = "mutated"
		id.Roles[0] = "mutated"

		got, err := s.GetSession(ctx, token)
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if got.Username == "mutated" {
			t.Fatalf("store aliased the caller's Identity")
		}
		if got.Roles[0] == "mutated" {
			t.Fatalf("store aliased the caller's Roles backing array")
		}

		// Mutating what GetSession returned must not affect a later Get.
		got.Roles[0] = "mutated-again"
		fresh, err := s.GetSession(ctx, token)
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if fresh.Roles[0] == "mutated-again" {
			t.Fatalf("store's copy was mutated by caller")
		}
	})
}

// TestEphemeralStore runs a battery of subtests against s. Pass a
// fresh, empty store.
func TestEphemeralStore(t *testing.T, s oidc.EphemeralStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("PutTake", func(t *testing.T) {
		if _, err := s.Take(ctx, "bogus"); !errors.Is(err, oidc.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}

		if err := s.Put(ctx, "tok1", []byte("payload"), time.Hour); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Take(ctx, "tok1")
		if err != nil {
			t.Fatalf("Take: %v", err)
		}
		if string(got) != "payload" {
			t.Fatalf("got %q, want %q", got, "payload")
		}

		// Take is single-use: a second call for the same token fails.
		if _, err := s.Take(ctx, "tok1"); !errors.Is(err, oidc.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound on replayed Take", err)
		}
	})

	t.Run("Expiry", func(t *testing.T) {
		if err := s.Put(ctx, "tok2", []byte("payload"), -time.Second); err != nil { // already expired
			t.Fatalf("Put: %v", err)
		}
		if _, err := s.Take(ctx, "tok2"); !errors.Is(err, oidc.ErrExpired) {
			t.Fatalf("got %v, want ErrExpired", err)
		}
		// Still single-use even though it was expired.
		if _, err := s.Take(ctx, "tok2"); !errors.Is(err, oidc.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound on replayed Take", err)
		}
	})
}
