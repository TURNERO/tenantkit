// Package storetest provides interface-conformance test helpers for
// identity/local's storage interfaces. A consumer's own store
// implementation can run these against a fresh instance to prove it
// satisfies the documented behavior of local.CredentialStore,
// local.SessionStore, and local.EphemeralStore -- not just that it
// compiles against the interface.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit/identity/local"
	"github.com/go-webauthn/webauthn/webauthn"
)

// TestCredentialStore runs a battery of subtests against s. Pass a
// fresh, empty store.
func TestCredentialStore(t *testing.T, s local.CredentialStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("PasswordHash", func(t *testing.T) {
		if _, err := s.GetPasswordHash(ctx, "acme", "u1"); !errors.Is(err, local.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}

		if err := s.SetPasswordHash(ctx, "acme", "u1", "hash1"); err != nil {
			t.Fatalf("SetPasswordHash: %v", err)
		}
		got, err := s.GetPasswordHash(ctx, "acme", "u1")
		if err != nil {
			t.Fatalf("GetPasswordHash: %v", err)
		}
		if got != "hash1" {
			t.Fatalf("got %q, want %q", got, "hash1")
		}

		// Same userID in a different tenant must not see this tenant's hash.
		if _, err := s.GetPasswordHash(ctx, "other-tenant", "u1"); !errors.Is(err, local.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound (tenant isolation)", err)
		}

		// Overwriting replaces, not appends.
		if err := s.SetPasswordHash(ctx, "acme", "u1", "hash2"); err != nil {
			t.Fatalf("SetPasswordHash overwrite: %v", err)
		}
		got, err = s.GetPasswordHash(ctx, "acme", "u1")
		if err != nil {
			t.Fatalf("GetPasswordHash after overwrite: %v", err)
		}
		if got != "hash2" {
			t.Fatalf("got %q, want %q", got, "hash2")
		}
	})

	t.Run("WebAuthnCredentials", func(t *testing.T) {
		creds, err := s.GetWebAuthnCredentials(ctx, "acme", "u2")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		if len(creds) != 0 {
			t.Fatalf("got %d credentials, want 0", len(creds))
		}

		cred1 := webauthn.Credential{ID: []byte("cred-1")}
		cred2 := webauthn.Credential{ID: []byte("cred-2")}
		if err := s.AddWebAuthnCredential(ctx, "acme", "u2", cred1); err != nil {
			t.Fatalf("AddWebAuthnCredential: %v", err)
		}
		if err := s.AddWebAuthnCredential(ctx, "acme", "u2", cred2); err != nil {
			t.Fatalf("AddWebAuthnCredential: %v", err)
		}

		creds, err = s.GetWebAuthnCredentials(ctx, "acme", "u2")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		if len(creds) != 2 {
			t.Fatalf("got %d credentials, want 2", len(creds))
		}

		// Same userID in a different tenant must not see this tenant's
		// credentials.
		creds, err = s.GetWebAuthnCredentials(ctx, "other-tenant", "u2")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		if len(creds) != 0 {
			t.Fatalf("got %d credentials, want 0 (tenant isolation)", len(creds))
		}
	})
}

// TestSessionStore runs a battery of subtests against s. Pass a fresh,
// empty store.
func TestSessionStore(t *testing.T, s local.SessionStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateGetDelete", func(t *testing.T) {
		if _, _, err := s.GetSession(ctx, "bogus"); !errors.Is(err, local.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}

		token, err := s.CreateSession(ctx, "acme", "u1", time.Hour)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if token == "" {
			t.Fatal("expected non-empty token")
		}

		tenantID, userID, err := s.GetSession(ctx, token)
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if tenantID != "acme" || userID != "u1" {
			t.Fatalf("got tenantID=%q userID=%q", tenantID, userID)
		}

		if err := s.DeleteSession(ctx, token); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		if _, _, err := s.GetSession(ctx, token); !errors.Is(err, local.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound after delete", err)
		}

		// Deleting an already-deleted/unknown token is not an error.
		if err := s.DeleteSession(ctx, token); err != nil {
			t.Fatalf("DeleteSession on already-deleted token: %v", err)
		}
	})

	t.Run("Expiry", func(t *testing.T) {
		token, err := s.CreateSession(ctx, "acme", "u1", -time.Second) // already expired
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if _, _, err := s.GetSession(ctx, token); !errors.Is(err, local.ErrExpired) {
			t.Fatalf("got %v, want ErrExpired", err)
		}
	})
}

// TestEphemeralStore runs a battery of subtests against s. Pass a
// fresh, empty store.
func TestEphemeralStore(t *testing.T, s local.EphemeralStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("PutTake", func(t *testing.T) {
		if _, err := s.Take(ctx, "bogus"); !errors.Is(err, local.ErrNotFound) {
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
		if _, err := s.Take(ctx, "tok1"); !errors.Is(err, local.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound on replayed Take", err)
		}
	})

	t.Run("Expiry", func(t *testing.T) {
		if err := s.Put(ctx, "tok2", []byte("payload"), -time.Second); err != nil { // already expired
			t.Fatalf("Put: %v", err)
		}
		if _, err := s.Take(ctx, "tok2"); !errors.Is(err, local.ErrExpired) {
			t.Fatalf("got %v, want ErrExpired", err)
		}
		// Still single-use even though it was expired.
		if _, err := s.Take(ctx, "tok2"); !errors.Is(err, local.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound on replayed Take", err)
		}
	})
}
