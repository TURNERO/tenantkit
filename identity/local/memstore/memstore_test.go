package memstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit/identity/local"
	"github.com/TURNERO/tenantkit/identity/local/memstore"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestCredentialStore_PasswordHash(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

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
}

func TestCredentialStore_WebAuthnCredentials(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

	creds, err := s.GetWebAuthnCredentials(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("got %d credentials, want 0", len(creds))
	}

	cred1 := webauthn.Credential{ID: []byte("cred-1")}
	cred2 := webauthn.Credential{ID: []byte("cred-2")}
	if err := s.AddWebAuthnCredential(ctx, "acme", "u1", cred1); err != nil {
		t.Fatalf("AddWebAuthnCredential: %v", err)
	}
	if err := s.AddWebAuthnCredential(ctx, "acme", "u1", cred2); err != nil {
		t.Fatalf("AddWebAuthnCredential: %v", err)
	}

	creds, err = s.GetWebAuthnCredentials(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("got %d credentials, want 2", len(creds))
	}

	// Mutating a byte of the returned credential's ID in place must not
	// affect the store's copy (guards against a shallow top-level-slice-only
	// copy in GetWebAuthnCredentials).
	creds[0].ID[0] = 'X'
	fresh, err := s.GetWebAuthnCredentials(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if string(fresh[0].ID) != "cred-1" {
		t.Fatalf("store's copy was mutated by caller: got %q", fresh[0].ID)
	}

	// Mutating a byte of the cred value passed into AddWebAuthnCredential,
	// after the call returns, must not affect what's later retrieved
	// (guards against AddWebAuthnCredential storing the caller's slice by
	// reference instead of a deep copy).
	cred3 := webauthn.Credential{ID: []byte("cred-3")}
	if err := s.AddWebAuthnCredential(ctx, "acme", "u1", cred3); err != nil {
		t.Fatalf("AddWebAuthnCredential: %v", err)
	}
	cred3.ID[0] = 'X'
	fresh, err = s.GetWebAuthnCredentials(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if string(fresh[2].ID) != "cred-3" {
		t.Fatalf("store's copy was mutated by caller's post-Add mutation: got %q", fresh[2].ID)
	}
}

func TestSessionStore(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

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
}

func TestSessionStore_Expiry(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

	token, err := s.CreateSession(ctx, "acme", "u1", -time.Second) // already expired
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, _, err := s.GetSession(ctx, token); !errors.Is(err, local.ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

func TestEphemeralStore(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

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
}

func TestEphemeralStore_Expiry(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

	if err := s.Put(ctx, "tok1", []byte("payload"), -time.Second); err != nil { // already expired
		t.Fatalf("Put: %v", err)
	}
	if _, err := s.Take(ctx, "tok1"); !errors.Is(err, local.ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
	// Still single-use even though it was expired.
	if _, err := s.Take(ctx, "tok1"); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound on replayed Take", err)
	}
}
