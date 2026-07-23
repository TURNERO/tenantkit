package memstore_test

import (
	"context"
	"testing"

	"github.com/TURNERO/tenantkit/identity/local/memstore"
	"github.com/TURNERO/tenantkit/identity/local/storetest"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestMemstoreConformsToCredentialStore(t *testing.T) {
	storetest.TestCredentialStore(t, memstore.New())
}

func TestMemstoreConformsToSessionStore(t *testing.T) {
	storetest.TestSessionStore(t, memstore.New())
}

func TestMemstoreConformsToEphemeralStore(t *testing.T) {
	storetest.TestEphemeralStore(t, memstore.New())
}

// TestMemstore_WebAuthnCredentialsDeepCopy is memstore-specific: it
// guards against shallow copies leaking mutable internal state, a
// property storetest can't assert generically (a SQL-backed store
// round-trips through the database, so this specific failure mode
// doesn't apply there the same way).
func TestMemstore_WebAuthnCredentialsDeepCopy(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

	cred1 := webauthn.Credential{ID: []byte("cred-1")}
	if err := s.AddWebAuthnCredential(ctx, "acme", "u1", cred1); err != nil {
		t.Fatalf("AddWebAuthnCredential: %v", err)
	}

	creds, err := s.GetWebAuthnCredentials(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
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
	cred2 := webauthn.Credential{ID: []byte("cred-2")}
	if err := s.AddWebAuthnCredential(ctx, "acme", "u1", cred2); err != nil {
		t.Fatalf("AddWebAuthnCredential: %v", err)
	}
	cred2.ID[0] = 'X'
	fresh, err = s.GetWebAuthnCredentials(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if string(fresh[1].ID) != "cred-2" {
		t.Fatalf("store's copy was mutated by caller's post-Add mutation: got %q", fresh[1].ID)
	}
}
