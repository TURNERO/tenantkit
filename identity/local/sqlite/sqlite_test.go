package sqlite_test

import (
	"context"
	"testing"

	"github.com/TURNERO/tenantkit/identity/local/sqlite"
	"github.com/TURNERO/tenantkit/identity/local/storetest"
)

func openTestDB(t *testing.T) *sqlite.Store {
	t.Helper()
	db, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSQLiteConformsToCredentialStore(t *testing.T) {
	storetest.TestCredentialStore(t, openTestDB(t))
}

func TestSQLiteConformsToSessionStore(t *testing.T) {
	storetest.TestSessionStore(t, openTestDB(t))
}

func TestSQLiteConformsToEphemeralStore(t *testing.T) {
	storetest.TestEphemeralStore(t, openTestDB(t))
}

func TestSQLiteStore_OpenTwiceIdempotent(t *testing.T) {
	dir := t.TempDir()
	dsn := dir + "/test.db"

	db1, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db2, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("second Open on same dsn: %v", err)
	}
	defer db2.Close()
}

func TestSQLiteStore_Durability(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dsn := dir + "/test.db"

	db1, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db1.SetPasswordHash(ctx, "acme", "u1", "hash1"); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db2, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()

	got, err := db2.GetPasswordHash(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetPasswordHash after reopen: %v", err)
	}
	if got != "hash1" {
		t.Fatalf("got %q, want %q", got, "hash1")
	}
}
