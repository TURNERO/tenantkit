package sqlite_test

import (
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

