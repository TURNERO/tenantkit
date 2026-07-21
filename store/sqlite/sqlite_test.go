package sqlite_test

import (
	"context"
	"sync"
	"testing"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store/sqlite"
	"github.com/TURNERO/tenantkit/storetest"
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

func TestSQLiteConformsToTenantStore(t *testing.T) {
	storetest.TestTenantStore(t, openTestDB(t))
}

func TestSQLiteConformsToUserStore(t *testing.T) {
	storetest.TestUserStore(t, openTestDB(t))
}

func TestSQLiteConformsToAPIKeyStore(t *testing.T) {
	storetest.TestAPIKeyStore(t, openTestDB(t))
}

func TestSQLiteConformsToClientCertStore(t *testing.T) {
	storetest.TestClientCertStore(t, openTestDB(t))
}

func TestSQLiteStore_UserRolesRoundTrip(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	want := &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice", Roles: []string{"admin", "billing"}}
	if err := db.CreateUser(ctx, want); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := db.GetUser(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if len(got.Roles) != 2 || got.Roles[0] != "admin" || got.Roles[1] != "billing" {
		t.Errorf("GetUser Roles = %v, want [admin billing]", got.Roles)
	}
}

// TestOpen_MemoryDSN_SharedAcrossConnections guards the exact footgun
// Open's ":memory:" handling exists to prevent: without limiting the
// pool to a single connection, SQLite gives each connection to a
// ":memory:" database its own private, empty database, so concurrent
// queries can intermittently fail with "no such table" or "not found"
// even though the caller only ever opened one *Store.
func TestOpen_MemoryDSN_SharedAcrossConnections(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.CreateTenant(ctx, &tenantkit.Tenant{ID: "acme", DisplayName: "Acme", Active: true}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := db.GetTenant(ctx, "acme"); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent GetTenant failed (likely :memory: not shared across connections): %v", err)
	}
}
