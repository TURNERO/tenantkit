package memstore_test

import (
	"testing"

	"github.com/TURNERO/tenantkit/identity/oidc/memstore"
	"github.com/TURNERO/tenantkit/identity/oidc/storetest"
)

func TestMemstoreConformsToSessionStore(t *testing.T) {
	storetest.TestSessionStore(t, memstore.New())
}

func TestMemstoreConformsToEphemeralStore(t *testing.T) {
	storetest.TestEphemeralStore(t, memstore.New())
}
