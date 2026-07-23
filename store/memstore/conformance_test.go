package memstore_test

import (
	"testing"

	"github.com/TURNERO/tenantkit/store/memstore"
	"github.com/TURNERO/tenantkit/storetest"
)

func TestMemstoreConformsToTenantStore(t *testing.T) {
	storetest.TestTenantStore(t, memstore.New())
}

func TestMemstoreConformsToUserStore(t *testing.T) {
	storetest.TestUserStore(t, memstore.New())
}

func TestMemstoreConformsToAPIKeyStore(t *testing.T) {
	storetest.TestAPIKeyStore(t, memstore.New())
}

func TestMemstoreConformsToClientCertStore(t *testing.T) {
	storetest.TestClientCertStore(t, memstore.New())
}

func TestMemstoreConformsToOIDCProviderStore(t *testing.T) {
	storetest.TestOIDCProviderStore(t, memstore.New())
}
