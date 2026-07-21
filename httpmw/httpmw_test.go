package httpmw_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/httpmw"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
	"github.com/TURNERO/tenantkit/store/memstore"
)

type fakeResolver struct {
	tenantID string
	ok       bool
	err      error
}

func (f fakeResolver) ResolveTenant(ctx context.Context, src resolve.Source) (string, bool, error) {
	return f.tenantID, f.ok, f.err
}

type fakeIdentityProvider struct {
	identity *tenantkit.Identity
	err      error
}

func (f fakeIdentityProvider) Authenticate(ctx context.Context, src resolve.Source) (*tenantkit.Identity, error) {
	return f.identity, f.err
}

func newTestTenantStore(t *testing.T, tenantID string, active bool) store.TenantStore {
	t.Helper()
	s := memstore.New()
	if err := s.CreateTenant(context.Background(), &tenantkit.Tenant{ID: tenantID, DisplayName: tenantID, Active: active}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	return s
}

func TestNew_ResolvesTenantAndCallsNext(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	var gotTenant *tenantkit.Tenant
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore: ts,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant, _ = tenantkit.TenantFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotTenant == nil || gotTenant.ID != "acme" {
		t.Errorf("TenantFromContext = %+v, want ID acme", gotTenant)
	}
}

func TestNew_NoCredentialsRejectedWith401(t *testing.T) {
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: false}},
		TenantStore: memstore.New(),
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestNew_InvalidCredentialsRejectedWith401(t *testing.T) {
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: true, err: errors.New("bad key")}},
		TenantStore: memstore.New(),
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestNew_InactiveTenantRejectedWith403(t *testing.T) {
	ts := newTestTenantStore(t, "acme", false)
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore: ts,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestNew_UnknownTenantRejectedWith403(t *testing.T) {
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "nope", ok: true}},
		TenantStore: memstore.New(),
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestNew_ResolverChainTriesNextOnOkFalse(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	handler := httpmw.New(httpmw.Config{
		Resolvers: []resolve.TenantResolver{
			fakeResolver{ok: false},
			fakeResolver{tenantID: "acme", ok: true},
		},
		TenantStore: ts,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (second resolver should have been tried)", rec.Code)
	}
}

func TestNew_NilIdentityProviderSkipsIdentityResolution(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	var gotOK bool
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore: ts,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, gotOK = tenantkit.IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotOK {
		t.Error("expected no Identity in context when IdentityProvider is nil")
	}
}

func TestNew_IdentityPopulatedWhenTenantsMatch(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	id := &tenantkit.Identity{UserID: "u1", TenantID: "acme"}
	var gotIdentity *tenantkit.Identity
	handler := httpmw.New(httpmw.Config{
		Resolvers:        []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore:      ts,
		IdentityProvider: fakeIdentityProvider{identity: id},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity, _ = tenantkit.IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotIdentity == nil || gotIdentity.UserID != "u1" {
		t.Errorf("IdentityFromContext = %+v, want UserID u1", gotIdentity)
	}
}

func TestNew_IdentityTenantMismatchRejectedWith403(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	handler := httpmw.New(httpmw.Config{
		Resolvers:        []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore:      ts,
		IdentityProvider: fakeIdentityProvider{identity: &tenantkit.Identity{UserID: "u1", TenantID: "globex"}},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestNew_IdentityProviderNilIdentityForServiceTraffic(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	handler := httpmw.New(httpmw.Config{
		Resolvers:        []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore:      ts,
		IdentityProvider: fakeIdentityProvider{identity: nil},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a nil Identity from a configured IdentityProvider is not an error)", rec.Code)
	}
}

func TestNew_CustomErrorHandler(t *testing.T) {
	called := false
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: false}},
		TenantStore: memstore.New(),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, status int, err error) {
			called = true
			w.WriteHeader(status)
			w.Write([]byte("custom: " + err.Error()))
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if !called {
		t.Error("expected the custom ErrorHandler to be invoked")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := rec.Body.String(); len(got) < 7 || got[:7] != "custom:" {
		t.Errorf("body = %q, want it to start with 'custom:'", got)
	}
}
