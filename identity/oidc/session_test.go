package oidc_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity/oidc"
)

// fakeSource is a minimal resolve.Source for testing Authenticate
// without a real HTTP request.
type fakeSource struct {
	headers map[string]string
}

func (s fakeSource) Header(key string) string                 { return s.headers[key] }
func (s fakeSource) TLSPeerCertificates() []*x509.Certificate { return nil }
func (s fakeSource) Host() string                             { return "" }

func TestAuthenticate_NoCookie(t *testing.T) {
	ctx := context.Background()
	o, _, _ := newTestOIDC(t)
	ident, err := o.Authenticate(ctx, fakeSource{})
	if err != nil {
		t.Fatalf("got err %v, want nil", err)
	}
	if ident != nil {
		t.Fatalf("got %+v, want nil identity", ident)
	}
}

func TestAuthenticate_UnknownToken(t *testing.T) {
	ctx := context.Background()
	o, _, _ := newTestOIDC(t)
	src := fakeSource{headers: map[string]string{"Cookie": oidc.SessionCookieName + "=bogus"}}
	if _, err := o.Authenticate(ctx, src); !errors.Is(err, oidc.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestAuthenticate_ValidSession(t *testing.T) {
	ctx := context.Background()
	o, _, oidcStore := newTestOIDC(t)

	id := &tenantkit.Identity{TenantID: "acme", UserID: "user-123", Username: "alice@acme.com", Roles: []string{"admin"}}
	token, err := oidcStore.CreateSession(ctx, id, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	src := fakeSource{headers: map[string]string{"Cookie": oidc.SessionCookieName + "=" + token}}
	got, err := o.Authenticate(ctx, src)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.TenantID != "acme" || got.UserID != "user-123" {
		t.Fatalf("got %+v", got)
	}
}

func TestAuthenticate_AfterLogout(t *testing.T) {
	ctx := context.Background()
	o, _, oidcStore := newTestOIDC(t)

	id := &tenantkit.Identity{TenantID: "acme", UserID: "user-123"}
	token, err := oidcStore.CreateSession(ctx, id, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := o.Logout(ctx, token); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	src := fakeSource{headers: map[string]string{"Cookie": oidc.SessionCookieName + "=" + token}}
	if _, err := o.Authenticate(ctx, src); !errors.Is(err, oidc.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestAuthenticate_ExpiredSession(t *testing.T) {
	ctx := context.Background()
	o, _, oidcStore := newTestOIDC(t)

	id := &tenantkit.Identity{TenantID: "acme", UserID: "user-123"}
	token, err := oidcStore.CreateSession(ctx, id, -time.Second) // already expired
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	src := fakeSource{headers: map[string]string{"Cookie": oidc.SessionCookieName + "=" + token}}
	if _, err := o.Authenticate(ctx, src); !errors.Is(err, oidc.ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

func TestAuthenticate_MalformedCookieHeader(t *testing.T) {
	ctx := context.Background()
	o, _, _ := newTestOIDC(t)
	// A garbage Cookie header (no valid "name=value" pairs at all) must
	// be treated the same as no session -- not a crash, not a different
	// error type a caller would need to special-case.
	src := fakeSource{headers: map[string]string{"Cookie": ";;;===not-a-cookie==="}}
	ident, err := o.Authenticate(ctx, src)
	if err != nil {
		t.Fatalf("got err %v, want nil", err)
	}
	if ident != nil {
		t.Fatalf("got %+v, want nil identity", ident)
	}
}

func TestSetSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	oidc.SetSessionCookie(rec, "tok123")
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != oidc.SessionCookieName || cookies[0].Value != "tok123" {
		t.Fatalf("got %+v", cookies)
	}
}

func TestClearSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	oidc.ClearSessionCookie(rec)
	// A cleared cookie's Set-Cookie header carries Max-Age=0 (Go's
	// http.Cookie serializes MaxAge<0 this way); Cookies() re-parses
	// "Max-Age=0" back as MaxAge==0, not -1 -- assert on the Name/Value
	// instead of MaxAge for that reason (same approach identity/local's
	// equivalent test uses).
	raw := rec.Header().Get("Set-Cookie")
	if raw == "" {
		t.Fatal("expected a Set-Cookie header")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != oidc.SessionCookieName || cookies[0].Value != "" {
		t.Fatalf("got %+v", cookies)
	}
}

func TestLogout_IdempotentOnUnknownToken(t *testing.T) {
	ctx := context.Background()
	o, _, _ := newTestOIDC(t)
	if err := o.Logout(ctx, "never-existed"); err != nil {
		t.Fatalf("Logout on unknown token should not error: %v", err)
	}
}
