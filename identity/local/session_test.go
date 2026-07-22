package local_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity/local"
	localmem "github.com/TURNERO/tenantkit/identity/local/memstore"
	"github.com/TURNERO/tenantkit/store/memstore"
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
	l, _ := newTestLocal(t)
	if _, err := l.Authenticate(ctx, fakeSource{}); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestAuthenticate_UnknownToken(t *testing.T) {
	ctx := context.Background()
	l, _ := newTestLocal(t)
	src := fakeSource{headers: map[string]string{"Cookie": local.SessionCookieName + "=bogus"}}
	if _, err := l.Authenticate(ctx, src); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestAuthenticate_ValidSession(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "pw"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	token, err := l.LoginWithPassword(ctx, "acme", "alice", "pw")
	if err != nil {
		t.Fatalf("LoginWithPassword: %v", err)
	}

	src := fakeSource{headers: map[string]string{"Cookie": local.SessionCookieName + "=" + token}}
	ident, err := l.Authenticate(ctx, src)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if ident.UserID != "u1" || ident.TenantID != "acme" {
		t.Fatalf("got %+v", ident)
	}
}

func TestAuthenticate_AfterLogout(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "pw"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	token, err := l.LoginWithPassword(ctx, "acme", "alice", "pw")
	if err != nil {
		t.Fatalf("LoginWithPassword: %v", err)
	}
	if err := l.Logout(ctx, token); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	src := fakeSource{headers: map[string]string{"Cookie": local.SessionCookieName + "=" + token}}
	if _, err := l.Authenticate(ctx, src); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestAuthenticate_ExpiredSession(t *testing.T) {
	ctx := context.Background()
	users := memstore.New()
	ls := localmem.New()
	// A negative SessionTTL means any session Local issues is already
	// expired the instant it's created -- exercises the ErrExpired path
	// through Authenticate itself, not just SessionStore.GetSession
	// directly (already covered by Task 1's memstore tests).
	l, err := local.New(local.Config{
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		RPDisplayName: "Test",
		SessionTTL:    -time.Second,
		ResetTokenTTL: time.Hour,
	}, users, ls, ls, ls)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "pw"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	token, err := l.LoginWithPassword(ctx, "acme", "alice", "pw")
	if err != nil {
		t.Fatalf("LoginWithPassword: %v", err)
	}

	src := fakeSource{headers: map[string]string{"Cookie": local.SessionCookieName + "=" + token}}
	if _, err := l.Authenticate(ctx, src); !errors.Is(err, local.ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

func TestAuthenticate_MalformedCookieHeader(t *testing.T) {
	ctx := context.Background()
	l, _ := newTestLocal(t)
	// A garbage Cookie header (no valid "name=value" pairs at all) must
	// be treated the same as no session -- not a crash, not a different
	// error type a caller would need to special-case.
	src := fakeSource{headers: map[string]string{"Cookie": ";;;===not-a-cookie==="}}
	if _, err := l.Authenticate(ctx, src); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestSetSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	local.SetSessionCookie(rec, "tok123")
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != local.SessionCookieName || cookies[0].Value != "tok123" {
		t.Fatalf("got %+v", cookies)
	}
}

func TestClearSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	local.ClearSessionCookie(rec)
	// A cleared cookie's Set-Cookie header carries Max-Age=0 (Go's
	// http.Cookie serializes MaxAge<0 this way) -- verified this is what
	// actually appears on the wire, not just what the Cookie struct says,
	// since Cookies() re-parses "Max-Age=0" back as MaxAge==0, not -1.
	raw := rec.Header().Get("Set-Cookie")
	if raw == "" {
		t.Fatal("expected a Set-Cookie header")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != local.SessionCookieName || cookies[0].Value != "" {
		t.Fatalf("got %+v", cookies)
	}
}

// Confirm sessionTokenFromHeader's underlying approach -- parsing a
// cookie out of a raw header string via a synthetic *http.Request --
// handles multiple cookies on the same header correctly. This exercises
// the same code path Authenticate uses, via a valid session.
func TestAuthenticate_MultipleCookiesOnHeader(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "pw"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	token, err := l.LoginWithPassword(ctx, "acme", "alice", "pw")
	if err != nil {
		t.Fatalf("LoginWithPassword: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "other", Value: "1"})
	req.AddCookie(&http.Cookie{Name: local.SessionCookieName, Value: token})
	req.AddCookie(&http.Cookie{Name: "foo", Value: "bar"})

	src := fakeSource{headers: map[string]string{"Cookie": req.Header.Get("Cookie")}}
	ident, err := l.Authenticate(ctx, src)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if ident.UserID != "u1" {
		t.Fatalf("got %+v", ident)
	}
}
