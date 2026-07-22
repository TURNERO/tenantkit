package local

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
)

// SessionCookieName is the cookie Local's session token travels in.
// SetSessionCookie/ClearSessionCookie and Authenticate all agree on this
// name -- a consumer's login/logout HTTP handlers should use the helpers
// below rather than hardcoding it, so the two sides can't drift.
const SessionCookieName = "tenantkit_session"

// Local satisfies identity.IdentityProvider via Authenticate below.
var _ identity.IdentityProvider = (*Local)(nil)

// SetSessionCookie sets token on w as Local's session cookie.
func SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie removes Local's session cookie on w.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// Authenticate satisfies identity.IdentityProvider. It reads the session
// cookie from src, validates it via SessionStore, and returns the full
// Identity via the UserStore Local was constructed with.
//
// Per the IdentityProvider contract, an absent session credential is not
// an error: if src carries no tenantkit_session cookie at all (no Cookie
// header, a Cookie header without that cookie, or one that can't be
// parsed), Authenticate returns (nil, nil) so callers degrade to
// anonymous rather than rejecting the request outright. A
// tenantkit_session cookie that IS present but doesn't resolve to a
// valid, unexpired session is a genuine authentication failure and still
// returns a real error.
func (l *Local) Authenticate(ctx context.Context, src resolve.Source) (*tenantkit.Identity, error) {
	token, ok := sessionTokenFromHeader(src.Header("Cookie"))
	if !ok {
		// No session credential offered at all -- not an error.
		return nil, nil
	}

	sessionTenantID, userID, err := l.sessions.GetSession(ctx, token)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
			return nil, err
		}
		return nil, fmt.Errorf("tenantkit/identity/local: get session: %w", err)
	}

	ident, err := l.users.GetUser(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("tenantkit/identity/local: session user no longer exists: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("tenantkit/identity/local: look up session user: %w", err)
	}
	if ident.TenantID != sessionTenantID {
		// Defense in depth: a SessionStore implementation should never
		// produce this (the tenantID it returns is the one CreateSession
		// was called with), but if it ever does, treat it as no session
		// rather than trusting a UserStore lookup that disagrees with
		// the session's own tenant.
		return nil, fmt.Errorf("tenantkit/identity/local: session/user tenant mismatch: %w", ErrNotFound)
	}

	return ident, nil
}

// sessionTokenFromHeader extracts the tenantkit_session cookie's value
// from a raw Cookie header. ok is false whenever no such cookie value
// can be extracted -- an empty header, a header without that cookie, or
// one that fails to parse -- never an error: absence of a session
// credential is not itself invalid input.
func sessionTokenFromHeader(cookieHeader string) (token string, ok bool) {
	if cookieHeader == "" {
		return "", false
	}
	req := &http.Request{Header: http.Header{"Cookie": []string{cookieHeader}}}
	c, err := req.Cookie(SessionCookieName)
	if err != nil {
		return "", false
	}
	return c.Value, true
}
