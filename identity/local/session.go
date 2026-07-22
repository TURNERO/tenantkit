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
func (l *Local) Authenticate(ctx context.Context, src resolve.Source) (*tenantkit.Identity, error) {
	token, err := sessionTokenFromHeader(src.Header("Cookie"))
	if err != nil {
		return nil, err
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

func sessionTokenFromHeader(cookieHeader string) (string, error) {
	if cookieHeader == "" {
		return "", ErrNotFound
	}
	req := &http.Request{Header: http.Header{"Cookie": []string{cookieHeader}}}
	c, err := req.Cookie(SessionCookieName)
	if err != nil {
		return "", ErrNotFound
	}
	return c.Value, nil
}
