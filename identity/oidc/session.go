package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity"
	"github.com/TURNERO/tenantkit/resolve"
)

// SessionCookieName is the cookie OIDC's session token travels in.
// SetSessionCookie/ClearSessionCookie and Authenticate all agree on
// this name -- a consumer's callback/logout HTTP handlers should use
// the helpers below rather than hardcoding it, so the two sides can't
// drift. Distinct from identity/local.SessionCookieName so both
// providers could in principle be configured on the same
// httpmw/grpcmw chain without colliding.
const SessionCookieName = "tenantkit_oidc_session"

// SetSessionCookie sets token on w as OIDC's session cookie.
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

// ClearSessionCookie removes OIDC's session cookie on w.
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

// StateCookieName is the cookie BeginLogin's returned state value
// travels in between BeginLogin and FinishLogin, binding the OAuth2
// ceremony to the browser that started it. See FinishLogin's doc
// comment for why this matters.
const StateCookieName = "tenantkit_oidc_state"

// SetStateCookie sets state on w as the OIDC login-ceremony state
// cookie. Its MaxAge matches the ceremony's own TTL, so it can't
// outlive the ceremony it protects.
func SetStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(loginCeremonyTTL.Seconds()),
	})
}

// ClearStateCookie removes the OIDC login-ceremony state cookie on w.
// Call this from your callback handler after FinishLogin, whether it
// succeeded or failed -- the ceremony is over either way.
func ClearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

var _ identity.IdentityProvider = (*OIDC)(nil)

// Authenticate satisfies identity.IdentityProvider. It reads the
// session cookie from src and validates it via SessionStore -- no IdP
// round-trip on this path at all, that's the entire reason FinishLogin
// created a local session in the first place.
//
// Per the IdentityProvider contract, an absent session credential is
// not an error: if src carries no OIDC session cookie at all (no
// Cookie header, a Cookie header without that cookie, or one that
// can't be parsed), Authenticate returns (nil, nil) so callers degrade
// to anonymous rather than rejecting the request outright -- the same
// contract identity/local.Authenticate follows (httpmw/grpcmw treat
// any non-nil Authenticate error as a hard 401/Unauthenticated).
func (o *OIDC) Authenticate(ctx context.Context, src resolve.Source) (*tenantkit.Identity, error) {
	token, ok := sessionTokenFromHeader(src.Header("Cookie"))
	if !ok {
		return nil, nil
	}

	ident, err := o.sessions.GetSession(ctx, token)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
			return nil, err
		}
		return nil, fmt.Errorf("tenantkit/identity/oidc: get session: %w", err)
	}
	return ident, nil
}

// Logout deletes the session identified by token. Deleting an
// already-expired or unknown token is not an error -- the end state
// (no valid session for that token) is the same either way.
func (o *OIDC) Logout(ctx context.Context, token string) error {
	if err := o.sessions.DeleteSession(ctx, token); err != nil {
		return fmt.Errorf("tenantkit/identity/oidc: logout: %w", err)
	}
	return nil
}

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
