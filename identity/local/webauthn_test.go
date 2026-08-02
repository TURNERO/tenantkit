package local_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity/local"
	localmem "github.com/TURNERO/tenantkit/identity/local/memstore"
	"github.com/TURNERO/tenantkit/store/memstore"
	"github.com/descope/virtualwebauthn"
)

func jsonRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestWebAuthnRegistrationAndLogin(t *testing.T) {
	ctx := context.Background()
	users := memstore.New()
	ls := localmem.New()
	l, err := local.New(local.Config{
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		RPDisplayName: "Test",
		SessionTTL:    time.Hour,
		ResetTokenTTL: time.Hour,
	}, users, ls, ls, ls)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}

	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	rp := virtualwebauthn.RelyingParty{ID: "localhost", Name: "Test", Origin: "http://localhost"}
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// --- Registration ---
	creation, regToken, err := l.BeginWebAuthnRegistration(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("BeginWebAuthnRegistration: %v", err)
	}
	creationJSON, err := json.Marshal(creation.Response)
	if err != nil {
		t.Fatalf("marshal creation: %v", err)
	}
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(creationJSON))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}
	attestationResp := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *attOpts)

	if err := l.FinishWebAuthnRegistration(ctx, "acme", "u1", regToken, jsonRequest(attestationResp)); err != nil {
		t.Fatalf("FinishWebAuthnRegistration: %v", err)
	}
	authenticator.AddCredential(credential)

	// A replayed finish (same regToken) must fail -- single-use.
	if err := l.FinishWebAuthnRegistration(ctx, "acme", "u1", regToken, jsonRequest(attestationResp)); err == nil {
		t.Fatal("expected error on replayed registration ceremony token")
	}

	// --- Login ---
	assertion, loginToken, err := l.BeginWebAuthnLogin(ctx, "acme", "alice")
	if err != nil {
		t.Fatalf("BeginWebAuthnLogin: %v", err)
	}
	assertionJSON, err := json.Marshal(assertion.Response)
	if err != nil {
		t.Fatalf("marshal assertion: %v", err)
	}
	assertOpts, err := virtualwebauthn.ParseAssertionOptions(string(assertionJSON))
	if err != nil {
		t.Fatalf("ParseAssertionOptions: %v", err)
	}
	assertionResp := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *assertOpts)

	sessionToken, err := l.FinishWebAuthnLogin(ctx, loginToken, jsonRequest(assertionResp))
	if err != nil {
		t.Fatalf("FinishWebAuthnLogin: %v", err)
	}
	if sessionToken == "" {
		t.Fatal("expected non-empty session token")
	}

	// A replayed finish (same loginToken) must fail -- single-use.
	if _, err := l.FinishWebAuthnLogin(ctx, loginToken, jsonRequest(assertionResp)); err == nil {
		t.Fatal("expected error on replayed login ceremony token")
	}
}

func TestBeginWebAuthnRegistration_UnknownUser(t *testing.T) {
	ctx := context.Background()
	l, _ := newTestLocal(t)
	if _, _, err := l.BeginWebAuthnRegistration(ctx, "acme", "nobody"); err == nil {
		t.Fatal("expected error for unknown user")
	}
}

func TestBeginWebAuthnLogin_UnknownUsername(t *testing.T) {
	ctx := context.Background()
	l, _ := newTestLocal(t)
	if _, _, err := l.BeginWebAuthnLogin(ctx, "acme", "nobody"); err == nil {
		t.Fatal("expected error for unknown username")
	}
}

func TestFinishWebAuthnRegistration_TenantUserMismatch(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)

	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u2", TenantID: "acme", Username: "bob"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, regToken, err := l.BeginWebAuthnRegistration(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("BeginWebAuthnRegistration: %v", err)
	}

	// Finishing against a different userID than the ceremony was issued
	// for must fail, even though the token itself is valid.
	if err := l.FinishWebAuthnRegistration(ctx, "acme", "u2", regToken, jsonRequest("")); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestBeginWebAuthnLogin_LockedOutAfterThreshold(t *testing.T) {
	ctx := context.Background()
	users := memstore.New()
	ls := localmem.New()
	limiter := localmem.NewLoginLimiter(3, time.Hour, time.Hour)
	l, err := local.New(local.Config{
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		RPDisplayName: "Test",
		SessionTTL:    time.Hour,
		ResetTokenTTL: time.Hour,
		LoginLimiter:  limiter,
	}, users, ls, ls, ls)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Register a credential so BeginWebAuthnLogin can proceed.
	rp := virtualwebauthn.RelyingParty{ID: "localhost", Name: "Test", Origin: "http://localhost"}
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	creation, regToken, err := l.BeginWebAuthnRegistration(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("BeginWebAuthnRegistration: %v", err)
	}
	creationJSON, err := json.Marshal(creation.Response)
	if err != nil {
		t.Fatalf("marshal creation: %v", err)
	}
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(creationJSON))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}
	attestationResp := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *attOpts)
	if err := l.FinishWebAuthnRegistration(ctx, "acme", "u1", regToken, jsonRequest(attestationResp)); err != nil {
		t.Fatalf("FinishWebAuthnRegistration: %v", err)
	}
	authenticator.AddCredential(credential)

	// Each failed attempt consumes a fresh ceremony (FinishWebAuthnLogin
	// takes the ceremony token single-use regardless of outcome), so a
	// malformed assertion body on each Finish is enough to drive
	// wa.FinishLogin to fail and trigger RecordFailure.
	for i := 0; i < 3; i++ {
		_, loginToken, err := l.BeginWebAuthnLogin(ctx, "acme", "alice")
		if err != nil {
			t.Fatalf("attempt %d: BeginWebAuthnLogin: %v", i, err)
		}
		if _, err := l.FinishWebAuthnLogin(ctx, loginToken, jsonRequest("")); err == nil {
			t.Fatalf("attempt %d: expected FinishWebAuthnLogin to fail on malformed assertion", i)
		}
	}

	// Locked out now -- BeginWebAuthnLogin must reject before even
	// generating a new challenge, so even a legitimate passkey never
	// gets the chance to be tried.
	if _, _, err := l.BeginWebAuthnLogin(ctx, "acme", "alice"); !errors.Is(err, local.ErrTooManyAttempts) {
		t.Fatalf("got %v, want ErrTooManyAttempts", err)
	}
}

// TestLoginLimiter_SharedAcrossPasswordAndWebAuthn proves the spec's
// headline claim: "any failed authentication attempt, regardless of
// method, counts against the same lockout." Password failures alone
// drive the account past the threshold; a WebAuthn login attempt for
// the same username must then also be rejected, since both methods
// key RecordFailure/Allow off the same (tenantID, username).
func TestLoginLimiter_SharedAcrossPasswordAndWebAuthn(t *testing.T) {
	ctx := context.Background()
	users := memstore.New()
	ls := localmem.New()
	limiter := localmem.NewLoginLimiter(3, time.Hour, time.Hour)
	l, err := local.New(local.Config{
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		RPDisplayName: "Test",
		SessionTTL:    time.Hour,
		ResetTokenTTL: time.Hour,
		LoginLimiter:  limiter,
	}, users, ls, ls, ls)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	// Drive enough failed password logins to hit the shared lockout
	// threshold.
	for i := 0; i < 3; i++ {
		if _, err := l.LoginWithPassword(ctx, "acme", "alice", "wrong"); !errors.Is(err, local.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: got %v, want ErrInvalidCredentials", i, err)
		}
	}

	// The lockout is keyed on (tenantID, username), not the auth
	// method -- a WebAuthn login attempt for the same username must
	// now also be rejected, proving the two methods share one counter.
	if _, _, err := l.BeginWebAuthnLogin(ctx, "acme", "alice"); !errors.Is(err, local.ErrTooManyAttempts) {
		t.Fatalf("got %v, want ErrTooManyAttempts", err)
	}
}

// TestBeginWebAuthnLogin_UnknownUsernameRecordsFailure proves fix #1:
// an unknown username probed via BeginWebAuthnLogin now counts toward
// that username's own lockout, closing what would otherwise be a
// rate-limit-free enumeration oracle (WebAuthn login didn't share
// LoginWithPassword's dummy-hash-then-record pattern for unknown
// users). Repeating past the threshold must flip the error from the
// lookup failure to ErrTooManyAttempts.
func TestBeginWebAuthnLogin_UnknownUsernameRecordsFailure(t *testing.T) {
	ctx := context.Background()
	users := memstore.New()
	ls := localmem.New()
	limiter := localmem.NewLoginLimiter(3, time.Hour, time.Hour)
	l, err := local.New(local.Config{
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		RPDisplayName: "Test",
		SessionTTL:    time.Hour,
		ResetTokenTTL: time.Hour,
		LoginLimiter:  limiter,
	}, users, ls, ls, ls)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, _, err := l.BeginWebAuthnLogin(ctx, "acme", "nobody"); err == nil || errors.Is(err, local.ErrTooManyAttempts) {
			t.Fatalf("attempt %d: got %v, want a non-nil, non-lockout lookup error", i, err)
		}
	}

	// The unknown username itself is now locked out -- provable
	// directly against the limiter, and via a further
	// BeginWebAuthnLogin call returning ErrTooManyAttempts instead of
	// the original lookup error.
	if allowed, err := limiter.Allow(ctx, "acme", "nobody"); err != nil {
		t.Fatalf("Allow: %v", err)
	} else if allowed {
		t.Fatal("expected unknown username to be locked out after repeated probing")
	}
	if _, _, err := l.BeginWebAuthnLogin(ctx, "acme", "nobody"); !errors.Is(err, local.ErrTooManyAttempts) {
		t.Fatalf("got %v, want ErrTooManyAttempts", err)
	}
}

// TestBeginWebAuthnLogin_NoCredentialsRecordsFailure proves fix #1's
// first bug from the second whole-branch review: an existing user
// with zero registered passkeys was a sharper enumeration signal than
// the unknown-username case it was supposed to close --
// CredentialStore.GetWebAuthnCredentials returns an empty slice (not
// an error), so loadUserForWebAuthn succeeded and the previous code
// let this sail through unrecorded (the actual failure only surfaced
// one line later, from wa.BeginLogin, on a branch that never called
// recordLoginFailure). Repeating past the threshold must now also
// lock this username out, just like the unknown-username case.
func TestBeginWebAuthnLogin_NoCredentialsRecordsFailure(t *testing.T) {
	ctx := context.Background()
	users := memstore.New()
	ls := localmem.New()
	limiter := localmem.NewLoginLimiter(3, time.Hour, time.Hour)
	l, err := local.New(local.Config{
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		RPDisplayName: "Test",
		SessionTTL:    time.Hour,
		ResetTokenTTL: time.Hour,
		LoginLimiter:  limiter,
	}, users, ls, ls, ls)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	// alice exists but never registered a passkey.
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, _, err := l.BeginWebAuthnLogin(ctx, "acme", "alice"); err == nil || errors.Is(err, local.ErrTooManyAttempts) {
			t.Fatalf("attempt %d: got %v, want a non-nil, non-lockout error", i, err)
		}
	}

	// alice herself is now locked out -- provable directly against the
	// limiter, and via a further BeginWebAuthnLogin call returning
	// ErrTooManyAttempts.
	if allowed, err := limiter.Allow(ctx, "acme", "alice"); err != nil {
		t.Fatalf("Allow: %v", err)
	} else if allowed {
		t.Fatal("expected a user with no registered passkeys to be locked out after repeated probing")
	}
	if _, _, err := l.BeginWebAuthnLogin(ctx, "acme", "alice"); !errors.Is(err, local.ErrTooManyAttempts) {
		t.Fatalf("got %v, want ErrTooManyAttempts", err)
	}
}

// errGetUser is the sentinel error erroringGetUserStore.GetUser
// returns, so TestBeginWebAuthnLogin_BackendErrorDoesNotRecordFailure
// can assert it survives wrapped, unrecorded, out of BeginWebAuthnLogin.
var errGetUser = errors.New("erroringGetUserStore: boom")

// erroringGetUserStore is a minimal store.UserStore test double: it
// embeds a real memstore.Store (so GetUserByUsername and CreateUser
// behave normally) but overrides GetUser to always fail with a
// genuine backend error, not local.ErrNotFound. This simulates
// loadUserForWebAuthn's "real GetUser/GetWebAuthnCredentials backend
// error" failure mode described in fix #1's second bug, as distinct
// from its tenant-mismatch (wrapped ErrNotFound) failure mode.
type erroringGetUserStore struct {
	*memstore.Store
}

func (s *erroringGetUserStore) GetUser(ctx context.Context, userID string) (*tenantkit.Identity, error) {
	return nil, errGetUser
}

// TestBeginWebAuthnLogin_BackendErrorDoesNotRecordFailure proves fix
// #1's second bug: since ident.UserID just came from a successful
// GetUserByUsername call, loadUserForWebAuthn's only realistic
// failure modes here are a genuine backend error, or the
// tenant-mismatch case (wrapped ErrNotFound). Only the latter should
// count toward lockout -- a transient database outage during a
// passkey-login burst must not lock a real user out for the full
// lockout duration.
func TestBeginWebAuthnLogin_BackendErrorDoesNotRecordFailure(t *testing.T) {
	ctx := context.Background()
	realUsers := memstore.New()
	users := &erroringGetUserStore{Store: realUsers}
	ls := localmem.New()
	limiter := localmem.NewLoginLimiter(3, time.Hour, time.Hour)
	l, err := local.New(local.Config{
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		RPDisplayName: "Test",
		SessionTTL:    time.Hour,
		ResetTokenTTL: time.Hour,
		LoginLimiter:  limiter,
	}, users, ls, ls, ls)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	if err := realUsers.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// GetUserByUsername succeeds (delegated to the real store), but the
	// subsequent GetUser call inside loadUserForWebAuthn always fails
	// with a genuine backend error -- not ErrNotFound. Run more than
	// maxAttempts times: if this were (wrongly) recorded as a login
	// failure, attempts past the threshold would come back as
	// ErrTooManyAttempts instead of errGetUser.
	for i := 0; i < 5; i++ {
		if _, _, err := l.BeginWebAuthnLogin(ctx, "acme", "alice"); !errors.Is(err, errGetUser) {
			t.Fatalf("attempt %d: got %v, want an error wrapping errGetUser", i, err)
		}
	}

	// None of those backend errors should have counted toward lockout.
	if allowed, err := limiter.Allow(ctx, "acme", "alice"); err != nil {
		t.Fatalf("Allow: %v", err)
	} else if !allowed {
		t.Fatal("a genuine backend error from loadUserForWebAuthn must not count toward lockout")
	}
}
