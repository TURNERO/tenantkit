package local_test

import (
	"context"
	"encoding/json"
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
