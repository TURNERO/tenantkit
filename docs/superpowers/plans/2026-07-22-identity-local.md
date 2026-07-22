# identity/local Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `tenantkit/identity/local`, the built-in `identity.IdentityProvider` implementation: password (bcrypt) and WebAuthn (passkey) authentication, opaque-token sessions, and a password-reset token flow.

**Architecture:** Three new storage interfaces (`CredentialStore`, `SessionStore`, `EphemeralStore`), owned by `identity/local` (not `tenantkit/store`), plus an in-memory reference implementation for tests. A single `Local` type wraps these plus the existing `store.UserStore` and a configured `*webauthn.WebAuthn`, exposing plain Go methods a consumer wires into their own HTTP handlers — `identity/local` owns no HTTP routes, matching tenantkit's existing "middleware, not a framework" positioning.

**Tech Stack:** `github.com/go-webauthn/webauthn` (WebAuthn ceremonies), `golang.org/x/crypto/bcrypt` (password hashing), `github.com/descope/virtualwebauthn` (test-only: simulates a real authenticator's cryptographic responses so ceremony tests run against real signature verification, not mocks).

Design spec: `docs/superpowers/specs/2026-07-22-identity-local-design.md`. All code below was scratch-verified in a disposable Go module before being written here — the WebAuthn round trip (registration + login, including the `SessionData` JSON round-trip through `EphemeralStore`'s `[]byte` payload), the bcrypt dummy-hash timing mitigation, cookie parsing from a raw header string via `resolve.Source.Header("Cookie")`, and the `Set-Cookie`/`Cookies()` round-trip for `ClearSessionCookie`'s `MaxAge: -1` all ran for real, not just read from documentation.

## Global Constraints

- Go directive stays `go 1.25.0` in the root `go.mod` -- every new dependency (`go-webauthn/webauthn`, `golang.org/x/crypto`, `descope/virtualwebauthn`) declares `go 1.25.0` itself (verified via `go list -m -f '{{.Path}} go={{.GoVersion}}' all` in scratch), so no version bump is needed this time.
- All new code lives in the **main module** (`github.com/TURNERO/tenantkit`), not `tools/` -- `identity/local` is a core library package like `resolve`/`httpmw`/`grpcmw`, not CLI tooling.
- The three new storage interfaces (`CredentialStore`, `SessionStore`, `EphemeralStore`) live in `identity/local`, never in `tenantkit/store` -- consumers using only API-key/mTLS auth never need to implement them.
- `EphemeralStore.Take` fetches and deletes atomically -- single-use is a property of the interface itself, verified by test in every task that uses it (a replayed ceremony-finish or reset-password call must fail).
- Sentinel errors live in `identity/local` with the message prefix `"tenantkit/identity/local: ..."`, matching `tenantkit/store`'s `"tenantkit/store: ..."` convention: `ErrNotFound`, `ErrExpired`, `ErrInvalidCredentials`.
- Session token transport is a cookie, name `local.SessionCookieName = "tenantkit_session"`, `Secure`+`HttpOnly`+`SameSite=Lax`. `Authenticate` parses it from `resolve.Source.Header("Cookie")` via a synthetic `*http.Request{Header: ...}` and `req.Cookie(name)` -- verified this works from a raw header string, not just a real `*http.Request`.
- Anti-enumeration handling is mandatory, not optional polish: `LoginWithPassword` returns the same `ErrInvalidCredentials` for "no such user" and "wrong password", running `bcrypt.CompareHashAndPassword` against a fixed dummy hash on the unknown-user path so both take comparable time. `RequestPasswordReset` returns a normal-shaped token and no error for an unknown username.
- `webauthnUser.WebAuthnID()` is `sha256.Sum256(tenantID + ":" + userID)`, never bare `UserID` and never the raw string composite -- see the design spec's WebAuthn section for why (64-byte WebAuthn user-handle limit, cross-tenant collision risk).
- Test files use the black-box `package local_test` (or `package memstore_test`) convention, matching `admin_test.go`/`resolve_test.go` throughout this codebase.
- `identity/local/memstore` mirrors `tenantkit/store/memstore`'s existing style: a single mutex-protected `Store` type, defensive copies on every read/write that returns or accepts a slice.
- Every method on `Local` assumes `tenantID`/`userID` already has a record in `store.UserStore` -- `Local` never creates users, only credentials for users that already exist.

---

### Task 1: Storage interfaces, sentinel errors, and in-memory reference implementation

**Files:**
- Create: `identity/local/store.go`
- Create: `identity/local/errors.go`
- Create: `identity/local/memstore/memstore.go`
- Test: `identity/local/memstore/memstore_test.go`

**Interfaces:**
- Consumes: nothing from this plan; `webauthn.Credential` from `github.com/go-webauthn/webauthn/webauthn`.
- Produces: `local.CredentialStore`, `local.SessionStore`, `local.EphemeralStore` interfaces; `local.ErrNotFound`, `local.ErrExpired`; `memstore.New() *memstore.Store` implementing all three interfaces. Every later task in this plan depends on these.

- [ ] **Step 1: Add the go-webauthn dependency**

Run from the repo root (`/home/rob/src/tenantkit`):

```bash
go get github.com/go-webauthn/webauthn@v0.17.4
```

Expected: `go.mod` gains a `require github.com/go-webauthn/webauthn v0.17.4` line plus its indirect dependencies (`fxamacker/cbor/v2`, `go-webauthn/x`, `golang-jwt/jwt/v5`, `google/go-tpm`, `tinylib/msgp`, etc.) in `go.sum`. `google/uuid` is already an indirect dependency via `modernc.org/libc`; MVS may bump its version -- that's expected, not a bug.

- [ ] **Step 2: Write the failing tests**

Create `identity/local/memstore/memstore_test.go`:

```go
package memstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit/identity/local"
	"github.com/TURNERO/tenantkit/identity/local/memstore"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestCredentialStore_PasswordHash(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

	if _, err := s.GetPasswordHash(ctx, "acme", "u1"); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}

	if err := s.SetPasswordHash(ctx, "acme", "u1", "hash1"); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	got, err := s.GetPasswordHash(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetPasswordHash: %v", err)
	}
	if got != "hash1" {
		t.Fatalf("got %q, want %q", got, "hash1")
	}

	// Same userID in a different tenant must not see this tenant's hash.
	if _, err := s.GetPasswordHash(ctx, "other-tenant", "u1"); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound (tenant isolation)", err)
	}

	// Overwriting replaces, not appends.
	if err := s.SetPasswordHash(ctx, "acme", "u1", "hash2"); err != nil {
		t.Fatalf("SetPasswordHash overwrite: %v", err)
	}
	got, err = s.GetPasswordHash(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetPasswordHash after overwrite: %v", err)
	}
	if got != "hash2" {
		t.Fatalf("got %q, want %q", got, "hash2")
	}
}

func TestCredentialStore_WebAuthnCredentials(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

	creds, err := s.GetWebAuthnCredentials(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("got %d credentials, want 0", len(creds))
	}

	cred1 := webauthn.Credential{ID: []byte("cred-1")}
	cred2 := webauthn.Credential{ID: []byte("cred-2")}
	if err := s.AddWebAuthnCredential(ctx, "acme", "u1", cred1); err != nil {
		t.Fatalf("AddWebAuthnCredential: %v", err)
	}
	if err := s.AddWebAuthnCredential(ctx, "acme", "u1", cred2); err != nil {
		t.Fatalf("AddWebAuthnCredential: %v", err)
	}

	creds, err = s.GetWebAuthnCredentials(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("got %d credentials, want 2", len(creds))
	}

	// Mutating the returned slice must not affect the store's copy.
	creds[0].ID = []byte("mutated")
	fresh, err := s.GetWebAuthnCredentials(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if string(fresh[0].ID) != "cred-1" {
		t.Fatalf("store's copy was mutated by caller: got %q", fresh[0].ID)
	}
}

func TestSessionStore(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

	if _, _, err := s.GetSession(ctx, "bogus"); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}

	token, err := s.CreateSession(ctx, "acme", "u1", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	tenantID, userID, err := s.GetSession(ctx, token)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if tenantID != "acme" || userID != "u1" {
		t.Fatalf("got tenantID=%q userID=%q", tenantID, userID)
	}

	if err := s.DeleteSession(ctx, token); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, _, err := s.GetSession(ctx, token); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound after delete", err)
	}

	// Deleting an already-deleted/unknown token is not an error.
	if err := s.DeleteSession(ctx, token); err != nil {
		t.Fatalf("DeleteSession on already-deleted token: %v", err)
	}
}

func TestSessionStore_Expiry(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

	token, err := s.CreateSession(ctx, "acme", "u1", -time.Second) // already expired
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, _, err := s.GetSession(ctx, token); !errors.Is(err, local.ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

func TestEphemeralStore(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

	if _, err := s.Take(ctx, "bogus"); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}

	if err := s.Put(ctx, "tok1", []byte("payload"), time.Hour); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Take(ctx, "tok1")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("got %q, want %q", got, "payload")
	}

	// Take is single-use: a second call for the same token fails.
	if _, err := s.Take(ctx, "tok1"); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound on replayed Take", err)
	}
}

func TestEphemeralStore_Expiry(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

	if err := s.Put(ctx, "tok1", []byte("payload"), -time.Second); err != nil { // already expired
		t.Fatalf("Put: %v", err)
	}
	if _, err := s.Take(ctx, "tok1"); !errors.Is(err, local.ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
	// Still single-use even though it was expired.
	if _, err := s.Take(ctx, "tok1"); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound on replayed Take", err)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./identity/... -v`
Expected: FAIL -- `package github.com/TURNERO/tenantkit/identity/local/memstore is not in std` or similar (the package doesn't exist yet).

- [ ] **Step 4: Create `identity/local/store.go` and `identity/local/errors.go`**

`identity/local/store.go`:

```go
// Package local is tenantkit's built-in identity.IdentityProvider
// implementation: password (bcrypt) and WebAuthn (passkey)
// authentication, opaque-token sessions, and a password-reset token
// flow.
package local

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// CredentialStore holds password hashes and WebAuthn credentials.
// Implementations key both by (tenantID, userID) -- usernames are only
// unique within a tenant, matching store.UserStore's existing scoping.
type CredentialStore interface {
	SetPasswordHash(ctx context.Context, tenantID, userID, hash string) error
	// GetPasswordHash returns ErrNotFound if the user has no password set
	// (e.g. a WebAuthn-only account).
	GetPasswordHash(ctx context.Context, tenantID, userID string) (string, error)
	AddWebAuthnCredential(ctx context.Context, tenantID, userID string, cred webauthn.Credential) error
	// GetWebAuthnCredentials returns an empty slice (not an error) for a
	// user with no registered credentials.
	GetWebAuthnCredentials(ctx context.Context, tenantID, userID string) ([]webauthn.Credential, error)
}

// SessionStore holds active login sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, tenantID, userID string, ttl time.Duration) (token string, err error)
	// GetSession returns ErrNotFound (no such token) or ErrExpired
	// (existed, past ttl).
	GetSession(ctx context.Context, token string) (tenantID, userID string, err error)
	DeleteSession(ctx context.Context, token string) error
}

// EphemeralStore holds short-lived, single-use opaque tokens: WebAuthn
// ceremony state and password-reset tokens both use this -- structurally
// identical (opaque token -> payload blob, TTL, consumed exactly once).
type EphemeralStore interface {
	Put(ctx context.Context, token string, payload []byte, ttl time.Duration) error
	// Take fetches and deletes atomically, so single-use is a property
	// of the interface -- a replayed ceremony-finish or reset request
	// always fails on the second attempt.
	Take(ctx context.Context, token string) ([]byte, error) // ErrNotFound / ErrExpired
}
```

`identity/local/errors.go`:

```go
package local

import "errors"

var (
	// ErrNotFound is returned by the storage interfaces (CredentialStore,
	// SessionStore, EphemeralStore) for a missing row.
	ErrNotFound = errors.New("tenantkit/identity/local: not found")
	// ErrExpired is returned by SessionStore and EphemeralStore for a row
	// that existed but is past its TTL.
	ErrExpired = errors.New("tenantkit/identity/local: expired")
	// ErrInvalidCredentials is returned by LoginWithPassword and the
	// WebAuthn login ceremony on a failed login -- deliberately not
	// ErrNotFound, so a caller can't distinguish "no such user" from
	// "wrong credential" even if it wanted to.
	ErrInvalidCredentials = errors.New("tenantkit/identity/local: invalid credentials")
)
```

- [ ] **Step 5: Create `identity/local/memstore/memstore.go`**

```go
// Package memstore is an in-memory implementation of identity/local's
// storage interfaces. It exists for tests -- both tenantkit's own and a
// consumer's -- not as a production backend: nothing is persisted, and
// every method takes a single mutex.
package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/TURNERO/tenantkit/identity/local"
	"github.com/TURNERO/tenantkit/store"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Store is an in-memory local.CredentialStore, local.SessionStore, and
// local.EphemeralStore.
type Store struct {
	mu sync.Mutex

	passwordHashes map[credentialKey]string
	webauthnCreds  map[credentialKey][]webauthn.Credential

	sessions  map[string]sessionRecord
	ephemeral map[string]ephemeralRecord
}

type credentialKey struct {
	tenantID string
	userID   string
}

type sessionRecord struct {
	tenantID string
	userID   string
	expires  time.Time
}

type ephemeralRecord struct {
	payload []byte
	expires time.Time
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		passwordHashes: make(map[credentialKey]string),
		webauthnCreds:  make(map[credentialKey][]webauthn.Credential),
		sessions:       make(map[string]sessionRecord),
		ephemeral:      make(map[string]ephemeralRecord),
	}
}

var (
	_ local.CredentialStore = (*Store)(nil)
	_ local.SessionStore    = (*Store)(nil)
	_ local.EphemeralStore  = (*Store)(nil)
)

func (s *Store) SetPasswordHash(ctx context.Context, tenantID, userID, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passwordHashes[credentialKey{tenantID, userID}] = hash
	return nil
}

func (s *Store) GetPasswordHash(ctx context.Context, tenantID, userID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.passwordHashes[credentialKey{tenantID, userID}]
	if !ok {
		return "", local.ErrNotFound
	}
	return hash, nil
}

func (s *Store) AddWebAuthnCredential(ctx context.Context, tenantID, userID string, cred webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := credentialKey{tenantID, userID}
	s.webauthnCreds[key] = append(s.webauthnCreds[key], cred)
	return nil
}

func (s *Store) GetWebAuthnCredentials(ctx context.Context, tenantID, userID string) ([]webauthn.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	creds := s.webauthnCreds[credentialKey{tenantID, userID}]
	out := make([]webauthn.Credential, len(creds))
	copy(out, creds)
	return out, nil
}

func (s *Store) CreateSession(ctx context.Context, tenantID, userID string, ttl time.Duration) (string, error) {
	token, err := store.GenerateSecret()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = sessionRecord{tenantID: tenantID, userID: userID, expires: time.Now().Add(ttl)}
	return token, nil
}

func (s *Store) GetSession(ctx context.Context, token string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[token]
	if !ok {
		return "", "", local.ErrNotFound
	}
	if time.Now().After(rec.expires) {
		return "", "", local.ErrExpired
	}
	return rec.tenantID, rec.userID, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
	return nil
}

func (s *Store) Put(ctx context.Context, token string, payload []byte, ttl time.Duration) error {
	cp := make([]byte, len(payload))
	copy(cp, payload)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ephemeral[token] = ephemeralRecord{payload: cp, expires: time.Now().Add(ttl)}
	return nil
}

func (s *Store) Take(ctx context.Context, token string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.ephemeral[token]
	if !ok {
		return nil, local.ErrNotFound
	}
	delete(s.ephemeral, token) // single-use regardless of outcome
	if time.Now().After(rec.expires) {
		return nil, local.ErrExpired
	}
	return rec.payload, nil
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./identity/... -v`
Expected: PASS, all tests in `identity/local/memstore`.

- [ ] **Step 7: Run `go mod tidy`, `go vet`, and commit**

```bash
go mod tidy
go vet ./...
git add go.mod go.sum identity/local/store.go identity/local/errors.go identity/local/memstore/memstore.go identity/local/memstore/memstore_test.go
git commit -m "feat: add identity/local storage interfaces and in-memory reference impl"
```

---

### Task 2: `Local` type and password authentication

**Files:**
- Create: `identity/local/local.go`
- Create: `identity/local/password.go`
- Test: `identity/local/password_test.go`

**Interfaces:**
- Consumes: `local.CredentialStore`/`SessionStore`/`EphemeralStore` (Task 1), `store.UserStore`/`store.ErrNotFound`/`store.GenerateSecret` (foundation), `memstore.New()` (Task 1, test-only) and `github.com/TURNERO/tenantkit/store/memstore.New()` (foundation, test-only).
- Produces: `local.Config`, `local.Local`, `local.New(...) (*Local, error)`, `(*Local).SetPassword`, `(*Local).LoginWithPassword`, `(*Local).Logout`. Also produces the `newTestLocal(t) (*local.Local, *memstore.Store)` test helper in `password_test.go`, which Tasks 3-5's tests reuse (`memstore` here is `github.com/TURNERO/tenantkit/store/memstore`, the `UserStore` implementation -- not `identity/local/memstore`).

- [ ] **Step 1: Add the bcrypt dependency**

```bash
go get golang.org/x/crypto@v0.54.0
```

Expected: `go.mod`'s existing `golang.org/x/crypto` (if any transitive) becomes a direct `require`, or is added; `golang.org/x/sys` may bump versions as a side effect of MVS -- expected, not a bug (same as the `google/uuid` bump in Task 1).

- [ ] **Step 2: Write the failing tests**

Create `identity/local/password_test.go`:

```go
package local_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity/local"
	localmem "github.com/TURNERO/tenantkit/identity/local/memstore"
	"github.com/TURNERO/tenantkit/store/memstore"
)

// newTestLocal returns a Local wired to fresh in-memory stores, plus the
// UserStore so tests can create users. Reused by Tasks 3-5's tests.
func newTestLocal(t *testing.T) (*local.Local, *memstore.Store) {
	t.Helper()
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
	return l, users
}

func TestSetPasswordAndLoginWithPassword(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)

	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	token, err := l.LoginWithPassword(ctx, "acme", "alice", "correct horse battery staple")
	if err != nil {
		t.Fatalf("LoginWithPassword: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty session token")
	}
}

func TestLoginWithPassword_WrongPassword(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if _, err := l.LoginWithPassword(ctx, "acme", "alice", "wrong"); !errors.Is(err, local.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginWithPassword_UnknownUsername(t *testing.T) {
	ctx := context.Background()
	l, _ := newTestLocal(t)
	if _, err := l.LoginWithPassword(ctx, "acme", "nobody", "whatever"); !errors.Is(err, local.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginWithPassword_NoPasswordSet(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := l.LoginWithPassword(ctx, "acme", "alice", "whatever"); !errors.Is(err, local.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

func TestSetPassword_Overwrites(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "old-password"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "new-password"); err != nil {
		t.Fatalf("SetPassword overwrite: %v", err)
	}
	if _, err := l.LoginWithPassword(ctx, "acme", "alice", "old-password"); !errors.Is(err, local.ErrInvalidCredentials) {
		t.Fatalf("old password should no longer work, got %v", err)
	}
	if _, err := l.LoginWithPassword(ctx, "acme", "alice", "new-password"); err != nil {
		t.Fatalf("new password should work: %v", err)
	}
}

func TestLogout(t *testing.T) {
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
	// Logout is idempotent -- deleting an already-deleted session is not
	// an error (the end state is the same either way).
	if err := l.Logout(ctx, token); err != nil {
		t.Fatalf("second Logout: %v", err)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./identity/... -v`
Expected: FAIL -- `undefined: local.Config` / `undefined: local.New` (the type doesn't exist yet).

- [ ] **Step 4: Create `identity/local/local.go`**

```go
package local

import (
	"fmt"
	"time"

	"github.com/TURNERO/tenantkit/identity"
	"github.com/TURNERO/tenantkit/store"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config configures a Local identity provider.
type Config struct {
	// RPID is the WebAuthn relying-party ID: your service's effective
	// domain (e.g. "example.com"), without scheme or port.
	RPID string
	// RPOrigins is the list of origins WebAuthn ceremonies are permitted
	// from (e.g. "https://example.com").
	RPOrigins []string
	// RPDisplayName is a human-readable name shown by browser/OS WebAuthn
	// UI during registration and login.
	RPDisplayName string
	// SessionTTL is how long a session (password or WebAuthn login) stays
	// valid.
	SessionTTL time.Duration
	// ResetTokenTTL is how long a password-reset token stays valid.
	ResetTokenTTL time.Duration
}

// Local is tenantkit's built-in password + WebAuthn identity provider.
// It satisfies identity.IdentityProvider via Authenticate.
type Local struct {
	cfg       Config
	users     store.UserStore
	creds     CredentialStore
	sessions  SessionStore
	ephemeral EphemeralStore
	wa        *webauthn.WebAuthn
}

var _ identity.IdentityProvider = (*Local)(nil)

// New returns a Local identity provider. It returns an error if cfg is
// invalid (e.g. missing RPID) -- see github.com/go-webauthn/webauthn's
// Config validation.
func New(cfg Config, users store.UserStore, creds CredentialStore, sessions SessionStore, ephemeral EphemeralStore) (*Local, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("tenantkit/identity/local: configure webauthn: %w", err)
	}
	return &Local{
		cfg:       cfg,
		users:     users,
		creds:     creds,
		sessions:  sessions,
		ephemeral: ephemeral,
		wa:        wa,
	}, nil
}
```

- [ ] **Step 5: Create `identity/local/password.go`**

```go
package local

import (
	"context"
	"errors"
	"fmt"

	"github.com/TURNERO/tenantkit/store"
	"golang.org/x/crypto/bcrypt"
)

// dummyHash is a fixed bcrypt hash with no known matching password, used
// to burn comparable time on LoginWithPassword's unknown-user/no-password
// paths so its timing doesn't leak whether a username exists -- a real
// bcrypt.CompareHashAndPassword call is measurably slower than an early
// return, and that gap is measurable over enough attempts.
const dummyHash = "$2a$10$CwTycUXWue0Thq9StjUM0uJ8Bm4/RGyGbYAgQtdRlz/DL6P/n2DDW"

// SetPassword hashes password and stores it for (tenantID, userID). It
// does not create the user -- tenantID/userID must already exist in the
// UserStore Local was constructed with (e.g. via
// tenantkit/admin.CreateUser); a nonexistent user is not checked here
// and simply orphans a credential record no user can ever log in with.
func (l *Local) SetPassword(ctx context.Context, tenantID, userID, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("tenantkit/identity/local: hash password: %w", err)
	}
	if err := l.creds.SetPasswordHash(ctx, tenantID, userID, string(hash)); err != nil {
		return fmt.Errorf("tenantkit/identity/local: set password: %w", err)
	}
	return nil
}

// LoginWithPassword validates username/password within tenantID and, on
// success, issues a session token. It returns ErrInvalidCredentials for
// an unknown username, a user with no password set, and a wrong
// password alike -- a caller can never distinguish these from the error
// alone.
func (l *Local) LoginWithPassword(ctx context.Context, tenantID, username, password string) (string, error) {
	ident, err := l.users.GetUserByUsername(ctx, tenantID, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
			return "", ErrInvalidCredentials
		}
		return "", fmt.Errorf("tenantkit/identity/local: look up user: %w", err)
	}

	hash, err := l.creds.GetPasswordHash(ctx, tenantID, ident.UserID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
			return "", ErrInvalidCredentials
		}
		return "", fmt.Errorf("tenantkit/identity/local: get password hash: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return "", ErrInvalidCredentials
	}

	token, err := l.sessions.CreateSession(ctx, tenantID, ident.UserID, l.cfg.SessionTTL)
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: create session: %w", err)
	}
	return token, nil
}

// Logout deletes the session identified by token. Deleting an
// already-expired or unknown token is not an error -- the end state (no
// valid session for that token) is the same either way.
func (l *Local) Logout(ctx context.Context, token string) error {
	if err := l.sessions.DeleteSession(ctx, token); err != nil {
		return fmt.Errorf("tenantkit/identity/local: logout: %w", err)
	}
	return nil
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./identity/... -v`
Expected: PASS, all tests in `identity/local` and `identity/local/memstore`.

- [ ] **Step 7: Run `go vet` and commit**

```bash
go vet ./...
git add identity/local/local.go identity/local/password.go identity/local/password_test.go
git commit -m "feat: add identity/local Local type and password authentication"
```

---

### Task 3: Session validation (`identity.IdentityProvider`) and cookie helpers

**Files:**
- Create: `identity/local/session.go`
- Test: `identity/local/session_test.go`

**Interfaces:**
- Consumes: `local.Local`/`Config`/`New` (Task 2), `newTestLocal` test helper (Task 2's `password_test.go`), `resolve.Source` (foundation).
- Produces: `(*Local).Authenticate` (satisfies `identity.IdentityProvider`), `local.SessionCookieName`, `local.SetSessionCookie`, `local.ClearSessionCookie`.

- [ ] **Step 1: Write the failing tests**

Create `identity/local/session_test.go`:

```go
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./identity/... -v`
Expected: FAIL -- `l.Authenticate undefined` and `local.SetSessionCookie undefined` (the method/functions don't exist yet).

- [ ] **Step 3: Create `identity/local/session.go`**

```go
package local

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
)

// SessionCookieName is the cookie Local's session token travels in.
// SetSessionCookie/ClearSessionCookie and Authenticate all agree on this
// name -- a consumer's login/logout HTTP handlers should use the helpers
// below rather than hardcoding it, so the two sides can't drift.
const SessionCookieName = "tenantkit_session"

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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./identity/... -v`
Expected: PASS, all tests in `identity/local` and `identity/local/memstore`.

- [ ] **Step 5: Run `go vet` and commit**

```bash
go vet ./...
git add identity/local/session.go identity/local/session_test.go
git commit -m "feat: add identity/local session validation and cookie helpers"
```

---

### Task 4: WebAuthn (passkey) registration and login

**Files:**
- Create: `identity/local/webauthn.go`
- Test: `identity/local/webauthn_test.go`

**Interfaces:**
- Consumes: `local.Local`/`Config`/`New` (Task 2), `local.CredentialStore`/`SessionStore`/`EphemeralStore`/`ErrNotFound`/`ErrExpired` (Task 1), `github.com/descope/virtualwebauthn` (test-only).
- Produces: `(*Local).BeginWebAuthnRegistration`, `(*Local).FinishWebAuthnRegistration`, `(*Local).BeginWebAuthnLogin`, `(*Local).FinishWebAuthnLogin`. Nothing later in this plan depends on these.

- [ ] **Step 1: Add the virtualwebauthn test dependency**

```bash
go get github.com/descope/virtualwebauthn@v1.0.5
```

Expected: `go.mod` gains `require github.com/descope/virtualwebauthn v1.0.5`. It's only ever imported from `_test.go` files, so it never reaches a consumer's build -- same reasoning already established for `store/sqlite`'s driver dependency.

- [ ] **Step 2: Write the failing tests**

Create `identity/local/webauthn_test.go`:

```go
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
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./identity/... -v`
Expected: FAIL -- `l.BeginWebAuthnRegistration undefined` (the methods don't exist yet).

- [ ] **Step 4: Create `identity/local/webauthn.go`**

```go
package local

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// webauthnCeremonyTTL bounds how long a WebAuthn ceremony (registration
// or login) has to complete before its EphemeralStore entry expires.
// Not exposed via Config -- 5 minutes comfortably covers a real
// browser/authenticator interaction, and there's no evidence yet that
// any consumer needs this tunable.
const webauthnCeremonyTTL = 5 * time.Minute

// webauthnUser bridges an Identity + its stored WebAuthn credentials to
// go-webauthn's webauthn.User interface.
type webauthnUser struct {
	identity *tenantkit.Identity
	creds    []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte {
	// Must be unique per Relying Party -- i.e. across the whole
	// deployment, not just within a tenant. Bare UserID isn't safe
	// (UserStore's uniqueness guarantee only spans tenantID+username),
	// and a raw tenantID+userID string composite doesn't fit WebAuthn's
	// 64-byte user-handle limit with tenantkit's default ID generators
	// (32-char tenant ID + 43-char user ID = 76 bytes combined). SHA-256
	// gives a fixed 32-byte opaque handle that's both collision-resistant
	// and safely under the limit.
	sum := sha256.Sum256([]byte(u.identity.TenantID + ":" + u.identity.UserID))
	return sum[:]
}
func (u *webauthnUser) WebAuthnName() string                       { return u.identity.Username }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.identity.Username }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// webauthnCeremony is the payload saved in EphemeralStore between a
// ceremony's Begin and Finish calls -- go-webauthn's SessionData plus
// which user this ceremony belongs to (FinishWebAuthnLogin doesn't take
// tenantID/userID again; this is where that comes from).
type webauthnCeremony struct {
	TenantID    string               `json:"tenant_id"`
	UserID      string               `json:"user_id"`
	SessionData webauthn.SessionData `json:"session_data"`
}

func (l *Local) loadUserForWebAuthn(ctx context.Context, tenantID, userID string) (*webauthnUser, error) {
	ident, err := l.users.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("tenantkit/identity/local: look up user: %w", err)
	}
	if ident.TenantID != tenantID {
		return nil, fmt.Errorf("tenantkit/identity/local: user does not belong to tenant: %w", ErrNotFound)
	}
	creds, err := l.creds.GetWebAuthnCredentials(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("tenantkit/identity/local: get webauthn credentials: %w", err)
	}
	return &webauthnUser{identity: ident, creds: creds}, nil
}

// BeginWebAuthnRegistration starts adding a passkey to an already-known
// user. It returns the challenge to send the browser as JSON, and a
// ceremonyToken the consumer's handler must round-trip back to
// FinishWebAuthnRegistration (a hidden form field or short-lived
// cookie, consumer's choice).
func (l *Local) BeginWebAuthnRegistration(ctx context.Context, tenantID, userID string) (*protocol.CredentialCreation, string, error) {
	user, err := l.loadUserForWebAuthn(ctx, tenantID, userID)
	if err != nil {
		return nil, "", err
	}

	creation, sessionData, err := l.wa.BeginRegistration(user)
	if err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/local: begin webauthn registration: %w", err)
	}

	ceremonyToken, err := l.saveCeremony(ctx, tenantID, userID, *sessionData)
	if err != nil {
		return nil, "", err
	}
	return creation, ceremonyToken, nil
}

// FinishWebAuthnRegistration completes a registration ceremony started
// by BeginWebAuthnRegistration, storing the resulting credential.
// ceremonyToken is single-use: a replayed finish request fails.
func (l *Local) FinishWebAuthnRegistration(ctx context.Context, tenantID, userID, ceremonyToken string, r *http.Request) error {
	ceremony, err := l.takeCeremony(ctx, ceremonyToken)
	if err != nil {
		return err
	}
	if ceremony.TenantID != tenantID || ceremony.UserID != userID {
		return fmt.Errorf("tenantkit/identity/local: ceremony token does not match tenant/user: %w", ErrNotFound)
	}

	user, err := l.loadUserForWebAuthn(ctx, tenantID, userID)
	if err != nil {
		return err
	}

	cred, err := l.wa.FinishRegistration(user, ceremony.SessionData, r)
	if err != nil {
		return fmt.Errorf("tenantkit/identity/local: finish webauthn registration: %w", err)
	}

	if err := l.creds.AddWebAuthnCredential(ctx, tenantID, userID, *cred); err != nil {
		return fmt.Errorf("tenantkit/identity/local: store webauthn credential: %w", err)
	}
	return nil
}

// BeginWebAuthnLogin starts a passkey login for username within
// tenantID. It returns the challenge to send the browser as JSON, and a
// ceremonyToken the consumer's handler must round-trip back to
// FinishWebAuthnLogin.
func (l *Local) BeginWebAuthnLogin(ctx context.Context, tenantID, username string) (*protocol.CredentialAssertion, string, error) {
	ident, err := l.users.GetUserByUsername(ctx, tenantID, username)
	if err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/local: look up user: %w", err)
	}
	user, err := l.loadUserForWebAuthn(ctx, tenantID, ident.UserID)
	if err != nil {
		return nil, "", err
	}

	assertion, sessionData, err := l.wa.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/local: begin webauthn login: %w", err)
	}

	ceremonyToken, err := l.saveCeremony(ctx, tenantID, ident.UserID, *sessionData)
	if err != nil {
		return nil, "", err
	}
	return assertion, ceremonyToken, nil
}

// FinishWebAuthnLogin completes a login ceremony started by
// BeginWebAuthnLogin and, on success, issues a session token.
// ceremonyToken is single-use.
func (l *Local) FinishWebAuthnLogin(ctx context.Context, ceremonyToken string, r *http.Request) (string, error) {
	ceremony, err := l.takeCeremony(ctx, ceremonyToken)
	if err != nil {
		return "", err
	}

	user, err := l.loadUserForWebAuthn(ctx, ceremony.TenantID, ceremony.UserID)
	if err != nil {
		return "", err
	}

	if _, err := l.wa.FinishLogin(user, ceremony.SessionData, r); err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: finish webauthn login: %w", err)
	}

	token, err := l.sessions.CreateSession(ctx, ceremony.TenantID, ceremony.UserID, l.cfg.SessionTTL)
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: create session: %w", err)
	}
	return token, nil
}

func (l *Local) saveCeremony(ctx context.Context, tenantID, userID string, sessionData webauthn.SessionData) (string, error) {
	token, err := store.GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: generate ceremony token: %w", err)
	}
	payload, err := json.Marshal(webauthnCeremony{TenantID: tenantID, UserID: userID, SessionData: sessionData})
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: encode webauthn ceremony: %w", err)
	}
	if err := l.ephemeral.Put(ctx, token, payload, webauthnCeremonyTTL); err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: save webauthn ceremony: %w", err)
	}
	return token, nil
}

func (l *Local) takeCeremony(ctx context.Context, ceremonyToken string) (*webauthnCeremony, error) {
	payload, err := l.ephemeral.Take(ctx, ceremonyToken)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
			return nil, err
		}
		return nil, fmt.Errorf("tenantkit/identity/local: load webauthn ceremony: %w", err)
	}
	var ceremony webauthnCeremony
	if err := json.Unmarshal(payload, &ceremony); err != nil {
		return nil, fmt.Errorf("tenantkit/identity/local: decode webauthn ceremony: %w", err)
	}
	return &ceremony, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./identity/... -v`
Expected: PASS, all tests in `identity/local` and `identity/local/memstore`, including the full registration+login round trip in `TestWebAuthnRegistrationAndLogin` against a real simulated authenticator (not a mock).

- [ ] **Step 6: Run `go mod tidy`, `go vet`, and commit**

```bash
go mod tidy
go vet ./...
git add go.mod go.sum identity/local/webauthn.go identity/local/webauthn_test.go
git commit -m "feat: add identity/local WebAuthn registration and login"
```

---

### Task 5: Password reset

**Files:**
- Create: `identity/local/reset.go`
- Test: `identity/local/reset_test.go`

**Interfaces:**
- Consumes: `local.Local`/`Config`/`New`/`SetPassword` (Task 2), `local.EphemeralStore`/`ErrNotFound`/`ErrExpired` (Task 1), `store.ErrNotFound`/`store.GenerateSecret` (foundation).
- Produces: `(*Local).RequestPasswordReset`, `(*Local).ResetPassword`. Nothing later in this plan depends on these -- this is the last task.

- [ ] **Step 1: Write the failing tests**

Create `identity/local/reset_test.go`:

```go
package local_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity/local"
	localmem "github.com/TURNERO/tenantkit/identity/local/memstore"
	"github.com/TURNERO/tenantkit/store/memstore"
)

func TestRequestAndResetPassword(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "old-password"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	token, err := l.RequestPasswordReset(ctx, "acme", "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	if err := l.ResetPassword(ctx, token, "new-password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	if _, err := l.LoginWithPassword(ctx, "acme", "alice", "old-password"); !errors.Is(err, local.ErrInvalidCredentials) {
		t.Fatalf("old password should no longer work, got %v", err)
	}
	if _, err := l.LoginWithPassword(ctx, "acme", "alice", "new-password"); err != nil {
		t.Fatalf("new password should work: %v", err)
	}
}

func TestRequestPasswordReset_UnknownUsername(t *testing.T) {
	ctx := context.Background()
	l, _ := newTestLocal(t)
	// Anti-enumeration: an unknown username still gets a normal-looking
	// token and no error, so a caller can't use the response shape to
	// probe for valid usernames.
	token, err := l.RequestPasswordReset(ctx, "acme", "nobody")
	if err != nil {
		t.Fatalf("expected no error for unknown username, got %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token even for unknown username")
	}
}

func TestResetPassword_TokenIsSingleUse(t *testing.T) {
	ctx := context.Background()
	l, users := newTestLocal(t)
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "old"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	token, err := l.RequestPasswordReset(ctx, "acme", "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := l.ResetPassword(ctx, token, "new1"); err != nil {
		t.Fatalf("first ResetPassword: %v", err)
	}
	if err := l.ResetPassword(ctx, token, "new2"); err == nil {
		t.Fatal("expected error on replayed reset token")
	}
}

func TestResetPassword_UnknownToken(t *testing.T) {
	ctx := context.Background()
	l, _ := newTestLocal(t)
	if err := l.ResetPassword(ctx, "bogus-token", "whatever"); !errors.Is(err, local.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	users := memstore.New()
	ls := localmem.New()
	// A negative ResetTokenTTL means the token RequestPasswordReset
	// issues is already expired the instant it's created -- exercises
	// the ErrExpired path through ResetPassword itself, not just
	// EphemeralStore.Take directly (already covered by Task 1's
	// memstore tests).
	l, err := local.New(local.Config{
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		RPDisplayName: "Test",
		SessionTTL:    time.Hour,
		ResetTokenTTL: -time.Second,
	}, users, ls, ls, ls)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	if err := users.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := l.SetPassword(ctx, "acme", "u1", "old"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	token, err := l.RequestPasswordReset(ctx, "acme", "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := l.ResetPassword(ctx, token, "new"); !errors.Is(err, local.ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./identity/... -v`
Expected: FAIL -- `l.RequestPasswordReset undefined` (the methods don't exist yet).

- [ ] **Step 3: Create `identity/local/reset.go`**

```go
package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TURNERO/tenantkit/store"
)

type resetPayload struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
}

// RequestPasswordReset generates a single-use reset token for username
// within tenantID and returns it -- delivering it (e.g. via email) is
// entirely the consumer's responsibility. If username doesn't exist,
// this still returns a syntactically valid token and no error, rather
// than a distinguishable error a caller could use to probe for valid
// usernames -- same anti-enumeration reasoning as LoginWithPassword.
func (l *Local) RequestPasswordReset(ctx context.Context, tenantID, username string) (string, error) {
	ident, err := l.users.GetUserByUsername(ctx, tenantID, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return randomLookingToken()
		}
		return "", fmt.Errorf("tenantkit/identity/local: look up user: %w", err)
	}

	token, err := store.GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: generate reset token: %w", err)
	}
	payload, err := json.Marshal(resetPayload{TenantID: tenantID, UserID: ident.UserID})
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: encode reset token: %w", err)
	}
	if err := l.ephemeral.Put(ctx, token, payload, l.cfg.ResetTokenTTL); err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: save reset token: %w", err)
	}
	return token, nil
}

// ResetPassword validates resetToken (single-use) and sets newPassword
// for the user it was issued to.
func (l *Local) ResetPassword(ctx context.Context, resetToken, newPassword string) error {
	payload, err := l.ephemeral.Take(ctx, resetToken)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
			return err
		}
		return fmt.Errorf("tenantkit/identity/local: load reset token: %w", err)
	}
	var reset resetPayload
	if err := json.Unmarshal(payload, &reset); err != nil {
		return fmt.Errorf("tenantkit/identity/local: decode reset token: %w", err)
	}
	return l.SetPassword(ctx, reset.TenantID, reset.UserID, newPassword)
}

// randomLookingToken returns a token indistinguishable in shape from a
// real one issued by RequestPasswordReset, for the unknown-username
// path -- the caller can't tell "no such user" from "reset issued" by
// looking at the return value alone.
func randomLookingToken() (string, error) {
	token, err := store.GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: generate reset token: %w", err)
	}
	return token, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./identity/... -v`
Expected: PASS, all tests in `identity/local` and `identity/local/memstore`.

- [ ] **Step 5: Run `go vet`, `go build`, and commit**

```bash
go vet ./...
go build ./...
git add identity/local/reset.go identity/local/reset_test.go
git commit -m "feat: add identity/local password reset"
```

---

## What's next

After all 5 tasks are complete and individually reviewed, per `superpowers:subagent-driven-development`: dispatch a final whole-branch review (most capable model), then `superpowers:finishing-a-development-branch` to merge. Sync any real findings back into this plan document and `docs/superpowers/specs/2026-07-22-identity-local-design.md` before merging, same as done for the Admin plan's Tasks 1-2 findings.

Deferred follow-ups, already tracked: issue #4 (persistent SQLite backend for the three new storage interfaces), issue #5 (`identity/oidc`), issue #6 (account lockout / login rate-limiting).
