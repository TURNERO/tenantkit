# identity/oidc Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `tenantkit/identity/oidc`, the second `identity.IdentityProvider` implementation: an OAuth2 Authorization Code ceremony against an externally-registered OIDC provider (`store.OIDCProviderStore`, already merged), verified-ID-token claims mapped to a `tenantkit.Identity`, and opaque-token sessions.

**Architecture:** Two new storage interfaces (`SessionStore`, `EphemeralStore`), independently declared from `identity/local`'s (not imported -- this package has no dependency on `identity/local` or `store.UserStore` at all: a verified ID token's claims *are* the Identity). A single `OIDC` type wraps these plus `store.OIDCProviderStore` and a lazily-built, per-`(tenantID, providerID)` cache of each registered provider's OAuth2/OIDC client. Plain Go functions (`BeginLogin`, `BeginLoginByDomain`, `FinishLogin`, `Authenticate`) a consumer wires into their own HTTP handlers -- no HTTP routes, matching `identity/local`'s and tenantkit's existing "middleware, not a framework" positioning.

**Tech Stack:** `github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2` (the OAuth2/OIDC ceremony), `github.com/go-jose/go-jose/v4` (test-only: signs fake ID tokens so tests never hit a real IdP over the network).

Design spec: `docs/superpowers/specs/2026-07-23-identity-oidc-design.md`. All code below was scratch-verified in a disposable Go module before being written here -- the full ceremony (`AuthCodeURL` generation, a fake IdP serving discovery/JWKS/token endpoints, in-process JWT signing via `go-jose`, verification via `go-oidc`'s `IDTokenVerifier`, wrong-audience and expired-token rejection) and the exact claims-mapping logic (`mapClaims`, including every default and rejection case) all ran for real, not just read from documentation.

## Global Constraints

- Go directive stays `go 1.25.0` in the root `go.mod` -- `go-oidc/v3` v3.20.0 and `golang.org/x/oauth2` v0.36.0 both declare `go 1.25.0`; `go-jose/v4` v4.1.4 declares `go 1.24.0`. All ≤ 1.25.0, so no bump is needed (verified via `go list -m -f '{{.Path}} go={{.GoVersion}}' all` in scratch).
- All new code lives in the **main module**, not `tools/` -- `identity/oidc` is a core library package like `identity/local`.
- `identity/oidc` has **no dependency on `identity/local` or `store.UserStore`**. Its `SessionStore` stores the full `*tenantkit.Identity`, not `(tenantID, userID)` -- there is no `UserStore` to re-fetch it from later.
- The two new storage interfaces (`SessionStore`, `EphemeralStore`) live in `identity/oidc`, independently declared -- not imported from `identity/local`, even though `EphemeralStore` is structurally identical to that package's.
- `EphemeralStore.Take` fetches and deletes atomically -- single-use is a property of the interface (a replayed callback, or a replayed/expired ceremony, always fails on a second attempt).
- Session token transport is a cookie, name `oidc.SessionCookieName = "tenantkit_oidc_session"` -- **distinct from `identity/local.SessionCookieName`** so both providers could in principle be configured on the same `httpmw`/`grpcmw` chain without colliding (unusual, but not prevented) -- `Secure`+`HttpOnly`+`SameSite=Lax`.
- `Authenticate` returns `(nil, nil)` for an absent session cookie, not an error -- per `identity.IdentityProvider`'s documented contract and `httpmw`/`grpcmw`'s "any non-nil `Authenticate` error is a hard 401/Unauthenticated" rule. This is baked into the design from the start in this plan (`identity/local` needed a fix-round for this exact bug after its final whole-branch review; this plan applies that lesson up front).
- Sentinel errors live in `identity/oidc` with the message prefix `"tenantkit/identity/oidc: ..."`: `ErrNotFound`, `ErrExpired`, `ErrUnknownProvider` (wraps `store.ErrNotFound` from a provider lookup), `ErrInvalidToken` (one bucket for every token/claims verification failure -- signature/issuer/audience/expiry, nonce mismatch, tenant-claim mismatch, missing/malformed mapped claim -- deliberately not split finer, mirroring `identity/local.ErrInvalidCredentials`'s non-enumerable-failure-reason philosophy).
- Provider-client cache (`OIDC.clients`, keyed by `(tenantID, providerID)`) is lazy, mutex-guarded, and **never evicted or invalidated in v1** -- an admin rotating a client secret or changing an issuer via the CLI while a process is running won't take effect until restart. Documented on `New`, not solved with more machinery (a TTL, a store watch) for v1.
- `FinishLogin` verifies the verified token's mapped `TenantID` against the `tenantID` the ceremony was *started* for, before ever creating a session -- defense in depth, same spirit as `identity/local.Authenticate`'s session/user tenant-mismatch guard.
- Import alias required throughout: `goidc "github.com/coreos/go-oidc/v3/oidc"` -- this package is itself named `oidc` (`identity/oidc`), so an unaliased import of `github.com/coreos/go-oidc/v3/oidc` collides with the package's own name.
- Test convention: black-box `package oidc_test` throughout, **except** `claims_test.go` (Task 2), which must be white-box `package oidc` since `mapClaims` is deliberately unexported (only `FinishLogin` calls it; a consumer never sees raw claims, tenantkit maps them internally).
- **`OIDC.Logout(ctx, token) error` is added in this plan** even though the existing design spec's prose doesn't mention it -- a real gap found while planning: the spec's own `SessionStore.DeleteSession` method exists specifically to support a logout primitive, but nothing in the spec ever calls it, and without `Logout` a consumer has no way to invalidate an OIDC session without reaching into the `SessionStore` implementation directly. Mirrors `identity/local.Logout` exactly. The design spec is being synced with this addition alongside this plan.
- No test exercises `loginCeremonyTTL`'s expiry directly -- matches `identity/local`'s established precedent for its structurally identical `webauthnCeremonyTTL` (an internal, non-configurable constant); already covered structurally by `EphemeralStore`'s own expiry tests in Task 1.

---

### Task 1: Storage interfaces, sentinel errors, in-memory reference implementation, and conformance suite

**Files:**
- Create: `identity/oidc/store.go`
- Create: `identity/oidc/errors.go`
- Create: `identity/oidc/storetest/storetest.go`
- Create: `identity/oidc/memstore/memstore.go`
- Create: `identity/oidc/memstore/memstore_test.go`

**Interfaces:**
- Consumes: `tenantkit.Identity` (foundation), `store.GenerateSecret` (foundation).
- Produces: `oidc.SessionStore`, `oidc.EphemeralStore` interfaces; `oidc.ErrNotFound`, `oidc.ErrExpired`, `oidc.ErrUnknownProvider`, `oidc.ErrInvalidToken`; `memstore.New() *memstore.Store` implementing both interfaces; `storetest.TestSessionStore(t, s)`, `storetest.TestEphemeralStore(t, s)`. Every later task in this plan depends on these.

- [ ] **Step 1: Write the failing tests**

Create `identity/oidc/memstore/memstore_test.go`:

```go
package memstore_test

import (
	"testing"

	"github.com/TURNERO/tenantkit/identity/oidc/memstore"
	"github.com/TURNERO/tenantkit/identity/oidc/storetest"
)

func TestMemstoreConformsToSessionStore(t *testing.T) {
	storetest.TestSessionStore(t, memstore.New())
}

func TestMemstoreConformsToEphemeralStore(t *testing.T) {
	storetest.TestEphemeralStore(t, memstore.New())
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./identity/oidc/... -v`
Expected: FAIL -- `package github.com/TURNERO/tenantkit/identity/oidc/memstore is not in std` or similar (none of these packages exist yet).

- [ ] **Step 3: Create `identity/oidc/store.go` and `identity/oidc/errors.go`**

`identity/oidc/store.go`:

```go
// Package oidc is tenantkit's built-in identity.IdentityProvider
// implementation wrapping an external OIDC-compliant identity
// provider: the OAuth2 Authorization Code ceremony
// (BeginLogin/BeginLoginByDomain/FinishLogin), verified-ID-token claims
// mapped to a tenantkit.Identity, and opaque-token sessions. It shares
// only the identity.IdentityProvider interface with identity/local and
// has no other dependency on it.
package oidc

import (
	"context"
	"time"

	"github.com/TURNERO/tenantkit"
)

// SessionStore holds active OIDC-backed login sessions. Unlike
// identity/local's SessionStore, this stores the full Identity, not
// just (tenantID, userID) -- there is no UserStore to re-fetch it from
// later; the verified ID token's claims are the Identity.
type SessionStore interface {
	CreateSession(ctx context.Context, id *tenantkit.Identity, ttl time.Duration) (token string, err error)
	// GetSession returns ErrNotFound (no such token) or ErrExpired
	// (existed, past ttl).
	GetSession(ctx context.Context, token string) (*tenantkit.Identity, error)
	DeleteSession(ctx context.Context, token string) error
}

// EphemeralStore holds short-lived, single-use opaque tokens: OAuth2
// state/nonce ceremony data between BeginLogin and FinishLogin.
type EphemeralStore interface {
	Put(ctx context.Context, token string, payload []byte, ttl time.Duration) error
	// Take fetches and deletes atomically, so a replayed callback (or a
	// replayed/expired ceremony) always fails on a second attempt.
	Take(ctx context.Context, token string) ([]byte, error) // ErrNotFound / ErrExpired
}
```

`identity/oidc/errors.go`:

```go
package oidc

import "errors"

var (
	// ErrNotFound is returned by the storage interfaces (SessionStore,
	// EphemeralStore) for a missing row.
	ErrNotFound = errors.New("tenantkit/identity/oidc: not found")
	// ErrExpired is returned by SessionStore and EphemeralStore for a
	// row that existed but is past its TTL.
	ErrExpired = errors.New("tenantkit/identity/oidc: expired")
	// ErrUnknownProvider wraps store.ErrNotFound from a provider lookup
	// (BeginLogin/BeginLoginByDomain/FinishLogin given a (tenantID,
	// providerID) or domain with no matching registration).
	ErrUnknownProvider = errors.New("tenantkit/identity/oidc: unknown provider")
	// ErrInvalidToken covers every token/claims verification failure --
	// signature/issuer/audience/expiry, a nonce mismatch, a
	// tenant-claim mismatch, and a missing/malformed mapped claim --
	// deliberately one bucket, not split into finer sentinel errors, so
	// a caller can't use error type to enumerate why a login failed.
	ErrInvalidToken = errors.New("tenantkit/identity/oidc: invalid token")
)
```

- [ ] **Step 4: Create `identity/oidc/storetest/storetest.go`**

```go
// Package storetest provides interface-conformance test helpers for
// identity/oidc's storage interfaces. A consumer's own store
// implementation can run these against a fresh instance to prove it
// satisfies the documented behavior of oidc.SessionStore and
// oidc.EphemeralStore -- not just that it compiles against the
// interface.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity/oidc"
)

// TestSessionStore runs a battery of subtests against s. Pass a fresh,
// empty store.
func TestSessionStore(t *testing.T, s oidc.SessionStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateGetDelete", func(t *testing.T) {
		if _, err := s.GetSession(ctx, "bogus"); !errors.Is(err, oidc.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}

		id := &tenantkit.Identity{TenantID: "acme", UserID: "u1", Username: "alice", Roles: []string{"admin"}}
		token, err := s.CreateSession(ctx, id, time.Hour)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if token == "" {
			t.Fatal("expected non-empty token")
		}

		got, err := s.GetSession(ctx, token)
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if got.TenantID != "acme" || got.UserID != "u1" || got.Username != "alice" {
			t.Fatalf("got %+v", got)
		}
		if len(got.Roles) != 1 || got.Roles[0] != "admin" {
			t.Fatalf("roles = %v", got.Roles)
		}

		if err := s.DeleteSession(ctx, token); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		if _, err := s.GetSession(ctx, token); !errors.Is(err, oidc.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound after delete", err)
		}

		// Deleting an already-deleted/unknown token is not an error.
		if err := s.DeleteSession(ctx, token); err != nil {
			t.Fatalf("DeleteSession on already-deleted token: %v", err)
		}
	})

	t.Run("Expiry", func(t *testing.T) {
		id := &tenantkit.Identity{TenantID: "acme", UserID: "u1"}
		token, err := s.CreateSession(ctx, id, -time.Second) // already expired
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if _, err := s.GetSession(ctx, token); !errors.Is(err, oidc.ErrExpired) {
			t.Fatalf("got %v, want ErrExpired", err)
		}
	})

	t.Run("StoredIdentityIsIsolatedFromCaller", func(t *testing.T) {
		id := &tenantkit.Identity{TenantID: "acme", UserID: "u2", Roles: []string{"member"}}
		token, err := s.CreateSession(ctx, id, time.Hour)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		// Mutating the caller's Identity (and its Roles backing array)
		// after CreateSession must not affect the stored copy.
		id.Username = "mutated"
		id.Roles[0] = "mutated"

		got, err := s.GetSession(ctx, token)
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if got.Username == "mutated" {
			t.Fatalf("store aliased the caller's Identity")
		}
		if got.Roles[0] == "mutated" {
			t.Fatalf("store aliased the caller's Roles backing array")
		}

		// Mutating what GetSession returned must not affect a later Get.
		got.Roles[0] = "mutated-again"
		fresh, err := s.GetSession(ctx, token)
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if fresh.Roles[0] == "mutated-again" {
			t.Fatalf("store's copy was mutated by caller")
		}
	})
}

// TestEphemeralStore runs a battery of subtests against s. Pass a
// fresh, empty store.
func TestEphemeralStore(t *testing.T, s oidc.EphemeralStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("PutTake", func(t *testing.T) {
		if _, err := s.Take(ctx, "bogus"); !errors.Is(err, oidc.ErrNotFound) {
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
		if _, err := s.Take(ctx, "tok1"); !errors.Is(err, oidc.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound on replayed Take", err)
		}
	})

	t.Run("Expiry", func(t *testing.T) {
		if err := s.Put(ctx, "tok2", []byte("payload"), -time.Second); err != nil { // already expired
			t.Fatalf("Put: %v", err)
		}
		if _, err := s.Take(ctx, "tok2"); !errors.Is(err, oidc.ErrExpired) {
			t.Fatalf("got %v, want ErrExpired", err)
		}
		// Still single-use even though it was expired.
		if _, err := s.Take(ctx, "tok2"); !errors.Is(err, oidc.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound on replayed Take", err)
		}
	})
}
```

- [ ] **Step 5: Create `identity/oidc/memstore/memstore.go`**

```go
// Package memstore is an in-memory implementation of identity/oidc's
// storage interfaces. It exists for tests -- both tenantkit's own and a
// consumer's -- not as a production backend: nothing is persisted, and
// every method takes a single mutex.
package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity/oidc"
	"github.com/TURNERO/tenantkit/store"
)

// Store is an in-memory oidc.SessionStore and oidc.EphemeralStore.
type Store struct {
	mu sync.Mutex

	sessions  map[string]sessionRecord
	ephemeral map[string]ephemeralRecord
}

type sessionRecord struct {
	identity *tenantkit.Identity
	expires  time.Time
}

type ephemeralRecord struct {
	payload []byte
	expires time.Time
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		sessions:  make(map[string]sessionRecord),
		ephemeral: make(map[string]ephemeralRecord),
	}
}

var (
	_ oidc.SessionStore   = (*Store)(nil)
	_ oidc.EphemeralStore = (*Store)(nil)
)

func cloneIdentity(id *tenantkit.Identity) *tenantkit.Identity {
	cp := *id
	cp.Roles = append([]string(nil), id.Roles...)
	return &cp
}

func (s *Store) CreateSession(ctx context.Context, id *tenantkit.Identity, ttl time.Duration) (string, error) {
	token, err := store.GenerateSecret()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = sessionRecord{identity: cloneIdentity(id), expires: time.Now().Add(ttl)}
	return token, nil
}

func (s *Store) GetSession(ctx context.Context, token string) (*tenantkit.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[token]
	if !ok {
		return nil, oidc.ErrNotFound
	}
	if time.Now().After(rec.expires) {
		return nil, oidc.ErrExpired
	}
	return cloneIdentity(rec.identity), nil
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
		return nil, oidc.ErrNotFound
	}
	delete(s.ephemeral, token) // single-use regardless of outcome
	if time.Now().After(rec.expires) {
		return nil, oidc.ErrExpired
	}
	return rec.payload, nil
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./identity/oidc/... -v`
Expected: PASS, all tests in `identity/oidc/memstore`.

- [ ] **Step 7: Run `go vet` and commit**

```bash
go vet ./...
git add identity/oidc/store.go identity/oidc/errors.go identity/oidc/storetest/storetest.go identity/oidc/memstore/memstore.go identity/oidc/memstore/memstore_test.go
git commit -m "feat: add identity/oidc storage interfaces and in-memory reference impl"
```

---

### Task 2: Claims mapping

**Files:**
- Create: `identity/oidc/claims.go`
- Test: `identity/oidc/claims_test.go`

**Interfaces:**
- Consumes: `ErrInvalidToken` (Task 1), `tenantkit.Identity`, `tenantkit.ClaimsMapping` (foundation).
- Produces: `mapClaims(claims map[string]any, m tenantkit.ClaimsMapping) (*tenantkit.Identity, error)` -- unexported, used internally by Task 4's `FinishLogin`.

**Note on test package:** unlike every other test file in this plan, `claims_test.go` is white-box (`package oidc`, not `package oidc_test`) -- `mapClaims` is deliberately unexported (only `FinishLogin` ever calls it), so its test must be in the same package to call it directly. This is intentional, not a mistake to "fix" by exporting the function.

- [ ] **Step 1: Write the failing tests**

Create `identity/oidc/claims_test.go`:

```go
package oidc

import (
	"errors"
	"testing"

	"github.com/TURNERO/tenantkit"
)

func TestMapClaims_AllDefaults(t *testing.T) {
	claims := map[string]any{
		"tenant": "acme",
		"sub":    "user-123",
		"email":  "alice@acme.com",
		"roles":  []any{"admin", "member"},
	}
	id, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"})
	if err != nil {
		t.Fatalf("mapClaims: %v", err)
	}
	if id.TenantID != "acme" || id.UserID != "user-123" || id.Username != "alice@acme.com" {
		t.Fatalf("got %+v", id)
	}
	if len(id.Roles) != 2 || id.Roles[0] != "admin" || id.Roles[1] != "member" {
		t.Fatalf("roles = %v", id.Roles)
	}
}

func TestMapClaims_CustomClaimNames(t *testing.T) {
	claims := map[string]any{
		"org_id":       "acme",
		"user_uuid":    "u-999",
		"preferred_un": "alice",
	}
	id, err := mapClaims(claims, tenantkit.ClaimsMapping{
		TenantIDClaim: "org_id",
		UserIDClaim:   "user_uuid",
		UsernameClaim: "preferred_un",
	})
	if err != nil {
		t.Fatalf("mapClaims: %v", err)
	}
	if id.TenantID != "acme" || id.UserID != "u-999" || id.Username != "alice" {
		t.Fatalf("got %+v", id)
	}
	if id.Roles != nil {
		t.Fatalf("roles = %v, want nil (claim absent)", id.Roles)
	}
}

func TestMapClaims_MissingTenantClaim(t *testing.T) {
	claims := map[string]any{"sub": "user-123"}
	if _, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestMapClaims_MissingUserIDClaim(t *testing.T) {
	claims := map[string]any{"tenant": "acme"}
	if _, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestMapClaims_MissingUsernameAndRolesClaimsOK(t *testing.T) {
	claims := map[string]any{"tenant": "acme", "sub": "user-123"}
	id, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"})
	if err != nil {
		t.Fatalf("mapClaims: %v", err)
	}
	if id.Username != "" {
		t.Fatalf("Username = %q, want empty", id.Username)
	}
	if id.Roles != nil {
		t.Fatalf("Roles = %v, want nil", id.Roles)
	}
}

func TestMapClaims_MalformedRolesClaimRejected(t *testing.T) {
	claims := map[string]any{"tenant": "acme", "sub": "user-123", "roles": "not-an-array"}
	if _, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestMapClaims_RolesArrayWithNonStringElementRejected(t *testing.T) {
	claims := map[string]any{"tenant": "acme", "sub": "user-123", "roles": []any{"admin", 42}}
	if _, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestMapClaims_TenantIDWrongTypeRejected(t *testing.T) {
	claims := map[string]any{"tenant": 12345, "sub": "user-123"}
	if _, err := mapClaims(claims, tenantkit.ClaimsMapping{TenantIDClaim: "tenant"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./identity/oidc/... -v`
Expected: FAIL -- `undefined: mapClaims` (the function doesn't exist yet).

- [ ] **Step 3: Create `identity/oidc/claims.go`**

```go
package oidc

import (
	"fmt"

	"github.com/TURNERO/tenantkit"
)

// mapClaims maps a verified ID token's claims to a tenantkit.Identity,
// applying m's defaults: UserIDClaim to "sub", UsernameClaim to
// "email", RolesClaim to "roles". TenantIDClaim and the resolved
// user-ID claim are required -- a missing or wrong-type value is
// ErrInvalidToken. Username/Roles degrade gracefully (empty
// string/nil slice) if their claim is simply absent, since not every
// IdP or scope grants them, but a present-and-malformed roles claim
// (not a JSON array of strings) is still rejected rather than
// silently ignored.
func mapClaims(claims map[string]any, m tenantkit.ClaimsMapping) (*tenantkit.Identity, error) {
	userIDClaim := m.UserIDClaim
	if userIDClaim == "" {
		userIDClaim = "sub"
	}
	usernameClaim := m.UsernameClaim
	if usernameClaim == "" {
		usernameClaim = "email"
	}
	rolesClaim := m.RolesClaim
	if rolesClaim == "" {
		rolesClaim = "roles"
	}

	tenantID, ok := claims[m.TenantIDClaim].(string)
	if !ok || tenantID == "" {
		return nil, fmt.Errorf("tenantkit/identity/oidc: missing/invalid %q claim: %w", m.TenantIDClaim, ErrInvalidToken)
	}
	userID, ok := claims[userIDClaim].(string)
	if !ok || userID == "" {
		return nil, fmt.Errorf("tenantkit/identity/oidc: missing/invalid %q claim: %w", userIDClaim, ErrInvalidToken)
	}
	username, _ := claims[usernameClaim].(string) // optional: falls back to "" rather than failing

	var roles []string
	if raw, ok := claims[rolesClaim]; ok {
		arr, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("tenantkit/identity/oidc: %q claim is not an array: %w", rolesClaim, ErrInvalidToken)
		}
		for _, v := range arr {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("tenantkit/identity/oidc: %q claim contains a non-string element: %w", rolesClaim, ErrInvalidToken)
			}
			roles = append(roles, s)
		}
	}

	return &tenantkit.Identity{TenantID: tenantID, UserID: userID, Username: username, Roles: roles}, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./identity/oidc/... -v`
Expected: PASS, all `TestMapClaims_*` tests in `identity/oidc`.

- [ ] **Step 5: Run `go vet` and commit**

```bash
go vet ./...
git add identity/oidc/claims.go identity/oidc/claims_test.go
git commit -m "feat: add identity/oidc claims-to-Identity mapping"
```

---

### Task 3: `OIDC` type, provider-client cache, `BeginLogin`, `BeginLoginByDomain`

**Files:**
- Create: `identity/oidc/oidc.go`
- Create: `identity/oidc/begin.go`
- Test: `identity/oidc/oidc_test.go`

**Interfaces:**
- Consumes: `oidc.SessionStore`/`EphemeralStore`/`ErrUnknownProvider` (Task 1), `store.OIDCProviderStore`/`store.ErrNotFound`/`store.GenerateSecret` (foundation), `tenantkit.OIDCProvider`/`tenantkit.ClaimsMapping` (foundation).
- Produces: `oidc.Config`, `oidc.OIDC`, `oidc.New(...) (*OIDC, error)`, `(*OIDC).BeginLogin`, `(*OIDC).BeginLoginByDomain`. Also produces the `newTestOIDC(t) (o *oidc.OIDC, providers store.OIDCProviderStore, oidcStore *oidcmem.Store)` test helper in `oidc_test.go`, which Tasks 4-5's tests reuse.

**Do not add** a compile-time `var _ identity.IdentityProvider = (*OIDC)(nil)` assertion in this task -- `Authenticate` isn't defined until Task 5. Placing it here would not compile (this exact sequencing mistake happened once already in `identity/local`'s plan and had to be fixed mid-implementation; this plan places the assertion correctly in Task 5 from the start).

- [ ] **Step 1: Add the go-oidc and oauth2 dependencies**

Run from the repo root:

```bash
go get github.com/coreos/go-oidc/v3@v3.20.0
go get golang.org/x/oauth2@v0.36.0
```

Expected: `go.mod` gains `require github.com/coreos/go-oidc/v3 v3.20.0` and `require golang.org/x/oauth2 v0.36.0`, plus a lightweight indirect dependency (`cloud.google.com/go/compute/metadata`, used by `oauth2` for GCE metadata support, harmless and never invoked outside a GCE environment). No other transitive dependencies -- verified in scratch.

- [ ] **Step 2: Write the failing tests**

Create `identity/oidc/oidc_test.go`:

```go
package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity/oidc"
	oidcmem "github.com/TURNERO/tenantkit/identity/oidc/memstore"
	"github.com/TURNERO/tenantkit/store"
	"github.com/TURNERO/tenantkit/store/memstore"
)

// newTestOIDC returns an OIDC instance wired to fresh in-memory stores,
// plus the OIDCProviderStore (for registering providers) and the
// identity/oidc memstore.Store (for seeding sessions/ephemeral data
// directly, bypassing the full login ceremony). Reused by Tasks 4-5's
// tests.
func newTestOIDC(t *testing.T) (o *oidc.OIDC, providers store.OIDCProviderStore, oidcStore *oidcmem.Store) {
	t.Helper()
	providers = memstore.New()
	oidcStore = oidcmem.New()
	o, err := oidc.New(oidc.Config{
		RedirectURL: "https://app.example.com/callback",
		SessionTTL:  time.Hour,
	}, providers, oidcStore, oidcStore)
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	return o, providers, oidcStore
}

// newFakeDiscoveryServer serves just enough of an OIDC discovery
// document and an empty JWKS for oidc.NewProvider to succeed. It never
// issues or verifies tokens -- BeginLogin/BeginLoginByDomain only need
// discovery to succeed to build a provider client, they never exchange
// a code or verify anything (that's Task 4's FinishLogin, which uses
// its own more complete fake IdP in finish_test.go).
func newFakeDiscoveryServer(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	var issuerURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":                                issuerURL,
			"authorization_endpoint":                issuerURL + "/authorize",
			"token_endpoint":                        issuerURL + "/token",
			"jwks_uri":                              issuerURL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	issuerURL = server.URL
	return issuerURL
}

func TestNew_RequiresRedirectURL(t *testing.T) {
	providers := memstore.New()
	oidcStore := oidcmem.New()
	if _, err := oidc.New(oidc.Config{}, providers, oidcStore, oidcStore); err == nil {
		t.Fatal("expected error for empty RedirectURL")
	}
}

func TestBeginLogin(t *testing.T) {
	ctx := context.Background()
	o, providers, _ := newTestOIDC(t)
	issuerURL := newFakeDiscoveryServer(t)

	if err := providers.CreateOIDCProvider(ctx, &tenantkit.OIDCProvider{
		TenantID:      "acme",
		ProviderID:    "okta",
		Name:          "Acme Okta",
		IssuerURL:     issuerURL,
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		Scopes:        []string{"email"},
		ClaimsMapping: tenantkit.ClaimsMapping{TenantIDClaim: "tenant"},
	}); err != nil {
		t.Fatalf("CreateOIDCProvider: %v", err)
	}

	redirectURL, err := o.BeginLogin(ctx, "acme", "okta")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}
	q := parsed.Query()
	if got := q.Get("client_id"); got != "test-client" {
		t.Errorf("client_id = %q", got)
	}
	if q.Get("state") == "" {
		t.Error("expected non-empty state")
	}
	if q.Get("nonce") == "" {
		t.Error("expected non-empty nonce")
	}
	if got := q.Get("redirect_uri"); got != "https://app.example.com/callback" {
		t.Errorf("redirect_uri = %q", got)
	}
}

func TestBeginLogin_UnknownProvider(t *testing.T) {
	ctx := context.Background()
	o, _, _ := newTestOIDC(t)
	if _, err := o.BeginLogin(ctx, "acme", "nonexistent"); !errors.Is(err, oidc.ErrUnknownProvider) {
		t.Fatalf("got %v, want ErrUnknownProvider", err)
	}
}

func TestBeginLoginByDomain(t *testing.T) {
	ctx := context.Background()
	o, providers, _ := newTestOIDC(t)
	issuerURL := newFakeDiscoveryServer(t)

	if err := providers.CreateOIDCProvider(ctx, &tenantkit.OIDCProvider{
		TenantID:      "acme",
		ProviderID:    "okta",
		Name:          "Acme Okta",
		IssuerURL:     issuerURL,
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		Domains:       []string{"acme.com"},
		ClaimsMapping: tenantkit.ClaimsMapping{TenantIDClaim: "tenant"},
	}); err != nil {
		t.Fatalf("CreateOIDCProvider: %v", err)
	}

	redirectURL, err := o.BeginLoginByDomain(ctx, "acme.com")
	if err != nil {
		t.Fatalf("BeginLoginByDomain: %v", err)
	}
	if redirectURL == "" {
		t.Fatal("expected non-empty redirect URL")
	}
}

func TestBeginLoginByDomain_UnknownDomain(t *testing.T) {
	ctx := context.Background()
	o, _, _ := newTestOIDC(t)
	if _, err := o.BeginLoginByDomain(ctx, "nonexistent.com"); !errors.Is(err, oidc.ErrUnknownProvider) {
		t.Fatalf("got %v, want ErrUnknownProvider", err)
	}
}

func TestBeginLogin_CachesProviderClient(t *testing.T) {
	ctx := context.Background()
	o, providers, _ := newTestOIDC(t)
	issuerURL := newFakeDiscoveryServer(t)

	if err := providers.CreateOIDCProvider(ctx, &tenantkit.OIDCProvider{
		TenantID:      "acme",
		ProviderID:    "okta",
		IssuerURL:     issuerURL,
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		ClaimsMapping: tenantkit.ClaimsMapping{TenantIDClaim: "tenant"},
	}); err != nil {
		t.Fatalf("CreateOIDCProvider: %v", err)
	}

	// First call builds and caches the provider client (a real
	// discovery round trip against the fake server). Deleting the
	// registration afterward and confirming a second BeginLogin call
	// still succeeds proves the second call used the cached client
	// rather than re-resolving from the store -- an incorrect
	// (non-caching, or wrongly-evicting) implementation would fail
	// this with ErrUnknownProvider.
	if _, err := o.BeginLogin(ctx, "acme", "okta"); err != nil {
		t.Fatalf("first BeginLogin: %v", err)
	}
	if err := providers.DeleteOIDCProvider(ctx, "acme", "okta"); err != nil {
		t.Fatalf("DeleteOIDCProvider: %v", err)
	}
	if _, err := o.BeginLogin(ctx, "acme", "okta"); err != nil {
		t.Fatalf("second BeginLogin (should use cache, provider was deleted): %v", err)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./identity/oidc/... -v`
Expected: FAIL -- `undefined: oidc.Config` / `undefined: oidc.New` (the type doesn't exist yet).

- [ ] **Step 4: Create `identity/oidc/oidc.go`**

```go
package oidc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	goidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"
)

// Config configures an OIDC identity provider.
type Config struct {
	// RedirectURL is fixed for the whole service -- registered
	// identically with every tenant's IdP (a callback route your
	// service's own router serves, e.g.
	// "https://app.example.com/auth/callback").
	RedirectURL string
	// SessionTTL is how long a session issued by FinishLogin stays valid.
	SessionTTL time.Duration
}

// OIDC satisfies identity.IdentityProvider via Authenticate (see
// session.go).
type OIDC struct {
	cfg       Config
	providers store.OIDCProviderStore
	sessions  SessionStore
	ephemeral EphemeralStore

	mu      sync.Mutex
	clients map[tenantProviderKey]*providerClient // lazily populated, never evicted -- see New's doc comment
}

type tenantProviderKey struct {
	tenantID   string
	providerID string
}

// providerClient is what resolveProviderClient (lazily) builds from a
// tenantkit.OIDCProvider registration: everything needed to run the
// OAuth2/OIDC ceremony for that one (tenant, provider) pair without
// hitting the store again.
type providerClient struct {
	oauth2Config *oauth2.Config
	verifier     *goidc.IDTokenVerifier
	mapping      tenantkit.ClaimsMapping
}

// New returns an OIDC identity provider. It returns an error if
// cfg.RedirectURL is empty.
//
// Each registered (tenant, provider)'s OAuth2/OIDC client is built
// lazily on first use and cached for the lifetime of the returned
// *OIDC -- never evicted or refreshed. go-oidc's provider discovery
// (fetching /.well-known/openid-configuration) and JWKS setup is a
// real network round-trip that shouldn't happen on every login.
// Trade-off accepted explicitly: if an admin updates a tenant's
// provider registration (rotates a client secret, changes issuer) via
// the CLI while this process is running, it keeps using the stale
// cached config until restart.
func New(cfg Config, providers store.OIDCProviderStore, sessions SessionStore, ephemeral EphemeralStore) (*OIDC, error) {
	if cfg.RedirectURL == "" {
		return nil, fmt.Errorf("tenantkit/identity/oidc: RedirectURL is required")
	}
	return &OIDC{
		cfg:       cfg,
		providers: providers,
		sessions:  sessions,
		ephemeral: ephemeral,
		clients:   make(map[tenantProviderKey]*providerClient),
	}, nil
}

// resolveProviderClient returns the cached *providerClient for
// (tenantID, providerID), building and caching it on a miss. Shared by
// BeginLogin (via BeginLogin/BeginLoginByDomain) and FinishLogin.
func (o *OIDC) resolveProviderClient(ctx context.Context, tenantID, providerID string) (*providerClient, error) {
	key := tenantProviderKey{tenantID: tenantID, providerID: providerID}

	o.mu.Lock()
	client, ok := o.clients[key]
	o.mu.Unlock()
	if ok {
		return client, nil
	}

	p, err := o.providers.GetOIDCProvider(ctx, tenantID, providerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("tenantkit/identity/oidc: look up provider: %w", ErrUnknownProvider)
		}
		return nil, fmt.Errorf("tenantkit/identity/oidc: look up provider: %w", err)
	}

	provider, err := goidc.NewProvider(ctx, p.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("tenantkit/identity/oidc: discover provider %s/%s: %w", tenantID, providerID, err)
	}

	client = &providerClient{
		oauth2Config: &oauth2.Config{
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			RedirectURL:  o.cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       append([]string{goidc.ScopeOpenID}, p.Scopes...),
		},
		verifier: provider.Verifier(&goidc.Config{ClientID: p.ClientID}),
		mapping:  p.ClaimsMapping,
	}

	// Benign race: two concurrent callers resolving the same missing
	// key both perform discovery and one's result overwrites the
	// other's -- both succeed, last write wins, no corruption. Not
	// worth a per-key sync.Once for v1.
	o.mu.Lock()
	o.clients[key] = client
	o.mu.Unlock()
	return client, nil
}
```

- [ ] **Step 5: Create `identity/oidc/begin.go`**

```go
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/TURNERO/tenantkit/store"
)

// loginCeremonyTTL bounds how long a login ceremony (the OAuth2
// state/nonce pair between BeginLogin and FinishLogin) has to complete
// before its EphemeralStore entry expires. Not exposed via Config -- 5
// minutes comfortably covers a real browser/IdP redirect round-trip,
// matching identity/local's webauthnCeremonyTTL precedent; no evidence
// yet that any consumer needs this tunable.
const loginCeremonyTTL = 5 * time.Minute

type loginCeremony struct {
	TenantID   string `json:"tenant_id"`
	ProviderID string `json:"provider_id"`
	Nonce      string `json:"nonce"`
}

// BeginLogin starts an OAuth2 Authorization Code login against
// tenantID's registered providerID. It returns the URL to redirect the
// browser to; the consumer's login handler performs the redirect.
func (o *OIDC) BeginLogin(ctx context.Context, tenantID, providerID string) (string, error) {
	client, err := o.resolveProviderClient(ctx, tenantID, providerID)
	if err != nil {
		return "", err
	}

	state, err := store.GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/oidc: generate state: %w", err)
	}
	nonce, err := store.GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/oidc: generate nonce: %w", err)
	}

	payload, err := json.Marshal(loginCeremony{TenantID: tenantID, ProviderID: providerID, Nonce: nonce})
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/oidc: encode login ceremony: %w", err)
	}
	if err := o.ephemeral.Put(ctx, state, payload, loginCeremonyTTL); err != nil {
		return "", fmt.Errorf("tenantkit/identity/oidc: save login ceremony: %w", err)
	}

	return client.oauth2Config.AuthCodeURL(state, goidc.Nonce(nonce)), nil
}

// BeginLoginByDomain looks up which (tenantID, providerID) domain is
// registered to via store.OIDCProviderStore.GetOIDCProviderByDomain,
// then starts the same ceremony as BeginLogin. Convenience for an
// identifier-first ("enter your email") login page.
func (o *OIDC) BeginLoginByDomain(ctx context.Context, domain string) (string, error) {
	p, err := o.providers.GetOIDCProviderByDomain(ctx, domain)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", fmt.Errorf("tenantkit/identity/oidc: look up provider by domain: %w", ErrUnknownProvider)
		}
		return "", fmt.Errorf("tenantkit/identity/oidc: look up provider by domain: %w", err)
	}
	return o.BeginLogin(ctx, p.TenantID, p.ProviderID)
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./identity/oidc/... -v`
Expected: PASS, all tests in `identity/oidc` and `identity/oidc/memstore`.

- [ ] **Step 7: Run `go mod tidy`, `go vet`, and commit**

```bash
go mod tidy
go vet ./...
git add go.mod go.sum identity/oidc/oidc.go identity/oidc/begin.go identity/oidc/oidc_test.go
git commit -m "feat: add identity/oidc OIDC type, provider-client cache, and BeginLogin"
```

---

### Task 4: `FinishLogin`

**Files:**
- Create: `identity/oidc/finish.go`
- Test: `identity/oidc/finish_test.go`

**Interfaces:**
- Consumes: `oidc.OIDC`/`Config`/`New`/`resolveProviderClient` (Task 3), `loginCeremony`/`loginCeremonyTTL` (Task 3), `mapClaims` (Task 2), `oidc.ErrNotFound`/`ErrExpired`/`ErrInvalidToken` (Task 1), `newTestOIDC` test helper (Task 3's `oidc_test.go`).
- Produces: `(*OIDC).FinishLogin`. Consumed by nothing else in this plan -- Task 5's `Authenticate` validates sessions `FinishLogin` already created, it doesn't call `FinishLogin` itself.

**Note on test coverage:** `finish_test.go` defines its own complete fake IdP (`fakeIdP`, with discovery, JWKS, *and* a working token endpoint that signs real ID tokens) -- separate from Task 3's `newFakeDiscoveryServer`, which only serves discovery/JWKS and is never extended here. Keeping them separate means each task's test file only contains what that task's own tests actually exercise, rather than Task 3 carrying token-signing code it never calls.

- [ ] **Step 1: Add the go-jose test dependency**

```bash
go get github.com/go-jose/go-jose/v4@v4.1.4
```

Expected: `go.mod` gains `require github.com/go-jose/go-jose/v4 v4.1.4`. It's only ever imported from `_test.go` files, so it never reaches a consumer's build -- same reasoning already established for `store/sqlite`'s driver dependency and `identity/local`'s `descope/virtualwebauthn`.

- [ ] **Step 2: Write the failing tests**

Create `identity/oidc/finish_test.go`:

```go
package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity/oidc"
	oidcmem "github.com/TURNERO/tenantkit/identity/oidc/memstore"
	"github.com/TURNERO/tenantkit/store/memstore"
	"github.com/go-jose/go-jose/v4"
)

// fakeIdP serves a minimal OIDC discovery document, JWKS endpoint, and
// token endpoint, and signs ID tokens in-process -- so FinishLogin's
// tests never hit a real IdP over the network.
type fakeIdP struct {
	server     *httptest.Server
	key        *rsa.PrivateKey
	kid        string
	nextClaims map[string]any // set by the test before calling FinishLogin
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	f := &fakeIdP{key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/jwks", f.handleJWKS)
	mux.HandleFunc("/token", f.handleToken)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIdP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                f.server.URL,
		"authorization_endpoint":                f.server.URL + "/authorize",
		"token_endpoint":                        f.server.URL + "/token",
		"jwks_uri":                              f.server.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (f *fakeIdP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := jose.JSONWebKey{Key: &f.key.PublicKey, KeyID: f.kid, Algorithm: "RS256", Use: "sig"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

func (f *fakeIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if f.nextClaims == nil {
		http.Error(w, "no claims configured for this test", http.StatusInternalServerError)
		return
	}
	idToken, err := f.signIDToken(f.nextClaims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (f *fakeIdP) signIDToken(claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"kid": f.kid},
	})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return sig.CompactSerialize()
}

// newTestOIDCWithIdP wires an OIDC instance to idp and registers a
// single (acme, okta) provider pointing at it.
func newTestOIDCWithIdP(t *testing.T, idp *fakeIdP) *oidc.OIDC {
	t.Helper()
	providers := memstore.New()
	oidcStore := oidcmem.New()
	o, err := oidc.New(oidc.Config{
		RedirectURL: "https://app.example.com/callback",
		SessionTTL:  time.Hour,
	}, providers, oidcStore, oidcStore)
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	if err := providers.CreateOIDCProvider(context.Background(), &tenantkit.OIDCProvider{
		TenantID:      "acme",
		ProviderID:    "okta",
		IssuerURL:     idp.server.URL,
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		ClaimsMapping: tenantkit.ClaimsMapping{TenantIDClaim: "tenant"},
	}); err != nil {
		t.Fatalf("CreateOIDCProvider: %v", err)
	}
	return o
}

// beginAndExtractState runs BeginLogin and pulls state/nonce back out
// of the redirect URL it returns, so the test can configure the fake
// IdP's next ID token to use the matching nonce before simulating the
// callback.
func beginAndExtractState(t *testing.T, o *oidc.OIDC) (state, nonce string) {
	t.Helper()
	redirectURL, err := o.BeginLogin(context.Background(), "acme", "okta")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}
	return parsed.Query().Get("state"), parsed.Query().Get("nonce")
}

func TestFinishLogin(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, nonce := beginAndExtractState(t, o)

	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss":    idp.server.URL,
		"sub":    "user-123",
		"aud":    "test-client",
		"exp":    now.Add(time.Hour).Unix(),
		"iat":    now.Unix(),
		"nonce":  nonce,
		"email":  "alice@acme.com",
		"tenant": "acme",
		"roles":  []string{"admin", "member"},
	}

	identity, sessionToken, err := o.FinishLogin(ctx, state, "fake-auth-code")
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if identity.TenantID != "acme" || identity.UserID != "user-123" || identity.Username != "alice@acme.com" {
		t.Fatalf("got %+v", identity)
	}
	if len(identity.Roles) != 2 || identity.Roles[0] != "admin" || identity.Roles[1] != "member" {
		t.Fatalf("roles = %v", identity.Roles)
	}
	if sessionToken == "" {
		t.Fatal("expected non-empty session token")
	}
}

func TestFinishLogin_ReplayedStateFails(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, nonce := beginAndExtractState(t, o)
	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss": idp.server.URL, "sub": "user-123", "aud": "test-client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"nonce": nonce, "tenant": "acme",
	}

	if _, _, err := o.FinishLogin(ctx, state, "fake-auth-code"); err != nil {
		t.Fatalf("first FinishLogin: %v", err)
	}
	if _, _, err := o.FinishLogin(ctx, state, "fake-auth-code"); !errors.Is(err, oidc.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound on replayed state", err)
	}
}

func TestFinishLogin_NonceMismatchRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, _ := beginAndExtractState(t, o)
	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss": idp.server.URL, "sub": "user-123", "aud": "test-client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"nonce": "wrong-nonce", "tenant": "acme",
	}

	if _, _, err := o.FinishLogin(ctx, state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestFinishLogin_TenantClaimMismatchRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, nonce := beginAndExtractState(t, o)
	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss": idp.server.URL, "sub": "user-123", "aud": "test-client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"nonce": nonce, "tenant": "some-other-tenant", // ceremony was started for "acme"
	}

	if _, _, err := o.FinishLogin(ctx, state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestFinishLogin_MalformedRolesClaimRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, nonce := beginAndExtractState(t, o)
	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss": idp.server.URL, "sub": "user-123", "aud": "test-client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"nonce": nonce, "tenant": "acme", "roles": "not-an-array",
	}

	if _, _, err := o.FinishLogin(ctx, state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestFinishLogin_ExpiredTokenRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	state, nonce := beginAndExtractState(t, o)
	now := time.Now()
	idp.nextClaims = map[string]any{
		"iss": idp.server.URL, "sub": "user-123", "aud": "test-client",
		"exp": now.Add(-time.Hour).Unix(), "iat": now.Add(-2 * time.Hour).Unix(), // already expired
		"nonce": nonce, "tenant": "acme",
	}

	if _, _, err := o.FinishLogin(ctx, state, "fake-auth-code"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestFinishLogin_UnknownStateFails(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	o := newTestOIDCWithIdP(t, idp)

	if _, _, err := o.FinishLogin(ctx, "bogus-state", "fake-auth-code"); !errors.Is(err, oidc.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./identity/oidc/... -v`
Expected: FAIL -- `o.FinishLogin undefined` (the method doesn't exist yet).

- [ ] **Step 4: Create `identity/oidc/finish.go`**

```go
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TURNERO/tenantkit"
)

// FinishLogin completes a login ceremony started by BeginLogin or
// BeginLoginByDomain. state and code are exactly what your callback
// handler receives on the query string. On success it returns the
// mapped Identity (e.g. to render a welcome page) and a session token
// (to set via SetSessionCookie).
func (o *OIDC) FinishLogin(ctx context.Context, state, code string) (*tenantkit.Identity, string, error) {
	payload, err := o.ephemeral.Take(ctx, state)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
			return nil, "", err
		}
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: load login ceremony: %w", err)
	}
	var ceremony loginCeremony
	if err := json.Unmarshal(payload, &ceremony); err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: decode login ceremony: %w", err)
	}

	client, err := o.resolveProviderClient(ctx, ceremony.TenantID, ceremony.ProviderID)
	if err != nil {
		return nil, "", err
	}

	oauth2Token, err := client.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: exchange code: %w", err)
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: token response has no id_token: %w", ErrInvalidToken)
	}

	idToken, err := client.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: verify id_token: %w", ErrInvalidToken)
	}
	if idToken.Nonce != ceremony.Nonce {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: nonce mismatch: %w", ErrInvalidToken)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: decode claims: %w", err)
	}
	identity, err := mapClaims(claims, client.mapping)
	if err != nil {
		return nil, "", err
	}
	if identity.TenantID != ceremony.TenantID {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: token tenant claim does not match ceremony tenant: %w", ErrInvalidToken)
	}

	token, err := o.sessions.CreateSession(ctx, identity, o.cfg.SessionTTL)
	if err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: create session: %w", err)
	}
	return identity, token, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./identity/oidc/... -v`
Expected: PASS, all tests in `identity/oidc` and `identity/oidc/memstore`, including the full `TestFinishLogin` registration+login round trip against a real simulated IdP (not a mock).

- [ ] **Step 6: Run `go mod tidy`, `go vet`, and commit**

```bash
go mod tidy
go vet ./...
git add go.mod go.sum identity/oidc/finish.go identity/oidc/finish_test.go
git commit -m "feat: add identity/oidc FinishLogin"
```

---

### Task 5: Session validation (`identity.IdentityProvider`), cookie helpers, and `Logout`

**Files:**
- Create: `identity/oidc/session.go`
- Test: `identity/oidc/session_test.go`

**Interfaces:**
- Consumes: `oidc.OIDC`/`Config`/`New` (Task 3), `oidc.ErrNotFound`/`ErrExpired` (Task 1), `resolve.Source` (foundation), `newTestOIDC` test helper (Task 3's `oidc_test.go`).
- Produces: `(*OIDC).Authenticate` (satisfies `identity.IdentityProvider`), `(*OIDC).Logout`, `oidc.SessionCookieName`, `oidc.SetSessionCookie`, `oidc.ClearSessionCookie`. This is the last task in the plan.

- [ ] **Step 1: Write the failing tests**

Create `identity/oidc/session_test.go`:

```go
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./identity/oidc/... -v`
Expected: FAIL -- `o.Authenticate undefined` and `oidc.SetSessionCookie undefined` (the method/functions don't exist yet).

- [ ] **Step 3: Create `identity/oidc/session.go`**

```go
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./identity/oidc/... -v`
Expected: PASS, all tests in `identity/oidc` and `identity/oidc/memstore`.

- [ ] **Step 5: Run `go vet`, `go build`, and commit**

```bash
go vet ./...
go build ./...
git add identity/oidc/session.go identity/oidc/session_test.go
git commit -m "feat: add identity/oidc session validation, cookie helpers, and Logout"
```

---

## What's next

After all 5 tasks are complete and individually reviewed, per `superpowers:subagent-driven-development`: dispatch a final whole-branch review (most capable model), then `superpowers:finishing-a-development-branch` to merge. Sync any real findings back into this plan document and `docs/superpowers/specs/2026-07-23-identity-oidc-design.md` before merging -- including the `Logout` addition already noted in the Global Constraints section, which should be added to the spec regardless of whether the review finds anything else.

The repository now requires all merges to `master` go through a PR with a passing `build-and-test` CI check (branch protection, added after the Admin/identity-local plans landed) -- the finishing step must open a PR and wait for CI rather than pushing directly to `master`.

Deferred follow-ups, to be tracked as new issues once this lands:
- A persistent (SQLite) `SessionStore`/`EphemeralStore` backend for `identity/oidc` -- same sequencing `identity/local/sqlite` followed after `identity/local`.
- Token refresh, RP-initiated logout, back-channel logout -- explicitly out of scope per the design spec.
- Provider-client cache invalidation (currently never evicted in v1) -- if this proves painful in practice, revisit with a TTL or a store-change notification mechanism.
