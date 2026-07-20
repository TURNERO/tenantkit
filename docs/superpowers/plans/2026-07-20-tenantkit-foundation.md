# tenantkit Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up tenantkit's foundation -- the Go module, core types, request-context helpers, the four store interfaces (including mTLS client-cert support alongside API keys), a reusable in-memory reference store, an interface-conformance test suite, and the crypto/validation helper functions everything else depends on.

**Architecture:** A single new Go module (`github.com/TURNERO/tenantkit`), stdlib-only. Core types and context helpers live in the root package; storage is interfaces-only (`store`), proven by a conformance-test suite (`storetest`) that both tenantkit's own in-memory reference implementation (`store/memstore`) and any future consumer implementation can run against themselves.

**Tech Stack:** Go 1.23+, standard library only (`context`, `crypto/rand`, `crypto/sha256`, `encoding/base64`, `encoding/hex`, `regexp`, `sync`, `sort`, `errors`, `fmt`, `testing`). No third-party dependencies in this plan -- those arrive in later plans (`identity/local` needs `go-webauthn`/`bcrypt`, `identity/oidc` needs `go-oidc`/`oauth2`).

## Global Constraints

- Module path: `github.com/TURNERO/tenantkit`. Go directive: `go 1.23`.
- Store-agnostic: nothing in this module talks to a real database. `store/memstore` is an in-memory reference/test fixture, not a production backend, and its doc comment must say so.
- API keys are hashed with SHA-256 (`crypto/sha256`), never bcrypt -- these are high-entropy generated values, not human passwords (per the design spec's stated reasoning).
- Tenant IDs are restricted to `^[a-z0-9-]+$` (`store.ValidTenantID`) -- consumers commonly interpolate a tenant ID into store-specific identifiers (role names, policy names), so a conservative charset is enforced once here.
- Every store interface method's not-found/already-exists behavior is a sentinel error (`store.ErrNotFound`, `store.ErrAlreadyExists`) checked via `errors.Is`, never a string comparison or a typed error consumers would need to import a concrete type to detect.
- All persisted records exposed by a Get*/List* method are returned as copies (not the store's internal pointers) so a caller mutating the result can't corrupt the store's state out from under it -- this matters most for `memstore`, which is otherwise just a map.

---

### Task 1: Module scaffolding, core types, and context helpers

**Files:**
- Create: `go.mod`
- Create: `types.go`
- Create: `context.go`
- Test: `context_test.go`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `tenantkit.Tenant{ID, DisplayName, Active}`, `tenantkit.Identity{UserID, TenantID, Username, Roles}`, `tenantkit.APIKey{Hash, TenantID, UserID}`, `tenantkit.ClientCert{Fingerprint, TenantID, UserID}`, and `tenantkit.WithTenant`/`TenantFromContext`/`WithIdentity`/`IdentityFromContext`. Every later task in this plan (and every future plan) imports these.

- [ ] **Step 1: Initialize the Go module**

Run: `cd /home/rob/src/tenantkit && go mod init github.com/TURNERO/tenantkit`

Then open the generated `go.mod` and make sure the `go` directive reads `go 1.23` (edit it by hand if `go mod init` picked a different installed-toolchain version -- the directive is a floor, not a pin, so `1.23` is fine to build with a newer installed toolchain).

Expected `go.mod`:

```
module github.com/TURNERO/tenantkit

go 1.23
```

- [ ] **Step 2: Write the core types**

Create `types.go`:

```go
package tenantkit

// Tenant is a single tenant's record as tenantkit understands it. A
// consumer's store implementation may track additional fields of its
// own; tenantkit only needs these three.
type Tenant struct {
	ID          string
	DisplayName string
	Active      bool
}

// Identity is an authenticated user: the result of an IdentityProvider
// authenticating a request, or a record looked up directly via
// store.UserStore.
type Identity struct {
	UserID   string
	TenantID string
	Username string
	// Roles is opaque to tenantkit -- it's carried through for a
	// consumer's own authorization logic to interpret, never read or
	// written by tenantkit itself.
	Roles []string
}

// APIKey is a service or user credential used for tenant-scoped access.
// UserID is empty for a tenant-level key (e.g. a service ingestion
// credential not tied to any one person) and non-empty for a
// user-level key.
type APIKey struct {
	Hash     string
	TenantID string
	UserID   string
}

// ClientCert is an mTLS client-certificate credential used for
// tenant-scoped access, an alternative (or complement) to APIKey.
// Fingerprint is the SHA-256 hex digest of the DER-encoded cert -- not
// a secret, just an identifier; TLS itself already verified the cert
// against a CA before tenantkit ever sees the request. UserID is empty
// for a tenant-level cert, non-empty for a user-level cert.
type ClientCert struct {
	Fingerprint string
	TenantID    string
	UserID      string
}
```

This step has no test of its own -- these are plain data types with no
behavior to assert on. The context helpers in the next step are what
actually exercise them.

- [ ] **Step 3: Write the failing test for context helpers**

Create `context_test.go`:

```go
package tenantkit_test

import (
	"context"
	"testing"

	"github.com/TURNERO/tenantkit"
)

func TestWithTenant_TenantFromContext(t *testing.T) {
	tenant := &tenantkit.Tenant{ID: "acme", DisplayName: "Acme Corp", Active: true}
	ctx := tenantkit.WithTenant(context.Background(), tenant)

	got, ok := tenantkit.TenantFromContext(ctx)
	if !ok {
		t.Fatal("expected TenantFromContext to return ok=true")
	}
	if got != tenant {
		t.Errorf("TenantFromContext returned %+v, want %+v", got, tenant)
	}
}

func TestTenantFromContext_Missing(t *testing.T) {
	_, ok := tenantkit.TenantFromContext(context.Background())
	if ok {
		t.Error("expected ok=false when no tenant is in context")
	}
}

func TestWithIdentity_IdentityFromContext(t *testing.T) {
	id := &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice", Roles: []string{"admin"}}
	ctx := tenantkit.WithIdentity(context.Background(), id)

	got, ok := tenantkit.IdentityFromContext(ctx)
	if !ok {
		t.Fatal("expected IdentityFromContext to return ok=true")
	}
	if got != id {
		t.Errorf("IdentityFromContext returned %+v, want %+v", got, id)
	}
}

func TestIdentityFromContext_Missing(t *testing.T) {
	_, ok := tenantkit.IdentityFromContext(context.Background())
	if ok {
		t.Error("expected ok=false when no identity is in context")
	}
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `go test ./... -run 'TestWithTenant_TenantFromContext|TestTenantFromContext_Missing|TestWithIdentity_IdentityFromContext|TestIdentityFromContext_Missing' -v`

Expected: FAIL to compile -- `tenantkit.WithTenant`, `tenantkit.TenantFromContext`, `tenantkit.WithIdentity`, `tenantkit.IdentityFromContext` undefined.

- [ ] **Step 5: Implement the context helpers**

Create `context.go`:

```go
package tenantkit

import "context"

type ctxKey int

const (
	tenantCtxKey ctxKey = iota
	identityCtxKey
)

// WithTenant returns a copy of ctx carrying t, retrievable via
// TenantFromContext.
func WithTenant(ctx context.Context, t *Tenant) context.Context {
	return context.WithValue(ctx, tenantCtxKey, t)
}

// TenantFromContext returns the tenant previously attached via
// WithTenant, or ok=false if none was.
func TenantFromContext(ctx context.Context) (*Tenant, bool) {
	t, ok := ctx.Value(tenantCtxKey).(*Tenant)
	return t, ok
}

// WithIdentity returns a copy of ctx carrying id, retrievable via
// IdentityFromContext.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityCtxKey, id)
}

// IdentityFromContext returns the identity previously attached via
// WithIdentity, or ok=false if none was (e.g. pure API-key/service
// traffic with no per-user identity).
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityCtxKey).(*Identity)
	return id, ok
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `go test ./... -run 'TestWithTenant_TenantFromContext|TestTenantFromContext_Missing|TestWithIdentity_IdentityFromContext|TestIdentityFromContext_Missing' -v`

Expected: PASS, all 4 tests.

- [ ] **Step 7: Commit**

```bash
git add go.mod types.go context.go context_test.go
git commit -m "feat: add core types and request-context helpers

First piece of the tenantkit foundation (see
docs/superpowers/specs/2026-07-20-tenantkit-design.md). Tenant,
Identity, APIKey, and ClientCert are the shared vocabulary every other
package builds on; WithTenant/TenantFromContext and WithIdentity/
IdentityFromContext are how httpmw/grpcmw (a later plan) will pass a
resolved tenant and identity down to request handlers."
```

---

### Task 2: Store interfaces and in-memory reference store

**Files:**
- Create: `store/store.go`
- Create: `store/memstore/memstore.go`
- Test: `store/memstore/memstore_test.go`

**Interfaces:**
- Consumes: `tenantkit.Tenant`, `tenantkit.Identity`, `tenantkit.APIKey`, `tenantkit.ClientCert` (Task 1).
- Produces: `store.TenantStore`, `store.UserStore`, `store.APIKeyStore`, `store.ClientCertStore` interfaces; `store.ErrNotFound`, `store.ErrAlreadyExists` sentinel errors; `memstore.New() *memstore.Store`, a value satisfying all four interfaces. Task 3 (`storetest`) and Task 4 (`RotateAPIKey`'s test) both depend on `memstore.New()` existing with this exact signature.

- [ ] **Step 1: Write the failing tests**

Create `store/memstore/memstore_test.go`:

```go
package memstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"
	"github.com/TURNERO/tenantkit/store/memstore"
)

func TestStore_CreateAndGetTenant(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()

	want := &tenantkit.Tenant{ID: "acme", DisplayName: "Acme Corp", Active: true}
	if err := s.CreateTenant(ctx, want); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	got, err := s.GetTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if *got != *want {
		t.Errorf("GetTenant = %+v, want %+v", got, want)
	}
}

func TestStore_GetTenant_NotFound(t *testing.T) {
	s := memstore.New()
	_, err := s.GetTenant(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetTenant error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_CreateTenant_DuplicateFails(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	t1 := &tenantkit.Tenant{ID: "acme", DisplayName: "Acme Corp", Active: true}
	if err := s.CreateTenant(ctx, t1); err != nil {
		t.Fatalf("first CreateTenant: %v", err)
	}
	err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: "acme", DisplayName: "Dup", Active: true})
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("CreateTenant error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
	}
}

func TestStore_ListTenants(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: "beta", DisplayName: "Beta", Active: true}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: "acme", DisplayName: "Acme", Active: true}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	got, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(got) != 2 || got[0].ID != "acme" || got[1].ID != "beta" {
		t.Errorf("ListTenants = %+v, want [acme, beta] in order", got)
	}
}

func TestStore_DeactivateTenant(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: "acme", DisplayName: "Acme", Active: true}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	if err := s.DeactivateTenant(ctx, "acme"); err != nil {
		t.Fatalf("DeactivateTenant: %v", err)
	}
	got, err := s.GetTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Active {
		t.Error("expected tenant to be inactive after DeactivateTenant")
	}
}

func TestStore_DeactivateTenant_NotFound(t *testing.T) {
	s := memstore.New()
	err := s.DeactivateTenant(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("DeactivateTenant error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_CreateAndGetUser(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	want := &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice", Roles: []string{"admin"}}
	if err := s.CreateUser(ctx, want); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetUser(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.UserID != want.UserID || got.TenantID != want.TenantID || got.Username != want.Username {
		t.Errorf("GetUser = %+v, want %+v", got, want)
	}
}

func TestStore_GetUser_NotFound(t *testing.T) {
	s := memstore.New()
	_, err := s.GetUser(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetUser error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_GetUserByUsername(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetUserByUsername(ctx, "acme", "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.UserID != "u1" {
		t.Errorf("GetUserByUsername returned UserID %q, want u1", got.UserID)
	}
}

func TestStore_GetUserByUsername_ScopedToTenant(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err := s.GetUserByUsername(ctx, "globex", "alice")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetUserByUsername in wrong tenant error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_CreateUser_DuplicateUserIDFails(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "someoneelse"})
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("CreateUser duplicate UserID error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
	}
}

func TestStore_CreateUser_DuplicateUsernameInTenantFails(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u1", TenantID: "acme", Username: "alice"}); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "u2", TenantID: "acme", Username: "alice"})
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("CreateUser duplicate username error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
	}
}

func TestStore_CreateAndGetAPIKey(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	want := &tenantkit.APIKey{Hash: "deadbeef", TenantID: "acme"}
	if err := s.CreateAPIKey(ctx, want); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	got, err := s.GetAPIKeyByHash(ctx, "deadbeef")
	if err != nil {
		t.Fatalf("GetAPIKeyByHash: %v", err)
	}
	if *got != *want {
		t.Errorf("GetAPIKeyByHash = %+v, want %+v", got, want)
	}
}

func TestStore_GetAPIKeyByHash_NotFound(t *testing.T) {
	s := memstore.New()
	_, err := s.GetAPIKeyByHash(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetAPIKeyByHash error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_CreateAPIKey_DuplicateFails(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: "deadbeef", TenantID: "acme"}); err != nil {
		t.Fatalf("first CreateAPIKey: %v", err)
	}
	err := s.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: "deadbeef", TenantID: "globex"})
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("CreateAPIKey duplicate error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
	}
}

func TestStore_RevokeAPIKey(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: "deadbeef", TenantID: "acme"}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	if err := s.RevokeAPIKey(ctx, "deadbeef"); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	_, err := s.GetAPIKeyByHash(ctx, "deadbeef")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetAPIKeyByHash after revoke error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_RevokeAPIKey_NotFound(t *testing.T) {
	s := memstore.New()
	err := s.RevokeAPIKey(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RevokeAPIKey error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_CreateAndGetClientCert(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	want := &tenantkit.ClientCert{Fingerprint: "cafef00d", TenantID: "acme"}
	if err := s.CreateClientCert(ctx, want); err != nil {
		t.Fatalf("CreateClientCert: %v", err)
	}
	got, err := s.GetClientCertByFingerprint(ctx, "cafef00d")
	if err != nil {
		t.Fatalf("GetClientCertByFingerprint: %v", err)
	}
	if *got != *want {
		t.Errorf("GetClientCertByFingerprint = %+v, want %+v", got, want)
	}
}

func TestStore_GetClientCertByFingerprint_NotFound(t *testing.T) {
	s := memstore.New()
	_, err := s.GetClientCertByFingerprint(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetClientCertByFingerprint error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_CreateClientCert_DuplicateFails(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: "cafef00d", TenantID: "acme"}); err != nil {
		t.Fatalf("first CreateClientCert: %v", err)
	}
	err := s.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: "cafef00d", TenantID: "globex"})
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("CreateClientCert duplicate error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
	}
}

func TestStore_RevokeClientCert(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: "cafef00d", TenantID: "acme"}); err != nil {
		t.Fatalf("CreateClientCert: %v", err)
	}

	if err := s.RevokeClientCert(ctx, "cafef00d"); err != nil {
		t.Fatalf("RevokeClientCert: %v", err)
	}
	_, err := s.GetClientCertByFingerprint(ctx, "cafef00d")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetClientCertByFingerprint after revoke error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestStore_RevokeClientCert_NotFound(t *testing.T) {
	s := memstore.New()
	err := s.RevokeClientCert(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RevokeClientCert error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./store/... -v`

Expected: FAIL to compile -- package `store` and package `store/memstore` don't exist yet.

- [ ] **Step 3: Write the store interfaces**

Create `store/store.go`:

```go
// Package store defines tenantkit's storage interfaces. tenantkit never
// implements these against a real database itself -- a consumer
// implements them against whatever store it already uses. See package
// storetest for a conformance-test suite any implementation can run
// against itself, and package memstore for an in-memory implementation
// used by tenantkit's own tests (and reusable in a consumer's tests too).
package store

import (
	"context"
	"errors"

	"github.com/TURNERO/tenantkit"
)

// ErrNotFound is returned by a Get*/lookup method when no matching
// record exists.
var ErrNotFound = errors.New("tenantkit/store: not found")

// ErrAlreadyExists is returned by a Create* method when the record would
// violate a uniqueness constraint (a duplicate tenant ID, user ID,
// (tenant, username) pair, or API key hash).
var ErrAlreadyExists = errors.New("tenantkit/store: already exists")

// TenantStore stores and retrieves tenant records.
type TenantStore interface {
	// GetTenant returns the tenant with the given ID, or ErrNotFound.
	GetTenant(ctx context.Context, tenantID string) (*tenantkit.Tenant, error)
	// CreateTenant inserts t, or returns ErrAlreadyExists if a tenant
	// with the same ID already exists.
	CreateTenant(ctx context.Context, t *tenantkit.Tenant) error
	// ListTenants returns every tenant.
	ListTenants(ctx context.Context) ([]*tenantkit.Tenant, error)
	// DeactivateTenant marks the tenant with the given ID inactive, or
	// returns ErrNotFound if it doesn't exist.
	DeactivateTenant(ctx context.Context, tenantID string) error
}

// UserStore stores and retrieves user identity records.
type UserStore interface {
	// GetUser returns the user with the given ID, or ErrNotFound.
	GetUser(ctx context.Context, userID string) (*tenantkit.Identity, error)
	// GetUserByUsername returns the user with the given username within
	// tenantID, or ErrNotFound -- including when the username exists
	// but under a different tenant.
	GetUserByUsername(ctx context.Context, tenantID, username string) (*tenantkit.Identity, error)
	// CreateUser inserts u, or returns ErrAlreadyExists if a user with
	// the same UserID, or the same (TenantID, Username) pair, already
	// exists.
	CreateUser(ctx context.Context, u *tenantkit.Identity) error
}

// APIKeyStore stores and retrieves API key records, keyed by the
// SHA-256 hash of the plaintext secret -- never the plaintext itself.
type APIKeyStore interface {
	// GetAPIKeyByHash returns the key with the given hash, or ErrNotFound.
	GetAPIKeyByHash(ctx context.Context, hash string) (*tenantkit.APIKey, error)
	// CreateAPIKey inserts k, or returns ErrAlreadyExists if a key with
	// the same hash already exists.
	CreateAPIKey(ctx context.Context, k *tenantkit.APIKey) error
	// RevokeAPIKey removes the key with the given hash, or returns
	// ErrNotFound if it doesn't exist.
	RevokeAPIKey(ctx context.Context, hash string) error
}

// ClientCertStore stores and retrieves mTLS client-certificate
// records, keyed by the SHA-256 hex fingerprint of the DER-encoded
// cert -- not a secret, just an identifier; the trust decision (is
// this cert signed by a CA we trust) happens in TLS itself, before
// tenantkit ever sees the request.
type ClientCertStore interface {
	// GetClientCertByFingerprint returns the cert with the given
	// fingerprint, or ErrNotFound.
	GetClientCertByFingerprint(ctx context.Context, fingerprint string) (*tenantkit.ClientCert, error)
	// CreateClientCert inserts c, or returns ErrAlreadyExists if a cert
	// with the same fingerprint already exists.
	CreateClientCert(ctx context.Context, c *tenantkit.ClientCert) error
	// RevokeClientCert removes the cert with the given fingerprint, or
	// returns ErrNotFound if it doesn't exist.
	RevokeClientCert(ctx context.Context, fingerprint string) error
}
```

- [ ] **Step 4: Write the in-memory reference store**

Create `store/memstore/memstore.go`:

```go
// Package memstore is an in-memory implementation of tenantkit's store
// interfaces. It exists for tests -- both tenantkit's own and a
// consumer's -- not as a production backend: nothing is persisted, and
// every method takes a single mutex.
package memstore

import (
	"context"
	"sort"
	"sync"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"
)

// Store is an in-memory store.TenantStore, store.UserStore, and
// store.APIKeyStore.
type Store struct {
	mu sync.Mutex

	tenants map[string]*tenantkit.Tenant

	users      map[string]*tenantkit.Identity
	usersByKey map[usernameKey]string // (tenantID, username) -> userID

	apiKeys map[string]*tenantkit.APIKey

	clientCerts map[string]*tenantkit.ClientCert
}

type usernameKey struct {
	tenantID string
	username string
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		tenants:     make(map[string]*tenantkit.Tenant),
		users:       make(map[string]*tenantkit.Identity),
		usersByKey:  make(map[usernameKey]string),
		apiKeys:     make(map[string]*tenantkit.APIKey),
		clientCerts: make(map[string]*tenantkit.ClientCert),
	}
}

var (
	_ store.TenantStore     = (*Store)(nil)
	_ store.UserStore       = (*Store)(nil)
	_ store.APIKeyStore     = (*Store)(nil)
	_ store.ClientCertStore = (*Store)(nil)
)

func (s *Store) GetTenant(ctx context.Context, tenantID string) (*tenantkit.Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[tenantID]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (s *Store) CreateTenant(ctx context.Context, t *tenantkit.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[t.ID]; ok {
		return store.ErrAlreadyExists
	}
	cp := *t
	s.tenants[t.ID] = &cp
	return nil
}

func (s *Store) ListTenants(ctx context.Context) ([]*tenantkit.Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*tenantkit.Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		cp := *t
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) DeactivateTenant(ctx context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[tenantID]
	if !ok {
		return store.ErrNotFound
	}
	t.Active = false
	return nil
}

func (s *Store) GetUser(ctx context.Context, userID string) (*tenantkit.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, tenantID, username string) (*tenantkit.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	userID, ok := s.usersByKey[usernameKey{tenantID: tenantID, username: username}]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.users[userID]
	return &cp, nil
}

func (s *Store) CreateUser(ctx context.Context, u *tenantkit.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.UserID]; ok {
		return store.ErrAlreadyExists
	}
	key := usernameKey{tenantID: u.TenantID, username: u.Username}
	if _, ok := s.usersByKey[key]; ok {
		return store.ErrAlreadyExists
	}
	cp := *u
	s.users[u.UserID] = &cp
	s.usersByKey[key] = u.UserID
	return nil
}

func (s *Store) GetAPIKeyByHash(ctx context.Context, hash string) (*tenantkit.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.apiKeys[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *k
	return &cp, nil
}

func (s *Store) CreateAPIKey(ctx context.Context, k *tenantkit.APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.apiKeys[k.Hash]; ok {
		return store.ErrAlreadyExists
	}
	cp := *k
	s.apiKeys[k.Hash] = &cp
	return nil
}

func (s *Store) RevokeAPIKey(ctx context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.apiKeys[hash]; !ok {
		return store.ErrNotFound
	}
	delete(s.apiKeys, hash)
	return nil
}

func (s *Store) GetClientCertByFingerprint(ctx context.Context, fingerprint string) (*tenantkit.ClientCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clientCerts[fingerprint]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (s *Store) CreateClientCert(ctx context.Context, c *tenantkit.ClientCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clientCerts[c.Fingerprint]; ok {
		return store.ErrAlreadyExists
	}
	cp := *c
	s.clientCerts[c.Fingerprint] = &cp
	return nil
}

func (s *Store) RevokeClientCert(ctx context.Context, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clientCerts[fingerprint]; !ok {
		return store.ErrNotFound
	}
	delete(s.clientCerts, fingerprint)
	return nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./store/... -v`

Expected: PASS, all tests in `store/memstore/memstore_test.go`.

- [ ] **Step 6: Commit**

```bash
git add store/store.go store/memstore/memstore.go store/memstore/memstore_test.go
git commit -m "feat: add store interfaces and in-memory reference store

TenantStore/UserStore/APIKeyStore/ClientCertStore (store/store.go) are
tenantkit's storage contract -- no implementation ships against a real
database. ClientCertStore supports mTLS as a credential type alongside
API keys, keyed by cert fingerprint rather than a secret hash since a
fingerprint isn't sensitive. store/memstore is an in-memory
implementation for tests, both tenantkit's own and a consumer's."
```

---

### Task 3: Interface-conformance test suite (storetest)

**Files:**
- Create: `storetest/storetest.go`
- Test: `store/memstore/conformance_test.go`

**Interfaces:**
- Consumes: `store.TenantStore`/`UserStore`/`APIKeyStore`/`ClientCertStore` (Task 2), `memstore.New()` (Task 2).
- Produces: `storetest.TestTenantStore(t *testing.T, s store.TenantStore)`, `storetest.TestUserStore(t *testing.T, s store.UserStore)`, `storetest.TestAPIKeyStore(t *testing.T, s store.APIKeyStore)`, `storetest.TestClientCertStore(t *testing.T, s store.ClientCertStore)`. Any future store implementation (in this repo or a consumer's) calls these against a fresh instance of itself to prove conformance.

- [ ] **Step 1: Write the failing test**

Create `store/memstore/conformance_test.go`:

```go
package memstore_test

import (
	"testing"

	"github.com/TURNERO/tenantkit/store/memstore"
	"github.com/TURNERO/tenantkit/storetest"
)

func TestMemstoreConformsToTenantStore(t *testing.T) {
	storetest.TestTenantStore(t, memstore.New())
}

func TestMemstoreConformsToUserStore(t *testing.T) {
	storetest.TestUserStore(t, memstore.New())
}

func TestMemstoreConformsToAPIKeyStore(t *testing.T) {
	storetest.TestAPIKeyStore(t, memstore.New())
}

func TestMemstoreConformsToClientCertStore(t *testing.T) {
	storetest.TestClientCertStore(t, memstore.New())
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./store/... -run TestMemstoreConformsTo -v`

Expected: FAIL to compile -- package `storetest` doesn't exist yet.

- [ ] **Step 3: Write the conformance suite**

Create `storetest/storetest.go`:

```go
// Package storetest provides interface-conformance test helpers for
// tenantkit's store interfaces. A consumer's own store implementation
// (SQL, NoSQL, or otherwise) can run these against a fresh instance to
// prove it satisfies the documented behavior of store.TenantStore,
// store.UserStore, store.APIKeyStore, and store.ClientCertStore -- not
// just that it compiles against the interface.
package storetest

import (
	"context"
	"errors"
	"testing"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"
)

// TestTenantStore runs a battery of subtests against s. Pass a fresh,
// empty store -- these subtests create tenants and do not clean up
// after themselves.
func TestTenantStore(t *testing.T, s store.TenantStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateAndGet", func(t *testing.T) {
		want := &tenantkit.Tenant{ID: "conformance-acme", DisplayName: "Acme Corp", Active: true}
		if err := s.CreateTenant(ctx, want); err != nil {
			t.Fatalf("CreateTenant: %v", err)
		}
		got, err := s.GetTenant(ctx, "conformance-acme")
		if err != nil {
			t.Fatalf("GetTenant: %v", err)
		}
		if got.ID != want.ID || got.DisplayName != want.DisplayName || got.Active != want.Active {
			t.Errorf("GetTenant = %+v, want %+v", got, want)
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		_, err := s.GetTenant(ctx, "conformance-does-not-exist")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetTenant error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("CreateDuplicateFails", func(t *testing.T) {
		id := "conformance-dupe"
		if err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: id, DisplayName: "First", Active: true}); err != nil {
			t.Fatalf("first CreateTenant: %v", err)
		}
		err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: id, DisplayName: "Second", Active: true})
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Errorf("CreateTenant duplicate error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
		}
	})

	t.Run("ListIncludesCreated", func(t *testing.T) {
		id := "conformance-listed"
		if err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: id, DisplayName: "Listed", Active: true}); err != nil {
			t.Fatalf("CreateTenant: %v", err)
		}
		got, err := s.ListTenants(ctx)
		if err != nil {
			t.Fatalf("ListTenants: %v", err)
		}
		found := false
		for _, tn := range got {
			if tn.ID == id {
				found = true
			}
		}
		if !found {
			t.Errorf("ListTenants did not include tenant %q", id)
		}
	})

	t.Run("Deactivate", func(t *testing.T) {
		id := "conformance-deactivate"
		if err := s.CreateTenant(ctx, &tenantkit.Tenant{ID: id, DisplayName: "Deactivate Me", Active: true}); err != nil {
			t.Fatalf("CreateTenant: %v", err)
		}
		if err := s.DeactivateTenant(ctx, id); err != nil {
			t.Fatalf("DeactivateTenant: %v", err)
		}
		got, err := s.GetTenant(ctx, id)
		if err != nil {
			t.Fatalf("GetTenant: %v", err)
		}
		if got.Active {
			t.Error("expected tenant to be inactive after DeactivateTenant")
		}
	})

	t.Run("DeactivateNotFound", func(t *testing.T) {
		err := s.DeactivateTenant(ctx, "conformance-does-not-exist-either")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeactivateTenant error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})
}

// TestUserStore runs a battery of subtests against s. Pass a fresh,
// empty store.
func TestUserStore(t *testing.T, s store.UserStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateAndGet", func(t *testing.T) {
		want := &tenantkit.Identity{UserID: "conformance-u1", TenantID: "conformance-tenant", Username: "alice", Roles: []string{"admin"}}
		if err := s.CreateUser(ctx, want); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		got, err := s.GetUser(ctx, "conformance-u1")
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if got.UserID != want.UserID || got.TenantID != want.TenantID || got.Username != want.Username {
			t.Errorf("GetUser = %+v, want %+v", got, want)
		}
	})

	t.Run("GetByUsername", func(t *testing.T) {
		if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "conformance-u2", TenantID: "conformance-tenant", Username: "bob"}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		got, err := s.GetUserByUsername(ctx, "conformance-tenant", "bob")
		if err != nil {
			t.Fatalf("GetUserByUsername: %v", err)
		}
		if got.UserID != "conformance-u2" {
			t.Errorf("GetUserByUsername returned UserID %q, want conformance-u2", got.UserID)
		}
	})

	t.Run("GetByUsernameScopedToTenant", func(t *testing.T) {
		if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: "conformance-u3", TenantID: "conformance-tenant-a", Username: "carol"}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		_, err := s.GetUserByUsername(ctx, "conformance-tenant-b", "carol")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetUserByUsername in wrong tenant error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		_, err := s.GetUser(ctx, "conformance-does-not-exist")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetUser error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("CreateDuplicateUserIDFails", func(t *testing.T) {
		id := "conformance-dupe-user"
		if err := s.CreateUser(ctx, &tenantkit.Identity{UserID: id, TenantID: "conformance-tenant", Username: "dupe-a"}); err != nil {
			t.Fatalf("first CreateUser: %v", err)
		}
		err := s.CreateUser(ctx, &tenantkit.Identity{UserID: id, TenantID: "conformance-tenant", Username: "dupe-b"})
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Errorf("CreateUser duplicate UserID error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
		}
	})
}

// TestAPIKeyStore runs a battery of subtests against s. Pass a fresh,
// empty store.
func TestAPIKeyStore(t *testing.T, s store.APIKeyStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateAndGet", func(t *testing.T) {
		want := &tenantkit.APIKey{Hash: "conformance-hash-1", TenantID: "conformance-tenant"}
		if err := s.CreateAPIKey(ctx, want); err != nil {
			t.Fatalf("CreateAPIKey: %v", err)
		}
		got, err := s.GetAPIKeyByHash(ctx, "conformance-hash-1")
		if err != nil {
			t.Fatalf("GetAPIKeyByHash: %v", err)
		}
		if got.Hash != want.Hash || got.TenantID != want.TenantID {
			t.Errorf("GetAPIKeyByHash = %+v, want %+v", got, want)
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		_, err := s.GetAPIKeyByHash(ctx, "conformance-does-not-exist")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetAPIKeyByHash error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("CreateDuplicateFails", func(t *testing.T) {
		hash := "conformance-hash-dupe"
		if err := s.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: hash, TenantID: "conformance-tenant"}); err != nil {
			t.Fatalf("first CreateAPIKey: %v", err)
		}
		err := s.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: hash, TenantID: "conformance-tenant-2"})
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Errorf("CreateAPIKey duplicate error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		hash := "conformance-hash-revoke"
		if err := s.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: hash, TenantID: "conformance-tenant"}); err != nil {
			t.Fatalf("CreateAPIKey: %v", err)
		}
		if err := s.RevokeAPIKey(ctx, hash); err != nil {
			t.Fatalf("RevokeAPIKey: %v", err)
		}
		_, err := s.GetAPIKeyByHash(ctx, hash)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetAPIKeyByHash after revoke error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("RevokeNotFound", func(t *testing.T) {
		err := s.RevokeAPIKey(ctx, "conformance-does-not-exist-2")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RevokeAPIKey error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})
}

// TestClientCertStore runs a battery of subtests against s. Pass a
// fresh, empty store.
func TestClientCertStore(t *testing.T, s store.ClientCertStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateAndGet", func(t *testing.T) {
		want := &tenantkit.ClientCert{Fingerprint: "conformance-fp-1", TenantID: "conformance-tenant"}
		if err := s.CreateClientCert(ctx, want); err != nil {
			t.Fatalf("CreateClientCert: %v", err)
		}
		got, err := s.GetClientCertByFingerprint(ctx, "conformance-fp-1")
		if err != nil {
			t.Fatalf("GetClientCertByFingerprint: %v", err)
		}
		if got.Fingerprint != want.Fingerprint || got.TenantID != want.TenantID {
			t.Errorf("GetClientCertByFingerprint = %+v, want %+v", got, want)
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		_, err := s.GetClientCertByFingerprint(ctx, "conformance-does-not-exist")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetClientCertByFingerprint error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("CreateDuplicateFails", func(t *testing.T) {
		fp := "conformance-fp-dupe"
		if err := s.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: fp, TenantID: "conformance-tenant"}); err != nil {
			t.Fatalf("first CreateClientCert: %v", err)
		}
		err := s.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: fp, TenantID: "conformance-tenant-2"})
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Errorf("CreateClientCert duplicate error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		fp := "conformance-fp-revoke"
		if err := s.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: fp, TenantID: "conformance-tenant"}); err != nil {
			t.Fatalf("CreateClientCert: %v", err)
		}
		if err := s.RevokeClientCert(ctx, fp); err != nil {
			t.Fatalf("RevokeClientCert: %v", err)
		}
		_, err := s.GetClientCertByFingerprint(ctx, fp)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetClientCertByFingerprint after revoke error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("RevokeNotFound", func(t *testing.T) {
		err := s.RevokeClientCert(ctx, "conformance-does-not-exist-2")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RevokeClientCert error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./store/... -run TestMemstoreConformsTo -v`

Expected: PASS, all 4 tests (each running its own subtests).

- [ ] **Step 5: Commit**

```bash
git add storetest/storetest.go store/memstore/conformance_test.go
git commit -m "feat: add storetest interface-conformance suite

storetest.TestTenantStore/TestUserStore/TestAPIKeyStore/
TestClientCertStore let any store implementation prove it satisfies
the documented contract (not-found and already-exists behavior,
tenant scoping), not just that it compiles against the interface. Run
here against memstore as both a test of storetest itself and proof
memstore conforms.
```

---

### Task 4: Crypto and validation helpers

**Files:**
- Create: `store/helpers.go`
- Test: `store/helpers_test.go`

**Interfaces:**
- Consumes: `store.APIKeyStore` (Task 2), `memstore.New()` (Task 2).
- Produces: `store.GenerateSecret() (string, error)`, `store.HashSecret(secret string) string`, `store.ValidTenantID(id string) bool`, `store.RotateAPIKey(ctx context.Context, ks APIKeyStore, oldHash, tenantID, userID string) (string, error)`. A later plan's `tenantkit/admin` package (tenant/key/user provisioning operations behind `cmd/tenantkit-admin`) depends on all four of these exact signatures.

- [ ] **Step 1: Write the failing tests**

Create `store/helpers_test.go`:

```go
package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"
	"github.com/TURNERO/tenantkit/store/memstore"
)

func TestGenerateSecret_ReturnsHighEntropyUniqueValues(t *testing.T) {
	a, err := store.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	b, err := store.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if a == b {
		t.Error("expected two calls to GenerateSecret to return different values")
	}
	if len(a) < 32 {
		t.Errorf("GenerateSecret returned a %d-char value, want at least 32", len(a))
	}
}

func TestHashSecret_Deterministic(t *testing.T) {
	h1 := store.HashSecret("my-secret")
	h2 := store.HashSecret("my-secret")
	if h1 != h2 {
		t.Errorf("HashSecret not deterministic: %q != %q", h1, h2)
	}
	if h1 == "my-secret" {
		t.Error("HashSecret returned the plaintext unchanged")
	}
}

func TestHashSecret_DifferentInputsDifferentHashes(t *testing.T) {
	if store.HashSecret("a") == store.HashSecret("b") {
		t.Error("expected different inputs to hash differently")
	}
}

func TestValidTenantID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"acme", true},
		{"acme-corp", true},
		{"acme123", true},
		{"", false},
		{"Acme", false},
		{"acme_corp", false},
		{"acme corp", false},
		{"acme/corp", false},
	}
	for _, c := range cases {
		if got := store.ValidTenantID(c.id); got != c.want {
			t.Errorf("ValidTenantID(%q) = %v, want %v", c.id, got, c.want)
		}
	}
}

func TestRotateAPIKey(t *testing.T) {
	ks := memstore.New()
	ctx := context.Background()

	oldSecret, err := store.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	oldHash := store.HashSecret(oldSecret)
	if err := ks.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: oldHash, TenantID: "acme", UserID: "u1"}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	newSecret, err := store.RotateAPIKey(ctx, ks, oldHash, "acme", "u1")
	if err != nil {
		t.Fatalf("RotateAPIKey: %v", err)
	}
	if newSecret == oldSecret {
		t.Error("expected RotateAPIKey to return a new secret, got the old one")
	}

	if _, err := ks.GetAPIKeyByHash(ctx, oldHash); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected old key to be revoked, GetAPIKeyByHash error = %v", err)
	}

	newHash := store.HashSecret(newSecret)
	got, err := ks.GetAPIKeyByHash(ctx, newHash)
	if err != nil {
		t.Fatalf("GetAPIKeyByHash for new key: %v", err)
	}
	if got.TenantID != "acme" || got.UserID != "u1" {
		t.Errorf("new key = %+v, want TenantID=acme UserID=u1", got)
	}
}

func TestRotateAPIKey_OldHashNotFound(t *testing.T) {
	ks := memstore.New()
	ctx := context.Background()

	_, err := store.RotateAPIKey(ctx, ks, "does-not-exist", "acme", "u1")
	if err == nil {
		t.Fatal("expected an error rotating a nonexistent key, got nil")
	}

	// Confirm RotateAPIKey didn't leave a new, orphaned key behind when
	// the old one didn't exist -- it must check for the old key before
	// creating a replacement.
	got, listErr := ks.GetAPIKeyByHash(ctx, "does-not-exist")
	if listErr == nil {
		t.Errorf("expected no key to exist for the failed rotation, got %+v", got)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./store/... -run 'TestGenerateSecret_ReturnsHighEntropyUniqueValues|TestHashSecret_Deterministic|TestHashSecret_DifferentInputsDifferentHashes|TestValidTenantID|TestRotateAPIKey|TestRotateAPIKey_OldHashNotFound' -v`

Expected: FAIL to compile -- `store.GenerateSecret`, `store.HashSecret`, `store.ValidTenantID`, `store.RotateAPIKey` undefined.

- [ ] **Step 3: Implement the helpers**

Create `store/helpers.go`:

```go
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/TURNERO/tenantkit"
)

var tenantIDPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// GenerateSecret returns a new high-entropy, URL-safe random secret
// suitable for an API key or a similar credential.
func GenerateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashSecret returns the SHA-256 hex digest of secret, for storing and
// comparing high-entropy generated credentials (API keys) -- not for
// human-chosen passwords, which need a slow, salted hash instead.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ValidTenantID reports whether id is safe to use as a tenant
// identifier. tenantkit itself never interpolates a tenant ID into
// anything injectable, but consumers commonly do (e.g. as a
// role/policy-name fragment in a database-specific RBAC statement), so
// a conservative charset is enforced here once rather than separately
// by every consumer.
func ValidTenantID(id string) bool {
	return tenantIDPattern.MatchString(id)
}

// RotateAPIKey replaces the API key identified by oldHash with a newly
// generated one for the same tenant/user, returning the new plaintext
// secret. It checks that oldHash exists before creating anything, so a
// call with a bad oldHash fails cleanly with no side effects. Once past
// that check, the new key is created before the old one is revoked, so
// there's a brief window where both are valid rather than a window
// where neither is -- the safer direction to err in for a credential
// rotation.
func RotateAPIKey(ctx context.Context, ks APIKeyStore, oldHash, tenantID, userID string) (string, error) {
	if _, err := ks.GetAPIKeyByHash(ctx, oldHash); err != nil {
		return "", fmt.Errorf("look up existing api key: %w", err)
	}
	newSecret, err := GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("generate new secret: %w", err)
	}
	newKey := &tenantkit.APIKey{Hash: HashSecret(newSecret), TenantID: tenantID, UserID: userID}
	if err := ks.CreateAPIKey(ctx, newKey); err != nil {
		return "", fmt.Errorf("create new api key: %w", err)
	}
	if err := ks.RevokeAPIKey(ctx, oldHash); err != nil {
		return "", fmt.Errorf("revoke old api key: %w", err)
	}
	return newSecret, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./store/... -run 'TestGenerateSecret_ReturnsHighEntropyUniqueValues|TestHashSecret_Deterministic|TestHashSecret_DifferentInputsDifferentHashes|TestValidTenantID|TestRotateAPIKey|TestRotateAPIKey_OldHashNotFound' -v`

Expected: PASS, all tests.

- [ ] **Step 5: Run the full module test suite**

Run: `go build ./... && go vet ./... && go test ./... -v`

Expected: builds clean, vets clean, all tests across `tenantkit`, `tenantkit/store`, `tenantkit/store/memstore`, and `tenantkit/storetest` pass.

- [ ] **Step 6: Commit**

```bash
git add store/helpers.go store/helpers_test.go
git commit -m "feat: add API key generation, hashing, and rotation helpers

GenerateSecret/HashSecret/ValidTenantID/RotateAPIKey are the pure,
store-agnostic operations the future tenantkit/admin package (and
cmd/tenantkit-admin) builds provisioning on top of. RotateAPIKey
checks the old key exists before creating a replacement, so a bad
oldHash fails without orphaning an unrevealed new key."
```

---

## What's next

This plan covers only the foundation. Three more plans, each independently
buildable/testable on top of this one, are still needed before tenantkit
matches the full design spec (`docs/superpowers/specs/2026-07-20-tenantkit-design.md`):

- **Tenant resolution & middleware** -- `tenantkit/resolve` (the
  `TenantResolver` interface and built-in strategies), `tenantkit/httpmw`,
  `tenantkit/grpcmw`.
- **Identity** -- `tenantkit/identity` (the `IdentityProvider` interface),
  `tenantkit/identity/local` (WebAuthn/bcrypt + sessions), and
  `tenantkit/identity/oidc`.
- **Admin** -- `tenantkit/admin` (the operations layer) and
  `cmd/tenantkit-admin` (the production CLI: subcommands, `--yes`
  confirmation, `--dry-run`, `--json`), per the spec's "Management plane"
  section. Depends on this plan's `store` helpers directly.

Each should be written as its own plan once this one is merged, per the
spec's own phased-rollout note.
