# store.OIDCProviderStore Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `store.OIDCProviderStore`, a new per-tenant storage interface for registering external OIDC IdPs (issuer/client credentials/domains/claims mapping), plus `memstore`/`sqlite` implementations, `storetest` conformance coverage, `tenantkit/admin` operations, and a `tenantkit-admin oidc` CLI subcommand -- the prerequisite for the `identity/oidc` adapter (a separate follow-up plan) to look up a tenant's IdP at login time.

**Architecture:** Mirrors the existing `store`/`admin`/CLI trio exactly (`TenantStore`/`APIKeyStore`/`ClientCertStore` already follow this shape): one new root type (`tenantkit.OIDCProvider`) plus a nested `ClaimsMapping`, one new interface (`store.OIDCProviderStore`), one new sentinel error (`store.ErrDomainTaken`), implemented by both `store/memstore` (in-memory) and `store/sqlite` (two tables: the provider row, and a domain-uniqueness index table), proven by a new `storetest.TestOIDCProviderStore` conformance suite, wrapped by five `tenantkit/admin` functions, exposed via a new `oidc` CLI subcommand (`register`/`list`/`show`/`update`/`remove`).

**Tech Stack:** Go 1.25, `database/sql`, `modernc.org/sqlite` (already a dependency), `spf13/cobra` (already a dependency of the `tools/` submodule). No new external dependencies.

**Spec:** `docs/superpowers/specs/2026-07-23-oidc-provider-store-design.md`

## Global Constraints

- Go 1.25.0 (module `github.com/TURNERO/tenantkit`; `tools/cmd/tenantkit-admin` is its own Go submodule depending on the main module).
- A tenant may register more than one `OIDCProvider` (key is `(TenantID, ProviderID)`, not `TenantID` alone).
- `Domains` must be globally unique across every tenant and provider. `CreateOIDCProvider`/`UpdateOIDCProvider` return the new `store.ErrDomainTaken` on a collision -- distinct from `store.ErrAlreadyExists`, which means the `(tenant_id, provider_id)` pair itself already exists.
- `ClaimsMapping` (which ID-token claim holds tenant ID/user ID/username/roles) is stored per registration, not service-wide.
- `ClientSecret` is stored as plain text, same as every other column in `store/sqlite` -- no column-level encryption anywhere in this codebase.
- Every non-`ErrNotFound`/`ErrAlreadyExists`/`ErrDomainTaken` failure from `store/sqlite` is wrapped with `fmt.Errorf("<action>: %w", err)`, matching that package's existing convention.
- CLI conventions to match exactly: noun-then-verb subcommands (`oidc register`, `oidc list`, ...); `--dry-run` on every mutating command; `--yes`/`-f` + a `confirm()` prompt on the destructive `remove` command (matching `key revoke`/`cert revoke`); `--json` only on `list` (matching `tenant list`); multi-value input as a single comma-separated flag split with `strings.Split` (matching `user create --roles`), not a repeatable flag.

---

### Task 1: Root type, interface, and sentinel error

**Files:**
- Modify: `types.go`
- Modify: `store/store.go`

**Interfaces:**
- Produces: `tenantkit.OIDCProvider`, `tenantkit.ClaimsMapping`, `store.OIDCProviderStore`, `store.ErrDomainTaken` -- every later task depends on these exact names/signatures.

- [ ] **Step 1: Add the root types**

Append to `types.go`:

```go
// OIDCProvider is a tenant's registration of an external OIDC-compliant
// IdP. A tenant may register more than one (ProviderID is unique per
// tenant, not globally); Domains must be globally unique across every
// tenant and provider (see store.OIDCProviderStore.GetOIDCProviderByDomain).
type OIDCProvider struct {
	TenantID      string
	ProviderID    string // slug, unique within a tenant, e.g. "okta", "google"
	Name          string // display label for a login picker, e.g. "Acme Corp Okta"
	IssuerURL     string
	ClientID      string
	ClientSecret  string   // plain text -- see store package doc for why
	Scopes        []string // e.g. []string{"openid", "email"}
	Domains       []string // e.g. []string{"acme.com", "acme.co.uk"} -- globally unique across all tenants
	ClaimsMapping ClaimsMapping
}

// ClaimsMapping says which of a verified OIDC ID token's claims
// identity/oidc reads to build an Identity. TenantIDClaim is required
// (no standard claim holds a tenant ID); the rest default when empty:
// UserIDClaim to "sub", UsernameClaim to "email", RolesClaim to "roles"
// (its claim value must be a JSON array of strings).
type ClaimsMapping struct {
	TenantIDClaim string
	UserIDClaim   string
	UsernameClaim string
	RolesClaim    string
}
```

- [ ] **Step 2: Add the sentinel error and interface**

Append to `store/store.go`:

```go
// ErrDomainTaken is returned by CreateOIDCProvider/UpdateOIDCProvider
// when one of the given Domains is already claimed by a different
// tenant/provider. Distinct from ErrAlreadyExists, which means the
// (tenant_id, provider_id) pair itself already exists.
var ErrDomainTaken = errors.New("tenantkit/store: domain already claimed by another provider")

// OIDCProviderStore stores and retrieves per-tenant OIDC IdP
// registrations. A tenant may register more than one provider (distinct
// ProviderIDs); Domains must be globally unique across every tenant and
// provider.
type OIDCProviderStore interface {
	// GetOIDCProvider returns the tenant's provider with the given ID,
	// or ErrNotFound.
	GetOIDCProvider(ctx context.Context, tenantID, providerID string) (*tenantkit.OIDCProvider, error)
	// GetOIDCProviderByDomain returns the provider that claims domain,
	// or ErrNotFound if no provider claims it.
	GetOIDCProviderByDomain(ctx context.Context, domain string) (*tenantkit.OIDCProvider, error)
	// ListOIDCProviders returns all providers registered for tenantID,
	// or an empty slice (not an error) if none are.
	ListOIDCProviders(ctx context.Context, tenantID string) ([]*tenantkit.OIDCProvider, error)
	// CreateOIDCProvider inserts p, or returns ErrAlreadyExists if
	// (p.TenantID, p.ProviderID) already exists, or ErrDomainTaken if
	// any of p.Domains is already claimed elsewhere.
	CreateOIDCProvider(ctx context.Context, p *tenantkit.OIDCProvider) error
	// UpdateOIDCProvider replaces the stored record for (p.TenantID,
	// p.ProviderID) with p, or returns ErrNotFound if it doesn't exist,
	// or ErrDomainTaken if any of p.Domains is now claimed by a
	// different tenant/provider.
	UpdateOIDCProvider(ctx context.Context, p *tenantkit.OIDCProvider) error
	// DeleteOIDCProvider removes the tenant's provider with the given
	// ID (and frees its claimed domains), or returns ErrNotFound if it
	// doesn't exist.
	DeleteOIDCProvider(ctx context.Context, tenantID, providerID string) error
}
```

- [ ] **Step 3: Verify it builds**

Run: `go build ./...`
Expected: succeeds (no implementations exist yet, but a pure type/interface addition can't fail to compile on its own).

- [ ] **Step 4: Commit**

```bash
git add types.go store/store.go
git commit -m "feat: add tenantkit.OIDCProvider and store.OIDCProviderStore"
```

---

### Task 2: storetest conformance suite + memstore implementation

**Files:**
- Modify: `storetest/storetest.go`
- Modify: `store/memstore/memstore.go`
- Modify: `store/memstore/conformance_test.go`

**Interfaces:**
- Consumes: `tenantkit.OIDCProvider`, `tenantkit.ClaimsMapping`, `store.OIDCProviderStore`, `store.ErrDomainTaken`, `store.ErrNotFound`, `store.ErrAlreadyExists` (Task 1).
- Produces: `storetest.TestOIDCProviderStore(t *testing.T, s store.OIDCProviderStore)` -- Task 3 (sqlite) runs this same function.

- [ ] **Step 1: Write the failing test (storetest function + memstore wiring)**

Append to `storetest/storetest.go` (add `"slices"` to the import block):

```go
import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"
)
```

```go
// TestOIDCProviderStore runs a battery of subtests against s. Pass a
// fresh, empty store -- these subtests create providers and do not
// clean up after themselves.
func TestOIDCProviderStore(t *testing.T, s store.OIDCProviderStore) {
	t.Helper()
	ctx := context.Background()

	newProvider := func(tenantID, providerID string, domains ...string) *tenantkit.OIDCProvider {
		return &tenantkit.OIDCProvider{
			TenantID:     tenantID,
			ProviderID:   providerID,
			Name:         "Test Provider",
			IssuerURL:    "https://idp.example/" + tenantID + "/" + providerID,
			ClientID:     "client-" + providerID,
			ClientSecret: "secret-" + providerID,
			Scopes:       []string{"openid", "email"},
			Domains:      domains,
			ClaimsMapping: tenantkit.ClaimsMapping{
				TenantIDClaim: "https://example/tenant_id",
				UserIDClaim:   "sub",
				UsernameClaim: "email",
				RolesClaim:    "roles",
			},
		}
	}

	t.Run("CreateAndGet", func(t *testing.T) {
		want := newProvider("conformance-acme", "okta", "conformance-acme-okta.example")
		if err := s.CreateOIDCProvider(ctx, want); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		got, err := s.GetOIDCProvider(ctx, "conformance-acme", "okta")
		if err != nil {
			t.Fatalf("GetOIDCProvider: %v", err)
		}
		if got.TenantID != want.TenantID || got.ProviderID != want.ProviderID || got.Name != want.Name ||
			got.IssuerURL != want.IssuerURL || got.ClientID != want.ClientID || got.ClientSecret != want.ClientSecret {
			t.Errorf("GetOIDCProvider = %+v, want %+v", got, want)
		}
		if !slices.Equal(got.Scopes, want.Scopes) {
			t.Errorf("GetOIDCProvider Scopes = %v, want %v", got.Scopes, want.Scopes)
		}
		if !slices.Equal(got.Domains, want.Domains) {
			t.Errorf("GetOIDCProvider Domains = %v, want %v", got.Domains, want.Domains)
		}
		if got.ClaimsMapping != want.ClaimsMapping {
			t.Errorf("GetOIDCProvider ClaimsMapping = %+v, want %+v", got.ClaimsMapping, want.ClaimsMapping)
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		_, err := s.GetOIDCProvider(ctx, "conformance-acme", "conformance-does-not-exist")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetOIDCProvider error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("GetByDomain", func(t *testing.T) {
		p := newProvider("conformance-globex", "google", "conformance-globex-google.example")
		if err := s.CreateOIDCProvider(ctx, p); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		got, err := s.GetOIDCProviderByDomain(ctx, "conformance-globex-google.example")
		if err != nil {
			t.Fatalf("GetOIDCProviderByDomain: %v", err)
		}
		if got.TenantID != "conformance-globex" || got.ProviderID != "google" {
			t.Errorf("GetOIDCProviderByDomain = %+v, want tenant conformance-globex provider google", got)
		}
	})

	t.Run("GetByDomainNotFound", func(t *testing.T) {
		_, err := s.GetOIDCProviderByDomain(ctx, "conformance-unclaimed.example")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetOIDCProviderByDomain error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("ListEmpty", func(t *testing.T) {
		got, err := s.ListOIDCProviders(ctx, "conformance-no-providers-tenant")
		if err != nil {
			t.Fatalf("ListOIDCProviders: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("ListOIDCProviders = %+v, want empty", got)
		}
	})

	t.Run("ListIncludesCreated", func(t *testing.T) {
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-multi", "okta")); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-multi", "google")); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		got, err := s.ListOIDCProviders(ctx, "conformance-multi")
		if err != nil {
			t.Fatalf("ListOIDCProviders: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("ListOIDCProviders = %+v, want 2 entries", got)
		}
	})

	t.Run("CreateDuplicateProviderIDFails", func(t *testing.T) {
		p := newProvider("conformance-dupe-tenant", "okta")
		if err := s.CreateOIDCProvider(ctx, p); err != nil {
			t.Fatalf("first CreateOIDCProvider: %v", err)
		}
		err := s.CreateOIDCProvider(ctx, newProvider("conformance-dupe-tenant", "okta"))
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Errorf("CreateOIDCProvider duplicate error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
		}
	})

	t.Run("CreateDomainTakenFails", func(t *testing.T) {
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-domain-a", "okta", "conformance-shared.example")); err != nil {
			t.Fatalf("first CreateOIDCProvider: %v", err)
		}
		err := s.CreateOIDCProvider(ctx, newProvider("conformance-domain-b", "okta", "conformance-shared.example"))
		if !errors.Is(err, store.ErrDomainTaken) {
			t.Errorf("CreateOIDCProvider domain-taken error = %v, want errors.Is(err, store.ErrDomainTaken)", err)
		}
	})

	t.Run("Update", func(t *testing.T) {
		p := newProvider("conformance-update-tenant", "okta", "conformance-update-old.example")
		if err := s.CreateOIDCProvider(ctx, p); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		p.Name = "Updated Name"
		p.Domains = []string{"conformance-update-new.example"}
		if err := s.UpdateOIDCProvider(ctx, p); err != nil {
			t.Fatalf("UpdateOIDCProvider: %v", err)
		}
		got, err := s.GetOIDCProvider(ctx, "conformance-update-tenant", "okta")
		if err != nil {
			t.Fatalf("GetOIDCProvider: %v", err)
		}
		if got.Name != "Updated Name" || !slices.Equal(got.Domains, []string{"conformance-update-new.example"}) {
			t.Errorf("GetOIDCProvider after update = %+v, want Name %q Domains %v", got, "Updated Name", []string{"conformance-update-new.example"})
		}
		// The old domain must be freed.
		_, err = s.GetOIDCProviderByDomain(ctx, "conformance-update-old.example")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetOIDCProviderByDomain for freed domain error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("UpdateNotFound", func(t *testing.T) {
		err := s.UpdateOIDCProvider(ctx, newProvider("conformance-update-missing", "okta"))
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdateOIDCProvider error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("UpdateDomainTakenFails", func(t *testing.T) {
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-ud-a", "okta", "conformance-ud-taken.example")); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		p := newProvider("conformance-ud-b", "okta")
		if err := s.CreateOIDCProvider(ctx, p); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		p.Domains = []string{"conformance-ud-taken.example"}
		err := s.UpdateOIDCProvider(ctx, p)
		if !errors.Is(err, store.ErrDomainTaken) {
			t.Errorf("UpdateOIDCProvider domain-taken error = %v, want errors.Is(err, store.ErrDomainTaken)", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		p := newProvider("conformance-delete-tenant", "okta", "conformance-delete.example")
		if err := s.CreateOIDCProvider(ctx, p); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		if err := s.DeleteOIDCProvider(ctx, "conformance-delete-tenant", "okta"); err != nil {
			t.Fatalf("DeleteOIDCProvider: %v", err)
		}
		_, err := s.GetOIDCProvider(ctx, "conformance-delete-tenant", "okta")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetOIDCProvider after delete error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
		_, err = s.GetOIDCProviderByDomain(ctx, "conformance-delete.example")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetOIDCProviderByDomain after delete error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
		// The freed domain must be claimable again.
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-delete-tenant-2", "google", "conformance-delete.example")); err != nil {
			t.Errorf("CreateOIDCProvider re-claiming freed domain: %v", err)
		}
	})

	t.Run("DeleteNotFound", func(t *testing.T) {
		err := s.DeleteOIDCProvider(ctx, "conformance-delete-missing", "okta")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteOIDCProvider error = %v, want errors.Is(err, store.ErrNotFound)", err)
		}
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-iso-a", "shared-id")); err != nil {
			t.Fatalf("CreateOIDCProvider: %v", err)
		}
		// Same ProviderID, different tenant -- must not collide.
		if err := s.CreateOIDCProvider(ctx, newProvider("conformance-iso-b", "shared-id")); err != nil {
			t.Errorf("CreateOIDCProvider in different tenant with same ProviderID: %v", err)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./storetest/... -v`
Expected: FAIL (or build error) -- `storetest` package compiles fine on its own (it only depends on Task 1's interface), but nothing calls `TestOIDCProviderStore` yet, so this step just confirms the file itself compiles: `go build ./storetest/...`. The real RED signal is in the next step.

Run: `go vet ./store/memstore/...`
Expected: FAIL -- `store/memstore.Store` does not implement `store.OIDCProviderStore` yet, so a conformance-wiring test referencing it (added in Step 3) won't compile until Step 4 implements the methods.

- [ ] **Step 3: Wire memstore's conformance test**

Append to `store/memstore/conformance_test.go`:

```go
func TestMemstoreConformsToOIDCProviderStore(t *testing.T) {
	storetest.TestOIDCProviderStore(t, memstore.New())
}
```

- [ ] **Step 4: Implement memstore**

In `store/memstore/memstore.go`, add to the `Store` struct and `New`:

```go
type Store struct {
	mu sync.Mutex

	tenants map[string]*tenantkit.Tenant

	users      map[string]*tenantkit.Identity
	usersByKey map[usernameKey]string

	apiKeys map[string]*tenantkit.APIKey

	clientCerts map[string]*tenantkit.ClientCert

	oidcProviders       map[oidcProviderKey]*tenantkit.OIDCProvider
	oidcProviderDomains map[string]oidcProviderKey // domain -> (tenantID, providerID)
}

type oidcProviderKey struct {
	tenantID   string
	providerID string
}
```

```go
func New() *Store {
	return &Store{
		tenants:             make(map[string]*tenantkit.Tenant),
		users:               make(map[string]*tenantkit.Identity),
		usersByKey:          make(map[usernameKey]string),
		apiKeys:             make(map[string]*tenantkit.APIKey),
		clientCerts:         make(map[string]*tenantkit.ClientCert),
		oidcProviders:       make(map[oidcProviderKey]*tenantkit.OIDCProvider),
		oidcProviderDomains: make(map[string]oidcProviderKey),
	}
}
```

Add to the `var (...)` interface-assertion block:

```go
var (
	_ store.TenantStore        = (*Store)(nil)
	_ store.UserStore          = (*Store)(nil)
	_ store.APIKeyStore        = (*Store)(nil)
	_ store.ClientCertStore    = (*Store)(nil)
	_ store.OIDCProviderStore  = (*Store)(nil)
)
```

Append the methods:

```go
func cloneOIDCProvider(p *tenantkit.OIDCProvider) *tenantkit.OIDCProvider {
	cp := *p
	cp.Scopes = append([]string(nil), p.Scopes...)
	cp.Domains = append([]string(nil), p.Domains...)
	return &cp
}

func (s *Store) GetOIDCProvider(ctx context.Context, tenantID, providerID string) (*tenantkit.OIDCProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.oidcProviders[oidcProviderKey{tenantID, providerID}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneOIDCProvider(p), nil
}

func (s *Store) GetOIDCProviderByDomain(ctx context.Context, domain string) (*tenantkit.OIDCProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.oidcProviderDomains[domain]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneOIDCProvider(s.oidcProviders[key]), nil
}

func (s *Store) ListOIDCProviders(ctx context.Context, tenantID string) ([]*tenantkit.OIDCProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*tenantkit.OIDCProvider
	for key, p := range s.oidcProviders {
		if key.tenantID == tenantID {
			out = append(out, cloneOIDCProvider(p))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProviderID < out[j].ProviderID })
	return out, nil
}

func (s *Store) CreateOIDCProvider(ctx context.Context, p *tenantkit.OIDCProvider) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := oidcProviderKey{p.TenantID, p.ProviderID}
	if _, ok := s.oidcProviders[key]; ok {
		return store.ErrAlreadyExists
	}
	for _, d := range p.Domains {
		if _, ok := s.oidcProviderDomains[d]; ok {
			return store.ErrDomainTaken
		}
	}
	s.oidcProviders[key] = cloneOIDCProvider(p)
	for _, d := range p.Domains {
		s.oidcProviderDomains[d] = key
	}
	return nil
}

func (s *Store) UpdateOIDCProvider(ctx context.Context, p *tenantkit.OIDCProvider) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := oidcProviderKey{p.TenantID, p.ProviderID}
	old, ok := s.oidcProviders[key]
	if !ok {
		return store.ErrNotFound
	}
	for _, d := range p.Domains {
		if owner, ok := s.oidcProviderDomains[d]; ok && owner != key {
			return store.ErrDomainTaken
		}
	}
	for _, d := range old.Domains {
		delete(s.oidcProviderDomains, d)
	}
	s.oidcProviders[key] = cloneOIDCProvider(p)
	for _, d := range p.Domains {
		s.oidcProviderDomains[d] = key
	}
	return nil
}

func (s *Store) DeleteOIDCProvider(ctx context.Context, tenantID, providerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := oidcProviderKey{tenantID, providerID}
	p, ok := s.oidcProviders[key]
	if !ok {
		return store.ErrNotFound
	}
	for _, d := range p.Domains {
		delete(s.oidcProviderDomains, d)
	}
	delete(s.oidcProviders, key)
	return nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./storetest/... ./store/memstore/... -v`
Expected: `PASS` for `TestMemstoreConformsToOIDCProviderStore` and all its subtests, plus every pre-existing test in both packages still passing.

- [ ] **Step 6: Commit**

```bash
git add storetest/storetest.go store/memstore/memstore.go store/memstore/conformance_test.go
git commit -m "feat: add OIDCProviderStore conformance suite and memstore implementation"
```

---

### Task 3: store/sqlite implementation

**Files:**
- Modify: `store/sqlite/sqlite.go`
- Modify: `store/sqlite/sqlite_test.go`

**Interfaces:**
- Consumes: `storetest.TestOIDCProviderStore`, `openTestDB` (Task 2 and pre-existing).
- Produces: `(*sqlite.Store)` satisfies `store.OIDCProviderStore` -- no later task in this plan depends on this directly, but the `identity/oidc` follow-up plan will use `*sqlite.Store` as a production `store.OIDCProviderStore`.

- [ ] **Step 1: Write the failing test**

Add to `store/sqlite/sqlite_test.go`:

```go
func TestSQLiteConformsToOIDCProviderStore(t *testing.T) {
	storetest.TestOIDCProviderStore(t, openTestDB(t))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./store/sqlite/... -run TestSQLiteConformsToOIDCProviderStore -v`
Expected: FAIL -- build error, `*sqlite.Store` does not implement `store.OIDCProviderStore` (no `oidc_providers`/`oidc_provider_domains` tables, no methods yet).

- [ ] **Step 3: Add the schema**

In `store/sqlite/sqlite.go`, append two entries to the `schema` slice:

```go
var schema = []string{
	`CREATE TABLE IF NOT EXISTS tenants (
		id           TEXT PRIMARY KEY,
		display_name TEXT NOT NULL,
		active       INTEGER NOT NULL DEFAULT 1
	)`,
	`CREATE TABLE IF NOT EXISTS users (
		user_id   TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		username  TEXT NOT NULL,
		roles     TEXT NOT NULL,
		UNIQUE(tenant_id, username)
	)`,
	`CREATE TABLE IF NOT EXISTS api_keys (
		hash      TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		user_id   TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS client_certs (
		fingerprint TEXT PRIMARY KEY,
		tenant_id   TEXT NOT NULL,
		user_id     TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS oidc_providers (
		tenant_id       TEXT NOT NULL,
		provider_id     TEXT NOT NULL,
		name            TEXT NOT NULL,
		issuer_url      TEXT NOT NULL,
		client_id       TEXT NOT NULL,
		client_secret   TEXT NOT NULL,
		scopes          TEXT NOT NULL,
		domains         TEXT NOT NULL,
		tenant_id_claim TEXT NOT NULL,
		user_id_claim   TEXT NOT NULL DEFAULT '',
		username_claim  TEXT NOT NULL DEFAULT '',
		roles_claim     TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (tenant_id, provider_id)
	)`,
	`CREATE TABLE IF NOT EXISTS oidc_provider_domains (
		domain      TEXT PRIMARY KEY,
		tenant_id   TEXT NOT NULL,
		provider_id TEXT NOT NULL
	)`,
}
```

(Only the last two entries are new -- the first four already exist; reproduced here so the whole slice's final shape is unambiguous.)

- [ ] **Step 4: Implement the methods**

Add `store.OIDCProviderStore` to the existing `var (...)` interface-assertion block:

```go
var (
	_ store.TenantStore     = (*Store)(nil)
	_ store.UserStore       = (*Store)(nil)
	_ store.APIKeyStore     = (*Store)(nil)
	_ store.ClientCertStore = (*Store)(nil)
	_ store.OIDCProviderStore = (*Store)(nil)
)
```

Append to `store/sqlite/sqlite.go`:

```go
func scanOIDCProvider(row *sql.Row) (*tenantkit.OIDCProvider, error) {
	var p tenantkit.OIDCProvider
	var scopesJSON, domainsJSON string
	err := row.Scan(&p.TenantID, &p.ProviderID, &p.Name, &p.IssuerURL, &p.ClientID, &p.ClientSecret,
		&scopesJSON, &domainsJSON, &p.ClaimsMapping.TenantIDClaim, &p.ClaimsMapping.UserIDClaim,
		&p.ClaimsMapping.UsernameClaim, &p.ClaimsMapping.RolesClaim)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get oidc provider: %w", err)
	}
	if err := json.Unmarshal([]byte(scopesJSON), &p.Scopes); err != nil {
		return nil, fmt.Errorf("decode scopes: %w", err)
	}
	if err := json.Unmarshal([]byte(domainsJSON), &p.Domains); err != nil {
		return nil, fmt.Errorf("decode domains: %w", err)
	}
	return &p, nil
}

const oidcProviderColumns = `tenant_id, provider_id, name, issuer_url, client_id, client_secret, scopes, domains, tenant_id_claim, user_id_claim, username_claim, roles_claim`

func (s *Store) GetOIDCProvider(ctx context.Context, tenantID, providerID string) (*tenantkit.OIDCProvider, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+oidcProviderColumns+` FROM oidc_providers WHERE tenant_id = ? AND provider_id = ?`, tenantID, providerID)
	return scanOIDCProvider(row)
}

func (s *Store) GetOIDCProviderByDomain(ctx context.Context, domain string) (*tenantkit.OIDCProvider, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT p.tenant_id, p.provider_id, p.name, p.issuer_url, p.client_id, p.client_secret, p.scopes, p.domains, p.tenant_id_claim, p.user_id_claim, p.username_claim, p.roles_claim
		FROM oidc_providers p
		JOIN oidc_provider_domains d ON d.tenant_id = p.tenant_id AND d.provider_id = p.provider_id
		WHERE d.domain = ?`, domain)
	return scanOIDCProvider(row)
}

func (s *Store) ListOIDCProviders(ctx context.Context, tenantID string) ([]*tenantkit.OIDCProvider, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+oidcProviderColumns+` FROM oidc_providers WHERE tenant_id = ? ORDER BY provider_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list oidc providers: %w", err)
	}
	defer rows.Close()

	var out []*tenantkit.OIDCProvider
	for rows.Next() {
		var p tenantkit.OIDCProvider
		var scopesJSON, domainsJSON string
		if err := rows.Scan(&p.TenantID, &p.ProviderID, &p.Name, &p.IssuerURL, &p.ClientID, &p.ClientSecret,
			&scopesJSON, &domainsJSON, &p.ClaimsMapping.TenantIDClaim, &p.ClaimsMapping.UserIDClaim,
			&p.ClaimsMapping.UsernameClaim, &p.ClaimsMapping.RolesClaim); err != nil {
			return nil, fmt.Errorf("scan oidc provider: %w", err)
		}
		if err := json.Unmarshal([]byte(scopesJSON), &p.Scopes); err != nil {
			return nil, fmt.Errorf("decode scopes: %w", err)
		}
		if err := json.Unmarshal([]byte(domainsJSON), &p.Domains); err != nil {
			return nil, fmt.Errorf("decode domains: %w", err)
		}
		out = append(out, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list oidc providers: %w", err)
	}
	return out, nil
}

func (s *Store) CreateOIDCProvider(ctx context.Context, p *tenantkit.OIDCProvider) error {
	scopesJSON, err := json.Marshal(p.Scopes)
	if err != nil {
		return fmt.Errorf("encode scopes: %w", err)
	}
	domainsJSON, err := json.Marshal(p.Domains)
	if err != nil {
		return fmt.Errorf("encode domains: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("create oidc provider: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `INSERT INTO oidc_providers (`+oidcProviderColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.TenantID, p.ProviderID, p.Name, p.IssuerURL, p.ClientID, p.ClientSecret, string(scopesJSON), string(domainsJSON),
		p.ClaimsMapping.TenantIDClaim, p.ClaimsMapping.UserIDClaim, p.ClaimsMapping.UsernameClaim, p.ClaimsMapping.RolesClaim)
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("create oidc provider: %w", err)
	}

	for _, d := range p.Domains {
		_, err := tx.ExecContext(ctx, `INSERT INTO oidc_provider_domains (domain, tenant_id, provider_id) VALUES (?, ?, ?)`, d, p.TenantID, p.ProviderID)
		if isUniqueViolation(err) {
			return store.ErrDomainTaken
		}
		if err != nil {
			return fmt.Errorf("create oidc provider: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("create oidc provider: %w", err)
	}
	return nil
}

func (s *Store) UpdateOIDCProvider(ctx context.Context, p *tenantkit.OIDCProvider) error {
	scopesJSON, err := json.Marshal(p.Scopes)
	if err != nil {
		return fmt.Errorf("encode scopes: %w", err)
	}
	domainsJSON, err := json.Marshal(p.Domains)
	if err != nil {
		return fmt.Errorf("encode domains: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("update oidc provider: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `UPDATE oidc_providers SET name = ?, issuer_url = ?, client_id = ?, client_secret = ?, scopes = ?, domains = ?, tenant_id_claim = ?, user_id_claim = ?, username_claim = ?, roles_claim = ? WHERE tenant_id = ? AND provider_id = ?`,
		p.Name, p.IssuerURL, p.ClientID, p.ClientSecret, string(scopesJSON), string(domainsJSON),
		p.ClaimsMapping.TenantIDClaim, p.ClaimsMapping.UserIDClaim, p.ClaimsMapping.UsernameClaim, p.ClaimsMapping.RolesClaim,
		p.TenantID, p.ProviderID)
	if err != nil {
		return fmt.Errorf("update oidc provider: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update oidc provider: %w", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_provider_domains WHERE tenant_id = ? AND provider_id = ?`, p.TenantID, p.ProviderID); err != nil {
		return fmt.Errorf("update oidc provider: %w", err)
	}
	for _, d := range p.Domains {
		_, err := tx.ExecContext(ctx, `INSERT INTO oidc_provider_domains (domain, tenant_id, provider_id) VALUES (?, ?, ?)`, d, p.TenantID, p.ProviderID)
		if isUniqueViolation(err) {
			return store.ErrDomainTaken
		}
		if err != nil {
			return fmt.Errorf("update oidc provider: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("update oidc provider: %w", err)
	}
	return nil
}

func (s *Store) DeleteOIDCProvider(ctx context.Context, tenantID, providerID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("delete oidc provider: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `DELETE FROM oidc_providers WHERE tenant_id = ? AND provider_id = ?`, tenantID, providerID)
	if err != nil {
		return fmt.Errorf("delete oidc provider: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete oidc provider: %w", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_provider_domains WHERE tenant_id = ? AND provider_id = ?`, tenantID, providerID); err != nil {
		return fmt.Errorf("delete oidc provider: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("delete oidc provider: %w", err)
	}
	return nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./store/sqlite/... -v`
Expected: `PASS` for `TestSQLiteConformsToOIDCProviderStore` and all its subtests, plus every pre-existing test in the package still passing.

- [ ] **Step 6: Commit**

```bash
git add store/sqlite/sqlite.go store/sqlite/sqlite_test.go
git commit -m "feat: add OIDCProviderStore sqlite implementation"
```

---

### Task 4: tenantkit/admin operations

**Files:**
- Modify: `admin/admin.go`
- Modify: `admin/admin_test.go`

**Interfaces:**
- Consumes: `store.OIDCProviderStore`, `tenantkit.OIDCProvider`, `tenantkit.ClaimsMapping` (Task 1); `store/memstore` (pre-existing, Task 2 adds the interface to it).
- Produces: `admin.RegisterOIDCProvider`, `admin.GetOIDCProvider`, `admin.ListOIDCProviders`, `admin.UpdateOIDCProvider`, `admin.RemoveOIDCProvider` -- Task 5 (CLI) calls these exact names/signatures.

- [ ] **Step 1: Write the failing tests**

Append to `admin/admin_test.go`:

```go
func testOIDCProvider(tenantID, providerID string) *tenantkit.OIDCProvider {
	return &tenantkit.OIDCProvider{
		TenantID:     tenantID,
		ProviderID:   providerID,
		Name:         "Acme Okta",
		IssuerURL:    "https://acme.okta.com",
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		Scopes:       []string{"openid", "email"},
		Domains:      []string{"acme.example"},
		ClaimsMapping: tenantkit.ClaimsMapping{
			TenantIDClaim: "https://acme.example/tenant_id",
		},
	}
}

func TestRegisterOIDCProvider(t *testing.T) {
	s := memstore.New()
	p := testOIDCProvider("acme", "okta")
	if err := admin.RegisterOIDCProvider(context.Background(), s, p); err != nil {
		t.Fatalf("RegisterOIDCProvider: %v", err)
	}
	got, err := s.GetOIDCProvider(context.Background(), "acme", "okta")
	if err != nil {
		t.Fatalf("GetOIDCProvider: %v", err)
	}
	if got.IssuerURL != p.IssuerURL {
		t.Errorf("GetOIDCProvider = %+v, want IssuerURL %q", got, p.IssuerURL)
	}
}

func TestRegisterOIDCProvider_MissingTenantIDClaim(t *testing.T) {
	s := memstore.New()
	p := testOIDCProvider("acme", "okta")
	p.ClaimsMapping.TenantIDClaim = ""
	if err := admin.RegisterOIDCProvider(context.Background(), s, p); err == nil {
		t.Fatal("expected an error when ClaimsMapping.TenantIDClaim is empty")
	}
}

func TestGetOIDCProvider(t *testing.T) {
	s := memstore.New()
	p := testOIDCProvider("acme", "okta")
	if err := admin.RegisterOIDCProvider(context.Background(), s, p); err != nil {
		t.Fatalf("RegisterOIDCProvider: %v", err)
	}
	got, err := admin.GetOIDCProvider(context.Background(), s, "acme", "okta")
	if err != nil {
		t.Fatalf("GetOIDCProvider: %v", err)
	}
	if got.ProviderID != "okta" {
		t.Errorf("GetOIDCProvider = %+v, want ProviderID okta", got)
	}
}

func TestListOIDCProviders(t *testing.T) {
	s := memstore.New()
	if err := admin.RegisterOIDCProvider(context.Background(), s, testOIDCProvider("acme", "okta")); err != nil {
		t.Fatalf("RegisterOIDCProvider: %v", err)
	}
	if err := admin.RegisterOIDCProvider(context.Background(), s, testOIDCProvider("acme", "google")); err != nil {
		t.Fatalf("RegisterOIDCProvider: %v", err)
	}
	got, err := admin.ListOIDCProviders(context.Background(), s, "acme")
	if err != nil {
		t.Fatalf("ListOIDCProviders: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("ListOIDCProviders = %+v, want 2 entries", got)
	}
}

func TestUpdateOIDCProvider(t *testing.T) {
	s := memstore.New()
	p := testOIDCProvider("acme", "okta")
	if err := admin.RegisterOIDCProvider(context.Background(), s, p); err != nil {
		t.Fatalf("RegisterOIDCProvider: %v", err)
	}
	p.Name = "Renamed"
	if err := admin.UpdateOIDCProvider(context.Background(), s, p); err != nil {
		t.Fatalf("UpdateOIDCProvider: %v", err)
	}
	got, err := s.GetOIDCProvider(context.Background(), "acme", "okta")
	if err != nil {
		t.Fatalf("GetOIDCProvider: %v", err)
	}
	if got.Name != "Renamed" {
		t.Errorf("GetOIDCProvider.Name = %q, want %q", got.Name, "Renamed")
	}
}

func TestRemoveOIDCProvider(t *testing.T) {
	s := memstore.New()
	p := testOIDCProvider("acme", "okta")
	if err := admin.RegisterOIDCProvider(context.Background(), s, p); err != nil {
		t.Fatalf("RegisterOIDCProvider: %v", err)
	}
	if err := admin.RemoveOIDCProvider(context.Background(), s, "acme", "okta"); err != nil {
		t.Fatalf("RemoveOIDCProvider: %v", err)
	}
	_, err := s.GetOIDCProvider(context.Background(), "acme", "okta")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetOIDCProvider after remove error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./admin/... -run OIDCProvider -v`
Expected: FAIL -- build error, `admin.RegisterOIDCProvider` (and the other four functions) don't exist yet.

- [ ] **Step 3: Implement the admin functions**

Append to `admin/admin.go`:

```go
// RegisterOIDCProvider validates p.ClaimsMapping.TenantIDClaim is set
// (the one field with no default -- without it, no token from this
// provider could ever be mapped to a tenant), then creates the
// registration.
func RegisterOIDCProvider(ctx context.Context, s store.OIDCProviderStore, p *tenantkit.OIDCProvider) error {
	if p.ClaimsMapping.TenantIDClaim == "" {
		return fmt.Errorf("register oidc provider: claims mapping TenantIDClaim is required")
	}
	if err := s.CreateOIDCProvider(ctx, p); err != nil {
		return fmt.Errorf("register oidc provider: %w", err)
	}
	return nil
}

// GetOIDCProvider returns the tenant's provider with the given ID.
func GetOIDCProvider(ctx context.Context, s store.OIDCProviderStore, tenantID, providerID string) (*tenantkit.OIDCProvider, error) {
	p, err := s.GetOIDCProvider(ctx, tenantID, providerID)
	if err != nil {
		return nil, fmt.Errorf("get oidc provider: %w", err)
	}
	return p, nil
}

// ListOIDCProviders returns every provider registered for tenantID.
func ListOIDCProviders(ctx context.Context, s store.OIDCProviderStore, tenantID string) ([]*tenantkit.OIDCProvider, error) {
	providers, err := s.ListOIDCProviders(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list oidc providers: %w", err)
	}
	return providers, nil
}

// UpdateOIDCProvider validates p.ClaimsMapping.TenantIDClaim is set (see
// RegisterOIDCProvider), then replaces the stored registration.
func UpdateOIDCProvider(ctx context.Context, s store.OIDCProviderStore, p *tenantkit.OIDCProvider) error {
	if p.ClaimsMapping.TenantIDClaim == "" {
		return fmt.Errorf("update oidc provider: claims mapping TenantIDClaim is required")
	}
	if err := s.UpdateOIDCProvider(ctx, p); err != nil {
		return fmt.Errorf("update oidc provider: %w", err)
	}
	return nil
}

// RemoveOIDCProvider removes the tenant's provider with the given ID.
func RemoveOIDCProvider(ctx context.Context, s store.OIDCProviderStore, tenantID, providerID string) error {
	if err := s.DeleteOIDCProvider(ctx, tenantID, providerID); err != nil {
		return fmt.Errorf("remove oidc provider: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./admin/... -v`
Expected: `PASS` for all six new tests, plus every pre-existing test in the package still passing.

- [ ] **Step 5: Commit**

```bash
git add admin/admin.go admin/admin_test.go
git commit -m "feat: add tenantkit/admin OIDC provider operations"
```

---

### Task 5: tenantkit-admin CLI subcommand

**Files:**
- Create: `tools/cmd/tenantkit-admin/oidc.go`
- Create: `tools/cmd/tenantkit-admin/oidc_test.go`
- Modify: `tools/cmd/tenantkit-admin/main.go`

**Interfaces:**
- Consumes: `admin.RegisterOIDCProvider`, `admin.GetOIDCProvider`, `admin.ListOIDCProviders`, `admin.UpdateOIDCProvider`, `admin.RemoveOIDCProvider` (Task 4); `openStore`, `confirm`, `execCmd` (pre-existing in this package).

- [ ] **Step 1: Write the failing tests**

Create `tools/cmd/tenantkit-admin/oidc_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

func TestOIDCRegisterAndShow(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	out, err := execCmd(t, "", "oidc", "register", "--db", dbPath,
		"--tenant", "acme", "--provider-id", "okta", "--name", "Acme Okta",
		"--issuer", "https://acme.okta.com", "--client-id", "cid", "--client-secret", "csecret",
		"--tenant-id-claim", "https://acme.example/tenant_id")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "registered") {
		t.Errorf("output = %q, want confirmation of registration", out)
	}

	showOut, err := execCmd(t, "", "oidc", "show", "--db", dbPath, "--tenant", "acme", "--provider-id", "okta")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, showOut)
	}
	if !strings.Contains(showOut, "https://acme.okta.com") {
		t.Errorf("show output = %q, want it to contain the issuer URL", showOut)
	}
}

func TestOIDCRegister_RequiresTenantIDClaim(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	_, err := execCmd(t, "", "oidc", "register", "--db", dbPath,
		"--tenant", "acme", "--provider-id", "okta",
		"--issuer", "https://acme.okta.com", "--client-id", "cid", "--client-secret", "csecret")
	if err == nil {
		t.Fatal("expected an error when --tenant-id-claim is missing")
	}
}

func TestOIDCList(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	for _, providerID := range []string{"okta", "google"} {
		if _, err := execCmd(t, "", "oidc", "register", "--db", dbPath,
			"--tenant", "acme", "--provider-id", providerID,
			"--issuer", "https://idp.example/"+providerID, "--client-id", "cid", "--client-secret", "csecret",
			"--tenant-id-claim", "tid"); err != nil {
			t.Fatalf("register %s: %v", providerID, err)
		}
	}

	out, err := execCmd(t, "", "oidc", "list", "--db", dbPath, "--tenant", "acme")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "okta") || !strings.Contains(out, "google") {
		t.Errorf("list output = %q, want both provider IDs", out)
	}
}

func TestOIDCUpdate(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := execCmd(t, "", "oidc", "register", "--db", dbPath,
		"--tenant", "acme", "--provider-id", "okta", "--name", "Old Name",
		"--issuer", "https://acme.okta.com", "--client-id", "cid", "--client-secret", "csecret",
		"--tenant-id-claim", "tid"); err != nil {
		t.Fatalf("register: %v", err)
	}

	out, err := execCmd(t, "", "oidc", "update", "--db", dbPath,
		"--tenant", "acme", "--provider-id", "okta", "--name", "New Name",
		"--issuer", "https://acme.okta.com", "--client-id", "cid", "--client-secret", "csecret",
		"--tenant-id-claim", "tid")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "updated") {
		t.Errorf("output = %q, want confirmation of update", out)
	}

	showOut, err := execCmd(t, "", "oidc", "show", "--db", dbPath, "--tenant", "acme", "--provider-id", "okta")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, showOut)
	}
	if !strings.Contains(showOut, "New Name") {
		t.Errorf("show output after update = %q, want it to contain %q", showOut, "New Name")
	}
}

func TestOIDCRemove(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := execCmd(t, "", "oidc", "register", "--db", dbPath,
		"--tenant", "acme", "--provider-id", "okta",
		"--issuer", "https://acme.okta.com", "--client-id", "cid", "--client-secret", "csecret",
		"--tenant-id-claim", "tid"); err != nil {
		t.Fatalf("register: %v", err)
	}

	out, err := execCmd(t, "y\n", "oidc", "remove", "--db", dbPath, "--tenant", "acme", "--provider-id", "okta")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "removed") {
		t.Errorf("output = %q, want confirmation of removal", out)
	}

	_, err = execCmd(t, "", "oidc", "show", "--db", dbPath, "--tenant", "acme", "--provider-id", "okta")
	if err == nil {
		t.Fatal("expected an error showing a removed provider")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./tools/cmd/tenantkit-admin/... -run TestOIDC -v`
Expected: FAIL -- build error or "unknown command \"oidc\"", since the `oidc` subcommand doesn't exist yet.

- [ ] **Step 3: Implement the CLI subcommand**

Create `tools/cmd/tenantkit-admin/oidc.go`:

```go
package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/admin"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func newOIDCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oidc",
		Short: "Manage per-tenant OIDC IdP registrations",
	}
	cmd.AddCommand(newOIDCRegisterCmd())
	cmd.AddCommand(newOIDCListCmd())
	cmd.AddCommand(newOIDCShowCmd())
	cmd.AddCommand(newOIDCUpdateCmd())
	cmd.AddCommand(newOIDCRemoveCmd())
	return cmd
}

func splitCommaList(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

// oidcProviderFlags holds the flags shared by "register" and "update"
// (both take the same full set of provider fields).
type oidcProviderFlags struct {
	tenantID      string
	providerID    string
	name          string
	issuerURL     string
	clientID      string
	clientSecret  string
	scopesRaw     string
	domainsRaw    string
	tenantIDClaim string
	userIDClaim   string
	usernameClaim string
	rolesClaim    string
}

// bind registers this struct's flags on fs -- shared between "register"
// and "update" since both take the identical set of provider fields.
func (f *oidcProviderFlags) bind(fs *pflag.FlagSet) {
	fs.StringVar(&f.tenantID, "tenant", "", "tenant ID")
	fs.StringVar(&f.providerID, "provider-id", "", "provider ID slug, unique within the tenant (e.g. \"okta\")")
	fs.StringVar(&f.name, "name", "", "display name for a login picker")
	fs.StringVar(&f.issuerURL, "issuer", "", "OIDC issuer URL")
	fs.StringVar(&f.clientID, "client-id", "", "OAuth2 client ID")
	fs.StringVar(&f.clientSecret, "client-secret", "", "OAuth2 client secret")
	fs.StringVar(&f.scopesRaw, "scopes", "", `comma-separated OAuth2 scopes in addition to "openid" (optional)`)
	fs.StringVar(&f.domainsRaw, "domains", "", "comma-separated email domains this provider claims (optional)")
	fs.StringVar(&f.tenantIDClaim, "tenant-id-claim", "", "ID token claim holding the tenant ID")
	fs.StringVar(&f.userIDClaim, "user-id-claim", "", `ID token claim holding the user ID (default "sub")`)
	fs.StringVar(&f.usernameClaim, "username-claim", "", `ID token claim holding the username (default "email")`)
	fs.StringVar(&f.rolesClaim, "roles-claim", "", `ID token claim holding roles (default "roles")`)
}

func (f *oidcProviderFlags) validate() error {
	if f.tenantID == "" {
		return fmt.Errorf("--tenant is required")
	}
	if f.providerID == "" {
		return fmt.Errorf("--provider-id is required")
	}
	if f.issuerURL == "" {
		return fmt.Errorf("--issuer is required")
	}
	if f.clientID == "" {
		return fmt.Errorf("--client-id is required")
	}
	if f.clientSecret == "" {
		return fmt.Errorf("--client-secret is required")
	}
	if f.tenantIDClaim == "" {
		return fmt.Errorf("--tenant-id-claim is required")
	}
	return nil
}

func (f *oidcProviderFlags) toProvider() *tenantkit.OIDCProvider {
	return &tenantkit.OIDCProvider{
		TenantID:     f.tenantID,
		ProviderID:   f.providerID,
		Name:         f.name,
		IssuerURL:    f.issuerURL,
		ClientID:     f.clientID,
		ClientSecret: f.clientSecret,
		Scopes:       splitCommaList(f.scopesRaw),
		Domains:      splitCommaList(f.domainsRaw),
		ClaimsMapping: tenantkit.ClaimsMapping{
			TenantIDClaim: f.tenantIDClaim,
			UserIDClaim:   f.userIDClaim,
			UsernameClaim: f.usernameClaim,
			RolesClaim:    f.rolesClaim,
		},
	}
}

func newOIDCRegisterCmd() *cobra.Command {
	var flags oidcProviderFlags
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new OIDC provider for a tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := flags.validate(); err != nil {
				return err
			}
			p := flags.toProvider()

			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintf(out, "[dry-run] would register oidc provider %q for tenant %q\n", p.ProviderID, p.TenantID)
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			if err := admin.RegisterOIDCProvider(cmd.Context(), db, p); err != nil {
				return err
			}
			fmt.Fprintf(out, "registered oidc provider %q for tenant %q\n", p.ProviderID, p.TenantID)
			return nil
		},
	}
	flags.bind(cmd.Flags())
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	return cmd
}

func newOIDCUpdateCmd() *cobra.Command {
	var flags oidcProviderFlags
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Replace a tenant's registered OIDC provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := flags.validate(); err != nil {
				return err
			}
			p := flags.toProvider()

			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintf(out, "[dry-run] would update oidc provider %q for tenant %q\n", p.ProviderID, p.TenantID)
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			if err := admin.UpdateOIDCProvider(cmd.Context(), db, p); err != nil {
				return err
			}
			fmt.Fprintf(out, "updated oidc provider %q for tenant %q\n", p.ProviderID, p.TenantID)
			return nil
		},
	}
	flags.bind(cmd.Flags())
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	return cmd
}

func newOIDCListCmd() *cobra.Command {
	var (
		tenantID string
		asJSON   bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a tenant's registered OIDC providers",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return fmt.Errorf("--tenant is required")
			}
			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			providers, err := admin.ListOIDCProviders(cmd.Context(), db, tenantID)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(providers)
			}
			for _, p := range providers {
				fmt.Fprintf(out, "%s\t%s\t%s\n", p.ProviderID, p.Name, p.IssuerURL)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func newOIDCShowCmd() *cobra.Command {
	var (
		tenantID   string
		providerID string
	)
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show a tenant's registered OIDC provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return fmt.Errorf("--tenant is required")
			}
			if providerID == "" {
				return fmt.Errorf("--provider-id is required")
			}
			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			p, err := admin.GetOIDCProvider(cmd.Context(), db, tenantID, providerID)
			if err != nil {
				return err
			}

			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(p)
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID")
	cmd.Flags().StringVar(&providerID, "provider-id", "", "provider ID")
	return cmd
}

func newOIDCRemoveCmd() *cobra.Command {
	var (
		tenantID   string
		providerID string
		yes        bool
		dryRun     bool
	)
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a tenant's registered OIDC provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return fmt.Errorf("--tenant is required")
			}
			if providerID == "" {
				return fmt.Errorf("--provider-id is required")
			}
			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintf(out, "[dry-run] would remove oidc provider %q for tenant %q\n", providerID, tenantID)
				return nil
			}
			if !yes && !confirm(cmd, fmt.Sprintf("Remove oidc provider %q for tenant %q?", providerID, tenantID)) {
				fmt.Fprintln(out, "aborted")
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			if err := admin.RemoveOIDCProvider(cmd.Context(), db, tenantID, providerID); err != nil {
				return err
			}
			fmt.Fprintln(out, "removed")
			return nil
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID")
	cmd.Flags().StringVar(&providerID, "provider-id", "", "provider ID")
	cmd.Flags().BoolVarP(&yes, "yes", "f", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	return cmd
}
```

`oidcProviderFlags.bind` takes `cmd.Flags()` (a `*pflag.FlagSet`)
directly -- `github.com/spf13/pflag` is already an indirect dependency
via `cobra`, so this adds no new dependency, just a direct import.

- [ ] **Step 4: Register the subcommand**

In `tools/cmd/tenantkit-admin/main.go`, add one line to `newRootCmd`:

```go
	cmd.AddCommand(newTenantCmd())
	cmd.AddCommand(newKeyCmd())
	cmd.AddCommand(newUserCmd())
	cmd.AddCommand(newCertCmd())
	cmd.AddCommand(newOIDCCmd())
	return cmd
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./tools/cmd/tenantkit-admin/... -v`
Expected: `PASS` for all five new `TestOIDC*` tests, plus every pre-existing test in the package still passing.

- [ ] **Step 6: Commit**

```bash
git add tools/cmd/tenantkit-admin/oidc.go tools/cmd/tenantkit-admin/oidc_test.go tools/cmd/tenantkit-admin/main.go
git commit -m "feat: add tenantkit-admin oidc CLI subcommand"
```

---

### Task 6: Update README status

**Files:**
- Modify: `README.md`

**Interfaces:** None (documentation only).

- [ ] **Step 1: Update the "What it deliberately doesn't do" bullet**

Find:

```
- **No database access.** tenantkit defines storage interfaces
  (`TenantStore`, `UserStore`, `APIKeyStore`, `ClientCertStore`); it never
  talks to a database itself. You implement those interfaces against
  whatever you're already using — SQL, NoSQL, or otherwise.
```

Replace with:

```
- **No database access.** tenantkit defines storage interfaces
  (`TenantStore`, `UserStore`, `APIKeyStore`, `ClientCertStore`,
  `OIDCProviderStore`); it never talks to a database itself. You
  implement those interfaces against whatever you're already using —
  SQL, NoSQL, or otherwise.
```

- [ ] **Step 2: Update the Status section**

Find:

```
The foundation, tenant resolution and middleware, admin tooling, and
password/passkey identity are implemented: core types, the four store
interfaces, an in-memory reference store (`store/memstore`) and a
persistent SQLite-backed store (`store/sqlite`), an interface-conformance
```

Replace with:

```
The foundation, tenant resolution and middleware, admin tooling, and
password/passkey identity are implemented: core types, the five store
interfaces (including per-tenant OIDC IdP registration via
`OIDCProviderStore`), an in-memory reference store (`store/memstore`)
and a persistent SQLite-backed store (`store/sqlite`), an
interface-conformance
```

- [ ] **Step 3: Verify the changes**

Run: `grep -n "OIDCProviderStore\|five store interfaces" README.md`
Expected: two matches, one in each edited section.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: update README Status for store.OIDCProviderStore"
```

---

## Final Verification

- [ ] Run the full test suite: `go build ./... && go vet ./... && gofmt -l . && go test ./...`
  Expected: all packages build, vet clean, `gofmt -l .` prints nothing, all tests `PASS`.
- [ ] Confirm the `tools/` submodule also builds and tests clean: from `tools/`, run `go build ./... && go vet ./... && go test ./...`.
- [ ] Push the branch and let CI (`.github/workflows/ci.yml`) confirm build+vet+test on the PR before merging to master, per this repo's existing merge gate.
