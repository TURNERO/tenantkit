# Tenant Resolution & Middleware Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give tenantkit a working tenant-resolution layer -- the `Source`/`TenantResolver` abstractions, four built-in resolvers (API-key, client-cert, header, subdomain), the `IdentityProvider` interface, and `net/http`/gRPC middleware that wires them together against the foundation's store interfaces.

**Architecture:** `tenantkit/resolve` defines a transport-agnostic `Source` interface (headers, TLS peer certs, host) so the same `TenantResolver` implementations work against both HTTP and gRPC. `tenantkit/identity` defines only the `IdentityProvider` interface (concrete implementations are a separate future plan). `tenantkit/httpmw` and `tenantkit/grpcmw` each wrap their transport's request shape into a `Source` and run the same resolution/authentication flow.

**Tech Stack:** Go, `github.com/TURNERO/tenantkit` module (already exists from the foundation plan). Adds `google.golang.org/grpc v1.82.1` as the module's first third-party dependency -- pulls in `golang.org/x/net`, `golang.org/x/sys`, `golang.org/x/text`, `google.golang.org/genproto/googleapis/rpc`, `google.golang.org/protobuf` as indirect deps. Adding it also raises the module's `go` directive from `1.23` to `1.25.0` (grpc-go v1.82.1's own `go.mod` requires it) -- confirmed by actually running `go get` in a scratch module before writing this plan, not assumed.

## Global Constraints

- `Source` is the transport-agnostic core of this plan: `Header(key string) string`, `TLSPeerCertificates() []*x509.Certificate`, `Host() string`. Every resolver, `IdentityProvider`, and both middlewares are written against `Source`, never against `*http.Request` or gRPC types directly (only the two adapters -- `httpmw`'s `httpSource` and `grpcmw`'s `grpcSource` -- touch transport-specific APIs).
- `TenantResolver.ResolveTenant` contract: `ok=false, nil` means "found no credential material of this kind" (try the next resolver). A non-nil `err` means "found credential material, but it's invalid" -- the chain stops immediately, it never falls through to the next resolver on invalid credentials (falling through would let a rejected credential be silently retried as a different, possibly spoofable, strategy).
- `tenantkit/identity` in this plan is the `IdentityProvider` interface only. `identity/local` and `identity/oidc` (concrete implementations) are a separate future plan -- do not implement them here.
- The session/identity-claim `TenantResolver` strategy is explicitly out of scope for this plan (deferred to the Identity plan, since it needs the session-token format decided there first -- tracked as issue #1). This plan ships exactly four resolvers: API-key, client-cert, header, subdomain.
- `IdentityProvider` is optional per `httpmw.Config`/`grpcmw.Config` (a nil value is valid and skips identity resolution entirely) -- a consumer authenticating only service credentials, with no human users, must not be forced to wire one up.
- Error mapping is fixed: no/invalid credentials -> HTTP `401`/`codes.Unauthenticated`. Resolved-but-not-found tenant, inactive tenant, or an identity/tenant mismatch -> HTTP `403`/`codes.PermissionDenied`.
- `httpmw.ErrorHandler` is optional; `httpmw.New` uses a minimal plain-text (`http.Error`-style) default when unset. `grpcmw` has no equivalent -- gRPC failures are reported via `status.Error`, there is no response body to customize.
- A cert fingerprint is computed directly with `crypto/sha256` on the DER-encoded certificate (`cert.Raw`), never via `store.HashSecret` -- a fingerprint isn't a secret being hashed for storage, it's already a public identifier, so reusing that helper would be a semantic mismatch even though the underlying operation is identical.
- Every new package's tests use `crypto/tls`/`crypto/x509`-generated in-process fixtures (self-signed certs, `httptest`, direct interceptor invocation with manually built contexts) -- no real network, no testcontainers, matching the foundation's testing bar.

---

### Task 1: `tenantkit/resolve` foundation, API-key resolver, client-cert resolver

**Files:**
- Create: `resolve/resolve.go`
- Create: `resolve/apikey.go`
- Create: `resolve/clientcert.go`
- Test: `resolve/fake_source_test.go`
- Test: `resolve/chain_test.go`
- Test: `resolve/apikey_test.go`
- Test: `resolve/clientcert_test.go`

**Interfaces:**
- Consumes: `tenantkit.Tenant`/`APIKey`/`ClientCert`, `store.APIKeyStore`/`ClientCertStore`, `store.HashSecret`, `store.GenerateSecret` (all from the foundation plan, already in the repo), `store/memstore` (test-only).
- Produces: `resolve.Source`, `resolve.TenantResolver`, `resolve.RunChain(ctx, []TenantResolver, Source) (string, error)`, `resolve.NewAPIKeyResolver(store.APIKeyStore) TenantResolver`, `resolve.NewClientCertResolver(store.ClientCertStore) TenantResolver`. Every later task in this plan depends on `Source`, `TenantResolver`, and `RunChain` with these exact signatures.

- [ ] **Step 1: Write the failing tests**

Create `resolve/fake_source_test.go` (shared fixture used by every test file in this package):

```go
package resolve_test

import "crypto/x509"

type fakeSource struct {
	headers map[string]string
	certs   []*x509.Certificate
	host    string
}

func (s fakeSource) Header(key string) string                 { return s.headers[key] }
func (s fakeSource) TLSPeerCertificates() []*x509.Certificate { return s.certs }
func (s fakeSource) Host() string                             { return s.host }
```

Create `resolve/chain_test.go`:

```go
package resolve_test

import (
	"context"
	"errors"
	"testing"

	"github.com/TURNERO/tenantkit/resolve"
)

type stubResolver struct {
	tenantID string
	ok       bool
	err      error
}

func (s stubResolver) ResolveTenant(ctx context.Context, src resolve.Source) (string, bool, error) {
	return s.tenantID, s.ok, s.err
}

func TestRunChain_FirstMatchWins(t *testing.T) {
	tenantID, err := resolve.RunChain(context.Background(), []resolve.TenantResolver{
		stubResolver{ok: false},
		stubResolver{tenantID: "acme", ok: true},
		stubResolver{tenantID: "should-not-be-reached", ok: true},
	}, fakeSource{})
	if err != nil {
		t.Fatalf("RunChain: %v", err)
	}
	if tenantID != "acme" {
		t.Errorf("RunChain tenantID = %q, want acme", tenantID)
	}
}

func TestRunChain_NoResolverMatches(t *testing.T) {
	tenantID, err := resolve.RunChain(context.Background(), []resolve.TenantResolver{
		stubResolver{ok: false},
		stubResolver{ok: false},
	}, fakeSource{})
	if err != nil {
		t.Fatalf("RunChain: %v", err)
	}
	if tenantID != "" {
		t.Errorf("RunChain tenantID = %q, want empty", tenantID)
	}
}

func TestRunChain_StopsOnFirstError(t *testing.T) {
	wantErr := errors.New("invalid credential")
	_, err := resolve.RunChain(context.Background(), []resolve.TenantResolver{
		stubResolver{ok: true, err: wantErr},
		stubResolver{tenantID: "should-not-be-reached", ok: true},
	}, fakeSource{})
	if !errors.Is(err, wantErr) {
		t.Errorf("RunChain error = %v, want %v", err, wantErr)
	}
}
```

Create `resolve/apikey_test.go`:

```go
package resolve_test

import (
	"context"
	"testing"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
	"github.com/TURNERO/tenantkit/store/memstore"
)

func TestAPIKeyResolver_ResolvesValidKey(t *testing.T) {
	ks := memstore.New()
	ctx := context.Background()
	secret, err := store.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if err := ks.CreateAPIKey(ctx, &tenantkit.APIKey{Hash: store.HashSecret(secret), TenantID: "acme"}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	r := resolve.NewAPIKeyResolver(ks)
	src := fakeSource{headers: map[string]string{"Authorization": "Bearer " + secret}}

	tenantID, ok, err := r.ResolveTenant(ctx, src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true for a present Authorization header")
	}
	if tenantID != "acme" {
		t.Errorf("ResolveTenant tenantID = %q, want acme", tenantID)
	}
}

func TestAPIKeyResolver_NoAuthorizationHeader(t *testing.T) {
	r := resolve.NewAPIKeyResolver(memstore.New())
	tenantID, ok, err := r.ResolveTenant(context.Background(), fakeSource{})
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false when no Authorization header is present")
	}
	if tenantID != "" {
		t.Errorf("ResolveTenant tenantID = %q, want empty", tenantID)
	}
}

func TestAPIKeyResolver_NonBearerAuthorizationHeader(t *testing.T) {
	r := resolve.NewAPIKeyResolver(memstore.New())
	src := fakeSource{headers: map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}}
	_, ok, err := r.ResolveTenant(context.Background(), src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false for a non-Bearer Authorization header")
	}
}

func TestAPIKeyResolver_UnknownKeyFailsChain(t *testing.T) {
	r := resolve.NewAPIKeyResolver(memstore.New())
	src := fakeSource{headers: map[string]string{"Authorization": "Bearer does-not-exist"}}
	_, ok, err := r.ResolveTenant(context.Background(), src)
	if err == nil {
		t.Fatal("expected an error for an unrecognized API key, got nil")
	}
	if !ok {
		t.Error("expected ok=true when credential material was present but invalid, so the chain does not fall through")
	}
}
```

Create `resolve/clientcert_test.go`:

```go
package resolve_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store/memstore"
)

func generateTestCert(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func fingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func TestClientCertResolver_ResolvesKnownCert(t *testing.T) {
	cert := generateTestCert(t, "acme-writer")
	cs := memstore.New()
	ctx := context.Background()
	if err := cs.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: fingerprintOf(cert), TenantID: "acme"}); err != nil {
		t.Fatalf("CreateClientCert: %v", err)
	}

	r := resolve.NewClientCertResolver(cs)
	src := fakeSource{certs: []*x509.Certificate{cert}}

	tenantID, ok, err := r.ResolveTenant(ctx, src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true for a present client certificate")
	}
	if tenantID != "acme" {
		t.Errorf("ResolveTenant tenantID = %q, want acme", tenantID)
	}
}

func TestClientCertResolver_NoPeerCertificates(t *testing.T) {
	r := resolve.NewClientCertResolver(memstore.New())
	tenantID, ok, err := r.ResolveTenant(context.Background(), fakeSource{})
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false when no peer certificates are present")
	}
	if tenantID != "" {
		t.Errorf("ResolveTenant tenantID = %q, want empty", tenantID)
	}
}

func TestClientCertResolver_UnknownCertFailsChain(t *testing.T) {
	cert := generateTestCert(t, "unknown")
	r := resolve.NewClientCertResolver(memstore.New())
	src := fakeSource{certs: []*x509.Certificate{cert}}

	_, ok, err := r.ResolveTenant(context.Background(), src)
	if err == nil {
		t.Fatal("expected an error for an unrecognized client certificate, got nil")
	}
	if !ok {
		t.Error("expected ok=true when credential material was present but invalid, so the chain does not fall through")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./resolve/... -v`

Expected: FAIL to compile -- package `resolve` doesn't exist yet.

- [ ] **Step 3: Write `resolve/resolve.go`**

```go
// Package resolve provides tenantkit's tenant-resolution abstractions:
// Source, a transport-agnostic view of an incoming request, and
// TenantResolver, a pluggable strategy for extracting a tenant ID from
// one. httpmw and grpcmw each wrap their transport's request shape into
// a Source, so the same TenantResolver implementations work against both
// HTTP and gRPC traffic.
package resolve

import (
	"context"
	"crypto/x509"
)

// Source abstracts over the transport (HTTP or gRPC) so the same
// TenantResolver/IdentityProvider implementations work against both.
type Source interface {
	// Header returns the value of the given header/metadata key, or ""
	// if not present. For a repeated key, implementations return the
	// first value.
	Header(key string) string
	// TLSPeerCertificates returns the already-TLS-verified client
	// certificate chain, or nil if the connection isn't using mTLS.
	TLSPeerCertificates() []*x509.Certificate
	// Host returns the request's target host (HTTP Host header /
	// gRPC :authority), without a port.
	Host() string
}

// TenantResolver extracts a tenant ID from src.
type TenantResolver interface {
	// ok=false means "found no credential material of this kind" --
	// distinct from an error, which means "found something, but it's
	// invalid." A resolver chain stops at the first resolver that
	// returns ok=true or a non-nil err; only ok=false, nil lets the
	// chain continue to the next resolver.
	ResolveTenant(ctx context.Context, src Source) (tenantID string, ok bool, err error)
}

// RunChain tries each resolver in order and returns the first tenant ID
// found. It returns ("", nil) if no resolver found any credential
// material (every resolver returned ok=false), and stops immediately
// with the first non-nil error a resolver returns -- see TenantResolver's
// doc comment for why falling through on an error would be unsafe.
func RunChain(ctx context.Context, resolvers []TenantResolver, src Source) (tenantID string, err error) {
	for _, r := range resolvers {
		tenantID, ok, err := r.ResolveTenant(ctx, src)
		if err != nil {
			return "", err
		}
		if ok {
			return tenantID, nil
		}
	}
	return "", nil
}
```

- [ ] **Step 4: Write `resolve/apikey.go`**

```go
package resolve

import (
	"context"
	"fmt"
	"strings"

	"github.com/TURNERO/tenantkit/store"
)

const bearerPrefix = "Bearer "

// NewAPIKeyResolver returns a TenantResolver that reads a bearer token
// from the Authorization header and looks it up via ks.
func NewAPIKeyResolver(ks store.APIKeyStore) TenantResolver {
	return &apiKeyResolver{ks: ks}
}

type apiKeyResolver struct {
	ks store.APIKeyStore
}

func (r *apiKeyResolver) ResolveTenant(ctx context.Context, src Source) (string, bool, error) {
	auth := src.Header("Authorization")
	if !strings.HasPrefix(auth, bearerPrefix) {
		return "", false, nil
	}
	token := strings.TrimPrefix(auth, bearerPrefix)
	key, err := r.ks.GetAPIKeyByHash(ctx, store.HashSecret(token))
	if err != nil {
		return "", true, fmt.Errorf("resolve tenant from api key: %w", err)
	}
	return key.TenantID, true, nil
}
```

- [ ] **Step 5: Write `resolve/clientcert.go`**

```go
package resolve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/TURNERO/tenantkit/store"
)

// NewClientCertResolver returns a TenantResolver that reads the
// already-TLS-verified peer certificate and looks up its fingerprint via
// cs.
func NewClientCertResolver(cs store.ClientCertStore) TenantResolver {
	return &clientCertResolver{cs: cs}
}

type clientCertResolver struct {
	cs store.ClientCertStore
}

func (r *clientCertResolver) ResolveTenant(ctx context.Context, src Source) (string, bool, error) {
	certs := src.TLSPeerCertificates()
	if len(certs) == 0 {
		return "", false, nil
	}
	sum := sha256.Sum256(certs[0].Raw)
	fingerprint := hex.EncodeToString(sum[:])

	cert, err := r.cs.GetClientCertByFingerprint(ctx, fingerprint)
	if err != nil {
		return "", true, fmt.Errorf("resolve tenant from client cert: %w", err)
	}
	return cert.TenantID, true, nil
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./resolve/... -v`

Expected: PASS, all tests in `resolve/*_test.go`.

- [ ] **Step 7: Run `go vet` and commit**

Run: `go vet ./resolve/...`

Expected: clean.

```bash
git add resolve/resolve.go resolve/apikey.go resolve/clientcert.go resolve/fake_source_test.go resolve/chain_test.go resolve/apikey_test.go resolve/clientcert_test.go
git commit -m "feat: add resolve package foundation, API-key and client-cert resolvers

Source is the transport-agnostic core of this plan (Header/
TLSPeerCertificates/Host) -- both httpmw and grpcmw (later tasks) wrap
their transport's request shape into a Source, so TenantResolver
implementations here work unmodified against HTTP and gRPC. RunChain
implements the resolver-chain contract: first ok=true or non-nil err
wins, no falling through on invalid credentials. API-key and
client-cert resolvers are the two that need a store lookup; header and
subdomain (next task) don't."
```

---

### Task 2: Header and subdomain resolvers

**Files:**
- Create: `resolve/header.go`
- Create: `resolve/subdomain.go`
- Test: `resolve/header_test.go`
- Test: `resolve/subdomain_test.go`

**Interfaces:**
- Consumes: `resolve.Source`, `resolve.TenantResolver` (Task 1).
- Produces: `resolve.NewHeaderResolver(headerName string) TenantResolver`, `resolve.NewSubdomainResolver() TenantResolver`.

- [ ] **Step 1: Write the failing tests**

Create `resolve/header_test.go`:

```go
package resolve_test

import (
	"context"
	"testing"

	"github.com/TURNERO/tenantkit/resolve"
)

func TestHeaderResolver_ResolvesFromHeader(t *testing.T) {
	r := resolve.NewHeaderResolver("X-Tenant-ID")
	src := fakeSource{headers: map[string]string{"X-Tenant-ID": "acme"}}

	tenantID, ok, err := r.ResolveTenant(context.Background(), src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true when the header is present")
	}
	if tenantID != "acme" {
		t.Errorf("ResolveTenant tenantID = %q, want acme", tenantID)
	}
}

func TestHeaderResolver_MissingHeader(t *testing.T) {
	r := resolve.NewHeaderResolver("X-Tenant-ID")
	tenantID, ok, err := r.ResolveTenant(context.Background(), fakeSource{})
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false when the header is absent")
	}
	if tenantID != "" {
		t.Errorf("ResolveTenant tenantID = %q, want empty", tenantID)
	}
}

func TestHeaderResolver_UsesConfiguredHeaderName(t *testing.T) {
	r := resolve.NewHeaderResolver("X-Custom-Tenant")
	src := fakeSource{headers: map[string]string{"X-Tenant-ID": "acme"}}

	_, ok, err := r.ResolveTenant(context.Background(), src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false when only a differently-named header is present")
	}
}
```

Create `resolve/subdomain_test.go`:

```go
package resolve_test

import (
	"context"
	"testing"

	"github.com/TURNERO/tenantkit/resolve"
)

func TestSubdomainResolver_ResolvesFirstLabel(t *testing.T) {
	r := resolve.NewSubdomainResolver()
	src := fakeSource{host: "acme.example.com"}

	tenantID, ok, err := r.ResolveTenant(context.Background(), src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true for a host with a subdomain")
	}
	if tenantID != "acme" {
		t.Errorf("ResolveTenant tenantID = %q, want acme", tenantID)
	}
}

func TestSubdomainResolver_NoDotInHost(t *testing.T) {
	r := resolve.NewSubdomainResolver()
	src := fakeSource{host: "localhost"}

	tenantID, ok, err := r.ResolveTenant(context.Background(), src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false for a host with no subdomain")
	}
	if tenantID != "" {
		t.Errorf("ResolveTenant tenantID = %q, want empty", tenantID)
	}
}

func TestSubdomainResolver_EmptyHost(t *testing.T) {
	r := resolve.NewSubdomainResolver()
	_, ok, err := r.ResolveTenant(context.Background(), fakeSource{})
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false for an empty host")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./resolve/... -run 'TestHeaderResolver|TestSubdomainResolver' -v`

Expected: FAIL to compile -- `resolve.NewHeaderResolver`, `resolve.NewSubdomainResolver` undefined.

- [ ] **Step 3: Write `resolve/header.go`**

```go
package resolve

import "context"

// NewHeaderResolver returns a TenantResolver that reads the tenant ID
// directly from the given header, with no store lookup. Intended for
// trusted-proxy deployments where something upstream already resolved
// the tenant -- tenant existence/active-checking still happens
// downstream via TenantStore.GetTenant regardless of which resolver
// produced the ID.
func NewHeaderResolver(headerName string) TenantResolver {
	return &headerResolver{headerName: headerName}
}

type headerResolver struct {
	headerName string
}

func (r *headerResolver) ResolveTenant(ctx context.Context, src Source) (string, bool, error) {
	v := src.Header(r.headerName)
	if v == "" {
		return "", false, nil
	}
	return v, true, nil
}
```

- [ ] **Step 4: Write `resolve/subdomain.go`**

```go
package resolve

import (
	"context"
	"strings"
)

// NewSubdomainResolver returns a TenantResolver that takes the first
// dot-separated label of the request's Host as the tenant ID.
func NewSubdomainResolver() TenantResolver {
	return &subdomainResolver{}
}

type subdomainResolver struct{}

func (r *subdomainResolver) ResolveTenant(ctx context.Context, src Source) (string, bool, error) {
	host := src.Host()
	i := strings.Index(host, ".")
	if i <= 0 {
		return "", false, nil
	}
	return host[:i], true, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./resolve/... -v`

Expected: PASS, all tests in the `resolve` package (Task 1's and Task 2's).

- [ ] **Step 6: Commit**

```bash
git add resolve/header.go resolve/subdomain.go resolve/header_test.go resolve/subdomain_test.go
git commit -m "feat: add header and subdomain resolvers

Both read directly from Source with no store lookup -- tenant
existence/active-checking happens downstream in httpmw/grpcmw
regardless of which resolver produced the ID, so a header/subdomain
resolver can't be used to spoof a nonexistent tenant into existing."
```

---

### Task 3: `tenantkit/identity` interface and `tenantkit/httpmw`

**Files:**
- Create: `identity/identity.go`
- Create: `httpmw/source.go`
- Create: `httpmw/httpmw.go`
- Test: `httpmw/source_test.go`
- Test: `httpmw/httpmw_test.go`

**Interfaces:**
- Consumes: `tenantkit.Tenant`/`Identity`, `tenantkit.WithTenant`/`TenantFromContext`/`WithIdentity`/`IdentityFromContext` (foundation), `store.TenantStore` (foundation), `resolve.Source`/`TenantResolver`/`RunChain` (Task 1/2).
- Produces: `identity.IdentityProvider`, `httpmw.ErrorHandler`, `httpmw.Config`, `httpmw.New(Config) func(http.Handler) http.Handler`. Task 4 (`grpcmw`) depends on `identity.IdentityProvider` with this exact signature and mirrors `httpmw.Config`'s shape (minus `ErrorHandler`).

- [ ] **Step 1: Write `identity/identity.go`**

```go
// Package identity defines tenantkit's identity-provider abstraction.
// Concrete implementations (identity/local, identity/oidc) are a
// separate package/plan; this package only defines the interface so
// httpmw and grpcmw have something concrete to depend on.
package identity

import (
	"context"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/resolve"
)

// IdentityProvider authenticates a request, returning the identity that
// made it, or nil for a request with no associated human identity (e.g.
// pure service/API-key traffic).
type IdentityProvider interface {
	Authenticate(ctx context.Context, src resolve.Source) (*tenantkit.Identity, error)
}
```

This step has no test of its own -- it's a single interface with no
behavior to assert on. `httpmw`'s tests below are what exercise it (via
a hand-written fake, since no real implementation exists yet).

- [ ] **Step 2: Write the failing tests**

Create `httpmw/source_test.go` (internal test -- `httpSource` is
unexported):

```go
package httpmw

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPSource_Header(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Tenant-ID", "acme")
	src := httpSource{r: r}

	if got := src.Header("X-Tenant-ID"); got != "acme" {
		t.Errorf("Header(X-Tenant-ID) = %q, want acme", got)
	}
}

func TestHTTPSource_TLSPeerCertificatesNilWithoutTLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	src := httpSource{r: r}

	if got := src.TLSPeerCertificates(); got != nil {
		t.Errorf("TLSPeerCertificates() = %v, want nil for a non-TLS request", got)
	}
}

func TestHTTPSource_HostStripsPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "acme.example.com:8080"
	src := httpSource{r: r}

	if got := src.Host(); got != "acme.example.com" {
		t.Errorf("Host() = %q, want acme.example.com", got)
	}
}

func TestHTTPSource_HostWithoutPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "acme.example.com"
	src := httpSource{r: r}

	if got := src.Host(); got != "acme.example.com" {
		t.Errorf("Host() = %q, want acme.example.com", got)
	}
}
```

Create `httpmw/httpmw_test.go` (external test -- exercises the public API):

```go
package httpmw_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/httpmw"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
	"github.com/TURNERO/tenantkit/store/memstore"
)

type fakeResolver struct {
	tenantID string
	ok       bool
	err      error
}

func (f fakeResolver) ResolveTenant(ctx context.Context, src resolve.Source) (string, bool, error) {
	return f.tenantID, f.ok, f.err
}

type fakeIdentityProvider struct {
	identity *tenantkit.Identity
	err      error
}

func (f fakeIdentityProvider) Authenticate(ctx context.Context, src resolve.Source) (*tenantkit.Identity, error) {
	return f.identity, f.err
}

func newTestTenantStore(t *testing.T, tenantID string, active bool) store.TenantStore {
	t.Helper()
	s := memstore.New()
	if err := s.CreateTenant(context.Background(), &tenantkit.Tenant{ID: tenantID, DisplayName: tenantID, Active: active}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	return s
}

func TestNew_ResolvesTenantAndCallsNext(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	var gotTenant *tenantkit.Tenant
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore: ts,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant, _ = tenantkit.TenantFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotTenant == nil || gotTenant.ID != "acme" {
		t.Errorf("TenantFromContext = %+v, want ID acme", gotTenant)
	}
}

func TestNew_NoCredentialsRejectedWith401(t *testing.T) {
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: false}},
		TenantStore: memstore.New(),
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestNew_InvalidCredentialsRejectedWith401(t *testing.T) {
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: true, err: errors.New("bad key")}},
		TenantStore: memstore.New(),
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestNew_InactiveTenantRejectedWith403(t *testing.T) {
	ts := newTestTenantStore(t, "acme", false)
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore: ts,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestNew_UnknownTenantRejectedWith403(t *testing.T) {
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "nope", ok: true}},
		TenantStore: memstore.New(),
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestNew_ResolverChainTriesNextOnOkFalse(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	handler := httpmw.New(httpmw.Config{
		Resolvers: []resolve.TenantResolver{
			fakeResolver{ok: false},
			fakeResolver{tenantID: "acme", ok: true},
		},
		TenantStore: ts,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (second resolver should have been tried)", rec.Code)
	}
}

func TestNew_NilIdentityProviderSkipsIdentityResolution(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	var gotOK bool
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore: ts,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, gotOK = tenantkit.IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotOK {
		t.Error("expected no Identity in context when IdentityProvider is nil")
	}
}

func TestNew_IdentityPopulatedWhenTenantsMatch(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	id := &tenantkit.Identity{UserID: "u1", TenantID: "acme"}
	var gotIdentity *tenantkit.Identity
	handler := httpmw.New(httpmw.Config{
		Resolvers:        []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore:      ts,
		IdentityProvider: fakeIdentityProvider{identity: id},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity, _ = tenantkit.IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotIdentity == nil || gotIdentity.UserID != "u1" {
		t.Errorf("IdentityFromContext = %+v, want UserID u1", gotIdentity)
	}
}

func TestNew_IdentityTenantMismatchRejectedWith403(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	handler := httpmw.New(httpmw.Config{
		Resolvers:        []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore:      ts,
		IdentityProvider: fakeIdentityProvider{identity: &tenantkit.Identity{UserID: "u1", TenantID: "globex"}},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestNew_IdentityProviderNilIdentityForServiceTraffic(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	handler := httpmw.New(httpmw.Config{
		Resolvers:        []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore:      ts,
		IdentityProvider: fakeIdentityProvider{identity: nil},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a nil Identity from a configured IdentityProvider is not an error)", rec.Code)
	}
}

func TestNew_IdentityAuthenticateErrorRejectedWith401(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	handler := httpmw.New(httpmw.Config{
		Resolvers:        []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore:      ts,
		IdentityProvider: fakeIdentityProvider{err: errors.New("invalid token")},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestNew_CustomErrorHandler(t *testing.T) {
	called := false
	handler := httpmw.New(httpmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: false}},
		TenantStore: memstore.New(),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, status int, err error) {
			called = true
			w.WriteHeader(status)
			w.Write([]byte("custom: " + err.Error()))
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if !called {
		t.Error("expected the custom ErrorHandler to be invoked")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := rec.Body.String(); len(got) < 7 || got[:7] != "custom:" {
		t.Errorf("body = %q, want it to start with 'custom:'", got)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./httpmw/... -v`

Expected: FAIL to compile -- package `httpmw` doesn't exist yet.

- [ ] **Step 4: Write `httpmw/source.go`**

```go
package httpmw

import (
	"crypto/x509"
	"net"
	"net/http"

	"github.com/TURNERO/tenantkit/resolve"
)

type httpSource struct {
	r *http.Request
}

func (s httpSource) Header(key string) string {
	return s.r.Header.Get(key)
}

func (s httpSource) TLSPeerCertificates() []*x509.Certificate {
	if s.r.TLS == nil {
		return nil
	}
	return s.r.TLS.PeerCertificates
}

func (s httpSource) Host() string {
	host := s.r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

var _ resolve.Source = httpSource{}
```

- [ ] **Step 5: Write `httpmw/httpmw.go`**

```go
package httpmw

import (
	"fmt"
	"net/http"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
)

// ErrorHandler writes an HTTP response for a rejected request. status is
// http.StatusUnauthorized (401, no/invalid credentials) or
// http.StatusForbidden (403, valid credentials but wrong/inactive tenant).
type ErrorHandler func(w http.ResponseWriter, r *http.Request, status int, err error)

// Config configures the middleware returned by New.
type Config struct {
	// Resolvers is tried in order; the first resolver that finds
	// credential material (ok=true or a non-nil error) decides the
	// outcome -- see resolve.TenantResolver's doc comment.
	Resolvers []resolve.TenantResolver
	// TenantStore looks up the resolved tenant to confirm it exists and
	// is active.
	TenantStore store.TenantStore
	// IdentityProvider is optional. When nil, identity resolution is
	// skipped entirely and no Identity is ever placed in context --
	// appropriate for consumers with no human users.
	IdentityProvider identity.IdentityProvider
	// ErrorHandler is optional. Defaults to a minimal plain-text
	// response (http.Error-style) if not set.
	ErrorHandler ErrorHandler
}

// New returns middleware that resolves the tenant (and, if configured,
// the identity) for each request, and rejects requests that fail to
// resolve.
func New(cfg Config) func(http.Handler) http.Handler {
	errorHandler := cfg.ErrorHandler
	if errorHandler == nil {
		errorHandler = defaultErrorHandler
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			src := httpSource{r: r}

			tenantID, err := resolve.RunChain(ctx, cfg.Resolvers, src)
			if err != nil {
				errorHandler(w, r, http.StatusUnauthorized, err)
				return
			}
			if tenantID == "" {
				errorHandler(w, r, http.StatusUnauthorized, errNoCredentials)
				return
			}

			tenant, err := cfg.TenantStore.GetTenant(ctx, tenantID)
			if err != nil {
				errorHandler(w, r, http.StatusForbidden, err)
				return
			}
			if !tenant.Active {
				errorHandler(w, r, http.StatusForbidden, errInactiveTenant)
				return
			}
			ctx = tenantkit.WithTenant(ctx, tenant)

			if cfg.IdentityProvider != nil {
				id, err := cfg.IdentityProvider.Authenticate(ctx, src)
				if err != nil {
					errorHandler(w, r, http.StatusUnauthorized, err)
					return
				}
				if id != nil {
					if id.TenantID != tenantID {
						errorHandler(w, r, http.StatusForbidden, errTenantMismatch)
						return
					}
					ctx = tenantkit.WithIdentity(ctx, id)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

var (
	errNoCredentials  = fmt.Errorf("httpmw: no credentials presented")
	errInactiveTenant = fmt.Errorf("httpmw: tenant is inactive")
	errTenantMismatch = fmt.Errorf("httpmw: identity's tenant does not match resolved tenant")
)

func defaultErrorHandler(w http.ResponseWriter, r *http.Request, status int, err error) {
	http.Error(w, err.Error(), status)
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./identity/... ./httpmw/... -v`

Expected: PASS, all tests (`identity` reports "no test files", which is
expected -- see Step 1's note).

- [ ] **Step 7: Run `go vet` and commit**

Run: `go vet ./identity/... ./httpmw/...`

Expected: clean.

```bash
git add identity/identity.go httpmw/source.go httpmw/httpmw.go httpmw/source_test.go httpmw/httpmw_test.go
git commit -m "feat: add identity.IdentityProvider interface and httpmw middleware

identity/identity.go is interface-only -- concrete implementations
(identity/local, identity/oidc) are a separate future plan. httpmw.New
wraps *http.Request into a Source, runs the resolver chain, checks the
resolved tenant is active, and (only if an IdentityProvider is
configured) authenticates and cross-checks the identity's tenant
against the resolved one. IdentityProvider and ErrorHandler are both
optional with sane defaults."
```

---

### Task 4: `tenantkit/grpcmw`

**Files:**
- Modify: `go.mod` (add `google.golang.org/grpc`)
- Create: `grpcmw/source.go`
- Create: `grpcmw/grpcmw.go`
- Test: `grpcmw/source_test.go`
- Test: `grpcmw/grpcmw_test.go`

**Interfaces:**
- Consumes: `resolve.Source`/`TenantResolver`/`RunChain` (Task 1/2), `identity.IdentityProvider` (Task 3), `tenantkit.WithTenant`/`WithIdentity` (foundation), `store.TenantStore` (foundation).
- Produces: `grpcmw.Config`, `grpcmw.UnaryServerInterceptor(Config) grpc.UnaryServerInterceptor`, `grpcmw.StreamServerInterceptor(Config) grpc.StreamServerInterceptor`. Nothing later in this plan depends on this task; it's the last one.

- [ ] **Step 1: Add the grpc-go dependency**

Run: `go get google.golang.org/grpc@v1.82.1`

Expected: `go.mod` gains a `require google.golang.org/grpc v1.82.1` line, and its indirect dependencies (`golang.org/x/net`, `golang.org/x/sys`, `golang.org/x/text`, `google.golang.org/genproto/googleapis/rpc`, `google.golang.org/protobuf`). **This also bumps the `go` directive from `1.23` to `1.25.0`** -- grpc-go v1.82.1's own `go.mod` requires it. This is expected; don't revert it.

- [ ] **Step 2: Write the failing tests**

Create `grpcmw/source_test.go` (internal test -- `grpcSource` is
unexported):

```go
package grpcmw

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func TestGRPCSource_Header(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer abc123"))
	src := grpcSource{ctx: ctx}

	if got := src.Header("Authorization"); got != "Bearer abc123" {
		t.Errorf("Header(Authorization) = %q, want %q", got, "Bearer abc123")
	}
}

func TestGRPCSource_HeaderMissing(t *testing.T) {
	src := grpcSource{ctx: context.Background()}
	if got := src.Header("Authorization"); got != "" {
		t.Errorf("Header(Authorization) = %q, want empty", got)
	}
}

func TestGRPCSource_TLSPeerCertificatesNilWithoutTLS(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.IPAddr{}})
	src := grpcSource{ctx: ctx}

	if got := src.TLSPeerCertificates(); got != nil {
		t.Errorf("TLSPeerCertificates() = %v, want nil without TLSInfo", got)
	}
}

func TestGRPCSource_TLSPeerCertificatesFromTLSInfo(t *testing.T) {
	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}},
	}
	ctx := peer.NewContext(context.Background(), p)
	src := grpcSource{ctx: ctx}

	if got := src.TLSPeerCertificates(); got != nil {
		t.Errorf("TLSPeerCertificates() = %v, want nil for an empty ConnectionState", got)
	}
}

func TestGRPCSource_HostFromAuthorityMetadata(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(":authority", "acme.example.com"))
	src := grpcSource{ctx: ctx}

	if got := src.Host(); got != "acme.example.com" {
		t.Errorf("Host() = %q, want acme.example.com", got)
	}
}

func TestGRPCSource_HostMissing(t *testing.T) {
	src := grpcSource{ctx: context.Background()}
	if got := src.Host(); got != "" {
		t.Errorf("Host() = %q, want empty", got)
	}
}
```

Create `grpcmw/grpcmw_test.go` (external test -- exercises the public
API):

```go
package grpcmw_test

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/grpcmw"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
	"github.com/TURNERO/tenantkit/store/memstore"
)

type fakeResolver struct {
	tenantID string
	ok       bool
	err      error
}

func (f fakeResolver) ResolveTenant(ctx context.Context, src resolve.Source) (string, bool, error) {
	return f.tenantID, f.ok, f.err
}

type fakeIdentityProvider struct {
	identity *tenantkit.Identity
	err      error
}

func (f fakeIdentityProvider) Authenticate(ctx context.Context, src resolve.Source) (*tenantkit.Identity, error) {
	return f.identity, f.err
}

func newTestTenantStore(t *testing.T, tenantID string, active bool) store.TenantStore {
	t.Helper()
	s := memstore.New()
	if err := s.CreateTenant(context.Background(), &tenantkit.Tenant{ID: tenantID, DisplayName: tenantID, Active: active}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	return s
}

func TestUnaryServerInterceptor_ResolvesTenantAndCallsHandler(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore: ts,
	})

	var gotTenant *tenantkit.Tenant
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		gotTenant, _ = tenantkit.TenantFromContext(ctx)
		return "ok", nil
	}

	resp, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if resp != "ok" {
		t.Errorf("resp = %v, want ok", resp)
	}
	if gotTenant == nil || gotTenant.ID != "acme" {
		t.Errorf("TenantFromContext = %+v, want ID acme", gotTenant)
	}
}

func TestUnaryServerInterceptor_NoCredentialsRejectedWithUnauthenticated(t *testing.T) {
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: false}},
		TenantStore: memstore.New(),
	})

	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("status code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestUnaryServerInterceptor_InvalidCredentialsRejectedWithUnauthenticated(t *testing.T) {
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: true, err: errors.New("bad key")}},
		TenantStore: memstore.New(),
	})

	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("status code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestUnaryServerInterceptor_InactiveTenantRejectedWithPermissionDenied(t *testing.T) {
	ts := newTestTenantStore(t, "acme", false)
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore: ts,
	})

	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("status code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestUnaryServerInterceptor_IdentityTenantMismatchRejectedWithPermissionDenied(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:        []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore:      ts,
		IdentityProvider: fakeIdentityProvider{identity: &tenantkit.Identity{UserID: "u1", TenantID: "globex"}},
	})

	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("status code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestUnaryServerInterceptor_IdentityPopulatedWhenTenantsMatch(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:        []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore:      ts,
		IdentityProvider: fakeIdentityProvider{identity: &tenantkit.Identity{UserID: "u1", TenantID: "acme"}},
	})

	var gotIdentity *tenantkit.Identity
	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		gotIdentity, _ = tenantkit.IdentityFromContext(ctx)
		return nil, nil
	})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if gotIdentity == nil || gotIdentity.UserID != "u1" {
		t.Errorf("IdentityFromContext = %+v, want UserID u1", gotIdentity)
	}
}

type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *fakeServerStream) Context() context.Context { return s.ctx }

func TestStreamServerInterceptor_ResolvesTenantAndCallsHandler(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	interceptor := grpcmw.StreamServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore: ts,
	})

	var gotTenant *tenantkit.Tenant
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		gotTenant, _ = tenantkit.TenantFromContext(ss.Context())
		return nil
	}

	err := interceptor(nil, &fakeServerStream{ctx: context.Background()}, &grpc.StreamServerInfo{}, handler)
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if gotTenant == nil || gotTenant.ID != "acme" {
		t.Errorf("TenantFromContext = %+v, want ID acme", gotTenant)
	}
}

func TestStreamServerInterceptor_NoCredentialsRejectedWithUnauthenticated(t *testing.T) {
	interceptor := grpcmw.StreamServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: false}},
		TenantStore: memstore.New(),
	})

	err := interceptor(nil, &fakeServerStream{ctx: context.Background()}, &grpc.StreamServerInfo{}, func(srv interface{}, ss grpc.ServerStream) error {
		t.Fatal("handler should not be called")
		return nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("status code = %v, want Unauthenticated", status.Code(err))
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./grpcmw/... -v`

Expected: FAIL to compile -- package `grpcmw` doesn't exist yet.

- [ ] **Step 4: Write `grpcmw/source.go`**

```go
package grpcmw

import (
	"context"
	"crypto/x509"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/TURNERO/tenantkit/resolve"
)

// grpcSource adapts a gRPC server-side context into resolve.Source.
type grpcSource struct {
	ctx context.Context
}

func (s grpcSource) Header(key string) string {
	md, ok := metadata.FromIncomingContext(s.ctx)
	if !ok {
		return ""
	}
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func (s grpcSource) TLSPeerCertificates() []*x509.Certificate {
	p, ok := peer.FromContext(s.ctx)
	if !ok || p.AuthInfo == nil {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	return tlsInfo.State.PeerCertificates
}

// Host returns the :authority pseudo-header if it happens to be exposed
// as regular incoming metadata (some gateways/proxies forward it this
// way); grpc-go's server-side API does not otherwise expose HTTP/2
// pseudo-headers through the standard metadata package. Returns "" if
// unavailable -- the subdomain resolver simply won't match, same as any
// other resolver given no credential material.
func (s grpcSource) Host() string {
	md, ok := metadata.FromIncomingContext(s.ctx)
	if !ok {
		return ""
	}
	vals := md.Get(":authority")
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

var _ resolve.Source = grpcSource{}
```

- [ ] **Step 5: Write `grpcmw/grpcmw.go`**

```go
package grpcmw

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
)

// Config configures the interceptors returned by UnaryServerInterceptor
// and StreamServerInterceptor. Same shape and semantics as httpmw.Config
// -- see its doc comment -- minus an HTTP-specific ErrorHandler; gRPC
// rejections are reported via status codes instead.
type Config struct {
	Resolvers        []resolve.TenantResolver
	TenantStore      store.TenantStore
	IdentityProvider identity.IdentityProvider
}

func resolveAndAuthenticate(ctx context.Context, cfg Config) (context.Context, error) {
	src := grpcSource{ctx: ctx}

	tenantID, err := resolve.RunChain(ctx, cfg.Resolvers, src)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if tenantID == "" {
		return nil, status.Error(codes.Unauthenticated, "grpcmw: no credentials presented")
	}

	tenant, err := cfg.TenantStore.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	if !tenant.Active {
		return nil, status.Error(codes.PermissionDenied, "grpcmw: tenant is inactive")
	}
	ctx = tenantkit.WithTenant(ctx, tenant)

	if cfg.IdentityProvider != nil {
		id, err := cfg.IdentityProvider.Authenticate(ctx, src)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		if id != nil {
			if id.TenantID != tenantID {
				return nil, status.Error(codes.PermissionDenied, "grpcmw: identity's tenant does not match resolved tenant")
			}
			ctx = tenantkit.WithIdentity(ctx, id)
		}
	}

	return ctx, nil
}

// UnaryServerInterceptor returns a grpc.UnaryServerInterceptor that
// resolves the tenant (and, if configured, the identity) for each unary
// call.
func UnaryServerInterceptor(cfg Config) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		ctx, err := resolveAndAuthenticate(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a grpc.StreamServerInterceptor that
// resolves the tenant (and, if configured, the identity) once at stream
// start.
func StreamServerInterceptor(cfg Config) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := resolveAndAuthenticate(ss.Context(), cfg)
		if err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *wrappedStream) Context() context.Context {
	return s.ctx
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./grpcmw/... -v`

Expected: PASS, all tests.

- [ ] **Step 7: Run `go mod tidy`, `go vet`, and the full module test suite**

Run: `go mod tidy && go build ./... && go vet ./... && go test ./... -v`

Expected: `go mod tidy` makes no unexpected changes beyond what Step 1
already introduced (check `git diff go.mod go.sum` if anything looks
off -- it should only touch grpc-related entries). Build, vet, and the
full suite (foundation packages plus this plan's four) all pass.

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum grpcmw/source.go grpcmw/grpcmw.go grpcmw/source_test.go grpcmw/grpcmw_test.go
git commit -m "feat: add grpcmw unary and stream interceptors

grpcSource adapts a gRPC server context (incoming metadata + peer TLS
info) into resolve.Source -- the same resolvers and IdentityProvider
implementations from httpmw work here unmodified. Config mirrors
httpmw.Config minus ErrorHandler (gRPC failures go through status
codes, no response body to customize). First third-party dependency
in this module: google.golang.org/grpc v1.82.1, which also raised the
go directive to 1.25.0 (grpc-go's own go.mod requirement)."
```

---

## What's next

This plan covers tenant resolution and middleware end to end for four of
the five originally-designed resolver strategies. Two pieces of the full
design spec (`docs/superpowers/specs/2026-07-20-tenantkit-design.md`)
remain, each its own future plan:

- **Identity** -- `identity/local` (WebAuthn/bcrypt + sessions) and
  `identity/oidc`. Once the session-token format is decided there (issue
  #1), a fifth `TenantResolver` (session/identity-claim) can be added to
  `tenantkit/resolve` as a small follow-up to this plan.
- **Admin** -- `tenantkit/admin` and `cmd/tenantkit-admin`, per the
  spec's "Management plane" section. Independent of this plan; depends
  only on the foundation plan's `store` package.
