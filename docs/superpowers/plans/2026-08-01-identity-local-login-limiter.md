# identity/local login rate-limiting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add pluggable account-lockout rate-limiting to `identity/local` login (issue #6): a `LoginLimiter` interface, optional on `Config`, consulted by both `LoginWithPassword` and the WebAuthn login ceremony against one shared per-`(tenantID, username)` counter, plus an in-memory sliding-window reference implementation and its conformance suite.

**Architecture:** A new minimal `local.LoginLimiter` interface (`Allow`/`RecordFailure`/`RecordSuccess`) and `local.ErrTooManyAttempts` sentinel, wired into `Config` as an optional field (nil preserves today's behavior exactly). `LoginWithPassword` and `BeginWebAuthnLogin` check `Allow` before doing any real work; both record failure/success around the actual credential check. `webauthnCeremony` gains a `Username` field so `FinishWebAuthnLogin` can record against the same key `BeginWebAuthnLogin` checked, without an extra `UserStore` round-trip. `identity/local/memstore.LoginLimiter` is the reference implementation: a sliding window of failure timestamps per key, pruned on each `RecordFailure`, plus a separate `lockout` duration independent of the counting window.

**Tech Stack:** Standard library only (`sync`, `time`) for the reference implementation -- no new dependencies.

Design spec: `docs/superpowers/specs/2026-08-01-identity-local-login-limiter-design.md`.

## Global Constraints

- Error wrapping follows this package's existing convention throughout: `fmt.Errorf("tenantkit/identity/local: <action>: %w", err)`.
- `local.LoginLimiter` is deliberately minimal -- `Allow` returns `(bool, error)`, no `retryAfter`/duration. Do not add one; a concrete implementation can expose richer methods beyond what the interface requires.
- `Config.LoginLimiter LoginLimiter` is optional -- nil must mean "never rate-limited," matching today's behavior exactly. This must not change `local.New`'s positional signature.
- `RecordFailure`/`RecordSuccess` errors are never swallowed -- on error, `LoginWithPassword`/`BeginWebAuthnLogin`/`FinishWebAuthnLogin` return the wrapped error instead of the underlying auth result (fail closed, not open).
- `Allow` is checked before any real work: before `UserStore.GetUserByUsername` in `LoginWithPassword`, before generating a WebAuthn challenge in `BeginWebAuthnLogin`.
- The limiter is keyed by `username`, not `userID` -- both `LoginWithPassword` and `BeginWebAuthnLogin` already receive `username` as an input parameter; never resolve to `userID` first just to key the limiter.
- `identity/local/memstore.LoginLimiter` uses a **sliding window**, not fixed: each failure is a `time.Time` in a per-key slice; `RecordFailure` prunes entries older than `window` on every call. `lockout` is a separate duration from `window` -- once tripped, the account stays locked for `lockout` regardless of whether failures have since aged out of the counting window.
- WebAuthn registration (`BeginWebAuthnRegistration`/`FinishWebAuthnRegistration`) is untouched by this plan -- not a login attempt, no `LoginLimiter` interaction.
- Out of scope (do not implement): a persistent/SQLite `LoginLimiter` backend, any "retry after N seconds" UX, rate-limiting `identity/oidc`, and `identity/local`'s password-reset flow.

---

### Task 1: `LoginLimiter` interface, `ErrTooManyAttempts`, and `Config` field

**Files:**
- Modify: `identity/local/store.go` (add `LoginLimiter` interface, end of file)
- Modify: `identity/local/errors.go` (add `ErrTooManyAttempts`)
- Modify: `identity/local/local.go` (add `Config.LoginLimiter` field, lines 12-27)
- Create: `identity/local/limiter_test.go`

**Interfaces:**
- Consumes: nothing new -- existing `local.Config` (`identity/local/local.go`), stdlib `context`.
- Produces: `local.LoginLimiter` interface (`Allow(ctx context.Context, tenantID, username string) (bool, error)`, `RecordFailure(ctx context.Context, tenantID, username string) error`, `RecordSuccess(ctx context.Context, tenantID, username string) error`); `local.ErrTooManyAttempts`; `local.Config.LoginLimiter LoginLimiter` field. Every later task in this plan depends on these.

- [ ] **Step 1: Write the failing test**

Create `identity/local/limiter_test.go`:

```go
package local_test

import (
	"context"
	"errors"
	"testing"

	"github.com/TURNERO/tenantkit/identity/local"
)

// fakeLimiter is a minimal local.LoginLimiter used only to prove the
// interface and Config field compile and wire together correctly,
// before any real implementation (memstore.LoginLimiter, Task 2)
// exists.
type fakeLimiter struct{}

func (fakeLimiter) Allow(ctx context.Context, tenantID, username string) (bool, error) {
	return true, nil
}
func (fakeLimiter) RecordFailure(ctx context.Context, tenantID, username string) error { return nil }
func (fakeLimiter) RecordSuccess(ctx context.Context, tenantID, username string) error { return nil }

var _ local.LoginLimiter = fakeLimiter{}

func TestErrTooManyAttempts_IsDistinctFromOtherErrors(t *testing.T) {
	if errors.Is(local.ErrTooManyAttempts, local.ErrInvalidCredentials) {
		t.Fatal("ErrTooManyAttempts must be distinct from ErrInvalidCredentials")
	}
	if errors.Is(local.ErrTooManyAttempts, local.ErrNotFound) {
		t.Fatal("ErrTooManyAttempts must be distinct from ErrNotFound")
	}
}

func TestConfig_LoginLimiterDefaultsToNil(t *testing.T) {
	cfg := local.Config{}
	if cfg.LoginLimiter != nil {
		t.Fatal("zero-value Config.LoginLimiter must be nil -- rate limiting is opt-in")
	}
	cfg.LoginLimiter = fakeLimiter{}
	if cfg.LoginLimiter == nil {
		t.Fatal("Config.LoginLimiter must be settable to a LoginLimiter implementation")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./identity/local/... -run 'TestErrTooManyAttempts_IsDistinctFromOtherErrors|TestConfig_LoginLimiterDefaultsToNil' -v`
Expected: FAIL to compile -- `undefined: local.LoginLimiter`, `undefined: local.ErrTooManyAttempts`, `unknown field LoginLimiter in struct literal`.

- [ ] **Step 3: Add the `LoginLimiter` interface**

In `identity/local/store.go`, append after the `EphemeralStore` interface (after line 46):

```go

// LoginLimiter tracks failed login attempts per (tenantID, username)
// and decides whether a login attempt should proceed. Consulted by
// LoginWithPassword and the WebAuthn login ceremony alike -- any
// failed authentication attempt, regardless of method, counts against
// the same lockout.
type LoginLimiter interface {
	// Allow reports whether a login attempt for (tenantID, username)
	// should proceed.
	Allow(ctx context.Context, tenantID, username string) (bool, error)
	// RecordFailure records a failed attempt, which may cause a
	// subsequent Allow to return false.
	RecordFailure(ctx context.Context, tenantID, username string) error
	// RecordSuccess resets any failure count for (tenantID, username).
	RecordSuccess(ctx context.Context, tenantID, username string) error
}
```

- [ ] **Step 4: Add `ErrTooManyAttempts`**

In `identity/local/errors.go`, add inside the existing `var (...)` block, after `ErrInvalidCredentials`:

```go
	// ErrTooManyAttempts is returned by LoginWithPassword and
	// BeginWebAuthnLogin when a configured LoginLimiter reports the
	// account is currently locked out.
	ErrTooManyAttempts = errors.New("tenantkit/identity/local: too many attempts")
```

- [ ] **Step 5: Add `Config.LoginLimiter`**

In `identity/local/local.go`, replace the `Config` struct (lines 12-27):

```go
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
	// LoginLimiter is optional. When nil, login attempts are never
	// rate-limited (today's behavior, unchanged) -- matches how
	// httpmw.Config.IdentityProvider being nil skips identity
	// resolution entirely, rather than erroring.
	LoginLimiter LoginLimiter
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./identity/local/... -run 'TestErrTooManyAttempts_IsDistinctFromOtherErrors|TestConfig_LoginLimiterDefaultsToNil' -v`
Expected: PASS.

- [ ] **Step 7: Run the full package test suite, `go vet`, `gofmt`, and commit**

```bash
go build ./...
go vet ./...
gofmt -l identity/local/
go test ./identity/local/... -v
git add identity/local/store.go identity/local/errors.go identity/local/local.go identity/local/limiter_test.go
git commit -m "feat: add identity/local LoginLimiter interface and Config field"
```

Expected: all commands clean, all existing `identity/local` tests still pass (this task is purely additive).

---

### Task 2: `memstore.LoginLimiter` reference implementation and conformance suite

**Files:**
- Create: `identity/local/memstore/limiter.go`
- Create: `identity/local/memstore/limiter_test.go`
- Modify: `identity/local/storetest/storetest.go` (add `TestLoginLimiter`)
- Modify: `identity/local/memstore/memstore_test.go` (wire the conformance suite against `memstore.LoginLimiter`)

**Interfaces:**
- Consumes: `local.LoginLimiter` (Task 1).
- Produces: `memstore.NewLoginLimiter(maxAttempts int, window, lockout time.Duration) *memstore.LoginLimiter` (satisfies `local.LoginLimiter`); `storetest.TestLoginLimiter(t *testing.T, limiter local.LoginLimiter, maxAttempts int)`. Tasks 3 and 4 depend on `memstore.NewLoginLimiter` for their own integration tests.

- [ ] **Step 1: Write the conformance suite**

In `identity/local/storetest/storetest.go`, append:

```go

// TestLoginLimiter runs a battery of subtests against limiter,
// constructed with maxAttempts as its failure threshold before
// locking an account out. Pass a fresh, empty limiter.
func TestLoginLimiter(t *testing.T, limiter local.LoginLimiter, maxAttempts int) {
	t.Helper()
	ctx := context.Background()

	t.Run("AllowedBelowThreshold", func(t *testing.T) {
		for i := 0; i < maxAttempts-1; i++ {
			if err := limiter.RecordFailure(ctx, "acme", "alice"); err != nil {
				t.Fatalf("RecordFailure: %v", err)
			}
		}
		allowed, err := limiter.Allow(ctx, "acme", "alice")
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if !allowed {
			t.Fatal("expected allowed one below threshold")
		}
	})

	t.Run("LockedAtThreshold", func(t *testing.T) {
		for i := 0; i < maxAttempts; i++ {
			if err := limiter.RecordFailure(ctx, "acme", "bob"); err != nil {
				t.Fatalf("RecordFailure: %v", err)
			}
		}
		allowed, err := limiter.Allow(ctx, "acme", "bob")
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if allowed {
			t.Fatal("expected locked out at threshold")
		}
	})

	t.Run("RecordSuccessResets", func(t *testing.T) {
		for i := 0; i < maxAttempts; i++ {
			if err := limiter.RecordFailure(ctx, "acme", "carol"); err != nil {
				t.Fatalf("RecordFailure: %v", err)
			}
		}
		if allowed, err := limiter.Allow(ctx, "acme", "carol"); err != nil {
			t.Fatalf("Allow: %v", err)
		} else if allowed {
			t.Fatal("expected locked out before RecordSuccess")
		}

		if err := limiter.RecordSuccess(ctx, "acme", "carol"); err != nil {
			t.Fatalf("RecordSuccess: %v", err)
		}

		allowed, err := limiter.Allow(ctx, "acme", "carol")
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if !allowed {
			t.Fatal("expected allowed after RecordSuccess")
		}
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		for i := 0; i < maxAttempts; i++ {
			if err := limiter.RecordFailure(ctx, "acme", "dave"); err != nil {
				t.Fatalf("RecordFailure: %v", err)
			}
		}
		allowed, err := limiter.Allow(ctx, "other-tenant", "dave")
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if !allowed {
			t.Fatal("expected allowed in a different tenant (tenant isolation)")
		}
	})
}
```

- [ ] **Step 2: Write the failing memstore tests**

Create `identity/local/memstore/limiter_test.go`:

```go
package memstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit/identity/local/memstore"
	"github.com/TURNERO/tenantkit/identity/local/storetest"
)

func TestMemstoreLoginLimiterConformsToLoginLimiter(t *testing.T) {
	storetest.TestLoginLimiter(t, memstore.NewLoginLimiter(3, time.Hour, time.Hour), 3)
}

// TestLoginLimiter_WindowPrunesOldFailures is memstore-specific: it
// proves failures older than window are pruned and don't count toward
// the threshold. storetest can't assert this generically -- it's
// implementation timing, not part of the interface contract.
func TestLoginLimiter_WindowPrunesOldFailures(t *testing.T) {
	ctx := context.Background()
	limiter := memstore.NewLoginLimiter(3, 50*time.Millisecond, time.Hour)

	if err := limiter.RecordFailure(ctx, "acme", "alice"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if err := limiter.RecordFailure(ctx, "acme", "alice"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	time.Sleep(80 * time.Millisecond) // longer than the 50ms window

	// This third failure is real, but the first two are now outside
	// the window and must be pruned -- only 1 failure counts, below
	// the threshold of 3.
	if err := limiter.RecordFailure(ctx, "acme", "alice"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	allowed, err := limiter.Allow(ctx, "acme", "alice")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !allowed {
		t.Fatal("expected allowed -- stale failures should have been pruned")
	}
}

// TestLoginLimiter_FailuresAccumulateAcrossTime proves a sliding
// window correctly accumulates failures spread over time within the
// window, rather than resetting them -- the property a fixed window
// would get wrong at a clock-aligned boundary.
func TestLoginLimiter_FailuresAccumulateAcrossTime(t *testing.T) {
	ctx := context.Background()
	limiter := memstore.NewLoginLimiter(3, 200*time.Millisecond, time.Hour)

	if err := limiter.RecordFailure(ctx, "acme", "bob"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if err := limiter.RecordFailure(ctx, "acme", "bob"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	time.Sleep(50 * time.Millisecond) // well within the 200ms window

	if err := limiter.RecordFailure(ctx, "acme", "bob"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	allowed, err := limiter.Allow(ctx, "acme", "bob")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if allowed {
		t.Fatal("expected locked out -- all 3 failures fall within the window")
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./identity/local/memstore/... -v`
Expected: FAIL to compile -- `undefined: memstore.NewLoginLimiter`.

- [ ] **Step 4: Implement `memstore.LoginLimiter`**

Create `identity/local/memstore/limiter.go`:

```go
package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/TURNERO/tenantkit/identity/local"
)

// LoginLimiter is an in-memory reference implementation of
// local.LoginLimiter: a sliding-window failure count per (tenantID,
// username). Not a production backend -- see package doc.
type LoginLimiter struct {
	mu          sync.Mutex
	maxAttempts int
	window      time.Duration
	lockout     time.Duration
	records     map[limiterKey]*limiterRecord
}

type limiterKey struct {
	tenantID string
	username string
}

// limiterRecord tracks recent failures (pruned to the last window on
// every RecordFailure) and, once maxAttempts is reached, the time the
// lockout lifts. lockedUntil is independent of window: an account
// doesn't unlock early just because old failures aged out of the
// counting window.
type limiterRecord struct {
	failures    []time.Time
	lockedUntil time.Time
}

// NewLoginLimiter returns a LoginLimiter that locks an account out for
// lockout after maxAttempts failures within a sliding window of
// duration window (see the design spec's "Design decisions" for why
// sliding rather than fixed).
func NewLoginLimiter(maxAttempts int, window, lockout time.Duration) *LoginLimiter {
	return &LoginLimiter{
		maxAttempts: maxAttempts,
		window:      window,
		lockout:     lockout,
		records:     make(map[limiterKey]*limiterRecord),
	}
}

var _ local.LoginLimiter = (*LoginLimiter)(nil)

func (l *LoginLimiter) Allow(ctx context.Context, tenantID, username string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.records[limiterKey{tenantID, username}]
	if !ok {
		return true, nil
	}
	return time.Now().After(rec.lockedUntil), nil
}

func (l *LoginLimiter) RecordFailure(ctx context.Context, tenantID, username string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := limiterKey{tenantID, username}
	rec, ok := l.records[key]
	if !ok {
		rec = &limiterRecord{}
		l.records[key] = rec
	}

	now := time.Now()
	rec.failures = append(rec.failures, now)

	cutoff := now.Add(-l.window)
	pruned := rec.failures[:0]
	for _, t := range rec.failures {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	rec.failures = pruned

	if len(rec.failures) >= l.maxAttempts {
		rec.lockedUntil = now.Add(l.lockout)
	}
	return nil
}

func (l *LoginLimiter) RecordSuccess(ctx context.Context, tenantID, username string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.records, limiterKey{tenantID, username})
	return nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./identity/local/memstore/... -v`
Expected: PASS -- `TestMemstoreLoginLimiterConformsToLoginLimiter`, `TestLoginLimiter_WindowPrunesOldFailures`, `TestLoginLimiter_FailuresAccumulateAcrossTime`.

- [ ] **Step 6: Run the full package test suite, `go vet`, `gofmt`, and commit**

```bash
go build ./...
go vet ./...
gofmt -l identity/local/
go test ./identity/local/... -v
git add identity/local/memstore/limiter.go identity/local/memstore/limiter_test.go identity/local/storetest/storetest.go
git commit -m "feat: add identity/local/memstore.LoginLimiter reference implementation"
```

Expected: all commands clean, all existing tests still pass.

---

### Task 3: `LoginWithPassword` integration

**Files:**
- Modify: `identity/local/password.go`
- Modify: `identity/local/password_test.go`

**Interfaces:**
- Consumes: `local.LoginLimiter`, `local.ErrTooManyAttempts` (Task 1); `memstore.NewLoginLimiter` (Task 2, test-only).
- Produces: `(*Local).recordLoginFailure(ctx context.Context, tenantID, username string, wantErr error) error` (unexported, `password.go`-only helper -- not reused by Task 4's WebAuthn integration, which records failures inline).

- [ ] **Step 1: Write the failing test**

In `identity/local/password_test.go`, append:

```go

func TestLoginWithPassword_LockedOutAfterThreshold(t *testing.T) {
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

	for i := 0; i < 3; i++ {
		if _, err := l.LoginWithPassword(ctx, "acme", "alice", "wrong"); !errors.Is(err, local.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: got %v, want ErrInvalidCredentials", i, err)
		}
	}

	// Locked out now -- even the correct password must be rejected.
	if _, err := l.LoginWithPassword(ctx, "acme", "alice", "correct horse battery staple"); !errors.Is(err, local.ErrTooManyAttempts) {
		t.Fatalf("got %v, want ErrTooManyAttempts", err)
	}
}
```

No new imports needed -- `context`, `errors`, `testing`, `time`, `tenantkit`, `local`, `localmem`, and `memstore` are already imported in `password_test.go`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./identity/local/... -run TestLoginWithPassword_LockedOutAfterThreshold -v`
Expected: FAIL -- `l.LoginWithPassword` never checks `LoginLimiter`, so all three "wrong" attempts return `ErrInvalidCredentials` as before, but the fourth (correct-password) attempt succeeds instead of returning `ErrTooManyAttempts`.

- [ ] **Step 3: Integrate the limiter into `LoginWithPassword`**

In `identity/local/password.go`, replace the `LoginWithPassword` function:

```go
// LoginWithPassword validates username/password within tenantID and, on
// success, issues a session token. It returns ErrInvalidCredentials for
// an unknown username, a user with no password set, and a wrong
// password alike -- a caller can never distinguish these from the error
// alone. If a Config.LoginLimiter is configured and the account is
// currently locked out, it returns ErrTooManyAttempts before doing any
// of that work.
func (l *Local) LoginWithPassword(ctx context.Context, tenantID, username, password string) (string, error) {
	if l.cfg.LoginLimiter != nil {
		allowed, err := l.cfg.LoginLimiter.Allow(ctx, tenantID, username)
		if err != nil {
			return "", fmt.Errorf("tenantkit/identity/local: check login rate limit: %w", err)
		}
		if !allowed {
			return "", ErrTooManyAttempts
		}
	}

	ident, err := l.users.GetUserByUsername(ctx, tenantID, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
			return "", l.recordLoginFailure(ctx, tenantID, username, ErrInvalidCredentials)
		}
		return "", fmt.Errorf("tenantkit/identity/local: look up user: %w", err)
	}

	hash, err := l.creds.GetPasswordHash(ctx, tenantID, ident.UserID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
			return "", l.recordLoginFailure(ctx, tenantID, username, ErrInvalidCredentials)
		}
		return "", fmt.Errorf("tenantkit/identity/local: get password hash: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return "", l.recordLoginFailure(ctx, tenantID, username, ErrInvalidCredentials)
	}

	if l.cfg.LoginLimiter != nil {
		if err := l.cfg.LoginLimiter.RecordSuccess(ctx, tenantID, username); err != nil {
			return "", fmt.Errorf("tenantkit/identity/local: record login success: %w", err)
		}
	}

	token, err := l.sessions.CreateSession(ctx, tenantID, ident.UserID, l.cfg.SessionTTL)
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: create session: %w", err)
	}
	return token, nil
}

// recordLoginFailure calls RecordFailure (if a limiter is configured)
// and returns wantErr on success, or a wrapped error if RecordFailure
// itself fails -- a rate-limiter backend outage becomes a visible
// error rather than silently not counting toward lockout.
func (l *Local) recordLoginFailure(ctx context.Context, tenantID, username string, wantErr error) error {
	if l.cfg.LoginLimiter == nil {
		return wantErr
	}
	if err := l.cfg.LoginLimiter.RecordFailure(ctx, tenantID, username); err != nil {
		return fmt.Errorf("tenantkit/identity/local: record login failure: %w", err)
	}
	return wantErr
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./identity/local/... -v`
Expected: PASS, including `TestLoginWithPassword_LockedOutAfterThreshold` and every pre-existing `identity/local` test (a nil `LoginLimiter` must leave all prior behavior unchanged).

- [ ] **Step 5: Run `go vet`, `gofmt`, and commit**

```bash
go build ./...
go vet ./...
gofmt -l identity/local/
git add identity/local/password.go identity/local/password_test.go
git commit -m "feat: consult LoginLimiter in LoginWithPassword"
```

---

### Task 4: WebAuthn login integration

**Files:**
- Modify: `identity/local/webauthn.go`
- Modify: `identity/local/webauthn_test.go`

**Interfaces:**
- Consumes: `local.LoginLimiter`, `local.ErrTooManyAttempts` (Task 1); `memstore.NewLoginLimiter` (Task 2, test-only).
- Produces: `webauthnCeremony.Username` field; `(*Local).saveCeremony(ctx context.Context, tenantID, userID, username string, sessionData webauthn.SessionData) (string, error)` (signature change -- both existing call sites, in `BeginWebAuthnRegistration` and `BeginWebAuthnLogin`, are updated in this task).

- [ ] **Step 1: Write the failing test**

In `identity/local/webauthn_test.go`, append:

```go

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

	// Each failed attempt consumes a fresh ceremony (FinishWebAuthnLogin
	// takes the ceremony token single-use regardless of outcome), so a
	// malformed assertion body on each Finish is enough to drive
	// wa.FinishLogin to fail and trigger RecordFailure -- no real
	// registered credential is needed to prove the lockout wiring.
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
```

No new imports needed -- `context`, `errors`, `testing`, `time`, `tenantkit`, `local`, `localmem`, and `memstore` are already imported in `webauthn_test.go`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./identity/local/... -run TestBeginWebAuthnLogin_LockedOutAfterThreshold -v`
Expected: FAIL -- `BeginWebAuthnLogin` never checks `LoginLimiter`, so the fourth call succeeds (returns a challenge) instead of `ErrTooManyAttempts`.

- [ ] **Step 3: Add `Username` to `webauthnCeremony`**

In `identity/local/webauthn.go`, replace the `webauthnCeremony` struct and its doc comment:

```go
// webauthnCeremony is the payload saved in EphemeralStore between a
// ceremony's Begin and Finish calls -- go-webauthn's SessionData plus
// which user this ceremony belongs to (FinishWebAuthnLogin doesn't take
// tenantID/userID again; this is where that comes from). Username is
// only populated for login ceremonies (empty for registration) -- it's
// what FinishWebAuthnLogin uses to record a LoginLimiter failure or
// success against the same key BeginWebAuthnLogin already checked,
// without an extra UserStore round-trip.
type webauthnCeremony struct {
	TenantID    string               `json:"tenant_id"`
	UserID      string               `json:"user_id"`
	Username    string               `json:"username"`
	SessionData webauthn.SessionData `json:"session_data"`
}
```

- [ ] **Step 4: Update `saveCeremony`'s signature and both call sites**

In `identity/local/webauthn.go`, replace `saveCeremony`:

```go
func (l *Local) saveCeremony(ctx context.Context, tenantID, userID, username string, sessionData webauthn.SessionData) (string, error) {
	token, err := store.GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: generate ceremony token: %w", err)
	}
	payload, err := json.Marshal(webauthnCeremony{TenantID: tenantID, UserID: userID, Username: username, SessionData: sessionData})
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: encode webauthn ceremony: %w", err)
	}
	if err := l.ephemeral.Put(ctx, token, payload, webauthnCeremonyTTL); err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: save webauthn ceremony: %w", err)
	}
	return token, nil
}
```

In `BeginWebAuthnRegistration`, update its call site (registration has no `LoginLimiter`-relevant username to carry):

```go
	ceremonyToken, err := l.saveCeremony(ctx, tenantID, userID, "", *sessionData)
```

- [ ] **Step 5: Integrate the limiter into `BeginWebAuthnLogin` and `FinishWebAuthnLogin`**

In `identity/local/webauthn.go`, replace `BeginWebAuthnLogin`:

```go
// BeginWebAuthnLogin starts a passkey login for username within
// tenantID. It returns the challenge to send the browser as JSON, and a
// ceremonyToken the consumer's handler must round-trip back to
// FinishWebAuthnLogin. If a Config.LoginLimiter is configured and the
// account is currently locked out, it returns ErrTooManyAttempts before
// generating a challenge.
func (l *Local) BeginWebAuthnLogin(ctx context.Context, tenantID, username string) (*protocol.CredentialAssertion, string, error) {
	if l.cfg.LoginLimiter != nil {
		allowed, err := l.cfg.LoginLimiter.Allow(ctx, tenantID, username)
		if err != nil {
			return nil, "", fmt.Errorf("tenantkit/identity/local: check login rate limit: %w", err)
		}
		if !allowed {
			return nil, "", ErrTooManyAttempts
		}
	}

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

	ceremonyToken, err := l.saveCeremony(ctx, tenantID, ident.UserID, username, *sessionData)
	if err != nil {
		return nil, "", err
	}
	return assertion, ceremonyToken, nil
}
```

Replace `FinishWebAuthnLogin`:

```go
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
		if l.cfg.LoginLimiter != nil {
			if rerr := l.cfg.LoginLimiter.RecordFailure(ctx, ceremony.TenantID, ceremony.Username); rerr != nil {
				return "", fmt.Errorf("tenantkit/identity/local: record login failure: %w", rerr)
			}
		}
		return "", fmt.Errorf("tenantkit/identity/local: finish webauthn login: %w", err)
	}

	if l.cfg.LoginLimiter != nil {
		if err := l.cfg.LoginLimiter.RecordSuccess(ctx, ceremony.TenantID, ceremony.Username); err != nil {
			return "", fmt.Errorf("tenantkit/identity/local: record login success: %w", err)
		}
	}

	token, err := l.sessions.CreateSession(ctx, ceremony.TenantID, ceremony.UserID, l.cfg.SessionTTL)
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: create session: %w", err)
	}
	return token, nil
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./identity/local/... -v`
Expected: PASS, including `TestBeginWebAuthnLogin_LockedOutAfterThreshold`, `TestWebAuthnRegistrationAndLogin` (registration's `saveCeremony` call site still works with the new `""` username argument), and every other pre-existing test.

- [ ] **Step 7: Run `go vet`, `gofmt`, and commit**

```bash
go build ./...
go vet ./...
gofmt -l identity/local/
git add identity/local/webauthn.go identity/local/webauthn_test.go
git commit -m "feat: consult LoginLimiter in WebAuthn login ceremony"
```

---

## Final Verification

After all four tasks:

```bash
go build ./...
go vet ./...
gofmt -l .
go test ./... -v
```

Expected: everything clean, every test passing, no gofmt diffs. This closes out [issue #6](https://github.com/TURNERO/tenantkit/issues/6).
