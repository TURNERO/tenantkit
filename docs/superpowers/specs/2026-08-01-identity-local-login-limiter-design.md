# identity/local login rate-limiting design

## Overview

[Issue #6](https://github.com/TURNERO/tenantkit/issues/6) asks whether
account lockout / rate-limiting for `identity/local` login attempts
should live inside the package (a pluggable interface) or stay a
permanent, undocumented-in-code consumer responsibility. This plan
picks the former: a new `LoginLimiter` interface, optional on `Config`
(nil preserves today's behavior exactly), consulted by both
`LoginWithPassword` and the WebAuthn login ceremony.

Any failed authentication attempt -- wrong password, a failed/replayed
WebAuthn assertion -- counts against one shared lockout counter per
`(tenantID, username)`. This matches the actual goal (protect the
account from being attacked, regardless of which credential type an
attacker tries) rather than protecting each method independently.
WebAuthn registration (`BeginWebAuthnRegistration`/
`FinishWebAuthnRegistration`) is untouched -- it's an already-known,
already-authenticated user adding a passkey, not a login attempt.

## Scope

In scope:
- `local.LoginLimiter` interface (`Allow`, `RecordFailure`,
  `RecordSuccess`), and `local.ErrTooManyAttempts`.
- `Config.LoginLimiter` -- new optional field, nil = no rate limiting
  (unchanged default behavior, no breaking change to `New`'s
  signature).
- `LoginWithPassword` and `BeginWebAuthnLogin`/`FinishWebAuthnLogin`
  integration: check `Allow` before doing any real work, record
  failure/success around the actual credential check.
- `webauthnCeremony` gains a `Username` field, so `FinishWebAuthnLogin`
  can record against the same `(tenantID, username)` key `Begin` used,
  without an extra `UserStore` round-trip.
- `identity/local/memstore.LoginLimiter` -- in-memory reference
  implementation, sliding-window failure count, fully configurable
  constructor (`maxAttempts`, `window`, `lockout` -- no hidden
  defaults).
- `identity/local/storetest.TestLoginLimiter` -- conformance suite.

Out of scope:
- A persistent (SQLite) `LoginLimiter` backend -- same deferred-backend
  sequencing already established for `identity/local`'s other storage
  interfaces (tracked as a natural follow-up once this lands, same
  shape as issue #4's resolution).
- Any UX for surfacing "retry after N seconds" to an end user --
  `Allow` returns a plain `bool`, not a duration. A consumer wanting
  richer UX can build it on top of their own `LoginLimiter`
  implementation's own methods, beyond what the interface requires.
- Rate-limiting `identity/oidc`'s login ceremony -- OIDC delegates
  credential verification entirely to the external IdP; there's no
  local password/passkey guess to rate-limit against, and the OAuth2
  code-exchange step is already bounded by the IdP's own token
  endpoint. Out of scope for this issue, which was `identity/local`-
  specific from the start.
- `identity/local`'s password-reset flow (`RequestPasswordReset`/
  `ResetPassword`) -- a separate, already-tracked issue (#7) covers its
  own (much smaller) anti-enumeration timing gap; not a brute-force
  target in the same sense as login (a reset token is a 32-byte random
  secret, not a guessable low-entropy password).

## Design decisions

**Interface is deliberately minimal -- no `retryAfter` in `Allow`'s
return value.** Every other interface in this codebase
(`CredentialStore`, `SessionStore`, `EphemeralStore`, and
`identity/oidc`'s equivalents) is storage/policy-minimal, not
UX-rich. `Allow` only needs to answer "proceed or not" for
`identity/local`'s internal purposes; a `RetryAfter`-style method can
be added to a concrete `LoginLimiter` implementation without touching
the interface, since nothing in `identity/local` needs it.

**Failures propagate as errors, not silently swallowed.** If
`RecordFailure`/`RecordSuccess` itself errors (e.g. the backing store
is down), `LoginWithPassword`/`BeginWebAuthnLogin`/`FinishWebAuthnLogin`
return that wrapped error instead of the underlying auth result. This
matches how every other unexpected store error in this codebase is
handled -- never swallowed -- at the cost of a rate-limiter backend
outage surfacing as a visible error rather than allowing login through
silently. That's the safer failure direction for a security control:
fail closed, not open.

**`Allow` is checked before any real work.** For `LoginWithPassword`,
that means before `UserStore.GetUserByUsername` or any bcrypt call --
a locked-out request costs nothing beyond the limiter check itself,
same "fail fast, minimal cost" shape the rest of this package already
uses (e.g. `SetPassword`'s doc comment on not checking user existence
first). For WebAuthn, the check happens in `BeginWebAuthnLogin`, before
generating a challenge or writing anything to `EphemeralStore`.

**Keyed by username, not userID.** `LoginWithPassword` and
`BeginWebAuthnLogin` both receive `username` as an input parameter --
keying the limiter on it (rather than resolving to `userID` first)
means a locked-out or unknown-username request never touches
`UserStore` at all, preserving both the cost-avoidance property above
and (as a side effect) not creating a timing difference between
known-username and unknown-username lockout checks. The tradeoff is
`FinishWebAuthnLogin` -- which only has `userID` from the ceremony
payload -- needs `username` added to `webauthnCeremony` so it can
record against the same key `Begin` used, rather than doing an extra
`UserStore` round-trip to resolve `userID` back to a username.

**Sliding window for the reference implementation.** Each failure is
recorded as a timestamp; `Allow`/`RecordFailure` count only the
timestamps still within `window` of now, pruning older ones as they
age out. This is deliberately not a fixed window (count reset to zero
at fixed clock-aligned boundaries) -- a fixed window lets an attacker
get up to ~2x the intended attempts by timing requests to straddle a
window boundary (e.g. `maxAttempts-1` failures at the tail of one
window, then `maxAttempts-1` more right after it resets, never
tripping the threshold in either window). The sliding-window
implementation is small (a `[]time.Time` per key instead of a
`(count, windowStart)` pair, plus a prune loop in `RecordFailure`) and
doesn't change the interface at all -- `Allow`/`RecordFailure`/
`RecordSuccess` are identical either way, so this is purely an
internal choice of `memstore.LoginLimiter`. `lockout` remains a
separate duration from `window`: once the threshold trips, the account
stays locked for `lockout` regardless of whether failures have since
aged out of the counting window.

## Types and interfaces

```go
// identity/local (store.go)

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

```go
// identity/local (errors.go)

// ErrTooManyAttempts is returned by LoginWithPassword and
// BeginWebAuthnLogin when a configured LoginLimiter reports the
// account is currently locked out.
var ErrTooManyAttempts = errors.New("tenantkit/identity/local: too many attempts")
```

```go
// identity/local (local.go)

type Config struct {
	RPID          string
	RPOrigins     []string
	RPDisplayName string
	SessionTTL    time.Duration
	ResetTokenTTL time.Duration
	// LoginLimiter is optional. When nil, login attempts are never
	// rate-limited (today's behavior, unchanged) -- matches how
	// httpmw.Config.IdentityProvider being nil skips identity
	// resolution entirely, rather than erroring.
	LoginLimiter LoginLimiter
}
```

```go
// identity/local/memstore (limiter.go)

// LoginLimiter is an in-memory reference implementation of
// local.LoginLimiter: a sliding-window failure count per (tenantID,
// username). Not a production backend -- see package doc.
type LoginLimiter struct {
	// unexported: mu sync.Mutex, maxAttempts int, window, lockout
	// time.Duration, records map[limiterKey]*limiterRecord
}

// limiterRecord (unexported): failures []time.Time (pruned to the
// last window on every RecordFailure), lockedUntil time.Time.

// NewLoginLimiter returns a LoginLimiter that locks an account out for
// lockout after maxAttempts failures within a sliding window of
// duration window (see "Design decisions" for why sliding rather than
// fixed).
func NewLoginLimiter(maxAttempts int, window, lockout time.Duration) *LoginLimiter
```

## `LoginWithPassword` integration

```go
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

The anti-enumeration dummy-hash comparison (from the original
`identity/local` design) is untouched -- `recordLoginFailure` wraps
around it, not instead of it. `l.cfg.LoginLimiter != nil` checks
appear at each of the three failure sites plus the success site,
matching `recordLoginFailure`'s own nil check for the failure paths
(the guard lives in the helper so the three call sites in the failure
paths stay one-line; the success path's guard is inline since there's
no reset-with-fallback-value symmetry to factor out).

## WebAuthn login integration

```go
// identity/local/webauthn.go

type webauthnCeremony struct {
	TenantID    string               `json:"tenant_id"`
	UserID      string               `json:"user_id"`
	Username    string               `json:"username"`  // new
	SessionData webauthn.SessionData `json:"session_data"`
}

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

The existing shared `saveCeremony` helper (also used by
`BeginWebAuthnRegistration`, keeping one ceremony-saving
implementation rather than two) gains a `username` parameter to
populate the new field -- registration's call site passes `""` since
registration ceremonies have no `LoginLimiter`-relevant username to
carry. `BeginWebAuthnRegistration`/`FinishWebAuthnRegistration` are
otherwise completely unchanged; they are not login attempts and have
no `LoginLimiter` interaction at all.

## Testing

`identity/local/storetest` gains:

```go
// TestLoginLimiter runs a battery of subtests against limiter,
// constructed with maxAttempts as its failure threshold before
// locking an account out. Pass a fresh, empty limiter.
func TestLoginLimiter(t *testing.T, limiter local.LoginLimiter, maxAttempts int)
```

Subtests: allowed up to one below threshold; locked at threshold;
`RecordSuccess` resets the counter (a subsequent `Allow` succeeds);
tenant isolation (same username, different tenant, not locked out).
Window-based pruning is implementation-specific timing, not part of
the interface contract, so it's tested separately against
`memstore.LoginLimiter` directly: a failure just outside `window` is
pruned and doesn't count toward the threshold, and (the property a
fixed window would get wrong) failures spanning a window boundary
still correctly accumulate toward the threshold rather than resetting.

`identity/local/memstore`'s own tests additionally verify
`NewLoginLimiter` satisfies `local.LoginLimiter` (compile-time
assertion) and run the conformance suite against it.

`password_test.go` and `webauthn_test.go` each gain one focused
integration test proving `LoginWithPassword`/`BeginWebAuthnLogin`
actually consult a configured `LoginLimiter` end-to-end: lock an
account out via repeated failures, then confirm a subsequent attempt
with the *correct* password/passkey still gets `ErrTooManyAttempts`
rather than succeeding -- this is the property that actually matters
(the limiter blocks even a legitimate credential once locked), not
just that the limiter's own unit tests pass in isolation.

## Open questions

None blocking. Deferred, tracked for follow-up:
- A persistent (SQLite) `LoginLimiter` backend. Sliding window maps
  naturally onto SQL -- more naturally than the in-memory
  implementation, arguably -- via a `login_attempts(tenant_id,
  username, attempted_at)` table indexed on `(tenant_id, username,
  attempted_at)`; `RecordFailure` inserts a row and can prune anything
  older than `window` in the same statement, no read-modify-write
  needed. Since `window` and `lockout` are separate durations (see
  "Design decisions"), a second small table --
  `login_lockouts(tenant_id, username, locked_until)` -- is still
  needed so `Allow` can cheaply check lockout state without
  re-counting rows on every call, and so a lockout doesn't lift early
  just because old failures aged out of the counting window.
