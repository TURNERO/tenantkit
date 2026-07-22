# identity/local design

## Overview

`tenantkit/identity/local` is the built-in `identity.IdentityProvider`
implementation: password (bcrypt) and WebAuthn (passkey) authentication,
opaque-token sessions, and a basic password-reset token flow. It's the
first of two planned `IdentityProvider` implementations — `identity/oidc`
(wrapping an external IdP) is a separate, later plan; the two share only
the `IdentityProvider` interface and don't otherwise depend on each other.

This plan resolves [issue #1](https://github.com/TURNERO/tenantkit/issues/1)
(now closed): sessions are an opaque random token validated via a store
round-trip, not a signed JWT. See
`docs/superpowers/specs/2026-07-20-tenantkit-design.md`'s Open Questions
section for that decision's rationale.

## Scope

In scope for this plan:
- Password authentication (bcrypt), with anti-enumeration handling.
- WebAuthn (passkey) registration and login, via `go-webauthn/webauthn`.
- Opaque-token session issuance/validation/revocation (`Authenticate`
  satisfies `identity.IdentityProvider`).
- A basic password-reset token flow (token lifecycle only; delivery,
  e.g. email, is the consumer's responsibility).
- Three new storage interfaces (`CredentialStore`, `SessionStore`,
  `EphemeralStore`), owned by `identity/local`, plus an in-memory
  reference implementation for tests.

Out of scope, deferred to follow-up plans:
- A persistent (SQLite) implementation of the three new interfaces —
  same sequencing as `store/sqlite` following the Foundation plan.
  Without it, `identity/local` has no production-usable backend yet;
  that's an accepted gap for this plan, closed by the follow-up.
- `identity/oidc`.
- Any HTTP transport (login/logout/registration routes, email delivery
  for password reset). `identity/local` exposes Go functions a consumer
  wires into their own handlers, matching tenantkit's existing
  "middleware, not a framework" and "no opinionated HTTP API" positioning
  (`cmd/tenantkit-admin` is a CLI, not an admin HTTP API, for the same
  reason).
- Account lockout / rate limiting on failed login attempts. Real
  production-hardening concern, but orthogonal to this plan's shape;
  a consumer wanting it today can rate-limit at their handler layer.

## Package layout

```
tenantkit/identity/local/
  local.go       // Config, Local, New
  password.go    // SetPassword, LoginWithPassword, Logout
  webauthn.go    // Begin/FinishWebAuthnRegistration, Begin/FinishWebAuthnLogin, webauthnUser adapter
  reset.go       // RequestPasswordReset, ResetPassword
  session.go     // Authenticate (IdentityProvider), SetSessionCookie, ClearSessionCookie, SessionCookieName
  store.go       // CredentialStore, SessionStore, EphemeralStore interfaces
  errors.go      // sentinel errors
```

A reference in-memory implementation of the three storage interfaces
lives in a new `identity/local/memstore` sub-package, mirroring
`tenantkit/store/memstore`'s role for the core store interfaces.

## Storage interfaces

```go
package local

// CredentialStore holds password hashes and WebAuthn credentials.
// Implementations key both by (tenantID, userID) -- usernames are only
// unique within a tenant, matching UserStore's existing scoping.
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
	// (existed, past ttl) -- callers treat both as "not authenticated",
	// but the distinction matters for implementations (ErrExpired
	// implies safe to garbage-collect the row).
	GetSession(ctx context.Context, token string) (tenantID, userID string, err error)
	DeleteSession(ctx context.Context, token string) error
}

// EphemeralStore holds short-lived, single-use opaque tokens: WebAuthn
// ceremony state (go-webauthn's SessionData, serialized) and
// password-reset tokens both use this -- structurally identical
// (opaque token -> payload blob, TTL, consumed exactly once), so one
// interface covers both rather than two near-duplicates.
type EphemeralStore interface {
	Put(ctx context.Context, token string, payload []byte, ttl time.Duration) error
	// Take fetches and deletes atomically, so single-use is a property
	// of the interface -- a replayed ceremony-finish or reset request
	// always fails on the second attempt, not something every caller
	// has to remember to enforce itself.
	Take(ctx context.Context, token string) ([]byte, error) // ErrNotFound / ErrExpired
}
```

## `Local` type

```go
package local

type Config struct {
	RPID          string        // WebAuthn relying-party ID (your domain)
	RPOrigins     []string      // allowed origins for WebAuthn ceremonies
	RPDisplayName string
	SessionTTL    time.Duration
	ResetTokenTTL time.Duration
}

type Local struct {
	// unexported: cfg Config, users store.UserStore, creds CredentialStore,
	// sessions SessionStore, ephemeral EphemeralStore, wa *webauthn.WebAuthn
}

func New(cfg Config, users store.UserStore, creds CredentialStore, sessions SessionStore, ephemeral EphemeralStore) (*Local, error)
```

Every method below assumes `tenantID`/`userID` already has a record in
`UserStore` -- `Local` never creates users itself, only credentials for
users that already exist (created via `tenantkit/admin.CreateUser` or a
consumer's own equivalent). A `tenantID`/`userID` pair with no matching
`UserStore` record is treated as `ErrNotFound`, same as any other
not-found lookup.

## Password authentication

```go
func (l *Local) SetPassword(ctx context.Context, tenantID, userID, password string) error
func (l *Local) LoginWithPassword(ctx context.Context, tenantID, username, password string) (token string, err error)
func (l *Local) Logout(ctx context.Context, token string) error
```

`SetPassword` is the primitive; this plan does not define the flow that
calls it (admin-driven invite vs. self-service "set your password" is a
consumer decision, same reasoning as `tenantkit/admin` not owning an
invite HTTP endpoint).

`LoginWithPassword` returns a single `ErrInvalidCredentials` whether the
username doesn't exist or the password is wrong -- a caller can never
distinguish "no such user" from "wrong password" from the error alone.
To avoid a timing side-channel leaking the same information (a real
`bcrypt.CompareHashAndPassword` call is measurably slower than an early
return), the unknown-user path still runs `bcrypt.CompareHashAndPassword`
against a fixed dummy hash so both paths take comparable time.

## WebAuthn (passkey) authentication

Uses `go-webauthn/webauthn`. An unexported adapter bridges `Identity` +
`CredentialStore` to its `webauthn.User` interface:

```go
type webauthnUser struct {
	identity *tenantkit.Identity
	creds    []webauthn.Credential
}
func (u *webauthnUser) WebAuthnID() []byte {
	sum := sha256.Sum256([]byte(u.identity.TenantID + ":" + u.identity.UserID))
	return sum[:]
}
func (u *webauthnUser) WebAuthnName() string        { return u.identity.Username }
func (u *webauthnUser) WebAuthnDisplayName() string { return u.identity.Username }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }
```

`WebAuthnID` must be unique per Relying Party -- i.e. across the whole
deployment, not just within a tenant. Bare `UserID` isn't safe for this:
`UserStore`'s own uniqueness guarantee only spans `(tenantID, username)`,
so two tenants could in principle produce the same `UserID` depending on
how a consumer assigns them. A raw `tenantID + ":" + userID` string
composite would fix the collision risk but not fit WebAuthn's 64-byte
user-handle limit (tenantkit's default ID generators alone produce a
32-char tenant ID + a 43-char user ID -- 76 bytes combined, before even
counting a real username). Hashing the composite with SHA-256 gives a
fixed 32-byte opaque handle that's both collision-resistant and safely
under the limit regardless of how long a consumer's own IDs are.

Registration adds a passkey to an already-known user -- not anonymous
signup:

```go
func (l *Local) BeginWebAuthnRegistration(ctx context.Context, tenantID, userID string) (challenge *protocol.CredentialCreation, ceremonyToken string, err error)
func (l *Local) FinishWebAuthnRegistration(ctx context.Context, tenantID, userID, ceremonyToken string, r *http.Request) error
```

`Begin` stores go-webauthn's `SessionData` (serialized) in
`EphemeralStore` under a fresh `ceremonyToken`, returning both the
challenge (the consumer's handler sends this to the browser as JSON) and
the token (round-tripped back to `Finish` by the consumer -- a hidden
form field or short-lived cookie, consumer's choice). `Finish` calls
`EphemeralStore.Take` (single-use), decodes the session data, and calls
go-webauthn's `FinishRegistration`, storing the resulting credential via
`CredentialStore.AddWebAuthnCredential`.

Login mirrors this shape:

```go
func (l *Local) BeginWebAuthnLogin(ctx context.Context, tenantID, username string) (challenge *protocol.CredentialAssertion, ceremonyToken string, err error)
func (l *Local) FinishWebAuthnLogin(ctx context.Context, ceremonyToken string, r *http.Request) (token string, err error)
```

`FinishWebAuthnLogin` doesn't take `tenantID`/`username` again -- the
ceremony token, consumed via `EphemeralStore.Take`, already carries which
user this assertion is being verified against (encoded into the saved
payload alongside go-webauthn's `SessionData`). On success it calls
`SessionStore.CreateSession`, same as the password path.

**Testing risk, flagged not solved here:** WebAuthn ceremonies involve
browser-side private-key signatures; `go-webauthn` ships no virtual
authenticator. The implementation plan needs to scratch-verify a testing
approach (likely pre-computed test vectors simulating an authenticator's
signed response) before this code is written into the plan itself --
same practice used to catch the SQLite `:memory:` pooling footgun ahead
of the Admin plan.

## Password reset

```go
func (l *Local) RequestPasswordReset(ctx context.Context, tenantID, username string) (token string, err error)
func (l *Local) ResetPassword(ctx context.Context, resetToken, newPassword string) error
```

`RequestPasswordReset` looks up the user, generates a random token,
stores it in `EphemeralStore` (payload: tenantID + userID, TTL =
`Config.ResetTokenTTL`), and returns it -- delivery (email, etc.) is
entirely the consumer's responsibility. If the username doesn't exist,
it still returns a syntactically valid token and no error, rather than a
distinguishable error a caller could use to probe for valid usernames --
same anti-enumeration reasoning as `LoginWithPassword`.

`ResetPassword` calls `EphemeralStore.Take(resetToken)` (single-use),
decodes the tenant/user, and calls `SetPassword`.

## Session validation (`identity.IdentityProvider`)

```go
func (l *Local) Authenticate(ctx context.Context, src resolve.Source) (*tenantkit.Identity, error)
```

Parses the session cookie out of `src.Header("Cookie")`, looks it up via
`SessionStore.GetSession`, then calls `UserStore.GetUser` for the full
`Identity`. `resolve.Source` gains no new methods -- `Header("Cookie")`
already covers this.

Per `identity.IdentityProvider`'s contract ("nil for a request with no
associated human identity"), an absent session credential is not an
error: no `Cookie` header, a `Cookie` header without the session cookie,
or one that fails to parse all return `(nil, nil)` -- `httpmw`/`grpcmw`
treat any non-nil `Authenticate` error as a hard 401/Unauthenticated, so
treating "no session offered" as an error would reject all API-key/mTLS
and anonymous traffic on a mixed route. A session cookie that IS present
but doesn't resolve to a valid, unexpired session is a genuine
authentication failure and still returns a real error.

Session token transport is a cookie, not a header: identity/local
sessions are fundamentally a browser/human-login concept (WebAuthn is
inherently a browser API), so a `Secure`/`HttpOnly` cookie set on login
and sent automatically thereafter is the natural fit. gRPC clients
wouldn't typically use session-cookie auth anyway (API keys or mTLS are
`grpcmw`'s expected paths).

The cookie name is an exported constant (`local.SessionCookieName`) plus
small helpers:

```go
func SetSessionCookie(w http.ResponseWriter, token string)
func ClearSessionCookie(w http.ResponseWriter)
```

so a consumer's login/logout HTTP handlers stay byte-for-byte consistent
with what `Authenticate` parses back out -- no risk of the cookie name
drifting between the two sides.

## Error handling

Sentinel errors, matching `tenantkit/store`'s `"tenantkit/<package>: ..."`
convention:

```go
var ErrNotFound          = errors.New("tenantkit/identity/local: not found")
var ErrExpired            = errors.New("tenantkit/identity/local: expired")
var ErrInvalidCredentials = errors.New("tenantkit/identity/local: invalid credentials")
```

`ErrNotFound`/`ErrExpired` are returned by the storage interfaces
(`CredentialStore`, `SessionStore`, `EphemeralStore`) for missing/expired
rows. `ErrInvalidCredentials` is `Local`'s own error for a failed login
(password or WebAuthn) -- deliberately not `ErrNotFound`, so a consumer
can't accidentally special-case "user doesn't exist" differently from
"wrong password" even if they wanted to.

## Testing strategy

- Password path: bcrypt round-trip, wrong password, unknown user (both
  take `ErrInvalidCredentials`), `SetPassword` overwriting an existing
  hash.
- Session store (in-memory reference impl): create/get/expire/delete,
  `GetSession` distinguishing `ErrNotFound` from `ErrExpired`.
- Ephemeral store (in-memory reference impl): TTL expiry, `Take` being
  genuinely single-use (second `Take` on the same token fails).
- `Authenticate`: no cookie, malformed cookie, unknown token, expired
  session, valid session -- table-driven against a fake `resolve.Source`.
- WebAuthn: registration and login ceremonies, using pre-computed test
  vectors (see Testing risk above) -- exact approach TBD during
  implementation, scratch-verified before being written into the plan.
- Password reset: request-then-reset happy path, unknown username still
  returns a token (anti-enumeration), reset token is single-use, expired
  reset token rejected.

## Open questions

None blocking. Deferred, tracked for follow-up plans:
- Persistent (SQLite) implementation of `CredentialStore`/`SessionStore`/
  `EphemeralStore`. (issue #4)
- `identity/oidc`. (issue #5)
- Account lockout / login rate-limiting. (issue #6)
