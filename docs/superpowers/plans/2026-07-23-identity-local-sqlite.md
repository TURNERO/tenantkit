# identity/local/sqlite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a persistent SQLite-backed implementation of `identity/local`'s three storage interfaces (`CredentialStore`, `SessionStore`, `EphemeralStore`), closing [issue #4](https://github.com/TURNERO/tenantkit/issues/4).

**Architecture:** A new `identity/local/sqlite` package, following `store/sqlite`'s existing pattern exactly: pure-Go `modernc.org/sqlite` driver, `Open(dsn)`/`Close()`, a `CREATE TABLE IF NOT EXISTS` schema list, one `Store` type implementing all three interfaces. A new `identity/local/storetest` package (mirroring `tenantkit/storetest`) provides interface-conformance test functions that both the existing `identity/local/memstore` and the new `sqlite` package run against.

**Tech Stack:** Go 1.25, `database/sql`, `modernc.org/sqlite` v1.54.0 (already a dependency), `github.com/go-webauthn/webauthn` v0.17.4 (already a dependency).

**Spec:** `docs/superpowers/specs/2026-07-23-identity-local-sqlite-design.md`

## Global Constraints

- Go 1.25.0 (module `github.com/TURNERO/tenantkit`).
- Pure-Go SQLite only: `modernc.org/sqlite` (no cgo). Register the driver via `sql.Open("sqlite", dsn)`.
- `identity/local/sqlite` is its own package, not folded into `tenantkit/store/sqlite`.
- Expiry is lazy-only: `GetSession`/`Take` check `expires_at` on read and return `local.ErrExpired`; no background sweep, no proactive deletion of expired rows.
- `Take` deletes its row unconditionally (in the same transaction) before evaluating expiry, so a token is single-use whether or not it had already expired.
- `SetPasswordHash` and `Put` are upsert-shaped (`INSERT ... ON CONFLICT DO UPDATE`), matching their documented "set"/"put" semantics.
- Every non-`ErrNotFound`/`ErrExpired` failure is wrapped with `fmt.Errorf("<action>: %w", err)`.

---

### Task 1: Extract identity/local/storetest conformance suite

**Files:**
- Create: `identity/local/storetest/storetest.go`
- Modify: `identity/local/memstore/memstore_test.go`

**Interfaces:**
- Produces: `storetest.TestCredentialStore(t *testing.T, s local.CredentialStore)`, `storetest.TestSessionStore(t *testing.T, s local.SessionStore)`, `storetest.TestEphemeralStore(t *testing.T, s local.EphemeralStore)` — later tasks (2-4) call these against `sqlite.Store`.

- [ ] **Step 1: Create the storetest package**

```go
// Package storetest provides interface-conformance test helpers for
// identity/local's storage interfaces. A consumer's own store
// implementation can run these against a fresh instance to prove it
// satisfies the documented behavior of local.CredentialStore,
// local.SessionStore, and local.EphemeralStore -- not just that it
// compiles against the interface.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit/identity/local"
	"github.com/go-webauthn/webauthn/webauthn"
)

// TestCredentialStore runs a battery of subtests against s. Pass a
// fresh, empty store.
func TestCredentialStore(t *testing.T, s local.CredentialStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("PasswordHash", func(t *testing.T) {
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
	})

	t.Run("WebAuthnCredentials", func(t *testing.T) {
		creds, err := s.GetWebAuthnCredentials(ctx, "acme", "u2")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		if len(creds) != 0 {
			t.Fatalf("got %d credentials, want 0", len(creds))
		}

		cred1 := webauthn.Credential{ID: []byte("cred-1")}
		cred2 := webauthn.Credential{ID: []byte("cred-2")}
		if err := s.AddWebAuthnCredential(ctx, "acme", "u2", cred1); err != nil {
			t.Fatalf("AddWebAuthnCredential: %v", err)
		}
		if err := s.AddWebAuthnCredential(ctx, "acme", "u2", cred2); err != nil {
			t.Fatalf("AddWebAuthnCredential: %v", err)
		}

		creds, err = s.GetWebAuthnCredentials(ctx, "acme", "u2")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		if len(creds) != 2 {
			t.Fatalf("got %d credentials, want 2", len(creds))
		}

		// Same userID in a different tenant must not see this tenant's
		// credentials.
		creds, err = s.GetWebAuthnCredentials(ctx, "other-tenant", "u2")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		if len(creds) != 0 {
			t.Fatalf("got %d credentials, want 0 (tenant isolation)", len(creds))
		}
	})
}

// TestSessionStore runs a battery of subtests against s. Pass a fresh,
// empty store.
func TestSessionStore(t *testing.T, s local.SessionStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateGetDelete", func(t *testing.T) {
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
	})

	t.Run("Expiry", func(t *testing.T) {
		token, err := s.CreateSession(ctx, "acme", "u1", -time.Second) // already expired
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if _, _, err := s.GetSession(ctx, token); !errors.Is(err, local.ErrExpired) {
			t.Fatalf("got %v, want ErrExpired", err)
		}
	})
}

// TestEphemeralStore runs a battery of subtests against s. Pass a
// fresh, empty store.
func TestEphemeralStore(t *testing.T, s local.EphemeralStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("PutTake", func(t *testing.T) {
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
	})

	t.Run("Expiry", func(t *testing.T) {
		if err := s.Put(ctx, "tok2", []byte("payload"), -time.Second); err != nil { // already expired
			t.Fatalf("Put: %v", err)
		}
		if _, err := s.Take(ctx, "tok2"); !errors.Is(err, local.ErrExpired) {
			t.Fatalf("got %v, want ErrExpired", err)
		}
		// Still single-use even though it was expired.
		if _, err := s.Take(ctx, "tok2"); !errors.Is(err, local.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound on replayed Take", err)
		}
	})
}
```

- [ ] **Step 2: Replace memstore_test.go with conformance calls + memstore-specific tests**

Replace the entire contents of `identity/local/memstore/memstore_test.go` with:

```go
package memstore_test

import (
	"context"
	"testing"

	"github.com/TURNERO/tenantkit/identity/local/memstore"
	"github.com/TURNERO/tenantkit/identity/local/storetest"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestMemstoreConformsToCredentialStore(t *testing.T) {
	storetest.TestCredentialStore(t, memstore.New())
}

func TestMemstoreConformsToSessionStore(t *testing.T) {
	storetest.TestSessionStore(t, memstore.New())
}

func TestMemstoreConformsToEphemeralStore(t *testing.T) {
	storetest.TestEphemeralStore(t, memstore.New())
}

// TestMemstore_WebAuthnCredentialsDeepCopy is memstore-specific: it
// guards against shallow copies leaking mutable internal state, a
// property storetest can't assert generically (a SQL-backed store
// round-trips through the database, so this specific failure mode
// doesn't apply there the same way).
func TestMemstore_WebAuthnCredentialsDeepCopy(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()

	cred1 := webauthn.Credential{ID: []byte("cred-1")}
	if err := s.AddWebAuthnCredential(ctx, "acme", "u1", cred1); err != nil {
		t.Fatalf("AddWebAuthnCredential: %v", err)
	}

	creds, err := s.GetWebAuthnCredentials(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}

	// Mutating a byte of the returned credential's ID in place must not
	// affect the store's copy (guards against a shallow top-level-slice-only
	// copy in GetWebAuthnCredentials).
	creds[0].ID[0] = 'X'
	fresh, err := s.GetWebAuthnCredentials(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if string(fresh[0].ID) != "cred-1" {
		t.Fatalf("store's copy was mutated by caller: got %q", fresh[0].ID)
	}

	// Mutating a byte of the cred value passed into AddWebAuthnCredential,
	// after the call returns, must not affect what's later retrieved
	// (guards against AddWebAuthnCredential storing the caller's slice by
	// reference instead of a deep copy).
	cred2 := webauthn.Credential{ID: []byte("cred-2")}
	if err := s.AddWebAuthnCredential(ctx, "acme", "u1", cred2); err != nil {
		t.Fatalf("AddWebAuthnCredential: %v", err)
	}
	cred2.ID[0] = 'X'
	fresh, err = s.GetWebAuthnCredentials(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if string(fresh[1].ID) != "cred-2" {
		t.Fatalf("store's copy was mutated by caller's post-Add mutation: got %q", fresh[1].ID)
	}
}
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `go test ./identity/local/storetest/... ./identity/local/memstore/... -v`
Expected: all tests `PASS` (memstore already satisfies the three interfaces; this step only restructures tests, so nothing should fail).

- [ ] **Step 4: Commit**

```bash
git add identity/local/storetest/storetest.go identity/local/memstore/memstore_test.go
git commit -m "test: extract identity/local/storetest conformance suite"
```

---

### Task 2: identity/local/sqlite skeleton + CredentialStore

**Files:**
- Create: `identity/local/sqlite/sqlite.go`
- Test: `identity/local/sqlite/sqlite_test.go`

**Interfaces:**
- Consumes: `local.CredentialStore`, `local.ErrNotFound` (`identity/local/store.go`, `identity/local/errors.go`); `webauthn.Credential` (`github.com/go-webauthn/webauthn/webauthn`); `storetest.TestCredentialStore` (Task 1).
- Produces: `sqlite.Store`, `sqlite.Open(dsn string) (*sqlite.Store, error)`, `(*sqlite.Store).Close() error` — later tasks (3-5) add methods to this same type and reuse `Open`/`Close`.

- [ ] **Step 1: Write the failing test**

Create `identity/local/sqlite/sqlite_test.go`:

```go
package sqlite_test

import (
	"testing"

	"github.com/TURNERO/tenantkit/identity/local/sqlite"
	"github.com/TURNERO/tenantkit/identity/local/storetest"
)

func openTestDB(t *testing.T) *sqlite.Store {
	t.Helper()
	db, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSQLiteConformsToCredentialStore(t *testing.T) {
	storetest.TestCredentialStore(t, openTestDB(t))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./identity/local/sqlite/... -v`
Expected: FAIL — build error, `package github.com/TURNERO/tenantkit/identity/local/sqlite is not in std` (the package doesn't exist yet).

- [ ] **Step 3: Implement the schema, Open/Close, and CredentialStore**

Create `identity/local/sqlite/sqlite.go`:

```go
// Package sqlite is a SQLite-backed implementation of identity/local's
// storage interfaces (CredentialStore, SessionStore, EphemeralStore),
// using the same pure-Go modernc.org/sqlite driver, Open/Close, and
// schema-migration pattern as tenantkit/store/sqlite. Unlike
// identity/local/memstore, this is meant for real use: a persistent
// backend for identity/local's password, WebAuthn, session, and
// password-reset state.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TURNERO/tenantkit/identity/local"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite"
)

var schema = []string{
	`CREATE TABLE IF NOT EXISTS password_hashes (
		tenant_id TEXT NOT NULL,
		user_id   TEXT NOT NULL,
		hash      TEXT NOT NULL,
		PRIMARY KEY (tenant_id, user_id)
	)`,
	`CREATE TABLE IF NOT EXISTS webauthn_credentials (
		credential_id TEXT PRIMARY KEY,
		tenant_id     TEXT NOT NULL,
		user_id       TEXT NOT NULL,
		data          TEXT NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS webauthn_credentials_user ON webauthn_credentials (tenant_id, user_id)`,
	`CREATE TABLE IF NOT EXISTS sessions (
		token      TEXT PRIMARY KEY,
		tenant_id  TEXT NOT NULL,
		user_id    TEXT NOT NULL,
		expires_at INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS ephemeral_tokens (
		token      TEXT PRIMARY KEY,
		payload    BLOB NOT NULL,
		expires_at INTEGER NOT NULL
	)`,
}

// Store is a SQLite-backed local.CredentialStore, local.SessionStore,
// and local.EphemeralStore.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) a SQLite database at dsn and runs
// its schema migration. dsn is passed directly to modernc.org/sqlite --
// a file path, or ":memory:" for a non-persistent in-process database
// (typically for tests).
//
// For ":memory:", Open limits the connection pool to a single
// connection, matching tenantkit/store/sqlite.Open -- SQLite's
// in-memory mode gives each connection its own private database, so
// without this, database/sql's connection pooling would make different
// queries silently see different, mostly-empty databases.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if dsn == ":memory:" {
		db.SetMaxOpenConns(1)
	}
	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database connection(s).
func (s *Store) Close() error {
	return s.db.Close()
}

var _ local.CredentialStore = (*Store)(nil)

func (s *Store) SetPasswordHash(ctx context.Context, tenantID, userID, hash string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO password_hashes (tenant_id, user_id, hash) VALUES (?, ?, ?)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET hash = excluded.hash`,
		tenantID, userID, hash)
	if err != nil {
		return fmt.Errorf("set password hash: %w", err)
	}
	return nil
}

func (s *Store) GetPasswordHash(ctx context.Context, tenantID, userID string) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT hash FROM password_hashes WHERE tenant_id = ? AND user_id = ?`, tenantID, userID).
		Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", local.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get password hash: %w", err)
	}
	return hash, nil
}

func (s *Store) AddWebAuthnCredential(ctx context.Context, tenantID, userID string, cred webauthn.Credential) error {
	data, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("encode webauthn credential: %w", err)
	}
	credentialID := base64.RawURLEncoding.EncodeToString(cred.ID)
	_, err = s.db.ExecContext(ctx, `INSERT INTO webauthn_credentials (credential_id, tenant_id, user_id, data) VALUES (?, ?, ?, ?)`,
		credentialID, tenantID, userID, string(data))
	if err != nil {
		return fmt.Errorf("add webauthn credential: %w", err)
	}
	return nil
}

func (s *Store) GetWebAuthnCredentials(ctx context.Context, tenantID, userID string) ([]webauthn.Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM webauthn_credentials WHERE tenant_id = ? AND user_id = ? ORDER BY credential_id`, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("get webauthn credentials: %w", err)
	}
	defer rows.Close()

	var out []webauthn.Credential
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scan webauthn credential: %w", err)
		}
		var cred webauthn.Credential
		if err := json.Unmarshal([]byte(data), &cred); err != nil {
			return nil, fmt.Errorf("decode webauthn credential: %w", err)
		}
		out = append(out, cred)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("get webauthn credentials: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./identity/local/sqlite/... -v`
Expected: `PASS` — `TestSQLiteConformsToCredentialStore` and its subtests (`PasswordHash`, `WebAuthnCredentials`) all pass.

- [ ] **Step 5: Commit**

```bash
git add identity/local/sqlite/sqlite.go identity/local/sqlite/sqlite_test.go
git commit -m "feat: add identity/local/sqlite CredentialStore"
```

---

### Task 3: identity/local/sqlite SessionStore

**Files:**
- Modify: `identity/local/sqlite/sqlite.go`
- Modify: `identity/local/sqlite/sqlite_test.go`

**Interfaces:**
- Consumes: `local.SessionStore`, `local.ErrExpired` (`identity/local/store.go`, `identity/local/errors.go`); `store.GenerateSecret() (string, error)` (`tenantkit/store/helpers.go`); `storetest.TestSessionStore` (Task 1); `sqlite.Store`, `openTestDB` (Task 2).
- Produces: `(*sqlite.Store).CreateSession`, `.GetSession`, `.DeleteSession` — no later task depends on these directly, but Task 5's durability test may exercise any of the three interfaces.

- [ ] **Step 1: Write the failing test**

Add to `identity/local/sqlite/sqlite_test.go`:

```go
func TestSQLiteConformsToSessionStore(t *testing.T) {
	storetest.TestSessionStore(t, openTestDB(t))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./identity/local/sqlite/... -run TestSQLiteConformsToSessionStore -v`
Expected: FAIL — build error, `*sqlite.Store` does not implement `local.SessionStore` isn't yet asserted, but `storetest.TestSessionStore` requires a `local.SessionStore` argument and `*sqlite.Store` is missing `CreateSession`/`GetSession`/`DeleteSession`, so this fails to compile: `cannot use openTestDB(t) (value of type *sqlite.Store) as local.SessionStore value`.

- [ ] **Step 3: Implement SessionStore**

Add to `identity/local/sqlite/sqlite.go` (extend the existing `import` block: add `"time"`, and add `"github.com/TURNERO/tenantkit/store"` for `GenerateSecret`):

```go
import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/TURNERO/tenantkit/identity/local"
	"github.com/TURNERO/tenantkit/store"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite"
)
```

Append:

```go
var _ local.SessionStore = (*Store)(nil)

func (s *Store) CreateSession(ctx context.Context, tenantID, userID string, ttl time.Duration) (string, error) {
	token, err := store.GenerateSecret()
	if err != nil {
		return "", err
	}
	expiresAt := time.Now().Add(ttl).Unix()
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions (token, tenant_id, user_id, expires_at) VALUES (?, ?, ?, ?)`,
		token, tenantID, userID, expiresAt)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return token, nil
}

func (s *Store) GetSession(ctx context.Context, token string) (string, string, error) {
	var tenantID, userID string
	var expiresAt int64
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id, user_id, expires_at FROM sessions WHERE token = ?`, token).
		Scan(&tenantID, &userID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", local.ErrNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("get session: %w", err)
	}
	if time.Now().Unix() > expiresAt {
		return "", "", local.ErrExpired
	}
	return tenantID, userID, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./identity/local/sqlite/... -v`
Expected: `PASS` for all tests, including `TestSQLiteConformsToSessionStore` and its subtests (`CreateGetDelete`, `Expiry`).

- [ ] **Step 5: Commit**

```bash
git add identity/local/sqlite/sqlite.go identity/local/sqlite/sqlite_test.go
git commit -m "feat: add identity/local/sqlite SessionStore"
```

---

### Task 4: identity/local/sqlite EphemeralStore

**Files:**
- Modify: `identity/local/sqlite/sqlite.go`
- Modify: `identity/local/sqlite/sqlite_test.go`

**Interfaces:**
- Consumes: `local.EphemeralStore` (`identity/local/store.go`); `storetest.TestEphemeralStore` (Task 1); `sqlite.Store`, `openTestDB` (Task 2).
- Produces: `(*sqlite.Store).Put`, `.Take` — completes `*sqlite.Store`'s conformance to all three `identity/local` storage interfaces.

- [ ] **Step 1: Write the failing test**

Add to `identity/local/sqlite/sqlite_test.go`:

```go
func TestSQLiteConformsToEphemeralStore(t *testing.T) {
	storetest.TestEphemeralStore(t, openTestDB(t))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./identity/local/sqlite/... -run TestSQLiteConformsToEphemeralStore -v`
Expected: FAIL — build error, `cannot use openTestDB(t) (value of type *sqlite.Store) as local.EphemeralStore value` (`Put`/`Take` not yet implemented).

- [ ] **Step 3: Implement EphemeralStore**

Append to `identity/local/sqlite/sqlite.go`:

```go
var _ local.EphemeralStore = (*Store)(nil)

func (s *Store) Put(ctx context.Context, token string, payload []byte, ttl time.Duration) error {
	expiresAt := time.Now().Add(ttl).Unix()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ephemeral_tokens (token, payload, expires_at) VALUES (?, ?, ?)
		ON CONFLICT (token) DO UPDATE SET payload = excluded.payload, expires_at = excluded.expires_at`,
		token, payload, expiresAt)
	if err != nil {
		return fmt.Errorf("put ephemeral token: %w", err)
	}
	return nil
}

// Take fetches and deletes token's row in one transaction, so the
// delete happens regardless of the outcome (found, expired, or not
// found) -- concurrent Take calls for the same token can't both
// succeed, matching local.EphemeralStore's single-use contract.
func (s *Store) Take(ctx context.Context, token string) ([]byte, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("take ephemeral token: %w", err)
	}
	defer tx.Rollback()

	var payload []byte
	var expiresAt int64
	err = tx.QueryRowContext(ctx, `SELECT payload, expires_at FROM ephemeral_tokens WHERE token = ?`, token).
		Scan(&payload, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, local.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("take ephemeral token: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM ephemeral_tokens WHERE token = ?`, token); err != nil {
		return nil, fmt.Errorf("take ephemeral token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("take ephemeral token: %w", err)
	}

	if time.Now().Unix() > expiresAt {
		return nil, local.ErrExpired
	}
	return payload, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./identity/local/sqlite/... -v`
Expected: `PASS` for all tests, including `TestSQLiteConformsToEphemeralStore` and its subtests (`PutTake`, `Expiry`).

- [ ] **Step 5: Commit**

```bash
git add identity/local/sqlite/sqlite.go identity/local/sqlite/sqlite_test.go
git commit -m "feat: add identity/local/sqlite EphemeralStore"
```

---

### Task 5: sqlite-specific tests (idempotent migration, durability)

**Files:**
- Modify: `identity/local/sqlite/sqlite_test.go`

**Interfaces:**
- Consumes: `sqlite.Open`, `(*sqlite.Store).Close`, `.SetPasswordHash`, `.GetPasswordHash` (Task 2).

- [ ] **Step 1: Write the tests**

Add to `identity/local/sqlite/sqlite_test.go` (add `"context"` to the import block):

```go
func TestSQLiteStore_OpenTwiceIdempotent(t *testing.T) {
	dir := t.TempDir()
	dsn := dir + "/test.db"

	db1, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db2, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("second Open on same dsn: %v", err)
	}
	defer db2.Close()
}

func TestSQLiteStore_Durability(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dsn := dir + "/test.db"

	db1, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db1.SetPasswordHash(ctx, "acme", "u1", "hash1"); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db2, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()

	got, err := db2.GetPasswordHash(ctx, "acme", "u1")
	if err != nil {
		t.Fatalf("GetPasswordHash after reopen: %v", err)
	}
	if got != "hash1" {
		t.Fatalf("got %q, want %q", got, "hash1")
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./identity/local/sqlite/... -v`
Expected: `PASS` for `TestSQLiteStore_OpenTwiceIdempotent` and `TestSQLiteStore_Durability`, plus all prior tests in the package still passing.

- [ ] **Step 3: Commit**

```bash
git add identity/local/sqlite/sqlite_test.go
git commit -m "test: cover identity/local/sqlite migration idempotency and durability"
```

---

### Task 6: Update README status

**Files:**
- Modify: `README.md`

**Interfaces:** None (documentation only).

- [ ] **Step 1: Update the Status section**

In `README.md`, find this text:

```
`identity/local` — password (bcrypt) and WebAuthn (passkey)
authentication, opaque-token sessions, and password reset, satisfying the
`IdentityProvider` interface `httpmw`/`grpcmw` already consume.
`identity/oidc` is not yet built — see `docs/superpowers/specs/` for the
full design and `docs/superpowers/plans/` for implementation status. Not
yet ready for production use.
```

Replace it with:

```
`identity/local` — password (bcrypt) and WebAuthn (passkey)
authentication, opaque-token sessions, and password reset, satisfying the
`IdentityProvider` interface `httpmw`/`grpcmw` already consume, plus a
persistent SQLite-backed store for it (`identity/local/sqlite`).
`identity/oidc` is not yet built — see `docs/superpowers/specs/` for the
full design and `docs/superpowers/plans/` for implementation status. Not
yet ready for production use.
```

- [ ] **Step 2: Verify the change**

Run: `grep -n "identity/local/sqlite" README.md`
Expected: one match, in the Status section.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: update README Status for identity/local/sqlite"
```

---

## Final Verification

- [ ] Run the full test suite: `go build ./... && go vet ./... && go test ./...`
  Expected: all packages build, vet clean, all tests `PASS`.
- [ ] Confirm `identity/local/sqlite` and `identity/local/storetest` both appear in `go test ./...` output.
- [ ] Push the branch and let CI (`.github/workflows/ci.yml`) confirm build+vet+test on the PR before merging to master, per this repo's existing merge gate.
