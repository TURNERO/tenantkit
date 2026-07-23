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
