// Package sqlite is a SQLite-backed implementation of all four
// tenantkit/store interfaces (TenantStore, UserStore, APIKeyStore,
// ClientCertStore), using the pure-Go modernc.org/sqlite driver -- no
// cgo, no server process, just a library reading/writing one file (or
// ":memory:" for tests). Unlike store/memstore, this is meant for real
// use: it's cmd/tenantkit-admin's default backend, and usable standalone
// by any consumer who wants a persistent store without writing their
// own.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"

	sqlite3 "modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"
)

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

// Store is a SQLite-backed store.TenantStore, store.UserStore,
// store.APIKeyStore, and store.ClientCertStore.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) a SQLite database at dsn and runs
// its schema migration. dsn is passed directly to modernc.org/sqlite --
// a file path, or ":memory:" for a non-persistent in-process database
// (typically for tests).
//
// For ":memory:", Open limits the connection pool to a single
// connection: SQLite's in-memory mode gives each connection its own
// private database, so without this, database/sql's connection pooling
// would make different queries silently see different, mostly-empty
// databases. A file-backed dsn doesn't have this problem -- all
// connections share the same file -- so the pool isn't limited in that
// case.
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

var (
	_ store.TenantStore       = (*Store)(nil)
	_ store.UserStore         = (*Store)(nil)
	_ store.APIKeyStore       = (*Store)(nil)
	_ store.ClientCertStore   = (*Store)(nil)
	_ store.OIDCProviderStore = (*Store)(nil)
)

// isUniqueViolation reports whether err is a SQLite PRIMARY KEY or
// UNIQUE constraint violation -- the only constraint failures this
// store's schema can produce through normal use (there's no NOT NULL
// or CHECK constraint reachable with a well-formed Go struct, and
// foreign keys aren't enforced since PRAGMA foreign_keys is never set).
// Any other error is left as a generic wrapped error rather than
// misreported as store.ErrAlreadyExists.
func isUniqueViolation(err error) bool {
	var serr *sqlite3.Error
	if !errors.As(err, &serr) {
		return false
	}
	switch serr.Code() {
	case sqlitelib.SQLITE_CONSTRAINT_PRIMARYKEY, sqlitelib.SQLITE_CONSTRAINT_UNIQUE:
		return true
	default:
		return false
	}
}

func (s *Store) GetTenant(ctx context.Context, tenantID string) (*tenantkit.Tenant, error) {
	var t tenantkit.Tenant
	var active int
	err := s.db.QueryRowContext(ctx, `SELECT id, display_name, active FROM tenants WHERE id = ?`, tenantID).
		Scan(&t.ID, &t.DisplayName, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get tenant: %w", err)
	}
	t.Active = active != 0
	return &t, nil
}

func (s *Store) CreateTenant(ctx context.Context, t *tenantkit.Tenant) error {
	active := 0
	if t.Active {
		active = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO tenants (id, display_name, active) VALUES (?, ?, ?)`, t.ID, t.DisplayName, active)
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("create tenant: %w", err)
	}
	return nil
}

func (s *Store) ListTenants(ctx context.Context) ([]*tenantkit.Tenant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, display_name, active FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	var out []*tenantkit.Tenant
	for rows.Next() {
		var t tenantkit.Tenant
		var active int
		if err := rows.Scan(&t.ID, &t.DisplayName, &active); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		t.Active = active != 0
		out = append(out, &t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	return out, nil
}

func (s *Store) DeactivateTenant(ctx context.Context, tenantID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tenants SET active = 0 WHERE id = ?`, tenantID)
	if err != nil {
		return fmt.Errorf("deactivate tenant: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("deactivate tenant: %w", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) GetUser(ctx context.Context, userID string) (*tenantkit.Identity, error) {
	row := s.db.QueryRowContext(ctx, `SELECT user_id, tenant_id, username, roles FROM users WHERE user_id = ?`, userID)
	return scanUser(row)
}

func (s *Store) GetUserByUsername(ctx context.Context, tenantID, username string) (*tenantkit.Identity, error) {
	row := s.db.QueryRowContext(ctx, `SELECT user_id, tenant_id, username, roles FROM users WHERE tenant_id = ? AND username = ?`, tenantID, username)
	return scanUser(row)
}

func scanUser(row *sql.Row) (*tenantkit.Identity, error) {
	var id tenantkit.Identity
	var rolesJSON string
	err := row.Scan(&id.UserID, &id.TenantID, &id.Username, &rolesJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if err := json.Unmarshal([]byte(rolesJSON), &id.Roles); err != nil {
		return nil, fmt.Errorf("decode roles: %w", err)
	}
	return &id, nil
}

func (s *Store) CreateUser(ctx context.Context, u *tenantkit.Identity) error {
	rolesJSON, err := json.Marshal(u.Roles)
	if err != nil {
		return fmt.Errorf("encode roles: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO users (user_id, tenant_id, username, roles) VALUES (?, ?, ?, ?)`, u.UserID, u.TenantID, u.Username, string(rolesJSON))
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (s *Store) GetAPIKeyByHash(ctx context.Context, hash string) (*tenantkit.APIKey, error) {
	var k tenantkit.APIKey
	err := s.db.QueryRowContext(ctx, `SELECT hash, tenant_id, user_id FROM api_keys WHERE hash = ?`, hash).
		Scan(&k.Hash, &k.TenantID, &k.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get api key: %w", err)
	}
	return &k, nil
}

func (s *Store) CreateAPIKey(ctx context.Context, k *tenantkit.APIKey) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_keys (hash, tenant_id, user_id) VALUES (?, ?, ?)`, k.Hash, k.TenantID, k.UserID)
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("create api key: %w", err)
	}
	return nil
}

func (s *Store) RevokeAPIKey(ctx context.Context, hash string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE hash = ?`, hash)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) GetClientCertByFingerprint(ctx context.Context, fingerprint string) (*tenantkit.ClientCert, error) {
	var c tenantkit.ClientCert
	err := s.db.QueryRowContext(ctx, `SELECT fingerprint, tenant_id, user_id FROM client_certs WHERE fingerprint = ?`, fingerprint).
		Scan(&c.Fingerprint, &c.TenantID, &c.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get client cert: %w", err)
	}
	return &c, nil
}

func (s *Store) CreateClientCert(ctx context.Context, c *tenantkit.ClientCert) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO client_certs (fingerprint, tenant_id, user_id) VALUES (?, ?, ?)`, c.Fingerprint, c.TenantID, c.UserID)
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("create client cert: %w", err)
	}
	return nil
}

func (s *Store) RevokeClientCert(ctx context.Context, fingerprint string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM client_certs WHERE fingerprint = ?`, fingerprint)
	if err != nil {
		return fmt.Errorf("revoke client cert: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke client cert: %w", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

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
