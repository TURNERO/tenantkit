// Package memstore is an in-memory implementation of identity/local's
// storage interfaces. It exists for tests -- both tenantkit's own and a
// consumer's -- not as a production backend: nothing is persisted, and
// every method takes a single mutex.
package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/TURNERO/tenantkit/identity/local"
	"github.com/TURNERO/tenantkit/store"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Store is an in-memory local.CredentialStore, local.SessionStore, and
// local.EphemeralStore.
type Store struct {
	mu sync.Mutex

	passwordHashes map[credentialKey]string
	webauthnCreds  map[credentialKey][]webauthn.Credential

	sessions  map[string]sessionRecord
	ephemeral map[string]ephemeralRecord
}

type credentialKey struct {
	tenantID string
	userID   string
}

type sessionRecord struct {
	tenantID string
	userID   string
	expires  time.Time
}

type ephemeralRecord struct {
	payload []byte
	expires time.Time
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		passwordHashes: make(map[credentialKey]string),
		webauthnCreds:  make(map[credentialKey][]webauthn.Credential),
		sessions:       make(map[string]sessionRecord),
		ephemeral:      make(map[string]ephemeralRecord),
	}
}

var (
	_ local.CredentialStore = (*Store)(nil)
	_ local.SessionStore    = (*Store)(nil)
	_ local.EphemeralStore  = (*Store)(nil)
)

func (s *Store) SetPasswordHash(ctx context.Context, tenantID, userID, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passwordHashes[credentialKey{tenantID, userID}] = hash
	return nil
}

func (s *Store) GetPasswordHash(ctx context.Context, tenantID, userID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.passwordHashes[credentialKey{tenantID, userID}]
	if !ok {
		return "", local.ErrNotFound
	}
	return hash, nil
}

func (s *Store) AddWebAuthnCredential(ctx context.Context, tenantID, userID string, cred webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := credentialKey{tenantID, userID}
	s.webauthnCreds[key] = append(s.webauthnCreds[key], cred)
	return nil
}

func (s *Store) GetWebAuthnCredentials(ctx context.Context, tenantID, userID string) ([]webauthn.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	creds := s.webauthnCreds[credentialKey{tenantID, userID}]
	out := make([]webauthn.Credential, len(creds))
	copy(out, creds)
	return out, nil
}

func (s *Store) CreateSession(ctx context.Context, tenantID, userID string, ttl time.Duration) (string, error) {
	token, err := store.GenerateSecret()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = sessionRecord{tenantID: tenantID, userID: userID, expires: time.Now().Add(ttl)}
	return token, nil
}

func (s *Store) GetSession(ctx context.Context, token string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[token]
	if !ok {
		return "", "", local.ErrNotFound
	}
	if time.Now().After(rec.expires) {
		return "", "", local.ErrExpired
	}
	return rec.tenantID, rec.userID, nil
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
		return nil, local.ErrNotFound
	}
	delete(s.ephemeral, token) // single-use regardless of outcome
	if time.Now().After(rec.expires) {
		return nil, local.ErrExpired
	}
	return rec.payload, nil
}
