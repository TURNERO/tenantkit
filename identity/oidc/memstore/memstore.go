// Package memstore is an in-memory implementation of identity/oidc's
// storage interfaces. It exists for tests -- both tenantkit's own and a
// consumer's -- not as a production backend: nothing is persisted, and
// every method takes a single mutex.
package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity/oidc"
	"github.com/TURNERO/tenantkit/store"
)

// Store is an in-memory oidc.SessionStore and oidc.EphemeralStore.
type Store struct {
	mu sync.Mutex

	sessions  map[string]sessionRecord
	ephemeral map[string]ephemeralRecord
}

type sessionRecord struct {
	identity *tenantkit.Identity
	expires  time.Time
}

type ephemeralRecord struct {
	payload []byte
	expires time.Time
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		sessions:  make(map[string]sessionRecord),
		ephemeral: make(map[string]ephemeralRecord),
	}
}

var (
	_ oidc.SessionStore   = (*Store)(nil)
	_ oidc.EphemeralStore = (*Store)(nil)
)

func cloneIdentity(id *tenantkit.Identity) *tenantkit.Identity {
	cp := *id
	cp.Roles = append([]string(nil), id.Roles...)
	return &cp
}

func (s *Store) CreateSession(ctx context.Context, id *tenantkit.Identity, ttl time.Duration) (string, error) {
	token, err := store.GenerateSecret()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = sessionRecord{identity: cloneIdentity(id), expires: time.Now().Add(ttl)}
	return token, nil
}

func (s *Store) GetSession(ctx context.Context, token string) (*tenantkit.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[token]
	if !ok {
		return nil, oidc.ErrNotFound
	}
	if time.Now().After(rec.expires) {
		return nil, oidc.ErrExpired
	}
	return cloneIdentity(rec.identity), nil
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
		return nil, oidc.ErrNotFound
	}
	delete(s.ephemeral, token) // single-use regardless of outcome
	if time.Now().After(rec.expires) {
		return nil, oidc.ErrExpired
	}
	return rec.payload, nil
}
