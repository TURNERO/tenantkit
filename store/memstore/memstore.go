// Package memstore is an in-memory implementation of tenantkit's store
// interfaces. It exists for tests -- both tenantkit's own and a
// consumer's -- not as a production backend: nothing is persisted, and
// every method takes a single mutex.
package memstore

import (
	"context"
	"sort"
	"sync"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"
)

// Store is an in-memory store.TenantStore, store.UserStore,
// store.APIKeyStore, and store.ClientCertStore.
type Store struct {
	mu sync.Mutex

	tenants map[string]*tenantkit.Tenant

	users      map[string]*tenantkit.Identity
	usersByKey map[usernameKey]string // (tenantID, username) -> userID

	apiKeys map[string]*tenantkit.APIKey

	clientCerts map[string]*tenantkit.ClientCert

	oidcProviders       map[oidcProviderKey]*tenantkit.OIDCProvider
	oidcProviderDomains map[string]oidcProviderKey // domain -> (tenantID, providerID)
}

type usernameKey struct {
	tenantID string
	username string
}

type oidcProviderKey struct {
	tenantID   string
	providerID string
}

// New returns an empty Store.
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

var (
	_ store.TenantStore       = (*Store)(nil)
	_ store.UserStore         = (*Store)(nil)
	_ store.APIKeyStore       = (*Store)(nil)
	_ store.ClientCertStore   = (*Store)(nil)
	_ store.OIDCProviderStore = (*Store)(nil)
)

func (s *Store) GetTenant(ctx context.Context, tenantID string) (*tenantkit.Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[tenantID]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (s *Store) CreateTenant(ctx context.Context, t *tenantkit.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[t.ID]; ok {
		return store.ErrAlreadyExists
	}
	cp := *t
	s.tenants[t.ID] = &cp
	return nil
}

func (s *Store) ListTenants(ctx context.Context) ([]*tenantkit.Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*tenantkit.Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		cp := *t
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) DeactivateTenant(ctx context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[tenantID]
	if !ok {
		return store.ErrNotFound
	}
	t.Active = false
	return nil
}

func (s *Store) GetUser(ctx context.Context, userID string) (*tenantkit.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *u
	cp.Roles = append([]string(nil), u.Roles...)
	return &cp, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, tenantID, username string) (*tenantkit.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	userID, ok := s.usersByKey[usernameKey{tenantID: tenantID, username: username}]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.users[userID]
	cp.Roles = append([]string(nil), s.users[userID].Roles...)
	return &cp, nil
}

func (s *Store) CreateUser(ctx context.Context, u *tenantkit.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.UserID]; ok {
		return store.ErrAlreadyExists
	}
	key := usernameKey{tenantID: u.TenantID, username: u.Username}
	if _, ok := s.usersByKey[key]; ok {
		return store.ErrAlreadyExists
	}
	cp := *u
	cp.Roles = append([]string(nil), u.Roles...)
	s.users[u.UserID] = &cp
	s.usersByKey[key] = u.UserID
	return nil
}

func (s *Store) GetAPIKeyByHash(ctx context.Context, hash string) (*tenantkit.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.apiKeys[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *k
	return &cp, nil
}

func (s *Store) CreateAPIKey(ctx context.Context, k *tenantkit.APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.apiKeys[k.Hash]; ok {
		return store.ErrAlreadyExists
	}
	cp := *k
	s.apiKeys[k.Hash] = &cp
	return nil
}

func (s *Store) RevokeAPIKey(ctx context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.apiKeys[hash]; !ok {
		return store.ErrNotFound
	}
	delete(s.apiKeys, hash)
	return nil
}

func (s *Store) GetClientCertByFingerprint(ctx context.Context, fingerprint string) (*tenantkit.ClientCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clientCerts[fingerprint]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (s *Store) CreateClientCert(ctx context.Context, c *tenantkit.ClientCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clientCerts[c.Fingerprint]; ok {
		return store.ErrAlreadyExists
	}
	cp := *c
	s.clientCerts[c.Fingerprint] = &cp
	return nil
}

func (s *Store) RevokeClientCert(ctx context.Context, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clientCerts[fingerprint]; !ok {
		return store.ErrNotFound
	}
	delete(s.clientCerts, fingerprint)
	return nil
}

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
