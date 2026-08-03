package oidc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	goidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/store"
)

// Config configures an OIDC identity provider.
type Config struct {
	// RedirectURL is fixed for the whole service -- registered
	// identically with every tenant's IdP (a callback route your
	// service's own router serves, e.g.
	// "https://app.example.com/auth/callback").
	RedirectURL string
	// SessionTTL is how long a session issued by FinishLogin stays valid.
	SessionTTL time.Duration
}

// OIDC satisfies identity.IdentityProvider via Authenticate (see
// session.go).
type OIDC struct {
	cfg       Config
	providers store.OIDCProviderStore
	sessions  SessionStore
	ephemeral EphemeralStore

	mu      sync.Mutex
	clients map[tenantProviderKey]*providerClient // lazily populated, never evicted -- see New's doc comment
}

type tenantProviderKey struct {
	tenantID   string
	providerID string
}

// providerClient is what resolveProviderClient (lazily) builds from a
// tenantkit.OIDCProvider registration: everything needed to run the
// OAuth2/OIDC ceremony for that one (tenant, provider) pair without
// hitting the store again.
type providerClient struct {
	oauth2Config *oauth2.Config
	verifier     *goidc.IDTokenVerifier
	mapping      tenantkit.ClaimsMapping
}

// New returns an OIDC identity provider. It returns an error if
// cfg.RedirectURL is empty.
//
// Each registered (tenant, provider)'s OAuth2/OIDC client is built
// lazily on first use and cached for the lifetime of the returned
// *OIDC -- never evicted or refreshed. go-oidc's provider discovery
// (fetching /.well-known/openid-configuration) and JWKS setup is a
// real network round-trip that shouldn't happen on every login.
// Trade-off accepted explicitly: if an admin updates a tenant's
// provider registration (rotates a client secret, changes issuer) via
// the CLI while this process is running, it keeps using the stale
// cached config until restart.
func New(cfg Config, providers store.OIDCProviderStore, sessions SessionStore, ephemeral EphemeralStore) (*OIDC, error) {
	if cfg.RedirectURL == "" {
		return nil, fmt.Errorf("tenantkit/identity/oidc: RedirectURL is required")
	}
	return &OIDC{
		cfg:       cfg,
		providers: providers,
		sessions:  sessions,
		ephemeral: ephemeral,
		clients:   make(map[tenantProviderKey]*providerClient),
	}, nil
}

// resolveProviderClient returns the cached *providerClient for
// (tenantID, providerID), building and caching it on a miss -- or
// ErrInvalidProviderConfig, without caching anything, if the
// registration itself isn't usable (e.g. an empty
// ClaimsMapping.TenantIDClaim). Shared by BeginLogin (via BeginLogin/
// BeginLoginByDomain) and FinishLogin.
func (o *OIDC) resolveProviderClient(ctx context.Context, tenantID, providerID string) (*providerClient, error) {
	key := tenantProviderKey{tenantID: tenantID, providerID: providerID}

	o.mu.Lock()
	client, ok := o.clients[key]
	o.mu.Unlock()
	if ok {
		return client, nil
	}

	p, err := o.providers.GetOIDCProvider(ctx, tenantID, providerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("tenantkit/identity/oidc: look up provider: %w", ErrUnknownProvider)
		}
		return nil, fmt.Errorf("tenantkit/identity/oidc: look up provider: %w", err)
	}
	if p.ClaimsMapping.TenantIDClaim == "" {
		return nil, fmt.Errorf("tenantkit/identity/oidc: provider %s/%s: claims mapping TenantIDClaim is required: %w", tenantID, providerID, ErrInvalidProviderConfig)
	}

	provider, err := goidc.NewProvider(ctx, p.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("tenantkit/identity/oidc: discover provider %s/%s: %w", tenantID, providerID, err)
	}

	client = &providerClient{
		oauth2Config: &oauth2.Config{
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			RedirectURL:  o.cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       append([]string{goidc.ScopeOpenID}, p.Scopes...),
		},
		verifier: provider.Verifier(&goidc.Config{ClientID: p.ClientID}),
		mapping:  p.ClaimsMapping,
	}

	// Benign race: two concurrent callers resolving the same missing
	// key both perform discovery and one's result overwrites the
	// other's -- both succeed, last write wins, no corruption. Not
	// worth a per-key sync.Once for v1.
	o.mu.Lock()
	o.clients[key] = client
	o.mu.Unlock()
	return client, nil
}
