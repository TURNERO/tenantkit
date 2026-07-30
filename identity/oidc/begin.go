package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/TURNERO/tenantkit/store"
)

// loginCeremonyTTL bounds how long a login ceremony (the OAuth2
// state/nonce pair between BeginLogin and FinishLogin) has to complete
// before its EphemeralStore entry expires. Not exposed via Config -- 5
// minutes comfortably covers a real browser/IdP redirect round-trip,
// matching identity/local's webauthnCeremonyTTL precedent; no evidence
// yet that any consumer needs this tunable.
const loginCeremonyTTL = 5 * time.Minute

type loginCeremony struct {
	TenantID   string `json:"tenant_id"`
	ProviderID string `json:"provider_id"`
	Nonce      string `json:"nonce"`
}

// BeginLogin starts an OAuth2 Authorization Code login against
// tenantID's registered providerID. It returns the URL to redirect the
// browser to; the consumer's login handler performs the redirect.
func (o *OIDC) BeginLogin(ctx context.Context, tenantID, providerID string) (string, error) {
	client, err := o.resolveProviderClient(ctx, tenantID, providerID)
	if err != nil {
		return "", err
	}

	state, err := store.GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/oidc: generate state: %w", err)
	}
	nonce, err := store.GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/oidc: generate nonce: %w", err)
	}

	payload, err := json.Marshal(loginCeremony{TenantID: tenantID, ProviderID: providerID, Nonce: nonce})
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/oidc: encode login ceremony: %w", err)
	}
	if err := o.ephemeral.Put(ctx, state, payload, loginCeremonyTTL); err != nil {
		return "", fmt.Errorf("tenantkit/identity/oidc: save login ceremony: %w", err)
	}

	return client.oauth2Config.AuthCodeURL(state, goidc.Nonce(nonce)), nil
}

// BeginLoginByDomain looks up which (tenantID, providerID) domain is
// registered to via store.OIDCProviderStore.GetOIDCProviderByDomain,
// then starts the same ceremony as BeginLogin. Convenience for an
// identifier-first ("enter your email") login page.
func (o *OIDC) BeginLoginByDomain(ctx context.Context, domain string) (string, error) {
	p, err := o.providers.GetOIDCProviderByDomain(ctx, domain)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", fmt.Errorf("tenantkit/identity/oidc: look up provider by domain: %w", ErrUnknownProvider)
		}
		return "", fmt.Errorf("tenantkit/identity/oidc: look up provider by domain: %w", err)
	}
	return o.BeginLogin(ctx, p.TenantID, p.ProviderID)
}
