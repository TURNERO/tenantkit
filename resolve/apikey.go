package resolve

import (
	"context"
	"fmt"
	"strings"

	"github.com/TURNERO/tenantkit/store"
)

const bearerPrefix = "Bearer "

// NewAPIKeyResolver returns a TenantResolver that reads a bearer token
// from the Authorization header and looks it up via ks.
func NewAPIKeyResolver(ks store.APIKeyStore) TenantResolver {
	return &apiKeyResolver{ks: ks}
}

type apiKeyResolver struct {
	ks store.APIKeyStore
}

func (r *apiKeyResolver) ResolveTenant(ctx context.Context, src Source) (string, bool, error) {
	auth := src.Header("Authorization")
	if !strings.HasPrefix(auth, bearerPrefix) {
		return "", false, nil
	}
	token := strings.TrimPrefix(auth, bearerPrefix)
	key, err := r.ks.GetAPIKeyByHash(ctx, store.HashSecret(token))
	if err != nil {
		return "", true, fmt.Errorf("resolve tenant from api key: %w", err)
	}
	return key.TenantID, true, nil
}
