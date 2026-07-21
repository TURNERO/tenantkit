package resolve

import (
	"context"
	"strings"
)

// NewSubdomainResolver returns a TenantResolver that takes the first
// dot-separated label of the request's Host as the tenant ID.
func NewSubdomainResolver() TenantResolver {
	return &subdomainResolver{}
}

type subdomainResolver struct{}

func (r *subdomainResolver) ResolveTenant(ctx context.Context, src Source) (string, bool, error) {
	host := src.Host()
	i := strings.Index(host, ".")
	if i <= 0 {
		return "", false, nil
	}
	return host[:i], true, nil
}
