package resolve

import "context"

// NewHeaderResolver returns a TenantResolver that reads the tenant ID
// directly from the given header, with no store lookup. Intended for
// trusted-proxy deployments where something upstream already resolved
// the tenant -- tenant existence/active-checking still happens
// downstream via TenantStore.GetTenant regardless of which resolver
// produced the ID.
func NewHeaderResolver(headerName string) TenantResolver {
	return &headerResolver{headerName: headerName}
}

type headerResolver struct {
	headerName string
}

func (r *headerResolver) ResolveTenant(ctx context.Context, src Source) (string, bool, error) {
	v := src.Header(r.headerName)
	if v == "" {
		return "", false, nil
	}
	return v, true, nil
}
