package tenantkit

import "context"

type ctxKey int

const (
	tenantCtxKey ctxKey = iota
	identityCtxKey
)

// WithTenant returns a copy of ctx carrying t, retrievable via
// TenantFromContext.
func WithTenant(ctx context.Context, t *Tenant) context.Context {
	return context.WithValue(ctx, tenantCtxKey, t)
}

// TenantFromContext returns the tenant previously attached via
// WithTenant, or ok=false if none was.
func TenantFromContext(ctx context.Context) (*Tenant, bool) {
	t, ok := ctx.Value(tenantCtxKey).(*Tenant)
	return t, ok
}

// WithIdentity returns a copy of ctx carrying id, retrievable via
// IdentityFromContext.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityCtxKey, id)
}

// IdentityFromContext returns the identity previously attached via
// WithIdentity, or ok=false if none was (e.g. pure API-key/service
// traffic with no per-user identity).
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityCtxKey).(*Identity)
	return id, ok
}
