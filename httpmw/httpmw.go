package httpmw

import (
	"fmt"
	"net/http"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
)

// ErrorHandler writes an HTTP response for a rejected request. status is
// http.StatusUnauthorized (401, no/invalid credentials) or
// http.StatusForbidden (403, valid credentials but wrong/inactive tenant).
type ErrorHandler func(w http.ResponseWriter, r *http.Request, status int, err error)

// Config configures the middleware returned by New.
type Config struct {
	// Resolvers is tried in order; the first resolver that finds
	// credential material (ok=true or a non-nil error) decides the
	// outcome -- see resolve.TenantResolver's doc comment.
	Resolvers []resolve.TenantResolver
	// TenantStore looks up the resolved tenant to confirm it exists and
	// is active.
	TenantStore store.TenantStore
	// IdentityProvider is optional. When nil, identity resolution is
	// skipped entirely and no Identity is ever placed in context --
	// appropriate for consumers with no human users.
	IdentityProvider identity.IdentityProvider
	// ErrorHandler is optional. Defaults to a minimal plain-text
	// response (http.Error-style) if not set.
	ErrorHandler ErrorHandler
}

// New returns middleware that resolves the tenant (and, if configured,
// the identity) for each request, and rejects requests that fail to
// resolve.
func New(cfg Config) func(http.Handler) http.Handler {
	errorHandler := cfg.ErrorHandler
	if errorHandler == nil {
		errorHandler = defaultErrorHandler
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			src := httpSource{r: r}

			tenantID, err := resolve.RunChain(ctx, cfg.Resolvers, src)
			if err != nil {
				errorHandler(w, r, http.StatusUnauthorized, err)
				return
			}
			if tenantID == "" {
				errorHandler(w, r, http.StatusUnauthorized, errNoCredentials)
				return
			}

			tenant, err := cfg.TenantStore.GetTenant(ctx, tenantID)
			if err != nil {
				errorHandler(w, r, http.StatusForbidden, err)
				return
			}
			if !tenant.Active {
				errorHandler(w, r, http.StatusForbidden, errInactiveTenant)
				return
			}
			ctx = tenantkit.WithTenant(ctx, tenant)

			if cfg.IdentityProvider != nil {
				id, err := cfg.IdentityProvider.Authenticate(ctx, src)
				if err != nil {
					errorHandler(w, r, http.StatusUnauthorized, err)
					return
				}
				if id != nil {
					if id.TenantID != tenantID {
						errorHandler(w, r, http.StatusForbidden, errTenantMismatch)
						return
					}
					ctx = tenantkit.WithIdentity(ctx, id)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

var (
	errNoCredentials  = fmt.Errorf("httpmw: no credentials presented")
	errInactiveTenant = fmt.Errorf("httpmw: tenant is inactive")
	errTenantMismatch = fmt.Errorf("httpmw: identity's tenant does not match resolved tenant")
)

func defaultErrorHandler(w http.ResponseWriter, r *http.Request, status int, err error) {
	http.Error(w, err.Error(), status)
}
