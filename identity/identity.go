// Package identity defines tenantkit's identity-provider abstraction.
// Concrete implementations (identity/local, identity/oidc) are a
// separate package/plan; this package only defines the interface so
// httpmw and grpcmw have something concrete to depend on.
package identity

import (
	"context"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/resolve"
)

// IdentityProvider authenticates a request, returning the identity that
// made it, or nil for a request with no associated human identity (e.g.
// pure service/API-key traffic).
type IdentityProvider interface {
	Authenticate(ctx context.Context, src resolve.Source) (*tenantkit.Identity, error)
}
