package oidc

import (
	"fmt"

	"github.com/TURNERO/tenantkit"
)

// mapClaims maps a verified ID token's claims to a tenantkit.Identity,
// applying m's defaults: UserIDClaim to "sub", UsernameClaim to
// "email", RolesClaim to "roles". TenantIDClaim and the resolved
// user-ID claim are required -- a missing or wrong-type value is
// ErrInvalidToken. Username/Roles degrade gracefully (empty
// string/nil slice) if their claim is simply absent, since not every
// IdP or scope grants them, but a present-and-malformed roles claim
// (not a JSON array of strings) is still rejected rather than
// silently ignored.
func mapClaims(claims map[string]any, m tenantkit.ClaimsMapping) (*tenantkit.Identity, error) {
	userIDClaim := m.UserIDClaim
	if userIDClaim == "" {
		userIDClaim = "sub"
	}
	usernameClaim := m.UsernameClaim
	if usernameClaim == "" {
		usernameClaim = "email"
	}
	rolesClaim := m.RolesClaim
	if rolesClaim == "" {
		rolesClaim = "roles"
	}

	tenantID, ok := claims[m.TenantIDClaim].(string)
	if !ok || tenantID == "" {
		return nil, fmt.Errorf("tenantkit/identity/oidc: missing/invalid %q claim: %w", m.TenantIDClaim, ErrInvalidToken)
	}
	userID, ok := claims[userIDClaim].(string)
	if !ok || userID == "" {
		return nil, fmt.Errorf("tenantkit/identity/oidc: missing/invalid %q claim: %w", userIDClaim, ErrInvalidToken)
	}
	username, _ := claims[usernameClaim].(string) // optional: falls back to "" rather than failing

	var roles []string
	if raw, ok := claims[rolesClaim]; ok {
		arr, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("tenantkit/identity/oidc: %q claim is not an array: %w", rolesClaim, ErrInvalidToken)
		}
		for _, v := range arr {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("tenantkit/identity/oidc: %q claim contains a non-string element: %w", rolesClaim, ErrInvalidToken)
			}
			roles = append(roles, s)
		}
	}

	return &tenantkit.Identity{TenantID: tenantID, UserID: userID, Username: username, Roles: roles}, nil
}
