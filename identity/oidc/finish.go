package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TURNERO/tenantkit"
)

// FinishLogin completes a login ceremony started by BeginLogin or
// BeginLoginByDomain. state and code are exactly what your callback
// handler receives on the query string. On success it returns the
// mapped Identity (e.g. to render a welcome page) and a session token
// (to set via SetSessionCookie).
func (o *OIDC) FinishLogin(ctx context.Context, state, code string) (*tenantkit.Identity, string, error) {
	payload, err := o.ephemeral.Take(ctx, state)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
			return nil, "", err
		}
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: load login ceremony: %w", err)
	}
	var ceremony loginCeremony
	if err := json.Unmarshal(payload, &ceremony); err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: decode login ceremony: %w", err)
	}

	client, err := o.resolveProviderClient(ctx, ceremony.TenantID, ceremony.ProviderID)
	if err != nil {
		return nil, "", err
	}

	oauth2Token, err := client.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: exchange code: %w", err)
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: token response has no id_token: %w", ErrInvalidToken)
	}

	idToken, err := client.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: verify id_token: %w: %w", err, ErrInvalidToken)
	}
	if idToken.Nonce != ceremony.Nonce {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: nonce mismatch: %w", ErrInvalidToken)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: decode claims: %w: %w", err, ErrInvalidToken)
	}
	identity, err := mapClaims(claims, client.mapping)
	if err != nil {
		return nil, "", err
	}
	if identity.TenantID != ceremony.TenantID {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: token tenant claim does not match ceremony tenant: %w", ErrInvalidToken)
	}

	token, err := o.sessions.CreateSession(ctx, identity, o.cfg.SessionTTL)
	if err != nil {
		return nil, "", fmt.Errorf("tenantkit/identity/oidc: create session: %w", err)
	}
	return identity, token, nil
}
