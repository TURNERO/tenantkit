package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/TURNERO/tenantkit"
)

var tenantIDPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// GenerateSecret returns a new high-entropy, URL-safe random secret
// suitable for an API key or a similar credential.
func GenerateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashSecret returns the SHA-256 hex digest of secret, for storing and
// comparing high-entropy generated credentials (API keys) -- not for
// human-chosen passwords, which need a slow, salted hash instead.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ValidTenantID reports whether id is safe to use as a tenant
// identifier. tenantkit itself never interpolates a tenant ID into
// anything injectable, but consumers commonly do (e.g. as a
// role/policy-name fragment in a database-specific RBAC statement), so
// a conservative charset is enforced here once rather than separately
// by every consumer.
func ValidTenantID(id string) bool {
	return tenantIDPattern.MatchString(id)
}

// RotateAPIKey replaces the API key identified by oldHash with a newly
// generated one for the same tenant/user, returning the new plaintext
// secret. It checks that oldHash exists before creating anything, so a
// call with a bad oldHash fails cleanly with no side effects. Once past
// that check, the new key is created before the old one is revoked, so
// there's a brief window where both are valid rather than a window
// where neither is -- the safer direction to err in for a credential
// rotation.
func RotateAPIKey(ctx context.Context, ks APIKeyStore, oldHash, tenantID, userID string) (string, error) {
	if _, err := ks.GetAPIKeyByHash(ctx, oldHash); err != nil {
		return "", fmt.Errorf("look up existing api key: %w", err)
	}
	newSecret, err := GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("generate new secret: %w", err)
	}
	newKey := &tenantkit.APIKey{Hash: HashSecret(newSecret), TenantID: tenantID, UserID: userID}
	if err := ks.CreateAPIKey(ctx, newKey); err != nil {
		return "", fmt.Errorf("create new api key: %w", err)
	}
	if err := ks.RevokeAPIKey(ctx, oldHash); err != nil {
		return "", fmt.Errorf("revoke old api key: %w", err)
	}
	return newSecret, nil
}
