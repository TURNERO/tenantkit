package resolve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/TURNERO/tenantkit/store"
)

// NewClientCertResolver returns a TenantResolver that reads the
// already-TLS-verified peer certificate and looks up its fingerprint via
// cs.
func NewClientCertResolver(cs store.ClientCertStore) TenantResolver {
	return &clientCertResolver{cs: cs}
}

type clientCertResolver struct {
	cs store.ClientCertStore
}

func (r *clientCertResolver) ResolveTenant(ctx context.Context, src Source) (string, bool, error) {
	certs := src.TLSPeerCertificates()
	if len(certs) == 0 {
		return "", false, nil
	}
	sum := sha256.Sum256(certs[0].Raw)
	fingerprint := hex.EncodeToString(sum[:])

	cert, err := r.cs.GetClientCertByFingerprint(ctx, fingerprint)
	if err != nil {
		return "", true, fmt.Errorf("resolve tenant from client cert: %w", err)
	}
	return cert.TenantID, true, nil
}
