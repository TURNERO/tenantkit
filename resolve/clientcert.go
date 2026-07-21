package resolve

import (
	"context"
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
	fingerprint := CertFingerprint(certs[0])

	cert, err := r.cs.GetClientCertByFingerprint(ctx, fingerprint)
	if err != nil {
		return "", true, fmt.Errorf("resolve tenant from client cert: %w", err)
	}
	return cert.TenantID, true, nil
}
