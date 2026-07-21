// Package resolve provides tenantkit's tenant-resolution abstractions:
// Source, a transport-agnostic view of an incoming request, and
// TenantResolver, a pluggable strategy for extracting a tenant ID from
// one. httpmw and grpcmw each wrap their transport's request shape into
// a Source, so the same TenantResolver implementations work against both
// HTTP and gRPC traffic.
package resolve

import (
	"context"
	"crypto/x509"
)

// Source abstracts over the transport (HTTP or gRPC) so the same
// TenantResolver/IdentityProvider implementations work against both.
type Source interface {
	// Header returns the value of the given header/metadata key, or ""
	// if not present. For a repeated key, implementations return the
	// first value.
	Header(key string) string
	// TLSPeerCertificates returns the already-TLS-verified client
	// certificate chain, or nil if the connection isn't using mTLS.
	TLSPeerCertificates() []*x509.Certificate
	// Host returns the request's target host (HTTP Host header /
	// gRPC :authority), without a port.
	Host() string
}

// TenantResolver extracts a tenant ID from src.
type TenantResolver interface {
	// ok=false means "found no credential material of this kind" --
	// distinct from an error, which means "found something, but it's
	// invalid." A resolver chain stops at the first resolver that
	// returns ok=true or a non-nil err; only ok=false, nil lets the
	// chain continue to the next resolver.
	ResolveTenant(ctx context.Context, src Source) (tenantID string, ok bool, err error)
}

// RunChain tries each resolver in order and returns the first tenant ID
// found. It returns ("", nil) if no resolver found any credential
// material (every resolver returned ok=false), and stops immediately
// with the first non-nil error a resolver returns -- see TenantResolver's
// doc comment for why falling through on an error would be unsafe.
func RunChain(ctx context.Context, resolvers []TenantResolver, src Source) (tenantID string, err error) {
	for _, r := range resolvers {
		tenantID, ok, err := r.ResolveTenant(ctx, src)
		if err != nil {
			return "", err
		}
		if ok {
			return tenantID, nil
		}
	}
	return "", nil
}
