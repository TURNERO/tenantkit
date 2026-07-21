package grpcmw

import (
	"context"
	"crypto/x509"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/TURNERO/tenantkit/resolve"
)

// grpcSource adapts a gRPC server-side context into resolve.Source.
type grpcSource struct {
	ctx context.Context
}

func (s grpcSource) Header(key string) string {
	md, ok := metadata.FromIncomingContext(s.ctx)
	if !ok {
		return ""
	}
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func (s grpcSource) TLSPeerCertificates() []*x509.Certificate {
	p, ok := peer.FromContext(s.ctx)
	if !ok || p.AuthInfo == nil {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	return tlsInfo.State.PeerCertificates
}

// Host returns the :authority pseudo-header if it happens to be exposed
// as regular incoming metadata (some gateways/proxies forward it this
// way); grpc-go's server-side API does not otherwise expose HTTP/2
// pseudo-headers through the standard metadata package. Returns "" if
// unavailable -- the subdomain resolver simply won't match, same as any
// other resolver given no credential material.
func (s grpcSource) Host() string {
	md, ok := metadata.FromIncomingContext(s.ctx)
	if !ok {
		return ""
	}
	vals := md.Get(":authority")
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

var _ resolve.Source = grpcSource{}
