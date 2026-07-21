package grpcmw

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func TestGRPCSource_Header(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer abc123"))
	src := grpcSource{ctx: ctx}

	if got := src.Header("Authorization"); got != "Bearer abc123" {
		t.Errorf("Header(Authorization) = %q, want %q", got, "Bearer abc123")
	}
}

func TestGRPCSource_HeaderMissing(t *testing.T) {
	src := grpcSource{ctx: context.Background()}
	if got := src.Header("Authorization"); got != "" {
		t.Errorf("Header(Authorization) = %q, want empty", got)
	}
}

func TestGRPCSource_TLSPeerCertificatesNilWithoutTLS(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.IPAddr{}})
	src := grpcSource{ctx: ctx}

	if got := src.TLSPeerCertificates(); got != nil {
		t.Errorf("TLSPeerCertificates() = %v, want nil without TLSInfo", got)
	}
}

func TestGRPCSource_TLSPeerCertificatesFromTLSInfo(t *testing.T) {
	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}},
	}
	ctx := peer.NewContext(context.Background(), p)
	src := grpcSource{ctx: ctx}

	if got := src.TLSPeerCertificates(); got != nil {
		t.Errorf("TLSPeerCertificates() = %v, want nil for an empty ConnectionState", got)
	}
}

func TestGRPCSource_HostFromAuthorityMetadata(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(":authority", "acme.example.com"))
	src := grpcSource{ctx: ctx}

	if got := src.Host(); got != "acme.example.com" {
		t.Errorf("Host() = %q, want acme.example.com", got)
	}
}

func TestGRPCSource_HostMissing(t *testing.T) {
	src := grpcSource{ctx: context.Background()}
	if got := src.Host(); got != "" {
		t.Errorf("Host() = %q, want empty", got)
	}
}
