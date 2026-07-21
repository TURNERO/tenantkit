package resolve_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store/memstore"
)

func generateTestCert(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func fingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func TestClientCertResolver_ResolvesKnownCert(t *testing.T) {
	cert := generateTestCert(t, "acme-writer")
	cs := memstore.New()
	ctx := context.Background()
	if err := cs.CreateClientCert(ctx, &tenantkit.ClientCert{Fingerprint: fingerprintOf(cert), TenantID: "acme"}); err != nil {
		t.Fatalf("CreateClientCert: %v", err)
	}

	r := resolve.NewClientCertResolver(cs)
	src := fakeSource{certs: []*x509.Certificate{cert}}

	tenantID, ok, err := r.ResolveTenant(ctx, src)
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true for a present client certificate")
	}
	if tenantID != "acme" {
		t.Errorf("ResolveTenant tenantID = %q, want acme", tenantID)
	}
}

func TestClientCertResolver_NoPeerCertificates(t *testing.T) {
	r := resolve.NewClientCertResolver(memstore.New())
	tenantID, ok, err := r.ResolveTenant(context.Background(), fakeSource{})
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if ok {
		t.Error("expected ok=false when no peer certificates are present")
	}
	if tenantID != "" {
		t.Errorf("ResolveTenant tenantID = %q, want empty", tenantID)
	}
}

func TestClientCertResolver_UnknownCertFailsChain(t *testing.T) {
	cert := generateTestCert(t, "unknown")
	r := resolve.NewClientCertResolver(memstore.New())
	src := fakeSource{certs: []*x509.Certificate{cert}}

	_, ok, err := r.ResolveTenant(context.Background(), src)
	if err == nil {
		t.Fatal("expected an error for an unrecognized client certificate, got nil")
	}
	if !ok {
		t.Error("expected ok=true when credential material was present but invalid, so the chain does not fall through")
	}
}
