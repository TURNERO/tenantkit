package resolve_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/TURNERO/tenantkit/resolve"
)

func TestCertFingerprint(t *testing.T) {
	cert := generateTestCert(t, "acme-writer")
	want := sha256.Sum256(cert.Raw)
	wantHex := hex.EncodeToString(want[:])

	if got := resolve.CertFingerprint(cert); got != wantHex {
		t.Errorf("CertFingerprint(cert) = %q, want %q", got, wantHex)
	}
}
