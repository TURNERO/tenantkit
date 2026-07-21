package resolve

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// CertFingerprint returns the SHA-256 hex digest of cert's DER-encoded
// bytes. Not a secret -- it's a public identifier, the same fingerprint
// any other observer of the certificate would compute.
func CertFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
