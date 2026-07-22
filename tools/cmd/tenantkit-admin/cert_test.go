package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// writeTestCertPEM generates a self-signed cert and writes it, PEM
// encoded, to a temp file, returning the file path.
func writeTestCertPEM(t *testing.T, commonName string) string {
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

	path := t.TempDir() + "/cert.pem"
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create temp cert file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("write PEM: %v", err)
	}
	return path
}

func TestCertRegister(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	certPath := writeTestCertPEM(t, "acme-writer")

	out, err := execCmd(t, "", "cert", "register", "--db", dbPath, "--cert-file", certPath, "--tenant", "acme")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, `registered cert for tenant "acme"`) {
		t.Errorf("output = %q, want confirmation of registration", out)
	}
}

func TestCertRegister_RequiresCertFile(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	_, err := execCmd(t, "", "cert", "register", "--db", dbPath, "--tenant", "acme")
	if err == nil {
		t.Fatal("expected an error when --cert-file is missing")
	}
}

func TestCertRegister_RequiresTenant(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	certPath := writeTestCertPEM(t, "acme-writer")
	_, err := execCmd(t, "", "cert", "register", "--db", dbPath, "--cert-file", certPath)
	if err == nil {
		t.Fatal("expected an error when --tenant is missing")
	}
}

func extractFingerprint(t *testing.T, out string) string {
	t.Helper()
	return extractSecret(t, out) // same "  <token>" output shape
}

func TestCertRevoke(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	certPath := writeTestCertPEM(t, "acme-writer")
	registerOut, err := execCmd(t, "", "cert", "register", "--db", dbPath, "--cert-file", certPath, "--tenant", "acme")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	fingerprint := extractFingerprint(t, registerOut)

	out, err := execCmd(t, "y\n", "cert", "revoke", "--db", dbPath, "--fingerprint", fingerprint)
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "revoked") {
		t.Errorf("output = %q, want confirmation of revocation", out)
	}

	_, err = execCmd(t, "", "cert", "revoke", "--db", dbPath, "--fingerprint", fingerprint, "--yes")
	if err == nil {
		t.Fatal("expected an error revoking an already-revoked cert")
	}
}

func TestCertRevoke_AbortedWithoutConfirmation(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	certPath := writeTestCertPEM(t, "acme-writer")
	registerOut, err := execCmd(t, "", "cert", "register", "--db", dbPath, "--cert-file", certPath, "--tenant", "acme")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	fingerprint := extractFingerprint(t, registerOut)

	out, err := execCmd(t, "n\n", "cert", "revoke", "--db", dbPath, "--fingerprint", fingerprint)
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "aborted") {
		t.Errorf("output = %q, want \"aborted\"", out)
	}
}
