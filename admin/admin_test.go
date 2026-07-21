package admin_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit/admin"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
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

func TestCreateTenant(t *testing.T) {
	ts := memstore.New()
	ctx := context.Background()

	got, err := admin.CreateTenant(ctx, ts, "acme", "Acme Corp")
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if got.ID != "acme" || got.DisplayName != "Acme Corp" || !got.Active {
		t.Errorf("CreateTenant returned %+v, want ID=acme DisplayName=\"Acme Corp\" Active=true", got)
	}

	stored, err := ts.GetTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if *stored != *got {
		t.Errorf("stored tenant %+v does not match returned %+v", stored, got)
	}
}

func TestCreateTenant_InvalidID(t *testing.T) {
	ts := memstore.New()
	_, err := admin.CreateTenant(context.Background(), ts, "Not Valid!", "Acme Corp")
	if err == nil {
		t.Fatal("expected an error for an invalid tenant ID, got nil")
	}
	if _, getErr := ts.GetTenant(context.Background(), "Not Valid!"); !errors.Is(getErr, store.ErrNotFound) {
		t.Error("expected no tenant to have been created for an invalid ID")
	}
}

func TestCreateTenant_DuplicateFails(t *testing.T) {
	ts := memstore.New()
	ctx := context.Background()
	if _, err := admin.CreateTenant(ctx, ts, "acme", "Acme Corp"); err != nil {
		t.Fatalf("first CreateTenant: %v", err)
	}
	_, err := admin.CreateTenant(ctx, ts, "acme", "Dupe")
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("CreateTenant duplicate error = %v, want errors.Is(err, store.ErrAlreadyExists)", err)
	}
}

func TestListTenants(t *testing.T) {
	ts := memstore.New()
	ctx := context.Background()
	if _, err := admin.CreateTenant(ctx, ts, "acme", "Acme Corp"); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	got, err := admin.ListTenants(ctx, ts)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(got) != 1 || got[0].ID != "acme" {
		t.Errorf("ListTenants = %+v, want one tenant with ID acme", got)
	}
}

func TestDeactivateTenant(t *testing.T) {
	ts := memstore.New()
	ctx := context.Background()
	if _, err := admin.CreateTenant(ctx, ts, "acme", "Acme Corp"); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	if err := admin.DeactivateTenant(ctx, ts, "acme"); err != nil {
		t.Fatalf("DeactivateTenant: %v", err)
	}
	got, err := ts.GetTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Active {
		t.Error("expected tenant to be inactive after DeactivateTenant")
	}
}

func TestDeactivateTenant_NotFound(t *testing.T) {
	ts := memstore.New()
	err := admin.DeactivateTenant(context.Background(), ts, "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("DeactivateTenant error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestCreateAPIKey(t *testing.T) {
	ks := memstore.New()
	ctx := context.Background()

	secret, err := admin.CreateAPIKey(ctx, ks, "acme", "u1")
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if secret == "" {
		t.Fatal("expected a non-empty secret")
	}

	stored, err := ks.GetAPIKeyByHash(ctx, store.HashSecret(secret))
	if err != nil {
		t.Fatalf("GetAPIKeyByHash: %v", err)
	}
	if stored.TenantID != "acme" || stored.UserID != "u1" {
		t.Errorf("stored key = %+v, want TenantID=acme UserID=u1", stored)
	}
}

func TestRevokeAPIKey(t *testing.T) {
	ks := memstore.New()
	ctx := context.Background()
	secret, err := admin.CreateAPIKey(ctx, ks, "acme", "")
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	if err := admin.RevokeAPIKey(ctx, ks, secret); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if _, err := ks.GetAPIKeyByHash(ctx, store.HashSecret(secret)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected key to be revoked, GetAPIKeyByHash error = %v", err)
	}
}

func TestRevokeAPIKey_UnknownSecret(t *testing.T) {
	ks := memstore.New()
	err := admin.RevokeAPIKey(context.Background(), ks, "not-a-real-secret")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RevokeAPIKey error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}

func TestRotateAPIKey(t *testing.T) {
	ks := memstore.New()
	ctx := context.Background()
	oldSecret, err := admin.CreateAPIKey(ctx, ks, "acme", "u1")
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	newSecret, err := admin.RotateAPIKey(ctx, ks, oldSecret)
	if err != nil {
		t.Fatalf("RotateAPIKey: %v", err)
	}
	if newSecret == oldSecret {
		t.Error("expected RotateAPIKey to return a new secret")
	}

	if _, err := ks.GetAPIKeyByHash(ctx, store.HashSecret(oldSecret)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected old key to be revoked, GetAPIKeyByHash error = %v", err)
	}
	newKey, err := ks.GetAPIKeyByHash(ctx, store.HashSecret(newSecret))
	if err != nil {
		t.Fatalf("GetAPIKeyByHash for new key: %v", err)
	}
	if newKey.TenantID != "acme" || newKey.UserID != "u1" {
		t.Errorf("new key = %+v, want the same TenantID/UserID as the old key (acme/u1) without being told again", newKey)
	}
}

func TestRotateAPIKey_UnknownSecret(t *testing.T) {
	ks := memstore.New()
	_, err := admin.RotateAPIKey(context.Background(), ks, "not-a-real-secret")
	if err == nil {
		t.Fatal("expected an error rotating an unknown key, got nil")
	}
}

func TestCreateUser(t *testing.T) {
	us := memstore.New()
	ctx := context.Background()

	got, err := admin.CreateUser(ctx, us, "u1", "acme", "alice", []string{"admin", "billing"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if got.UserID != "u1" || got.TenantID != "acme" || got.Username != "alice" {
		t.Errorf("CreateUser returned %+v, want UserID=u1 TenantID=acme Username=alice", got)
	}

	stored, err := us.GetUser(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if len(stored.Roles) != 2 || stored.Roles[0] != "admin" || stored.Roles[1] != "billing" {
		t.Errorf("stored user Roles = %v, want [admin billing]", stored.Roles)
	}
}

func TestRegisterClientCert(t *testing.T) {
	cs := memstore.New()
	ctx := context.Background()
	cert := generateTestCert(t, "acme-writer")

	got, err := admin.RegisterClientCert(ctx, cs, cert, "acme", "u1")
	if err != nil {
		t.Fatalf("RegisterClientCert: %v", err)
	}
	if got.Fingerprint != resolve.CertFingerprint(cert) {
		t.Errorf("RegisterClientCert fingerprint = %q, want %q", got.Fingerprint, resolve.CertFingerprint(cert))
	}
	if got.TenantID != "acme" || got.UserID != "u1" {
		t.Errorf("RegisterClientCert returned %+v, want TenantID=acme UserID=u1", got)
	}

	stored, err := cs.GetClientCertByFingerprint(ctx, resolve.CertFingerprint(cert))
	if err != nil {
		t.Fatalf("GetClientCertByFingerprint: %v", err)
	}
	if stored.TenantID != "acme" {
		t.Errorf("stored cert = %+v, want TenantID=acme", stored)
	}
}

func TestRevokeClientCert(t *testing.T) {
	cs := memstore.New()
	ctx := context.Background()
	cert := generateTestCert(t, "acme-writer")
	if _, err := admin.RegisterClientCert(ctx, cs, cert, "acme", ""); err != nil {
		t.Fatalf("RegisterClientCert: %v", err)
	}

	fingerprint := resolve.CertFingerprint(cert)
	if err := admin.RevokeClientCert(ctx, cs, fingerprint); err != nil {
		t.Fatalf("RevokeClientCert: %v", err)
	}
	if _, err := cs.GetClientCertByFingerprint(ctx, fingerprint); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected cert to be revoked, GetClientCertByFingerprint error = %v", err)
	}
}

func TestRevokeClientCert_UnknownFingerprint(t *testing.T) {
	cs := memstore.New()
	err := admin.RevokeClientCert(context.Background(), cs, "not-a-real-fingerprint")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RevokeClientCert error = %v, want errors.Is(err, store.ErrNotFound)", err)
	}
}
