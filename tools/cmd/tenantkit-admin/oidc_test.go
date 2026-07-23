package main

import (
	"strings"
	"testing"
)

func TestOIDCRegisterAndShow(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	out, err := execCmd(t, "", "oidc", "register", "--db", dbPath,
		"--tenant", "acme", "--provider-id", "okta", "--name", "Acme Okta",
		"--issuer", "https://acme.okta.com", "--client-id", "cid", "--client-secret", "csecret",
		"--tenant-id-claim", "https://acme.example/tenant_id")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "registered") {
		t.Errorf("output = %q, want confirmation of registration", out)
	}

	showOut, err := execCmd(t, "", "oidc", "show", "--db", dbPath, "--tenant", "acme", "--provider-id", "okta")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, showOut)
	}
	if !strings.Contains(showOut, "https://acme.okta.com") {
		t.Errorf("show output = %q, want it to contain the issuer URL", showOut)
	}
}

func TestOIDCShow_RedactsClientSecretByDefault(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := execCmd(t, "", "oidc", "register", "--db", dbPath,
		"--tenant", "acme", "--provider-id", "okta", "--name", "Acme Okta",
		"--issuer", "https://acme.okta.com", "--client-id", "cid", "--client-secret", "supersecretvalue",
		"--tenant-id-claim", "https://acme.example/tenant_id"); err != nil {
		t.Fatalf("register: %v", err)
	}

	showOut, err := execCmd(t, "", "oidc", "show", "--db", dbPath, "--tenant", "acme", "--provider-id", "okta")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, showOut)
	}
	if strings.Contains(showOut, "supersecretvalue") {
		t.Errorf("show output = %q, must not contain the real client secret", showOut)
	}
	if !strings.Contains(showOut, "(redacted)") {
		t.Errorf("show output = %q, want it to contain the redaction placeholder", showOut)
	}
}

func TestOIDCShow_RevealSecretFlag(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := execCmd(t, "", "oidc", "register", "--db", dbPath,
		"--tenant", "acme", "--provider-id", "okta", "--name", "Acme Okta",
		"--issuer", "https://acme.okta.com", "--client-id", "cid", "--client-secret", "supersecretvalue",
		"--tenant-id-claim", "https://acme.example/tenant_id"); err != nil {
		t.Fatalf("register: %v", err)
	}

	showOut, err := execCmd(t, "", "oidc", "show", "--db", dbPath, "--tenant", "acme", "--provider-id", "okta", "--reveal-secret")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, showOut)
	}
	if !strings.Contains(showOut, "supersecretvalue") {
		t.Errorf("show --reveal-secret output = %q, want it to contain the real client secret", showOut)
	}
}

func TestOIDCListJSON_RedactsClientSecret(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := execCmd(t, "", "oidc", "register", "--db", dbPath,
		"--tenant", "acme", "--provider-id", "okta", "--name", "Acme Okta",
		"--issuer", "https://acme.okta.com", "--client-id", "cid", "--client-secret", "supersecretvalue",
		"--tenant-id-claim", "https://acme.example/tenant_id"); err != nil {
		t.Fatalf("register: %v", err)
	}

	out, err := execCmd(t, "", "oidc", "list", "--db", dbPath, "--tenant", "acme", "--json")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if strings.Contains(out, "supersecretvalue") {
		t.Errorf("list --json output = %q, must not contain the real client secret", out)
	}
	if !strings.Contains(out, "(redacted)") {
		t.Errorf("list --json output = %q, want it to contain the redaction placeholder", out)
	}
}

func TestOIDCRegister_RequiresTenantIDClaim(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	_, err := execCmd(t, "", "oidc", "register", "--db", dbPath,
		"--tenant", "acme", "--provider-id", "okta",
		"--issuer", "https://acme.okta.com", "--client-id", "cid", "--client-secret", "csecret")
	if err == nil {
		t.Fatal("expected an error when --tenant-id-claim is missing")
	}
}

func TestOIDCList(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	for _, providerID := range []string{"okta", "google"} {
		if _, err := execCmd(t, "", "oidc", "register", "--db", dbPath,
			"--tenant", "acme", "--provider-id", providerID,
			"--issuer", "https://idp.example/"+providerID, "--client-id", "cid", "--client-secret", "csecret",
			"--tenant-id-claim", "tid"); err != nil {
			t.Fatalf("register %s: %v", providerID, err)
		}
	}

	out, err := execCmd(t, "", "oidc", "list", "--db", dbPath, "--tenant", "acme")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "okta") || !strings.Contains(out, "google") {
		t.Errorf("list output = %q, want both provider IDs", out)
	}
}

func TestOIDCUpdate(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := execCmd(t, "", "oidc", "register", "--db", dbPath,
		"--tenant", "acme", "--provider-id", "okta", "--name", "Old Name",
		"--issuer", "https://acme.okta.com", "--client-id", "cid", "--client-secret", "csecret",
		"--tenant-id-claim", "tid"); err != nil {
		t.Fatalf("register: %v", err)
	}

	out, err := execCmd(t, "", "oidc", "update", "--db", dbPath,
		"--tenant", "acme", "--provider-id", "okta", "--name", "New Name",
		"--issuer", "https://acme.okta.com", "--client-id", "cid", "--client-secret", "csecret",
		"--tenant-id-claim", "tid")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "updated") {
		t.Errorf("output = %q, want confirmation of update", out)
	}

	showOut, err := execCmd(t, "", "oidc", "show", "--db", dbPath, "--tenant", "acme", "--provider-id", "okta")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, showOut)
	}
	if !strings.Contains(showOut, "New Name") {
		t.Errorf("show output after update = %q, want it to contain %q", showOut, "New Name")
	}
}

func TestOIDCRemove(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := execCmd(t, "", "oidc", "register", "--db", dbPath,
		"--tenant", "acme", "--provider-id", "okta",
		"--issuer", "https://acme.okta.com", "--client-id", "cid", "--client-secret", "csecret",
		"--tenant-id-claim", "tid"); err != nil {
		t.Fatalf("register: %v", err)
	}

	out, err := execCmd(t, "y\n", "oidc", "remove", "--db", dbPath, "--tenant", "acme", "--provider-id", "okta")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "removed") {
		t.Errorf("output = %q, want confirmation of removal", out)
	}

	_, err = execCmd(t, "", "oidc", "show", "--db", dbPath, "--tenant", "acme", "--provider-id", "okta")
	if err == nil {
		t.Fatal("expected an error showing a removed provider")
	}
}
