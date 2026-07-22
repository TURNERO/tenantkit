package main

import (
	"regexp"
	"strings"
	"testing"
)

var secretLineRE = regexp.MustCompile(`(?m)^  (\S+)$`)

func extractSecret(t *testing.T, out string) string {
	t.Helper()
	m := secretLineRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not find a printed secret in output:\n%s", out)
	}
	return m[1]
}

func TestKeyCreate(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	out, err := execCmd(t, "", "key", "create", "--db", dbPath, "--tenant", "acme")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "shown once") {
		t.Errorf("output = %q, want the shown-once warning", out)
	}
	extractSecret(t, out) // fails the test if no secret was printed
}

func TestKeyCreate_RequiresTenant(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	_, err := execCmd(t, "", "key", "create", "--db", dbPath)
	if err == nil {
		t.Fatal("expected an error when --tenant is missing")
	}
}

func TestKeyRevoke(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	createOut, err := execCmd(t, "", "key", "create", "--db", dbPath, "--tenant", "acme")
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	secret := extractSecret(t, createOut)

	out, err := execCmd(t, "y\n", "key", "revoke", "--db", dbPath, "--key", secret)
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "revoked") {
		t.Errorf("output = %q, want confirmation of revocation", out)
	}

	// Revoking again should now fail -- the key is gone.
	_, err = execCmd(t, "", "key", "revoke", "--db", dbPath, "--key", secret, "--yes")
	if err == nil {
		t.Fatal("expected an error revoking an already-revoked key")
	}
}

func TestKeyRevoke_AbortedWithoutConfirmation(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	createOut, err := execCmd(t, "", "key", "create", "--db", dbPath, "--tenant", "acme")
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	secret := extractSecret(t, createOut)

	out, err := execCmd(t, "n\n", "key", "revoke", "--db", dbPath, "--key", secret)
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "aborted") {
		t.Errorf("output = %q, want \"aborted\"", out)
	}

	// The key should still work -- revoke should succeed now for real.
	revokeOut, err := execCmd(t, "", "key", "revoke", "--db", dbPath, "--key", secret, "--yes")
	if err != nil {
		t.Fatalf("expected the key to still exist after the aborted revoke: %v\noutput:\n%s", err, revokeOut)
	}
}

func TestKeyRotate(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	createOut, err := execCmd(t, "", "key", "create", "--db", dbPath, "--tenant", "acme", "--user", "u1")
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	oldSecret := extractSecret(t, createOut)

	rotateOut, err := execCmd(t, "", "key", "rotate", "--db", dbPath, "--key", oldSecret)
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, rotateOut)
	}
	newSecret := extractSecret(t, rotateOut)
	if newSecret == oldSecret {
		t.Error("expected a different secret after rotation")
	}

	// Rotate does NOT require confirmation -- no prompt should appear.
	if strings.Contains(rotateOut, "[y/N]") {
		t.Errorf("output = %q, want no confirmation prompt for key rotate", rotateOut)
	}

	// The old key should no longer work.
	_, err = execCmd(t, "", "key", "revoke", "--db", dbPath, "--key", oldSecret, "--yes")
	if err == nil {
		t.Fatal("expected the old key to already be revoked after rotation")
	}
}
