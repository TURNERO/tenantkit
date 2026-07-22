package main

import (
	"strings"
	"testing"
)

func TestUserCreate_ExplicitID(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	out, err := execCmd(t, "", "user", "create", "--db", dbPath, "--user-id", "u1", "--tenant", "acme", "--username", "alice", "--roles", "admin,billing")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, `created user "u1"`) {
		t.Errorf("output = %q, want confirmation of the created user", out)
	}
}

func TestUserCreate_GenerateID(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	out, err := execCmd(t, "", "user", "create", "--db", dbPath, "--generate-user-id", "--tenant", "acme", "--username", "alice")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "created user") {
		t.Errorf("output = %q, want confirmation of a created user", out)
	}
}

func TestUserCreate_IDAndGenerateIDMutuallyExclusive(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	_, err := execCmd(t, "", "user", "create", "--db", dbPath, "--user-id", "u1", "--generate-user-id", "--tenant", "acme", "--username", "alice")
	if err == nil {
		t.Fatal("expected an error when both --user-id and --generate-user-id are given")
	}
}

func TestUserCreate_NeitherIDNorGenerateID(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	_, err := execCmd(t, "", "user", "create", "--db", dbPath, "--tenant", "acme", "--username", "alice")
	if err == nil {
		t.Fatal("expected an error when neither --user-id nor --generate-user-id is given")
	}
}

func TestUserCreate_MissingTenant(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	_, err := execCmd(t, "", "user", "create", "--db", dbPath, "--user-id", "u1", "--username", "alice")
	if err == nil {
		t.Fatal("expected an error when --tenant is missing")
	}
}

func TestUserCreate_MissingUsername(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	_, err := execCmd(t, "", "user", "create", "--db", dbPath, "--user-id", "u1", "--tenant", "acme")
	if err == nil {
		t.Fatal("expected an error when --username is missing")
	}
}

func TestUserCreate_DryRunDoesNotCreate(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	out, err := execCmd(t, "", "user", "create", "--db", dbPath, "--user-id", "u1", "--tenant", "acme", "--username", "alice", "--dry-run")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.HasPrefix(out, "[dry-run]") {
		t.Errorf("output = %q, want it to start with [dry-run]", out)
	}

	// A second create with the same ID should succeed if the dry-run
	// really didn't create anything.
	_, err = execCmd(t, "", "user", "create", "--db", dbPath, "--user-id", "u1", "--tenant", "acme", "--username", "alice")
	if err != nil {
		t.Fatalf("expected user creation to succeed after a --dry-run left nothing behind: %v", err)
	}
}
