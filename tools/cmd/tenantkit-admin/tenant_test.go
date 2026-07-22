package main

import (
	"bytes"
	"strings"
	"testing"
)

// execCmd runs newRootCmd() (a fresh command tree) with args, feeding
// stdin (for confirmation prompts) and capturing combined stdout.
func execCmd(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestTenantCreate_ExplicitID(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	out, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, `created tenant "acme" (Acme Corp)`) {
		t.Errorf("output = %q, want it to mention the created tenant", out)
	}

	listOut, err := execCmd(t, "", "tenant", "list", "--db", dbPath)
	if err != nil {
		t.Fatalf("execCmd (list): %v\noutput:\n%s", err, listOut)
	}
	if !strings.Contains(listOut, "acme") {
		t.Errorf("list output = %q, want it to include the created tenant", listOut)
	}
}

func TestTenantCreate_GenerateID(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	out, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--generate-id", "--name", "Acme Corp")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "created tenant") {
		t.Errorf("output = %q, want it to mention a created tenant", out)
	}
}

func TestTenantCreate_IDAndGenerateIDMutuallyExclusive(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	_, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--generate-id", "--name", "Acme Corp")
	if err == nil {
		t.Fatal("expected an error when both --id and --generate-id are given")
	}
}

func TestTenantCreate_NeitherIDNorGenerateID(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	_, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--name", "Acme Corp")
	if err == nil {
		t.Fatal("expected an error when neither --id nor --generate-id is given")
	}
}

func TestTenantCreate_DryRunDoesNotCreate(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	out, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp", "--dry-run")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.HasPrefix(out, "[dry-run]") {
		t.Errorf("output = %q, want it to start with [dry-run]", out)
	}

	listOut, err := execCmd(t, "", "tenant", "list", "--db", dbPath)
	if err != nil {
		t.Fatalf("execCmd (list): %v\noutput:\n%s", err, listOut)
	}
	if strings.Contains(listOut, "acme") {
		t.Errorf("list output = %q, want no tenant to have been created by a --dry-run", listOut)
	}
}

func TestTenantList_JSON(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create: %v", err)
	}

	out, err := execCmd(t, "", "tenant", "list", "--db", dbPath, "--json")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, `"ID": "acme"`) {
		t.Errorf("JSON output = %q, want it to contain the tenant's ID field", out)
	}
}

func TestTenantDeactivate_RequiresConfirmation(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Answering "n" (or anything but y/yes) must abort without deactivating.
	out, err := execCmd(t, "n\n", "tenant", "deactivate", "--db", dbPath, "--id", "acme")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "aborted") {
		t.Errorf("output = %q, want \"aborted\" after declining confirmation", out)
	}

	listOut, _ := execCmd(t, "", "tenant", "list", "--db", dbPath)
	if !strings.Contains(listOut, "active=true") {
		t.Errorf("list output = %q, want the tenant to still be active after an aborted deactivate", listOut)
	}
}

func TestTenantDeactivate_ConfirmedProceeds(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create: %v", err)
	}

	out, err := execCmd(t, "y\n", "tenant", "deactivate", "--db", dbPath, "--id", "acme")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, `deactivated tenant "acme"`) {
		t.Errorf("output = %q, want confirmation of deactivation", out)
	}

	listOut, _ := execCmd(t, "", "tenant", "list", "--db", dbPath)
	if !strings.Contains(listOut, "active=false") {
		t.Errorf("list output = %q, want the tenant to be inactive", listOut)
	}
}

func TestTenantDeactivate_YesFlagSkipsPrompt(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	if _, err := execCmd(t, "", "tenant", "create", "--db", dbPath, "--id", "acme", "--name", "Acme Corp"); err != nil {
		t.Fatalf("create: %v", err)
	}

	// No stdin provided at all -- if this blocked on a prompt, it would
	// read EOF and fail the "y/yes" check, so this also proves --yes
	// really does skip the confirm() call rather than just answering it.
	out, err := execCmd(t, "", "tenant", "deactivate", "--db", dbPath, "--id", "acme", "--yes")
	if err != nil {
		t.Fatalf("execCmd: %v\noutput:\n%s", err, out)
	}
	if strings.Contains(out, "[y/N]") {
		t.Errorf("output = %q, want no confirmation prompt when --yes is set", out)
	}
	if !strings.Contains(out, `deactivated tenant "acme"`) {
		t.Errorf("output = %q, want confirmation of deactivation", out)
	}
}

func TestTenantDeactivate_NotFound(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	_, err := execCmd(t, "", "tenant", "deactivate", "--db", dbPath, "--id", "nope", "--yes")
	if err == nil {
		t.Fatal("expected an error deactivating a nonexistent tenant")
	}
}
