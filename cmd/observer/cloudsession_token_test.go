package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCloudSessionTokenCLI pins `observer cloud-session token` (CA-D18): a
// mint per cloud environment prints the secret once with its expiry, a second
// mint for the same environment is refused, list shows the environment and
// the time left but never the secret, and revoke ends it.
func TestCloudSessionTokenCLI(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	dbPath := filepath.Join(dir, "observer.db")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(dbPath)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		cmd := newCloudSessionCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(append(args, "--config", cfgPath))
		err := cmd.ExecuteContext(context.Background())
		return out.String(), err
	}
	out, err := run("token", "mint", "claude web env")
	if err != nil {
		t.Fatalf("mint: %v\n%s", err, out)
	}
	secret := regexp.MustCompile(`sbocs_[A-Za-z0-9_-]{43}`).FindString(out)
	id := regexp.MustCompile(`cst_[0-9a-f]{24}`).FindString(out)
	if secret == "" || id == "" || !strings.Contains(out, `"claude web env"`) || !strings.Contains(out, "expires") {
		t.Fatalf("mint output:\n%s", out)
	}
	if out, err := run("token", "mint", "CLAUDE WEB ENV"); err == nil || !strings.Contains(err.Error(), "already has an active ship token") {
		t.Fatalf("second mint for one environment: %v\n%s", err, out)
	}
	if _, err := run("token", "mint", "  "); err == nil {
		t.Fatal("a blank environment label was accepted")
	}
	out, err = run("token", "list")
	if err != nil || !strings.Contains(out, id) || !strings.Contains(out, "claude web env") || !strings.Contains(out, "active") || strings.Contains(out, secret) {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if out, err := run("token", "revoke", id); err != nil || !strings.Contains(out, "revoked "+id) {
		t.Fatalf("revoke: %v\n%s", err, out)
	}
	if out, _ := run("token", "list"); !strings.Contains(out, "revoked") {
		t.Fatalf("list after revoke:\n%s", out)
	}
	if _, err := run("token", "revoke", "nope"); err == nil {
		t.Fatal("a malformed token id was accepted")
	}
}
