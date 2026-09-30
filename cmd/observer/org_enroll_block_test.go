package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestEnsureOrgClientBlockWritesServerURL is tracker #41: the block enroll
// writes must carry org_server_url, because the policy-bundle runner and
// the disclosure surfaces read it from config (the push loop reads the DB
// enrolment row) — an enrolled node without the key ran its guard
// org-layer silently unwired.
func TestEnsureOrgClientBlockWritesServerURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	seed := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "observer.db")) + "\"\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	added, err := ensureOrgClientBlock(path, "https://org.acme.example", false)
	if err != nil || !added {
		t.Fatalf("ensureOrgClientBlock = (%v, %v), want (true, nil)", added, err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(body), `org_server_url = "https://org.acme.example"`) {
		t.Fatalf("block missing org_server_url:\n%s", body)
	}
	// The appended block must parse: Load the file and confirm both keys.
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatalf("config.Load on appended block: %v", err)
	}
	if !cfg.OrgClient.Enabled || cfg.OrgClient.OrgServerURL != "https://org.acme.example" {
		t.Fatalf("loaded org_client = enabled=%v url=%q", cfg.OrgClient.Enabled, cfg.OrgClient.OrgServerURL)
	}

	// Idempotent: a second call must not touch the file.
	before, _ := os.ReadFile(path)
	added, err = ensureOrgClientBlock(path, "https://other.example", false)
	if err != nil || added {
		t.Fatalf("second ensureOrgClientBlock = (%v, %v), want (false, nil)", added, err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("existing block was modified")
	}
}

// TestEnsureOrgClientBlockToleratesEmptyURL: older callers (or a link-only
// enrolment that failed to resolve a URL) omit the key rather than writing
// an empty string TOML users would have to clean up.
func TestEnsureOrgClientBlockToleratesEmptyURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	added, err := ensureOrgClientBlock(path, "  ", false)
	if err != nil || !added {
		t.Fatalf("ensureOrgClientBlock = (%v, %v), want (true, nil)", added, err)
	}
	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), "org_server_url") {
		t.Fatalf("empty URL should omit the key:\n%s", body)
	}
}

// TestEnsureOrgClientBlockIgnoresCommentMentions pins the header check to
// real TOML table headers: a config whose COMMENTS mention [org_client] (the
// shipped gateway-role template does, twice) must still receive the block,
// and a config with a real header — even indented — must not receive a
// second one.
func TestEnsureOrgClientBlockIgnoresCommentMentions(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantAdded bool
	}{
		{
			name:      "comment mention only",
			body:      "# enroll appends its [org_client] block here\n[proxy]\nport = 8820\n",
			wantAdded: true,
		},
		{
			name:      "real header",
			body:      "[org_client]\nenabled = true\n",
			wantAdded: false,
		},
		{
			name:      "indented real header",
			body:      "  [org_client]\nenabled = false\n",
			wantAdded: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			added, err := ensureOrgClientBlock(path, "https://org.acme.example", false)
			if err != nil {
				t.Fatal(err)
			}
			if added != tc.wantAdded {
				t.Fatalf("added = %v, want %v", added, tc.wantAdded)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(string(body), "\n[org_client]\n"); tc.wantAdded && got != 1 {
				t.Fatalf("appended block count = %d, want 1", got)
			}
		})
	}
}
