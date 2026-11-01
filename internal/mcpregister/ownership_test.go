package mcpregister

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestDecideMCPEntryTable is one case per row of mcpOwnershipRules (U2).
func TestDecideMCPEntryTable(t *testing.T) {
	want := mcpEntryFacts{command: "/n/bin/observer", args: []string{"serve"}}
	missing := func(string) bool { return false }
	present := func(string) bool { return true }
	self := func(c string) bool { return c == "/n/lib/node_modules/@superbased/observer-linux-x64/bin/observer" }
	cases := []struct {
		name   string
		have   mcpEntryFacts
		env    mcpOwnershipEnv
		action mcpWriteAction
		rule   string
	}{
		{"identical", want, mcpOwnershipEnv{commandExists: present}, mcpActionAlreadySet, "identical"},
		{"same command, --config drift", mcpEntryFacts{command: want.command, args: []string{"serve", "--config", "/c"}}, mcpOwnershipEnv{commandExists: present}, mcpActionRefresh, "same-command"},
		{"force", mcpEntryFacts{command: "/x/other", args: []string{"run"}}, mcpOwnershipEnv{force: true, commandExists: present}, mcpActionRefresh, "force"},
		{"stale observer entry (npm deleted it)", mcpEntryFacts{command: "/n/lib/node_modules/@superbased/observer/node_modules/@superbased/observer-linux-x64/bin/observer", args: []string{"serve"}}, mcpOwnershipEnv{commandExists: missing}, mcpActionRefresh, "stale-observer"},
		{"stale observer entry with --config", mcpEntryFacts{command: "/gone/observer", args: []string{"serve", "--config", "/c"}}, mcpOwnershipEnv{commandExists: missing}, mcpActionRefresh, "stale-observer"},
		{"same install by its real path", mcpEntryFacts{command: "/n/lib/node_modules/@superbased/observer-linux-x64/bin/observer", args: []string{"serve"}}, mcpOwnershipEnv{commandExists: present, sameInstall: self}, mcpActionRefresh, "same-install"},
		{"missing command but not Observer-shaped", mcpEntryFacts{command: "/gone/thing", args: []string{"mcp"}}, mcpOwnershipEnv{commandExists: missing}, mcpActionConflict, "foreign"},
		{"another existing install", mcpEntryFacts{command: "/opt/other/observer", args: []string{"serve"}}, mcpOwnershipEnv{commandExists: present, sameInstall: self}, mcpActionConflict, "foreign"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, r := decideMCPEntry(c.have, want, c.env)
			if a != c.action || r != c.rule {
				t.Fatalf("decideMCPEntry = (%d, %s), want (%d, %s)", a, r, c.action, c.rule)
			}
		})
	}
}

// TestRegisterRefreshesStaleObserverEntryWithoutForce is U2's red/green: an
// entry an older init wrote into an npm tree that npm then deleted is
// rewritten by a plain init (no --force), for all three file shapes.
func TestRegisterRefreshesStaleObserverEntryWithoutForce(t *testing.T) {
	home := t.TempDir()
	stale := filepath.Join(home, "gone", "node_modules", "@superbased", "observer-linux-x64", "bin", "observer")
	writeFile := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// strconv.Quote keeps a Windows temp path (backslashes) a valid JSON
	// and TOML string; a POSIX path quotes to the same bytes as before.
	writeFile(filepath.Join(home, ".claude.json"), `{"mcpServers":{"observer":{"command":`+strconv.Quote(stale)+`,"args":["serve"]}}}`)
	writeFile(filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.observer]\ncommand = "+strconv.Quote(stale)+"\nargs = [\"serve\"]\n")
	r, err := NewRegistrar(RegisterOptions{BinaryPath: "/new/bin/observer", HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"claude-code", "codex"} {
		res := r.Register(tool)
		if res.Error != nil || !res.Added {
			t.Fatalf("%s: Register = %+v, want a refresh without --force", tool, res)
		}
	}
	for _, p := range []string{filepath.Join(home, ".claude.json"), filepath.Join(home, ".codex", "config.toml")} {
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), stale) || !strings.Contains(string(b), "/new/bin/observer") {
			t.Fatalf("%s not refreshed: %s", p, b)
		}
	}
}

// TestRepairOnly pins the start-time repair: it rewrites only a stale
// Observer entry, never adds one and never touches an entry whose command
// exists.
func TestRepairOnly(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistrar(RegisterOptions{BinaryPath: "/new/bin/observer", HomeDir: home, RepairOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	// No entry: nothing is added (MCP stays opt-in).
	if res := r.Register("cursor"); res.Added || res.Error != nil {
		t.Fatalf("repair added an entry: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(home, ".cursor", "mcp.json")); err == nil {
		t.Fatal("repair created mcp.json")
	}
	// A foreign entry whose command exists: untouched, no error.
	existing := filepath.Join(home, "other-observer")
	if err := os.WriteFile(existing, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"mcpServers":{"observer":{"command":` + strconv.Quote(existing) + `,"args":["serve"]}}}`
	p := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("cursor"); res.Added || res.Error != nil {
		t.Fatalf("repair touched a live entry: %+v", res)
	}
	if b, _ := os.ReadFile(p); string(b) != body {
		t.Fatal("repair changed a live entry")
	}
	// A stale entry: repaired.
	if err := os.Remove(existing); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("cursor"); !res.Added || res.Error != nil {
		t.Fatalf("repair did not fix a stale entry: %+v", res)
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), "/new/bin/observer") {
		t.Fatalf("stale entry not repaired: %s", b)
	}
}
