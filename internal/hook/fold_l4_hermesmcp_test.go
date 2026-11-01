package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHermesMCPKeepsCredentials pins review T-384 for Hermes' MCP writer:
// config.yaml holds a provider key (the fake fixture), so registering and
// removing the MCP server edits only mcp_servers, keeps the comment, the
// key and the mode, and leaves no backup copy.
func TestHermesMCPKeepsCredentials(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, HermesConfigFile)
	body := "# hermes config\nmodel:\n  provider: openrouter\n  api_key: " + credFixtureSecret + "\nmcp_servers:\n  other:\n    command: npx\n    env:\n      OTHER_TOKEN: " + credFixtureSecret + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg, 0o640); err != nil {
		t.Fatal(err)
	}
	opts := HermesOptions{HermesHome: home, BinaryPath: "/opt/observer"}
	check := func(stage string, wantObserver bool) {
		t.Helper()
		got, _ := os.ReadFile(cfg)
		s := string(got)
		if strings.Count(s, credFixtureSecret) != 2 || !strings.Contains(s, "# hermes config") {
			t.Errorf("%s: a credential or the comment was lost:\n%s", stage, s)
		}
		if strings.Index(s, "model:") > strings.Index(s, "mcp_servers:") {
			t.Errorf("%s: top-level keys were re-sorted:\n%s", stage, s)
		}
		if strings.Contains(s, "  "+HermesMCPServerName+":") != wantObserver {
			t.Errorf("%s: observer entry present = %v, want %v:\n%s", stage, !wantObserver, wantObserver, s)
		}
		if fi, _ := os.Stat(cfg); posixModes && fi.Mode().Perm() != 0o640 {
			t.Errorf("%s: mode = %v, want 0640 kept", stage, fi.Mode().Perm())
		}
		if _, err := os.Stat(cfg + ".bak"); !os.IsNotExist(err) {
			t.Errorf("%s: a backup copy of the credential file was written", stage)
		}
	}
	if _, err := RegisterHermesMCP(opts); err != nil {
		t.Fatalf("RegisterHermesMCP: %v", err)
	}
	check("register", true)
	if _, err := UnregisterHermesMCP(opts); err != nil {
		t.Fatalf("UnregisterHermesMCP: %v", err)
	}
	check("unregister", false)

	// A file that does not parse is refused without quoting it.
	bad := "api_key: " + credFixtureSecret + "\n  : [\n"
	if err := os.WriteFile(cfg, []byte(bad), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterHermesMCP(opts); err == nil || strings.Contains(err.Error(), credFixtureSecret) {
		t.Errorf("RegisterHermesMCP on an unparsable file = %v, want a refusal that does not quote it", err)
	}
}
