package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestPickInitProxyPortTable: one case per row of initProxyPortRules.
func TestPickInitProxyPortTable(t *testing.T) {
	cases := []struct {
		name              string
		flagSet           bool
		flagPort, cfgPort int
		wantPort          int
		wantRule          string
	}{
		{"an explicit flag wins over the config", true, 9000, 18820, 9000, "flag"},
		{"an explicit 8820 still wins", true, 8820, 18820, 8820, "flag"},
		{"no flag: the config's [proxy].port", false, 8820, 18820, 18820, "config"},
		{"no flag, no config port: 8820", false, 8820, 0, 8820, "default"},
		{"a zero flag falls through to the config", true, 0, 18820, 18820, "config"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, rule := pickInitProxyPort(c.flagSet, c.flagPort, c.cfgPort)
			if p != c.wantPort || rule != c.wantRule {
				t.Fatalf("got %d (%s), want %d (%s)", p, rule, c.wantPort, c.wantRule)
			}
		})
	}
}

// TestInitRouteUsesConfigProxyPort: `observer init --claude-code` with no
// --proxy-port writes the route on [proxy].port, and --proxy-port still
// overrides it (D-591). Real writes, but only into a throwaway HOME with
// the crossmount probe disabled.
func TestInitRouteUsesConfigProxyPort(t *testing.T) {
	requireActiveAdapters(t, "claude-code")
	requireComponents(t, "integration.proxy-route")
	home := t.TempDir()
	pinToolHomesAt(t, home)
	t.Setenv(crossmount.EnvDisableForeignHomes, "1")
	cfg := filepath.Join(home, ".observer", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("[proxy]\nport = 18820\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	run := func(args ...string) string {
		t.Helper()
		cmd := newInitCmd()
		cmd.SetArgs(append([]string{"--claude-code", "--skip-hooks", "--skip-mcp", "--guard=false", "--skip-extension", "--config", cfg}, args...))
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		if err := cmd.Execute(); err != nil {
			t.Fatalf("init %v: %v (%s)", args, err, out.String())
		}
		raw, err := os.ReadFile(settings)
		if err != nil {
			t.Fatalf("no settings.json after init: %v (%s)", err, out.String())
		}
		return string(raw)
	}
	if s := run(); !strings.Contains(s, "127.0.0.1:18820") {
		t.Fatalf("init without --proxy-port did not route to [proxy].port 18820:\n%s", s)
	}
	if s := run("--proxy-port", "9123", "--force"); !strings.Contains(s, "127.0.0.1:9123") {
		t.Fatalf("--proxy-port 9123 did not override the config:\n%s", s)
	}
}
