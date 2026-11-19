//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestHostedSetKeySource (decision SBXD-4): the dialog's switch writes the
// tool's entry of tool_keys or login_seed into the config file, keeps every
// other line, removes the entry when switched off, and refuses a tool with
// no grounded file or an unknown source.
func TestHostedSetKeySource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("# kept\n[terminal.sandbox.hosted]\nkey_custody = \"in_box_api_key\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := hostedSetKeySource(path, "tool_keys", "opencode", true); err != nil {
		t.Fatal(err)
	}
	if err := hostedSetKeySource(path, "login_seed", "claude-code", true); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.Terminal.Sandbox.Hosted
	if !h.ToolKeys["opencode"] || !h.LoginSeed["claude-code"] || h.KeyCustody != "in_box_api_key" {
		t.Fatalf("after switching on: %+v %+v %q", h.ToolKeys, h.LoginSeed, h.KeyCustody)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "# kept") {
		t.Fatalf("the comment was lost:\n%s", b)
	}
	if err := hostedSetKeySource(path, "tool_keys", "opencode", false); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.Load(config.LoadOptions{GlobalPath: path})
	if cfg.Terminal.Sandbox.Hosted.ToolKeys["opencode"] {
		t.Fatal("switching off kept the entry")
	}
	for _, tc := range [][2]string{{"tool_keys", "droid"}, {"login_seed", "opencode"}, {"bogus", "opencode"}} {
		if err := hostedSetKeySource(path, tc[0], tc[1], true); err == nil {
			t.Errorf("%s for %s was accepted", tc[0], tc[1])
		}
	}
}
