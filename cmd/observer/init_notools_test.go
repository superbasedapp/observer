package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestInitAllNoToolsSaysSoAfterGateNotes pins T-744 (node 3, rc.2): `observer
// init --all` in an empty HOME on a build whose MCP component is inactive
// printed only "mcp skipped: ... inactive" and never said that --all found no
// AI tool, because the gate note stood in for the whole answer. The note is
// still printed, followed by the no-tool line. Dry run in a throwaway HOME.
func TestInitAllNoToolsSaysSoAfterGateNotes(t *testing.T) {
	home := t.TempDir()
	pinToolHomesAt(t, home)
	t.Setenv(crossmount.EnvDisableForeignHomes, "1")
	cfg := filepath.Join(home, ".observer", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("[components]\nremove = [\"integration.mcp-server\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newInitCmd()
	cmd.SetArgs([]string{"--all", "--dry-run", "--skip-proxy-route", "--guard=false", "--skip-extension", "--config", cfg})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --all: %v (%s)", err, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "mcp") || !strings.Contains(got, "skipped") {
		t.Fatalf("the gate note for the inactive MCP component is missing:\n%s", got)
	}
	if !strings.Contains(got, "--all found no supported AI tool installed on this machine; nothing to wire") {
		t.Fatalf("init --all with no AI tool did not say so:\n%s", got)
	}
}
