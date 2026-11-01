package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestInitAllHermesOnlyWhenDetected: `observer init --all` selects Hermes
// only when its vendor home exists (the same detection class as the plugin
// shim hosts); an explicit --hermes still installs regardless. Dry runs
// only, in a throwaway HOME with the crossmount probe disabled, so nothing
// is written anywhere.
func TestInitAllHermesOnlyWhenDetected(t *testing.T) {
	home := t.TempDir()
	pinToolHomesAt(t, home)
	t.Setenv(crossmount.EnvDisableForeignHomes, "1")
	cfg := filepath.Join(home, ".observer", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	hermesHome := filepath.Join(home, ".hermes")
	if runtime.GOOS == "windows" {
		hermesHome = filepath.Join(home, "AppData", "Local", "hermes")
	}
	run := func(args ...string) string {
		t.Helper()
		cmd := newInitCmd()
		cmd.SetArgs(append(args, "--dry-run", "--skip-mcp", "--skip-proxy-route", "--guard=false", "--skip-extension", "--config", cfg))
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		if err := cmd.Execute(); err != nil {
			t.Fatalf("init %v: %v (%s)", args, err, out.String())
		}
		return out.String()
	}

	if out := run("--all"); strings.Contains(out, "hermes:") {
		t.Fatalf("init --all with no Hermes home selected hermes:\n%s", out)
	}
	if out := run("--hermes"); !strings.Contains(out, "hermes: would write plugin to") {
		t.Fatalf("an explicit --hermes must still install:\n%s", out)
	}
	if err := os.MkdirAll(hermesHome, 0o755); err != nil {
		t.Fatal(err)
	}
	if out := run("--all"); !strings.Contains(out, "hermes: would write plugin to") {
		t.Fatalf("init --all with a Hermes home did not select hermes:\n%s", out)
	}
}
