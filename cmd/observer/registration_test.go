package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestRegistrationCommandNPMLayout is U1's red/green through the real I/O
// seam: a binary inside an npm global tree registers the npm bin launcher
// (which `npm install -g` keeps), and a binary anywhere else keeps its path.
func TestRegistrationCommandNPMLayout(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("POSIX npm layout")
	}
	prefix := t.TempDir()
	shim := filepath.Join(prefix, "lib", "node_modules", "@superbased", "observer", "bin", "observer.js")
	bin := filepath.Join(prefix, "lib", "node_modules", "@superbased", "observer-linux-x64", "bin", "observer")
	launcher := filepath.Join(prefix, "bin", "observer")
	for _, p := range []string{shim, bin} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(launcher), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := testSymlink(t, "../lib/node_modules/@superbased/observer/bin/observer.js", launcher); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(launcher))
	real, _ := filepath.EvalSymlinks(bin)
	if got := registrationCommand(real); got != launcher {
		t.Fatalf("registrationCommand(npm binary) = %q, want the launcher %q", got, launcher)
	}
	other := filepath.Join(t.TempDir(), "observer")
	if got := registrationCommand(other); got != other {
		t.Fatalf("registrationCommand(archive binary) = %q, want itself", got)
	}
}

// TestRegistrationConfigArgOneRenderer is U5: init and auto-register render
// the same --config argument, omitting it for the default config file (which
// a hook reads anyway) and keeping any other path.
func TestRegistrationConfigArgOneRenderer(t *testing.T) {
	home := t.TempDir()
	def := filepath.Join(home, ".observer", "config.toml")
	if got := registrationConfigArg(def, home); got != "" {
		t.Fatalf("default config rendered as %q, want no --config", got)
	}
	if got := registrationConfigArg("", home); got != "" {
		t.Fatalf("empty config rendered as %q", got)
	}
	custom := filepath.Join(home, "ab", "observer-config.toml")
	if got := registrationConfigArg(custom, home); got != custom {
		t.Fatalf("custom config rendered as %q, want %q", got, custom)
	}
}

// TestCodexTrustLineCountsRegisteredHooks is U8: the /hooks instruction
// counts the entries the codex writer registers (it said 6 after the writer
// grew to 9).
func TestCodexTrustLineCountsRegisteredHooks(t *testing.T) {
	line := codexTrustLine()
	if strings.Contains(line, "all 6 ") {
		t.Fatalf("stale count: %q", line)
	}
	if want := fmt.Sprintf("its own %d hook entries", len(hook.CodexHookEvents())); !strings.Contains(line, want) {
		t.Fatalf("line = %q, want it to name %q", line, want)
	}
}
