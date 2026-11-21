package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTerminalSandboxSeccompKey (lane N2): [terminal.sandbox].seccomp is
// off by default and when absent (D7), and decodes when set.
func TestTerminalSandboxSeccompKey(t *testing.T) {
	if Default().Terminal.Sandbox.Seccomp {
		t.Fatal("seccomp is on by default")
	}
	for body, want := range map[string]bool{
		"[terminal.sandbox]\nenabled = true\n":                  false,
		"[terminal.sandbox]\nenabled = true\nseccomp = true\n":  true,
		"[terminal.sandbox]\nenabled = true\nseccomp = false\n": false,
	} {
		p := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(LoadOptions{GlobalPath: p, Env: func(string) string { return "" }})
		if err != nil {
			t.Fatalf("%q: %v", body, err)
		}
		if cfg.Terminal.Sandbox.Seccomp != want {
			t.Fatalf("%q: seccomp = %v, want %v", body, cfg.Terminal.Sandbox.Seccomp, want)
		}
	}
}
