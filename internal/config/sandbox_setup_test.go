package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSandboxSetupAllowElevated pins [terminal.sandbox.setup].allow_elevated
// (sandbox installation lifecycle plan, decision P-250): off by default, so
// an elevated setup step reads as a guide step until the person turns the
// key on, and an explicit value sticks.
func TestSandboxSetupAllowElevated(t *testing.T) {
	if Default().Terminal.Sandbox.Setup.AllowElevated {
		t.Fatal("Default() must leave Terminal.Sandbox.Setup.AllowElevated false (P-250)")
	}
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"no setup block keeps false", "[terminal.sandbox]\nenabled = true\n", false},
		{"explicit true sticks", "[terminal.sandbox.setup]\nallow_elevated = true\n", true},
		{"explicit false sticks", "[terminal.sandbox.setup]\nallow_elevated = false\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg, err := Load(LoadOptions{GlobalPath: path, Env: func(string) string { return "" }})
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.Terminal.Sandbox.Setup.AllowElevated; got != tc.want {
				t.Errorf("AllowElevated = %v, want %v", got, tc.want)
			}
		})
	}
}
