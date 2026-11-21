package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSeccompAllowSeizeDefaultsOff (lane ptrace, PT-96): the strace switch
// is off by default and in a partial [terminal.sandbox] block that turns
// the filter on; only an explicit true turns it on.
func TestSeccompAllowSeizeDefaultsOff(t *testing.T) {
	if Default().Terminal.Sandbox.SeccompAllowSeize {
		t.Fatal("Default() turns the strace switch on")
	}
	for body, want := range map[string]bool{
		"[terminal.sandbox]\nseccomp = true\n":                             false,
		"[terminal.sandbox]\nenabled = true\n":                             false,
		"[terminal.sandbox]\nseccomp = true\nseccomp_allow_seize = true\n": true,
	} {
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(LoadOptions{GlobalPath: path})
		if err != nil {
			t.Fatalf("%q: %v", body, err)
		}
		if got := cfg.Terminal.Sandbox.SeccompAllowSeize; got != want {
			t.Errorf("%q: seccomp_allow_seize %v, want %v", body, got, want)
		}
	}
}
