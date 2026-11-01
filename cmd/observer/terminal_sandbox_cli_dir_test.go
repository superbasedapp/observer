//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestSandboxObserverDirNeverLiteralHome: a config that never went through
// Load (config.Default's "~/.observer/observer.db") resolves the relay's
// folder under the home, never under a literal "~" in the working
// directory (RB1 gate: cmd/observer/~/.observer/sandbox-relay was created
// by a test).
func TestSandboxObserverDirNeverLiteralHome(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	abs := filepath.Join(t.TempDir(), "obs", "observer.db")
	for _, tc := range []struct{ db, want string }{
		{config.Default().Observer.DBPath, filepath.Join(home, ".observer")},
		{"~/x/observer.db", filepath.Join(home, "x")},
		{"", filepath.Join(home, ".observer")},
		{abs, filepath.Dir(abs)},
	} {
		cfg := config.Default()
		cfg.Observer.DBPath = tc.db
		if got := sandboxObserverDirFor(cfg); got != tc.want {
			t.Errorf("sandboxObserverDirFor(%q) = %q, want %q", tc.db, got, tc.want)
		}
	}
}
