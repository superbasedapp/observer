package host

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/shellwrap"
)

// TestNewEnvExcludesCommandWrappingShims pins the production wiring of the
// recursion guard: every Env the launchers, the dashboard preflight and the
// node-intervention probe build skips the shellwrap shim dir and any file
// carrying the shim marker.
func TestNewEnvExcludesCommandWrappingShims(t *testing.T) {
	env := NewEnv(Options{})
	if env.ExcludeMarker != shellwrap.ShimMarker {
		t.Fatalf("ExcludeMarker = %q", env.ExcludeMarker)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home")
	}
	want := filepath.Clean(shellwrap.DefaultShimDir(shellwrap.Host{GOOS: runtime.GOOS, Home: home}))
	found := false
	for _, d := range env.ExcludeDirs {
		if filepath.Clean(d) == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("ExcludeDirs %v lacks %s", env.ExcludeDirs, want)
	}
}
