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

// TestShimExcludeDirsCoverTheWindowsBridgeTarget: on a WSL daemon the Windows
// homes' shim dirs (the WSL bridge target, T-419) are skipped too, so a
// resolution over the drive mount never takes a bridge shim for the vendor
// binary.
func TestShimExcludeDirsCoverTheWindowsBridgeTarget(t *testing.T) {
	got := shimExcludeDirs("linux", "/home/u", []string{"/mnt/c/Users/u"})
	want := []string{"/home/u/.observer/shims", "/mnt/c/Users/u/.observer/shims"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		// ToSlash: the linux shape is checked on any test host (a Windows
		// one joins with backslashes; a WSL daemon never does).
		if filepath.ToSlash(filepath.Clean(got[i])) != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
