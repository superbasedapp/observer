package testhome

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPinProcessMovesEveryProfileRoot pins that after PinProcess every home
// Go resolves (os.UserHomeDir, os.UserConfigDir, os.UserCacheDir) is under
// the new temp home, the XDG dirs are unset, the home is under os.TempDir
// (where testwriteguard allows test writes) and starts empty.
func TestPinProcessMovesEveryProfileRoot(t *testing.T) {
	// t.Setenv restores each variable when the test ends, whatever
	// PinProcess does to it.
	for _, name := range append(Vars(), "GOCACHE", "GOPATH", "GOMODCACHE", "GOENV") {
		t.Setenv(name, os.Getenv(name))
	}
	home, cleanup, err := PinProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	under := func(label, p string) {
		t.Helper()
		rel, err := filepath.Rel(home, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Errorf("%s = %q, not under the pinned home %q", label, p, home)
		}
	}
	if h, err := os.UserHomeDir(); err != nil {
		t.Errorf("UserHomeDir: %v", err)
	} else {
		under("UserHomeDir", h)
	}
	if d, err := os.UserConfigDir(); err != nil {
		t.Errorf("UserConfigDir: %v", err)
	} else {
		under("UserConfigDir", d)
	}
	if d, err := os.UserCacheDir(); err != nil {
		t.Errorf("UserCacheDir: %v", err)
	} else {
		under("UserCacheDir", d)
	}
	for _, name := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "OBSERVER_CONFIG"} {
		if v, ok := os.LookupEnv(name); ok {
			t.Errorf("%s = %q after PinProcess, want unset", name, v)
		}
	}
	tmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	if rel, err := filepath.Rel(tmp, realHome); err != nil || strings.HasPrefix(rel, "..") {
		t.Errorf("pinned home %q is not under os.TempDir %q", realHome, tmp)
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Errorf("pinned home %q is not a fresh empty dir: %v (err %v)", home, entries, err)
	}
	// The go toolchain's locations were kept off the temp home.
	for _, name := range []string{"GOCACHE", "GOMODCACHE"} {
		if v := os.Getenv(name); v != "" && strings.HasPrefix(v, home) {
			t.Errorf("%s = %q moved into the temp home", name, v)
		}
	}
}
