package testhome

import (
	"fmt"
	"os"
	"path/filepath"
)

// pinned is the profile-root table: each variable is set to a path under
// the temp home (rel; empty = the home itself) or, with clear, unset so its
// readers fall back under the pinned home. Order is the apply order.
var pinned = []struct {
	name  string
	clear bool
	rel   []string
}{
	{name: "HOME"},
	{name: "USERPROFILE"},
	{name: "APPDATA", rel: []string{"AppData", "Roaming"}},
	{name: "LOCALAPPDATA", rel: []string{"AppData", "Local"}},
	{name: "XDG_CONFIG_HOME", clear: true},
	{name: "XDG_DATA_HOME", clear: true},
	{name: "XDG_STATE_HOME", clear: true},
	{name: "XDG_CACHE_HOME", clear: true},
	{name: "OBSERVER_CONFIG", clear: true},
}

// Vars returns the names PinProcess moves or clears, in apply order.
func Vars() []string {
	out := make([]string, 0, len(pinned))
	for _, p := range pinned {
		out = append(out, p.name)
	}
	return out
}

// goToolchainVars are the go command's per-user locations, which default to
// paths under the profile. PinProcess sets each unset one to what it
// resolves to before the profile moves.
var goToolchainVars = []struct {
	name     string
	fallback func() string
}{
	{"GOCACHE", func() string {
		d, err := os.UserCacheDir()
		if err != nil {
			return ""
		}
		return filepath.Join(d, "go-build")
	}},
	{"GOPATH", defaultGOPATH},
	{"GOMODCACHE", func() string {
		p := os.Getenv("GOPATH")
		if p == "" {
			p = defaultGOPATH()
		}
		if p == "" {
			return ""
		}
		return filepath.Join(filepath.SplitList(p)[0], "pkg", "mod")
	}},
	{"GOENV", func() string {
		d, err := os.UserConfigDir()
		if err != nil {
			return ""
		}
		return filepath.Join(d, "go", "env")
	}},
}

func defaultGOPATH() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, "go")
}

// PinProcess pins the profile roots, for the whole process, to one new
// empty directory made with os.MkdirTemp (so under os.TempDir, where
// testwriteguard allows test writes), and returns the home and a cleanup
// that removes it. Children the tests exec inherit the pin. Call it from
// TestMain before m.Run; it is not for use inside a test (use t.Setenv
// there).
func PinProcess() (home string, cleanup func(), err error) {
	for _, g := range goToolchainVars {
		if os.Getenv(g.name) != "" {
			continue
		}
		if v := g.fallback(); v != "" {
			if err := os.Setenv(g.name, v); err != nil {
				return "", nil, fmt.Errorf("testhome.PinProcess: set %s: %w", g.name, err)
			}
		}
	}
	home, err = os.MkdirTemp("", "observer-test-home-")
	if err != nil {
		return "", nil, fmt.Errorf("testhome.PinProcess: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(home) }
	for _, p := range pinned {
		if p.clear {
			if err := os.Unsetenv(p.name); err != nil {
				cleanup()
				return "", nil, fmt.Errorf("testhome.PinProcess: unset %s: %w", p.name, err)
			}
			continue
		}
		val := filepath.Join(append([]string{home}, p.rel...)...)
		if err := os.Setenv(p.name, val); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("testhome.PinProcess: set %s: %w", p.name, err)
		}
	}
	return home, cleanup, nil
}
