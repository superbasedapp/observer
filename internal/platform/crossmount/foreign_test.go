package crossmount

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestUnderForeignHome(t *testing.T) {
	t.Parallel()
	homes := []HomeRoot{
		{Path: "/home/me", OS: OSLinux, Origin: "native"},
		{Path: "", OS: OSWindows, Origin: "wsl-mnt:empty"},
		{Path: "/mnt/c/Users/win", OS: OSWindows, Origin: "wsl-mnt:win"},
	}
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"native home is never foreign", "/home/me/.local/share/tool.db", false},
		{"under a foreign home", "/mnt/c/Users/win/AppData/tool.db", true},
		{"forward slash after the home", "/mnt/c/Users/win/x", true},
		{"the home itself is not under it", "/mnt/c/Users/win", false},
		{"a sibling with the home as a name prefix", "/mnt/c/Users/win2/tool.db", false},
		{"an empty home matches nothing", "/var/lib/tool.db", false},
		{"relative path", "tool.db", false},
	}
	for _, tc := range cases {
		if got := UnderForeignHome(tc.path, homes); got != tc.want {
			t.Errorf("%s: UnderForeignHome(%q) = %v, want %v", tc.name, tc.path, got, tc.want)
		}
	}
	if UnderForeignHome("/mnt/c/Users/win/x", nil) {
		t.Error("no homes: want false")
	}
}

// TestDetectorNeverYieldsEmptyHomePath pins that the home list AllHomes is
// built from never carries an empty Path: the native home is dropped when
// it does not resolve, and every cross-mount home is a join under a fixed,
// non-empty mount root. So UnderForeignHome's empty-home guard only matters
// for a hand-built home list (a test seam); for AllHomes output it is
// unreachable, and the adapters whose copies lacked the guard behave the same.
func TestDetectorNeverYieldsEmptyHomePath(t *testing.T) {
	t.Parallel()
	users := wslWindowsUsersRoot
	linuxFS := &fakeFS{
		dirs: map[string]bool{
			users:                                    true,
			filepath.Join(users, "AppData"):          true,
			filepath.Join(users, "auzy_"):            true,
			filepath.Join(users, "auzy_", "AppData"): true,
			filepath.Join(users, "other"):            true,
		},
		listings: map[string][]string{
			users: {"", "auzy_", "other"},
		},
	}
	root := `\\wsl.localhost\`
	ub := filepath.Join(root, "Ubuntu")
	windowsFS := &fakeFS{
		dirs: map[string]bool{
			root:                               true,
			filepath.Join(ub, "home"):          true,
			filepath.Join(ub, "home", "marmu"): true,
		},
		listings: map[string][]string{
			root:                      {"Ubuntu"},
			filepath.Join(ub, "home"): {"", "marmu"},
		},
	}
	cases := []struct {
		name string
		d    *detector
	}{
		{"wsl2, native home unresolved", &detector{
			runtimeOS:  OSLinux,
			nativeHome: func() (string, error) { return "", nil },
			statDir:    linuxFS.statDir,
			readDir:    linuxFS.readDir,
			exists:     linuxFS.exists,
			getenv:     func(string) string { return "" },
		}},
		{"wsl2, all profiles forced", &detector{
			runtimeOS:  OSLinux,
			nativeHome: func() (string, error) { return "", errors.New("no home") },
			statDir:    linuxFS.statDir,
			readDir:    linuxFS.readDir,
			exists:     linuxFS.exists,
			getenv: func(name string) string {
				if name == EnvAllWindowsProfiles {
					return "1"
				}
				return ""
			},
		}},
		{"windows host", &detector{
			runtimeOS:  OSWindows,
			nativeHome: func() (string, error) { return "", nil },
			statDir:    windowsFS.statDir,
			readDir:    windowsFS.readDir,
		}},
	}
	for _, tc := range cases {
		got := tc.d.allHomes()
		if len(got) == 0 {
			t.Errorf("%s: no homes enumerated; the layout is not exercised", tc.name)
		}
		for _, h := range got {
			if h.Path == "" {
				t.Errorf("%s: home with an empty Path: %+v", tc.name, h)
			}
		}
	}
}
