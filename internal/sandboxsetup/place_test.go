package sandboxsetup

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
	"time"
)

func TestToolsRoot(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		name string
		env  map[string]string
		home string
		want string
		err  error
	}{
		{"xdg set", map[string]string{"XDG_DATA_HOME": "/data"}, "/home/u", "/data/superbased-observer/sandbox-tools", nil},
		{"xdg relative ignored", map[string]string{"XDG_DATA_HOME": "rel/data"}, "/home/u", "/home/u/.local/share/superbased-observer/sandbox-tools", nil},
		{"default", nil, "/home/u", "/home/u/.local/share/superbased-observer/sandbox-tools", nil},
		{"xdg cleaned", map[string]string{"XDG_DATA_HOME": "/data/../xdg/"}, "", "/xdg/superbased-observer/sandbox-tools", nil},
		{"no home", nil, "", "", ErrNoDataHome},
		{"relative home", nil, "home/u", "", ErrNoDataHome},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToolsRoot(env(tc.env), tc.home)
			if !errors.Is(err, tc.err) || got != filepath.FromSlash(tc.want) {
				t.Errorf("ToolsRoot = %q, %v; want %q, %v", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestPinDirAndPath(t *testing.T) {
	root := "/d/superbased-observer/sandbox-tools"
	cases := []struct {
		name    string
		root    string
		pin     Pin
		dir     string
		path    string
		wantErr error
	}{
		{"ok", root, Pin{ID: "cloud-hypervisor", Version: "54.0"}, root + "/cloud-hypervisor/54.0", root + "/cloud-hypervisor/54.0/cloud-hypervisor", nil},
		{"dotdot version", root, Pin{ID: "x", Version: ".."}, "", "", ErrBadPinPath},
		{"slash id", root, Pin{ID: "a/b", Version: "1"}, "", "", ErrBadPinPath},
		{"empty version", root, Pin{ID: "x"}, "", "", ErrBadPinPath},
		{"relative root", "rel", Pin{ID: "x", Version: "1"}, "", "", ErrPlacementForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := PinDir(tc.root, tc.pin)
			if !errors.Is(err, tc.wantErr) || d != filepath.FromSlash(tc.dir) {
				t.Errorf("PinDir = %q, %v", d, err)
			}
			p, err := PinPath(tc.root, tc.pin)
			if !errors.Is(err, tc.wantErr) || p != filepath.FromSlash(tc.path) {
				t.Errorf("PinPath = %q, %v", p, err)
			}
		})
	}
}

func TestCheckPlacement(t *testing.T) {
	cases := []struct {
		name   string
		target string
		home   string
		bound  []string
		ok     bool
	}{
		{"data home", "/home/u/.local/share/superbased-observer/sandbox-tools/x/1", "/home/u", nil, true},
		{"under .observer", "/home/u/.observer/tools/x", "/home/u", nil, false},
		{"is .observer", "/home/u/.observer", "/home/u", nil, false},
		{"dotdot into .observer", "/home/u/.local/../.observer/x", "/home/u", nil, false},
		{"sibling prefix allowed", "/home/u/.observer-tools/x", "/home/u", nil, true},
		{"under a writable bind", "/work/repo/tools/x", "/home/u", []string{"/work/repo"}, false},
		{"empty bound skipped", "/srv/x", "/home/u", []string{""}, true},
		{"relative bound", "/srv/x", "/home/u", []string{"repo"}, false},
		{"relative target", "tools/x", "/home/u", nil, false},
		{"relative home", "/srv/x", "home", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPlacement(filepath.FromSlash(tc.target), filepath.FromSlash(tc.home), tc.bound)
			if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrPlacementForbidden)) {
				t.Errorf("CheckPlacement = %v, want ok %v", err, tc.ok)
			}
		})
	}
}

func TestPlacedModes(t *testing.T) {
	if PlacedFileMode != 0o755 || PlacedDirMode != 0o700 {
		t.Errorf("modes = %o, %o", PlacedFileMode, PlacedDirMode)
	}
	if PlacedFileMode&0o022 != 0 || PlacedDirMode&0o077 != 0 {
		t.Error("a placed mode is writable or readable by others")
	}
}

// facts is a minimal fs.FileInfo.
type facts struct {
	mode fs.FileMode
	size int64
}

func (f facts) Name() string       { return "f" }
func (f facts) Size() int64        { return f.size }
func (f facts) Mode() fs.FileMode  { return f.mode }
func (f facts) ModTime() time.Time { return time.Time{} }
func (f facts) IsDir() bool        { return f.mode.IsDir() }
func (f facts) Sys() any           { return nil }

func TestCheckFromFile(t *testing.T) {
	p := Pin{ID: "x", Version: "1", Size: 100}
	abs := filepath.FromSlash("/home/u/Downloads/x")
	cases := []struct {
		name string
		path string
		fi   fs.FileInfo
		err  error
	}{
		{"regular within size", abs, facts{0o644, 100}, nil},
		{"smaller than pin", abs, facts{0o644, 99}, nil},
		{"symlink", abs, facts{fs.ModeSymlink | 0o777, 10}, ErrFromFileSymlink},
		{"directory", abs, facts{fs.ModeDir | 0o755, 10}, ErrFromFileNotRegular},
		{"device", abs, facts{fs.ModeDevice | 0o600, 10}, ErrFromFileNotRegular},
		{"no facts", abs, nil, ErrFromFileNotRegular},
		{"over size", abs, facts{0o644, 101}, ErrFromFileSize},
		{"empty", abs, facts{0o644, 0}, ErrFromFileSize},
		{"relative", "x", facts{0o644, 10}, ErrFromFileRelative},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckFromFile(tc.path, tc.fi, p); !errors.Is(err, tc.err) || (tc.err == nil) != (err == nil) {
				t.Errorf("CheckFromFile = %v, want %v", err, tc.err)
			}
		})
	}
}
