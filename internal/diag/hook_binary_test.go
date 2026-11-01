package diag

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// hookBinaryFixture lays out an npm-shaped install: the real Go binary under
// node_modules, the npm launcher on PATH (a script, as npm's shim is on some
// installs), a bin symlink to the real binary, another observer, and a path
// that no longer exists.
type hookBinaryFixture struct {
	real, launcher, symlink, other, stale string
}

func newHookBinaryFixture(t *testing.T) hookBinaryFixture {
	t.Helper()
	root := t.TempDir()
	f := hookBinaryFixture{
		real:     filepath.Join(root, "lib", "node_modules", "@superbased", "observer-linux-x64", "bin", "observer"),
		launcher: filepath.Join(root, "usr", "local", "bin", "observer"),
		symlink:  filepath.Join(root, "home", "bin", "observer"),
		other:    filepath.Join(root, "opt", "elsewhere", "observer"),
		stale:    filepath.Join(root, "lib", "node_modules", "@superbased", "observer", "node_modules", "old", "bin", "observer"),
	}
	for _, p := range []string{f.real, f.launcher, f.other} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(f.symlink), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.real, f.symlink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	return f
}

// TestHookBinaryMatches pins hookBinaryRules (T-874), one case per row plus
// the two mismatches that must stay risks.
func TestHookBinaryMatches(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink fixture")
	}
	f := newHookBinaryFixture(t)
	npm := HookBinaryIdentity{Command: f.launcher, Real: f.real}
	cases := []struct {
		name     string
		recorded string
		id       HookBinaryIdentity
		want     bool
	}{
		{"npm launcher recorded, daemon runs the real binary (shim vs real)", f.launcher, npm, true},
		{"older registration named the real binary", f.real, npm, true},
		{"recorded path is a symlink to the running binary", f.symlink, HookBinaryIdentity{Command: f.real, Real: f.real}, true},
		{"symlink recorded, caller knows only the real binary", f.symlink, HookBinaryIdentity{Command: f.real}, true},
		{"cleaned spelling of the command", f.launcher + "/", npm, true},
		{"a truly different observer binary", f.other, npm, false},
		{"a stale path that no longer exists", f.stale, npm, false},
		{"nothing recorded", "", npm, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HookBinaryMatches(tc.recorded, tc.id); got != tc.want {
				t.Fatalf("HookBinaryMatches(%q, %+v) = %v, want %v", tc.recorded, tc.id, got, tc.want)
			}
		})
	}
}

// TestHookBinaryMismatchUsesDoctorEquivalence runs the same registry through
// the managed-integrity probe and `observer doctor`'s hooks.binary check:
// both see only the genuinely different and the stale entry (T-874: demo
// node 1 reported 21 mismatches where doctor saw 1).
func TestHookBinaryMismatchUsesDoctorEquivalence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink fixture")
	}
	f := newHookBinaryFixture(t)
	home := t.TempDir()
	recorded := map[string]string{
		"launcher": f.launcher, "real": f.real, "symlink": f.symlink,
		"other": f.other, "stale": f.stale,
	}
	entries := map[string]map[string]any{}
	for name, bin := range recorded {
		cfg := filepath.Join(home, "."+name, "hooks.json")
		if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfg, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		entries[cfg] = map[string]any{"binary_path": bin, "tool": name, "sha256": "x"}
	}
	body, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".observer"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".observer", "hook_checksums.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	sig := InspectCaptureIntegrityWith(home, CaptureIntegrityOptions{BinaryPath: f.launcher, RealBinaryPath: f.real})
	got := map[string]bool{}
	for _, it := range sig.Items {
		if it.Risk == orgcontract.CaptureRiskHookBinaryMismatch {
			got[it.Tool] = true
		}
	}
	want := map[string]bool{"other": true, "stale": true}
	if len(got) != len(want) || !got["other"] || !got["stale"] {
		t.Fatalf("probe mismatches = %v, want %v", got, want)
	}

	check := checkHookCommandsBinary(home, f.launcher, f.real)
	if check.Status != StatusWarn || len(check.Details) != len(want) {
		t.Fatalf("doctor hooks.binary = %s %v, want a warning naming %d entries", check.Status, check.Details, len(want))
	}
}
