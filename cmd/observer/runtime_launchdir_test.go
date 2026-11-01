// runtime_launchdir_test.go pins review M3-18 on the cmd side: the runtime
// probe runs in the directory the tool will start in, a version-manager shim
// is not judged from a directory that is not the launch's, and an installed
// package's whole engines range is checked, not only its floor.

package main

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/toolinstall"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

const asdfNode = "/home/u/.asdf/shims/node"

// asdfEnv is node1's gemini shim with node reachable only through an asdf
// shim, whose answer depends on the directory it runs in.
func asdfEnv() toolresolve.Env {
	files := map[string]fs.FileMode{n1Shim: exeBin, asdfNode: exeBin}
	env := fakeEnv("linux", false, "/home/u", nil, []string{"/home/u/.local/bin", "/home/u/.asdf/shims"}, files)
	env.ReadHead = func(path string, n int) ([]byte, error) {
		if path == n1Shim {
			return []byte("#!/usr/bin/env node\n"), nil
		}
		return nil, fs.ErrNotExist
	}
	return env
}

// recordProbe stubs the probe with one answer and records each directory it
// was run in.
func recordProbe(t *testing.T, out string) *[]string {
	t.Helper()
	var dirs []string
	orig := execRuntimeVersion
	execRuntimeVersion = func(_, dir string) (string, error) {
		dirs = append(dirs, dir)
		return out, nil
	}
	resetRuntimeProbeCache()
	t.Cleanup(func() {
		execRuntimeVersion = orig
		resetRuntimeProbeCache()
	})
	return &dirs
}

func TestRuntimeProbeRunsInTheLaunchDirectory(t *testing.T) {
	skipLinuxFakeOnWindows(t)
	spec := mustBinary(t, "gemini-cli") // registry floor: node >= 20
	env := asdfEnv()
	res := toolresolve.Resolve(*spec, env)

	t.Run("daemon preflight: a shim is not judged from the wrong directory", func(t *testing.T) {
		dirs := recordProbe(t, "v18.19.1")
		c, ok := launchRuntimeCheck(spec, res, env, "linux", "")
		if !ok {
			t.Fatalf("check did not apply (verdict %s, interpreter %q)", res.Verdict, res.Interpreter)
		}
		if c.Status != toolinstall.RuntimeUnknown || !c.DirDependent || c.Blocking() {
			t.Fatalf("status %s dirDependent=%v blocking=%v; want unknown, dir-dependent, not blocking", c.Status, c.DirDependent, c.Blocking())
		}
		if len(*dirs) != 0 {
			t.Fatalf("probed the shim from the daemon's directory: %v", *dirs)
		}
		if p := runtimeStatusPhrase(c, "the launch"); !strings.Contains(p, "version-manager shim") {
			t.Fatalf("doctor phrase = %q", p)
		}
	})
	t.Run("launcher: the shim is probed where the tool starts", func(t *testing.T) {
		dirs := recordProbe(t, "v18.19.1")
		c, _ := launchRuntimeCheck(spec, res, env, "linux", "/work/proj")
		if c.Status != toolinstall.RuntimeTooOld || !c.Blocking() {
			t.Fatalf("status %s, want too_old", c.Status)
		}
		if len(*dirs) != 1 || (*dirs)[0] != "/work/proj" {
			t.Fatalf("probe dirs = %v, want [/work/proj]", *dirs)
		}
	})
	t.Run("install check from the daemon: same rule", func(t *testing.T) {
		dirs := recordProbe(t, "v18.19.1")
		c, ok := installRuntimeCheck(spec, "npm", env, "linux", "")
		if !ok {
			t.Skip("npm channel not on this row")
		}
		if c.Status != toolinstall.RuntimeUnknown || c.Blocking() || len(*dirs) != 0 {
			t.Fatalf("status %s probes %v; want unknown with no probe", c.Status, *dirs)
		}
	})
}

// TestLaunchRuntimeChecksTheWholeInstalledRange: a version above the floor
// that the installed package's range leaves out is reported, never blocked.
func TestLaunchRuntimeChecksTheWholeInstalledRange(t *testing.T) {
	skipLinuxFakeOnWindows(t)
	spec := mustBinary(t, "gemini-cli")
	cases := []struct {
		node      string
		wantState toolinstall.RuntimeStatus
	}{
		{"v22.23.3", toolinstall.RuntimeTooOld},
		{"v24.16.0", toolinstall.RuntimeOK},
		{"v25.2.0", toolinstall.RuntimeOutsideRange},
		{"v26.0.9", toolinstall.RuntimeOutsideRange},
		{"v26.1.0", toolinstall.RuntimeOK},
	}
	for _, tc := range cases {
		t.Run(tc.node, func(t *testing.T) {
			env := node1PkgEnv([]byte(`{"engines":{"node":">=24.16.0<25||>=26.1.0"}}`))
			swapRuntimeProbe(t, probeReturns(tc.node, nil))
			res := toolresolve.Resolve(*spec, env)
			c, ok := launchRuntimeCheck(spec, res, env, "linux", "/work/proj")
			if !ok || c.Status != tc.wantState {
				t.Fatalf("status %s (applies=%v), want %s", c.Status, ok, tc.wantState)
			}
			if tc.wantState == toolinstall.RuntimeOutsideRange {
				if c.Blocking() || c.Range == "" || !strings.Contains(c.Summary, "leaves out") {
					t.Fatalf("outside_range check = %+v", c)
				}
				if p := runtimeStatusPhrase(c, "the launch"); !strings.Contains(p, "not blocked") {
					t.Fatalf("doctor phrase = %q", p)
				}
			}
		})
	}
}
