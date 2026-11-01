// runtime_preflight_test.go — the minimum-runtime seam (runtime_preflight.go)
// through every surface: a launcher's resolveToolBin, the dashboard preflight,
// the guided-install refusal and doctor. A map-backed resolver env and a
// stubbed `--version` probe stand in for the host; nothing real is spawned.
//
// The headline case is demo node 1, 2026-10-04: Gemini CLI 0.62.0 (engines
// node >= 20) installed by the dashboard into ~/.local/bin on a host whose only
// node is /usr/bin/node v18.19.1; `observer gemini` then crashed at startup.

package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

const (
	n1Shim = "/home/u/.local/bin/gemini"
	n1Node = "/usr/bin/node"
)

// swapRuntimeProbe stubs the `--version` probe and clears its cache.
func swapRuntimeProbe(t *testing.T, fn func(path string) (string, error)) {
	t.Helper()
	orig := execRuntimeVersion
	execRuntimeVersion = func(path, _ string) (string, error) { return fn(path) }
	resetRuntimeProbeCache()
	t.Cleanup(func() {
		execRuntimeVersion = orig
		resetRuntimeProbeCache()
	})
}

func resetRuntimeProbeCache() {
	runtimeProbeCache.Lock()
	runtimeProbeCache.m = map[string]runtimeProbeEntry{}
	runtimeProbeCache.Unlock()
}

// node1Env is the node-1 shape: the gemini shim (a `#!/usr/bin/env node`
// script) in ~/.local/bin, node only at /usr/bin/node. withShim=false drops the
// shim (gemini not installed yet); shebang overrides the shim's first line.
func node1Env(withShim bool, shebang string) toolresolve.Env {
	files := map[string]fs.FileMode{n1Node: exeBin, "/usr/bin/npm": exeBin}
	if withShim {
		files[n1Shim] = exeBin
	}
	env := fakeEnv("linux", false, "/home/u", nil, []string{"/home/u/.local/bin", "/usr/bin"}, files)
	env.ReadHead = func(path string, n int) ([]byte, error) {
		if path == n1Shim {
			return []byte(shebang), nil
		}
		return nil, fs.ErrNotExist
	}
	return env
}

func probeReturns(out string, err error) func(string) (string, error) {
	return func(string) (string, error) { return out, err }
}

// rtEmptyConfig keeps a seam off the host's real config.
func rtEmptyConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte("[observer]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestResolveToolBinRuntimeGate: every launcher refuses a node shim whose node
// is older than the registry floor, with the plain sentence, and launches
// otherwise. One case per row of the decision.
func TestResolveToolBinRuntimeGate(t *testing.T) {
	skipLinuxFakeOnWindows(t)
	cases := []struct {
		name    string
		shebang string
		probe   func(string) (string, error)
		wantErr []string // substrings of the visible refusal; nil = launches
	}{
		{"node 18 refuses (node 1)", "#!/usr/bin/env node\n", probeReturns("v18.19.1\n", nil), []string{
			"Gemini CLI needs Node.js 20 or newer.",
			"This machine has 18.19.1 (/usr/bin/node).\n",
			"\nInstall a newer Node.js first:\n  ",
		}},
		{"node 20 launches", "#!/usr/bin/env node\n", probeReturns("v20.0.0\n", nil), nil},
		{"node 24 launches", "#!/usr/bin/env node\n", probeReturns("v24.21.0\n", nil), nil},
		{"an unreadable version never blocks", "#!/usr/bin/env node\n", probeReturns("", errors.New("timeout")), nil},
		{"a native binary is not a node shim: not checked", "\x7fELF\x02\x01", probeReturns("v18.19.1", nil), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			swapResolveEnv(t, node1Env(true, tc.shebang))
			swapRuntimeProbe(t, tc.probe)
			bin, err := resolveToolBin("gemini-cli", "", "--gemini-path", rtEmptyConfig(t), io.Discard)
			if tc.wantErr == nil {
				if err != nil || bin != n1Shim {
					t.Fatalf("bin=%q err=%v, want the shim to launch", bin, err)
				}
				return
			}
			var visible launcherMessageError
			if err == nil || !errors.As(err, &visible) {
				t.Fatalf("err = %v, want a visible refusal", err)
			}
			for _, w := range tc.wantErr {
				if !strings.Contains(visible.launcherMessage(), w) {
					t.Errorf("refusal %q misses %q", visible.launcherMessage(), w)
				}
			}
		})
	}
}

// TestResolveToolBinRuntimeIgnoresUngroundedRows: a tool with no grounded
// requirement (opencode publishes no engines.node) is never checked.
func TestResolveToolBinRuntimeIgnoresUngroundedRows(t *testing.T) {
	skipLinuxFakeOnWindows(t)
	files := map[string]fs.FileMode{"/home/u/.local/bin/opencode": exeBin, n1Node: exeBin}
	env := fakeEnv("linux", false, "/home/u", nil, []string{"/home/u/.local/bin", "/usr/bin"}, files)
	env.ReadHead = func(string, int) ([]byte, error) { return []byte("#!/usr/bin/env node\n"), nil }
	swapResolveEnv(t, env)
	probed := false
	swapRuntimeProbe(t, func(string) (string, error) { probed = true; return "v12.0.0", nil })
	if _, err := resolveToolBin("opencode", "", "--opencode-path", rtEmptyConfig(t), io.Discard); err != nil {
		t.Fatalf("opencode refused: %v", err)
	}
	if probed {
		t.Error("probed a runtime for a row with no grounded requirement")
	}
}

// swapDashEnv installs env as the dashboard's resolver env.
func swapDashEnv(t *testing.T, env toolresolve.Env) {
	t.Helper()
	prevBuild := dashResolveEnvBuild
	prevHave, prevAt, prevVal := dashResolveEnvHave, dashResolveEnvAt, dashResolveEnvVal
	t.Cleanup(func() {
		dashResolveEnvBuild = prevBuild
		dashResolveEnvHave, dashResolveEnvAt, dashResolveEnvVal = prevHave, prevAt, prevVal
	})
	dashResolveEnvBuild = func() toolresolve.Env { return env }
	dashResolveEnvHave = false
}

// TestToolPreflightRuntime: the dashboard preflight carries the same verdict.
// Installed + node 18: launch_runtime too_old (the dialog disables Start).
// Not installed + node 18: install_runtime too_old, CanInstall false, and the
// install route's refusal is the same sentence.
func TestToolPreflightRuntime(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the fixture is the Linux node-1 shape")
	}
	swapRuntimeProbe(t, probeReturns("v18.19.1\n", nil))

	t.Run("installed: launch blocked", func(t *testing.T) {
		swapDashEnv(t, node1Env(true, "#!/usr/bin/env node\n"))
		pf, ok := toolPreflightSeam(rtEmptyConfig(t), func() bool { return true })("gemini-cli")
		if !ok {
			t.Fatal("gemini-cli not launchable")
		}
		lr := pf.LaunchRuntime
		if lr == nil || lr.Status != string(toolinstall.RuntimeTooOld) || lr.Have != "18.19.1" || lr.Min != "20" || lr.Path != n1Node {
			t.Fatalf("launch_runtime = %+v", lr)
		}
		if lr.Summary != "Gemini CLI needs Node.js 20 or newer. This machine has 18.19.1." || lr.FixCommand == "" || lr.FixNote == "" {
			t.Errorf("structured parts = summary %q command %q note %q", lr.Summary, lr.FixCommand, lr.FixNote)
		}
		if !strings.Contains(lr.Remedy, "\n  "+lr.FixCommand+"\n") {
			t.Errorf("remedy does not put the command on its own line: %q", lr.Remedy)
		}
	})

	t.Run("not installed: install refused before installing", func(t *testing.T) {
		swapDashEnv(t, node1Env(false, ""))
		pf, ok := toolPreflightSeam(rtEmptyConfig(t), func() bool { return true })("gemini-cli")
		if !ok {
			t.Fatal("gemini-cli not launchable")
		}
		if pf.LaunchRuntime != nil {
			t.Errorf("launch_runtime on a not-installed tool: %+v", pf.LaunchRuntime)
		}
		ir := pf.InstallRuntime
		if ir == nil || ir.Status != string(toolinstall.RuntimeTooOld) {
			t.Fatalf("install_runtime = %+v", ir)
		}
		if pf.CanInstall {
			t.Error("CanInstall = true with a too-old runtime")
		}
		if pf.InstallCommand == "" {
			t.Error("the install command must stay on display")
		}
		if got := toolInstallBlockedSeam()("gemini-cli"); got != ir.Remedy || got == "" {
			t.Errorf("install refusal %q, want the preflight remedy %q", got, ir.Remedy)
		}
	})

	t.Run("not installed, node 22: installable", func(t *testing.T) {
		swapDashEnv(t, node1Env(false, ""))
		swapRuntimeProbe(t, probeReturns("v22.3.0", nil))
		pf, _ := toolPreflightSeam(rtEmptyConfig(t), func() bool { return true })("gemini-cli")
		if pf.InstallRuntime == nil || pf.InstallRuntime.Status != string(toolinstall.RuntimeOK) || !pf.CanInstall {
			t.Fatalf("install_runtime = %+v can_install=%v", pf.InstallRuntime, pf.CanInstall)
		}
		if got := toolInstallBlockedSeam()("gemini-cli"); got != "" {
			t.Errorf("install refused: %q", got)
		}
	})
}

// TestInstallRuntimeOnlyForHostRuntimeChannels: a vendor script or brew brings
// its own runtime, so only an npm plan is checked.
func TestInstallRuntimeOnlyForHostRuntimeChannels(t *testing.T) {
	swapRuntimeProbe(t, probeReturns("v18.19.1", nil))
	env := node1Env(false, "")
	spec := mustBinary(t, "gemini-cli")
	for _, tc := range []struct {
		channel string
		applies bool
	}{{"npm", true}, {"script", false}, {"brew", false}, {"winget", false}} {
		_, ok := installRuntimeCheck(spec, tc.channel, env, "linux", "")
		if ok != tc.applies {
			t.Errorf("channel %s: applies = %v, want %v", tc.channel, ok, tc.applies)
		}
	}
}

// TestRuntimeDoctorLine: `observer doctor gemini-cli` reports the same check.
func TestRuntimeDoctorLine(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the fixture is the Linux node-1 shape")
	}
	swapRuntimeProbe(t, probeReturns("v18.19.1", nil))
	swapDashEnv(t, node1Env(true, "#!/usr/bin/env node\n"))
	msg, details, blocking, ok := runtimeDoctorLine("gemini-cli")
	if !ok || !blocking || !strings.Contains(msg, "needs Node.js 20 or newer") || !strings.Contains(msg, "18.19.1") || !strings.Contains(msg, "too old") {
		t.Fatalf("doctor line = %q blocking=%v ok=%v", msg, blocking, ok)
	}
	// The command sits on a detail line of its own.
	if len(details) != 3 || details[0] != "Install a newer Node.js first:" || !strings.HasPrefix(details[1], "  curl -fsSL https://deb.nodesource.com/setup_lts.x") {
		t.Fatalf("doctor details = %q", details)
	}
	swapRuntimeProbe(t, probeReturns("v24.21.0", nil))
	msg, details, blocking, _ = runtimeDoctorLine("gemini-cli")
	if blocking || details != nil || !strings.Contains(msg, "24.21.0") || !strings.Contains(msg, ": ok") {
		t.Fatalf("ok doctor line = %q details=%q blocking=%v", msg, details, blocking)
	}
	if _, _, _, ok := runtimeDoctorLine("opencode"); ok {
		t.Error("opencode has no grounded requirement; doctor must not invent one")
	}
}

// TestRuntimeDoctorLineNotApplicable (T-367): an installed binary that does
// not run on Node.js gets a plain line, never "does not run on the host's
// Node.js": a native binary needs no Node.js check, and a script for another
// interpreter names that interpreter. Neither blocks.
func TestRuntimeDoctorLineNotApplicable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the fixture is the Linux node-1 shape")
	}
	swapRuntimeProbe(t, probeReturns("v18.19.1", nil))
	for _, tc := range []struct {
		name, head string
		want       []string
	}{
		{"native binary", "\x7fELF\x02\x01", []string{"the installed gemini is a native binary, so it needs no Node.js check", "(Node.js 20 or newer applies to its npm install only)"}},
		{"another interpreter", "#!/usr/bin/env python3\n", []string{"the installed gemini runs on python3, not Node.js, so no Node.js check applies"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swapDashEnv(t, node1Env(true, tc.head))
			msg, details, blocking, ok := runtimeDoctorLine("gemini-cli")
			if !ok || blocking || details != nil {
				t.Fatalf("line = %q details=%q blocking=%v ok=%v, want a non-blocking line", msg, details, blocking, ok)
			}
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("line %q misses %q", msg, w)
				}
			}
			if strings.Contains(msg, "does not run on the host") {
				t.Errorf("line %q still uses the old wording", msg)
			}
		})
	}
}

// TestChildPATHMatchesToolresolveOrder pins the runtime check to the PATH the
// launcher really composes: toolresolve.ChildPathDirs must list the same dirs,
// in the same order, as childPATH.
func TestChildPATHMatchesToolresolveOrder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	process := []string{"/usr/bin", "/bin", "/usr/bin"}
	login := []string{"/opt/node/bin", "/usr/bin"}
	env := toolresolve.Env{GOOS: "linux", ProcessPath: process, LoginPath: func() ([]string, error) { return login, nil }}
	_, loginOnly := toolresolve.MergedPathDirs(env)
	got := strings.Join(toolresolve.ChildPathDirs(env, "/home/u/.local/bin"), string(os.PathListSeparator))
	want := childPATH(process, loginOnly, "/home/u/.local/bin")
	if got != want {
		t.Errorf("ChildPathDirs = %q, childPATH = %q", got, want)
	}
}

func mustBinary(t *testing.T, tool string) *integration.BinaryResolveSpec {
	t.Helper()
	c, ok := integration.For(tool)
	if !ok || c.Binary == nil {
		t.Fatalf("%s: no Binary row", tool)
	}
	return c.Binary
}
