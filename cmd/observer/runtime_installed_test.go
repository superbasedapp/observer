// runtime_installed_test.go — the launch check prefers the INSTALLED npm
// package's own engines.node over the registry floor (exact for the version on
// disk), and falls back to the registry floor when the package.json is absent,
// unparseable, or declares no floor.

package main

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/toolinstall"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

const (
	n1ShimTarget = "/home/u/.local/lib/node_modules/@google/gemini-cli/bundle/gemini.js"
	n1PkgJSON    = "/home/u/.local/lib/node_modules/@google/gemini-cli/package.json"
)

// node1PkgEnv is node1Env with the shim symlinked into its npm package, whose
// package.json reads pkgJSON (nil = no package.json on disk).
func node1PkgEnv(pkgJSON []byte) toolresolve.Env {
	env := node1Env(true, "#!/usr/bin/env node\n")
	env.EvalSymlinks = func(p string) (string, error) {
		switch p {
		case n1Shim:
			return n1ShimTarget, nil
		case n1Node:
			return n1Node, nil
		}
		return "", fs.ErrNotExist
	}
	env.ReadHead = func(path string, n int) ([]byte, error) {
		switch path {
		case n1Shim, n1ShimTarget:
			return []byte("#!/usr/bin/env node\n"), nil
		case n1PkgJSON:
			if pkgJSON == nil {
				return nil, fs.ErrNotExist
			}
			return pkgJSON, nil
		}
		return nil, fs.ErrNotExist
	}
	return env
}

func TestLaunchRuntimePrefersInstalledEngines(t *testing.T) {
	skipLinuxFakeOnWindows(t)
	spec := mustBinary(t, "gemini-cli") // registry floor: node >= 20
	cases := []struct {
		name      string
		pkg       []byte
		node      string
		wantMin   string
		wantFrom  string
		wantState toolinstall.RuntimeStatus
	}{
		{
			"present and stricter than the registry: node 20 too old for >=22",
			[]byte(`{"name":"@google/gemini-cli","engines":{"node":">=22"}}`), "v20.11.0", "22", toolinstall.FloorFromInstalled, toolinstall.RuntimeTooOld,
		},
		{
			"present and looser than the registry: node 18 passes >=18",
			[]byte(`{"engines":{"node":">=18"}}`), "v18.19.1", "18", toolinstall.FloorFromInstalled, toolinstall.RuntimeOK,
		},
		{
			"range with a floor: >=24.16.0<25||>=26.1.0",
			[]byte(`{"engines":{"node":">=24.16.0<25||>=26.1.0"}}`), "v22.23.3", "24.16", toolinstall.FloorFromInstalled, toolinstall.RuntimeTooOld,
		},
		{
			"absent package.json: registry floor 20",
			nil, "v18.19.1", "20", toolinstall.FloorFromRegistry, toolinstall.RuntimeTooOld,
		},
		{
			"absent engines field: registry floor 20",
			[]byte(`{"name":"@google/gemini-cli"}`), "v22.23.3", "20", toolinstall.FloorFromRegistry, toolinstall.RuntimeOK,
		},
		{
			"unparseable package.json: registry floor 20",
			[]byte(`{"engines": {"node": ">=22"`), "v18.19.1", "20", toolinstall.FloorFromRegistry, toolinstall.RuntimeTooOld,
		},
		{
			"no floor (*): registry floor 20",
			[]byte(`{"engines":{"node":"*"}}`), "v18.19.1", "20", toolinstall.FloorFromRegistry, toolinstall.RuntimeTooOld,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := node1PkgEnv(tc.pkg)
			swapRuntimeProbe(t, probeReturns(tc.node, nil))
			res := toolresolve.Resolve(*spec, env)
			c, ok := launchRuntimeCheck(spec, res, env, "linux", "")
			if !ok {
				t.Fatalf("check did not apply (verdict %s, interpreter %q)", res.Verdict, res.Interpreter)
			}
			if c.Min != tc.wantMin || c.FloorFrom != tc.wantFrom || c.Status != tc.wantState {
				t.Fatalf("min %q from %q status %s; want %q from %q status %s", c.Min, c.FloorFrom, c.Status, tc.wantMin, tc.wantFrom, tc.wantState)
			}
		})
	}
}

// TestDoctorNamesInstalledFloor: doctor says where the floor came from.
func TestDoctorNamesInstalledFloor(t *testing.T) {
	skipLinuxFakeOnWindows(t)
	swapRuntimeProbe(t, probeReturns("v20.11.0", nil))
	swapDashEnv(t, node1PkgEnv([]byte(`{"engines":{"node":">=22"}}`)))
	msg, _, blocking, ok := runtimeDoctorLine("gemini-cli")
	if !ok || !blocking || !strings.HasPrefix(msg, "needs Node.js 22 or newer (from the installed package)") {
		t.Fatalf("doctor line = %q blocking=%v", msg, blocking)
	}
}
