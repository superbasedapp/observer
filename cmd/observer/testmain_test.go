package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// testMainHelperDispatch runs a helper verb named by argv[1] instead of the
// suite; nil in a build without the sandbox module. TestMain lived in the
// sandbox-tagged file before RB1, so a build without that module (the
// minimal edition) ran this package with no home pin and wrote into the
// real home (found by the RB1 gate run as a non-root user).
var testMainHelperDispatch func(args []string) (int, bool)

// TestMain first lets the test binary stand in for the observer binary as a
// sandbox network helper where that module is compiled in
// (testMainHelperDispatch, sandbox_helpers_main_test.go).
//
// It stubs the launcher's daemon lane probe (daemonLanes) so no test
// can query a real daemon's proxy.
//
// It also exports crossmount.EnvDisableForeignHomes for the whole run. This
// binary is already covered by crossmount's test-binary guard; the env var is
// for the REAL observer binaries some tests build and exec (probe-hook, hook
// subprocess tests), which inherit it and so can never resolve the operator's
// real /mnt/c/Users/<u>/.claude either (incident 2026-10-02).
func TestMain(m *testing.M) {
	if testMainHelperDispatch != nil {
		if code, ok := testMainHelperDispatch(os.Args); ok {
			os.Exit(code)
		}
	}
	if err := os.Setenv(crossmount.EnvDisableForeignHomes, "1"); err != nil {
		os.Exit(2)
	}
	// Pin every per-user home (HOME, USERPROFILE, APPDATA, LOCALAPPDATA, the
	// XDG dirs and every tool home variable) to one process temp home, so a
	// test that sets only HOME can never reach the real profile on Windows
	// (surface-gap FU-4, FU-20; testhomes_helpers_test.go). Tests that drive
	// a writer pin their own home on top with pinToolHomes.
	cleanupHomes, err := pinProcessToolHomes()
	if err != nil {
		os.Exit(2)
	}
	// No test may inherit the CI markers of the machine running it: the
	// tool gate's per-call ask host probe (internal/hook askhost.go, D-791
	// Q27) withdraws a native ask for a CI run, so on a CI runner every
	// claude-code ask these tests assert became a deny (ci run 41216039594).
	// internal/hook's own TestMain pins that probe; this package drives the
	// real hook receivers, so it clears the markers instead. The CI branch
	// itself is tested in internal/hook (askhost_test.go); the probe is
	// memoized per process, so a test here could not set it per test anyway.
	if err := clearCIEnvironment(); err != nil {
		os.Exit(2)
	}
	// No test may reach a REAL running daemon's proxy through the launcher
	// lane preflight (T-308): a developer machine's daemon would answer for
	// it. Tests that exercise the daemon answer stub daemonLanes themselves.
	daemonLanes = func(string) (map[string]bool, bool) { return nil, false }
	// No launcher read of a system-wide settings file (the route gate's
	// saved sign-in, the launch shadow check) may reach the real machine
	// root: it resolves under a directory that does not exist.
	launchFiles.systemRoot = filepath.Join(os.TempDir(), "sbo-test-no-system-root")
	// No hook invocation under test may append a liveness record to a REAL
	// ~/.observer spool a running daemon would drain: emissions land only
	// in a spool under the temp dir.
	hookActivityDepsFor = tempOnlyHookActivityDeps
	// Fail the run when any config write was refused for landing outside
	// t.TempDir() or under a real foreign-OS mount (incident 2026-10-20).
	code := testwriteguard.Run(m)
	removeProbeHookBinary()
	cleanupHomes()
	os.Exit(code)
}

// clearCIEnvironment unsets, for the whole process, every variable
// integration.CIEnvironment names (the one list the ask host probe reads),
// so the suite sees what a developer's terminal run sees. Children the
// tests exec inherit the cleared environment.
func clearCIEnvironment() error {
	for _, k := range integration.CIEnvironment {
		if err := os.Unsetenv(k); err != nil {
			return err
		}
	}
	return nil
}

// TestSuiteRunsWithoutCIMarkers pins TestMain's clearCIEnvironment: no CI
// marker the ask host probe reads reaches this package's tests, so a CI
// runner answers the hook gate tests exactly as a terminal run does.
func TestSuiteRunsWithoutCIMarkers(t *testing.T) {
	for _, k := range integration.CIEnvironment {
		if v, ok := os.LookupEnv(k); ok {
			t.Errorf("%s=%q is set in the test process; TestMain must clear it", k, v)
		}
	}
}

// tempOnlyHookActivityDeps is productionHookActivityDeps with the spool
// path cleared unless it resolves under os.TempDir().
func tempOnlyHookActivityDeps(getenv func(string) string) hookActivityDeps {
	d := productionHookActivityDeps(getenv)
	resolve := d.spoolPath
	d.spoolPath = func(configPath string) string {
		p := resolve(configPath)
		tmp, err := filepath.Abs(os.TempDir())
		if err != nil || p == "" {
			return ""
		}
		if rel, err := filepath.Rel(tmp, p); err != nil || strings.HasPrefix(rel, "..") {
			return ""
		}
		return p
	}
	return d
}
