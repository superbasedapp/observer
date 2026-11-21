//go:build !sbo_omit_terminals_sandbox_landlock && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxlandlock"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_landlock_test.go: the process_lite driver (lane
// SBX-P3B). Its live proof on a 7.1+ host is register entry LIN-1; these
// tests pin the opt-in rule, the explicit-only rule, the host-only tier and
// the plan file.

// landlockTestConfig is a config with the sandbox on and the host tier.
func landlockTestConfig(t *testing.T, selectDriver bool, backends ...string) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	cfg.Terminal.Sandbox.Enabled = true
	cfg.Terminal.Sandbox.Egress = "host"
	cfg.Terminal.Sandbox.Backends = backends
	if selectDriver {
		cfg.Components.Add = []string{landlockComponent}
	}
	return cfg
}

// fakeLandlockABI replaces the probe's I/O with a counted ABI answer.
func fakeLandlockABI(t *testing.T, abi int) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	prev := landlockProbeEnvFn
	landlockProbeEnvFn = func() sandboxlandlock.ProbeEnv {
		return sandboxlandlock.ProbeEnv{Host: sandboxlandlock.HostLinux, ABI: func() (int, error) { n.Add(1); return abi, nil }}
	}
	t.Cleanup(func() { landlockProbeEnvFn = prev })
	return &n
}

func landlockTestRuntime(t *testing.T, cfg config.Config) *sandboxRuntime {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, t.TempDir(), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.applyDaemonConfig(cfg)
	return rt
}

// TestLandlockDriverIsOptIn: no [components] block (every existing install)
// never gets the driver and nothing reads the ABI; a block that adds it,
// with process_lite listed, probes it.
func TestLandlockDriverIsOptIn(t *testing.T) {
	n := fakeLandlockABI(t, 9)
	legacy := landlockTestRuntime(t, landlockTestConfig(t, false, "process_lite"))
	if _, ok := legacy.drivers[sandboxbackend.BackendProcessLite]; ok || legacy.inactiveDrivers[sandboxbackend.BackendProcessLite] != landlockComponent {
		t.Fatalf("legacy drivers %v inactive %v", legacy.drivers, legacy.inactiveDrivers)
	}
	_ = legacy.ProbeSandbox(context.Background())
	if n.Load() != 0 {
		t.Fatal("the ABI was read on an install that never selected the driver")
	}
	notListed := landlockTestRuntime(t, landlockTestConfig(t, true, "bwrap"))
	if p := notListed.drivers[sandboxbackend.BackendProcessLite].probe(context.Background()); p.Verdict != "disabled_by_config" || n.Load() != 0 {
		t.Fatalf("not listed: %+v (reads %d)", p, n.Load())
	}
	rt := landlockTestRuntime(t, landlockTestConfig(t, true, "process_lite"))
	p := rt.drivers[sandboxbackend.BackendProcessLite].probe(context.Background())
	if p.Verdict != sandboxlandlock.VerdictAvailable || p.Version != "9" || n.Load() == 0 {
		t.Fatalf("selected and listed: %+v", p)
	}
}

// TestLandlockNeverPickedAutomatically (S1b, P-062): with process_lite the
// only listed and available row, a launch naming no backend refuses; a
// launch naming it takes it.
func TestLandlockNeverPickedAutomatically(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process_lite runs on Linux")
	}
	if sandboxHostKind() == sandboxbackend.HostWSL2 {
		t.Skip("process_lite does not run on WSL2 (its registry row refuses it there)")
	}
	fakeLandlockABI(t, 9)
	rt := landlockTestRuntime(t, landlockTestConfig(t, true, "process_lite"))
	if d, err := rt.chosenDriver(context.Background(), ""); d != nil || err == nil {
		t.Fatalf("an automatic launch took the explicit-only row: %v %v", d, err)
	}
	d, err := rt.chosenDriver(context.Background(), sandboxbackend.BackendProcessLite)
	if err != nil || d == nil {
		t.Fatalf("a launch naming process_lite: %v %v", d, err)
	}
	for _, b := range rt.ProbeSandbox(context.Background()).Backends {
		if b.ID == sandboxbackend.BackendProcessLite && (!b.Available || !b.Beta) {
			t.Fatalf("row %+v: available and labelled beta expected", b)
		}
	}
}

// TestLandlockOnlyTheHostTier: any other tier is refused by name, never run
// on another tier; an ABI below 9 is refused by name.
func TestLandlockOnlyTheHostTier(t *testing.T) {
	fakeLandlockABI(t, 9)
	cfg := landlockTestConfig(t, true, "process_lite")
	cfg.Terminal.Sandbox.Egress = "proxy_only"
	rt := landlockTestRuntime(t, cfg)
	d := rt.drivers[sandboxbackend.BackendProcessLite].(*landlockDriver)
	err := d.floor(launchFloorConfig(rt.cfg, string(rt.egress.Mode)))
	if err == nil || !strings.Contains(err.Error(), "only tier is host") {
		t.Fatalf("a proxy_only launch: %v", err)
	}
	fakeLandlockABI(t, 7)
	rt2 := landlockTestRuntime(t, landlockTestConfig(t, true, "process_lite"))
	if p := rt2.drivers[sandboxbackend.BackendProcessLite].probe(context.Background()); p.Verdict != sandboxlandlock.VerdictLandlockABITooOld {
		t.Fatalf("ABI 7: %+v", p)
	}
}

// TestLandlockComposeWritesThePlan: the PTY child runs the host services and
// then the exec step on a plan file that holds no secret, whose ruleset
// grants the workspace and never the observer directory, and denies the
// dashboard port.
func TestLandlockComposeWritesThePlan(t *testing.T) {
	skipDriverOffHost(t, "Landlock")
	noteTestDashboard(t, "127.0.0.1:8081")
	home := t.TempDir()
	setTestHome(t, home)
	if real, err := filepath.EvalSymlinks(home); err == nil {
		home = real
	}
	_ = os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	ws := filepath.Join(home, "proj")
	_ = os.MkdirAll(ws, 0o700)
	fakeLandlockABI(t, 9)
	cfg := landlockTestConfig(t, true, "process_lite")
	exe, _ := os.Executable()
	rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, filepath.Join(home, ".observer"), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.applyDaemonConfig(cfg)
	d := rt.drivers[sandboxbackend.BackendProcessLite].(*landlockDriver)
	runID := "runlandlock00000001"
	wrap, err := d.compose(termsvc.CreateResult{Run: termsvc.SandboxRun{ID: runID, Tool: "claude-code", Dir: ws}}, 9)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(wrap, " ")
	if !strings.Contains(joined, " sandbox-host ") || !strings.Contains(joined, landlockExecVerb+" --plan ") || wrap[len(wrap)-1] != "--" {
		t.Fatalf("argv %v", wrap)
	}
	planPath := wrap[len(wrap)-2]
	raw, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret", "token", "key\""} {
		if strings.Contains(strings.ToLower(string(raw)), secret) {
			t.Fatalf("the plan file carries %q: %s", secret, raw)
		}
	}
	var plan landlockPlanFile
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.MinABI != 9 || plan.Plan.Workspace != ws || plan.Plan.ObserverDir != rt.observerDir {
		t.Fatalf("plan %+v", plan)
	}
	rs, err := sandboxlandlock.BuildRuleset(plan.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Allowed(filepath.Join(ws, "a.go"))&sandboxlandlock.AccessFSWriteFile == 0 || rs.Allowed(filepath.Join(rt.observerDir, "observer.db")) != 0 {
		t.Fatal("the ruleset does not mirror the plan")
	}
	if sandboxlandlock.Allows(rs.Ports, 8081) || !sandboxlandlock.Allows(rs.Ports, 8820) {
		t.Fatalf("ports: the dashboard must be denied and the proxy reachable: %v", rs.Ports)
	}
}

// TestParseLandlockExecArgs: `--plan <file> -- <launch...>`.
func TestParseLandlockExecArgs(t *testing.T) {
	p, launch, err := parseLandlockExecArgs([]string{"--plan", "/x.json", "--", "/usr/bin/observer", "claude"})
	if err != nil || p != "/x.json" || launch[1] != "claude" {
		t.Fatalf("%q %v %v", p, launch, err)
	}
	for _, bad := range [][]string{nil, {"--plan", "/x"}, {"--plan", "/x", "--"}, {"-p", "/x", "--", "a"}} {
		if _, _, err := parseLandlockExecArgs(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

// TestLandlockPlanGrantsTheLauncherItsConfig (Linux live check 2026-10-23,
// LIN-1 F3): the plan gives the inner launcher the read-only config view the
// bwrap and container rows bind (config.toml and the observer-dir files a
// config load reads), and nothing else of the observer directory: the
// database, a secret and a symlinked entry stay unreachable.
func TestLandlockPlanGrantsTheLauncherItsConfig(t *testing.T) {
	skipOnWindows(t, "Landlock is a Linux driver")
	noteTestDashboard(t, "127.0.0.1:8081")
	home := t.TempDir()
	setTestHome(t, home)
	if real, err := filepath.EvalSymlinks(home); err == nil {
		home = real
	}
	_ = os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	ws := filepath.Join(home, "proj")
	_ = os.MkdirAll(ws, 0o700)
	obs := filepath.Join(home, ".observer")
	_ = os.MkdirAll(obs, 0o700)
	for _, f := range []string{"config.toml", "guard-org-lock.json", "observer.db", "remote-secret"} {
		if err := os.WriteFile(filepath.Join(obs, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A planted link in the config view's place must not carry the grant.
	if err := testSymlink(t, filepath.Join(obs, "observer.db"), filepath.Join(obs, "governance-effective.json")); err != nil {
		t.Fatal(err)
	}
	fakeLandlockABI(t, 9)
	cfg := landlockTestConfig(t, true, "process_lite")
	exe, _ := os.Executable()
	rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, obs, exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.applyDaemonConfig(cfg)
	d := rt.drivers[sandboxbackend.BackendProcessLite].(*landlockDriver)
	wrap, err := d.compose(termsvc.CreateResult{Run: termsvc.SandboxRun{ID: "runlandlock00000002", Tool: "claude-code", Dir: ws}}, 9)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(wrap[len(wrap)-2])
	if err != nil {
		t.Fatal(err)
	}
	var plan landlockPlanFile
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	view := map[string]bool{}
	for _, p := range plan.Plan.ConfigRO {
		view[p] = true
	}
	for _, want := range []string{"config.toml", "guard-org-lock.json"} {
		if !view[filepath.Join(obs, want)] {
			t.Errorf("the config view lacks %s: %v", want, plan.Plan.ConfigRO)
		}
	}
	for _, never := range []string{"observer.db", "remote-secret", "governance-effective.json"} {
		if view[filepath.Join(obs, never)] {
			t.Errorf("the config view holds %s", never)
		}
	}
	rs, err := sandboxlandlock.BuildRuleset(plan.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if a := rs.Allowed(filepath.Join(obs, "config.toml")); a&sandboxlandlock.AccessFSReadFile == 0 || a&sandboxlandlock.AccessFSWriteFile != 0 {
		t.Errorf("config.toml: allowed %#x, want read and never write", a)
	}
	for _, never := range []string{"observer.db", "remote-secret", "governance-effective.json"} {
		if a := rs.Allowed(filepath.Join(obs, never)); a != 0 {
			t.Errorf("%s is reachable: %#x", never, a)
		}
	}
}

// TestLandlockPlanVersionSeccomp: a plan with a seccomp profile is written
// as version 2, which an exec step from before the filter refuses; the
// version and the field must agree.
func TestLandlockPlanVersionSeccomp(t *testing.T) {
	t.Parallel()
	if landlockPlanVersionFor("") != landlockPlanVersion || landlockPlanVersionFor("observer_default") != landlockPlanVersionSeccomp {
		t.Fatal("landlockPlanVersionFor")
	}
	for _, c := range []struct {
		version int
		seccomp string
		ok      bool
	}{
		{1, "", true},
		{2, "observer_default", true},
		{1, "observer_default", false},
		{2, "", false},
		{3, "", false},
	} {
		err := checkLandlockPlanVersion(landlockPlanFile{Version: c.version, Seccomp: c.seccomp})
		if (err == nil) != c.ok {
			t.Errorf("version %d seccomp %q: %v", c.version, c.seccomp, err)
		}
	}
}

// TestSeccompProfileFor: the switch off plans nothing; on, only a Linux
// host with a supported architecture gets the profile, anything else is
// refused (never run unfiltered).
func TestSeccompProfileFor(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		goos, goarch string
		ok           bool
	}{
		{"linux", "amd64", true},
		{"linux", "arm64", true},
		{"linux", "riscv64", false},
		{"darwin", "arm64", false},
		{"windows", "amd64", false},
	} {
		p, err := seccompProfileFor(c.goos, c.goarch, "observer_default")
		if (err == nil) != c.ok || (c.ok && p != "observer_default") {
			t.Errorf("%s/%s: %q, %v", c.goos, c.goarch, p, err)
		}
	}
	if p, err := sandboxSeccompProfile(config.TerminalSandboxConfig{}, landlockRow(), ""); p != "" || err != nil {
		t.Fatalf("off: %q, %v", p, err)
	}
	oci, _ := sandboxbackend.Get(sandboxbackend.BackendOCIRunc)
	if p, err := sandboxSeccompProfile(config.TerminalSandboxConfig{Seccomp: true}, oci, ""); p != "" || err != nil {
		t.Fatalf("a row with the engine's own filter: %q, %v", p, err)
	}
	if runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") {
		if p, err := sandboxSeccompProfile(config.TerminalSandboxConfig{Seccomp: true}, landlockRow(), ""); p != "observer_default" || err != nil {
			t.Fatalf("on: %q, %v", p, err)
		}
		// The strace opt-in (lane ptrace): the recorded seize profile is
		// planned only while the opt-in is on; a non-seize record or the
		// opt-in off keeps observer_default.
		for _, c := range []struct {
			cfg      config.TerminalSandboxConfig
			recorded string
			want     string
		}{
			{config.TerminalSandboxConfig{Seccomp: true, SeccompAllowSeize: true}, "observer_seize_yama", "observer_seize_yama"},
			{config.TerminalSandboxConfig{Seccomp: true}, "observer_seize_yama", "observer_default"},
			{config.TerminalSandboxConfig{Seccomp: true, SeccompAllowSeize: true}, "observer_default", "observer_default"},
			{config.TerminalSandboxConfig{Seccomp: true, SeccompAllowSeize: true}, "off", "observer_default"},
			{config.TerminalSandboxConfig{SeccompAllowSeize: true}, "observer_seize_yama", ""},
		} {
			if p, err := sandboxSeccompProfile(c.cfg, landlockRow(), c.recorded); p != c.want || err != nil {
				t.Errorf("%+v recorded %q: %q, %v; want %q", c.cfg, c.recorded, p, err, c.want)
			}
		}
	}
}

// TestLandlockComposeSeccomp (lane N2): with [terminal.sandbox].seccomp on,
// the plan file is version 2 and names the profile, and the host helper is
// told to read the filter back; off, neither appears.
func TestLandlockComposeSeccomp(t *testing.T) {
	skipDriverOffHost(t, "Landlock")
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("the seccomp assembler targets amd64 and arm64")
	}
	// process_lite shares the host network, so its compose needs the
	// dashboard address to deny (the release line's LAUNCH-1 rule).
	noteTestDashboard(t, "127.0.0.1:8081")
	for _, on := range []bool{false, true} {
		home := t.TempDir()
		setTestHome(t, home)
		if real, err := filepath.EvalSymlinks(home); err == nil {
			home = real
		}
		_ = os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
		ws := filepath.Join(home, "proj")
		_ = os.MkdirAll(ws, 0o700)
		fakeLandlockABI(t, 9)
		cfg := landlockTestConfig(t, true, "process_lite")
		cfg.Terminal.Sandbox.Seccomp = on
		exe, _ := os.Executable()
		rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, filepath.Join(home, ".observer"), exe, nil)
		if err != nil {
			t.Fatal(err)
		}
		rt.applyDaemonConfig(cfg)
		d := rt.drivers[sandboxbackend.BackendProcessLite].(*landlockDriver)
		wrap, err := d.compose(termsvc.CreateResult{Run: termsvc.SandboxRun{ID: "runlandlockseccomp01", Tool: "claude-code", Dir: ws}}, 9)
		if err != nil {
			t.Fatal(err)
		}
		host, err := sandbox.ParseHostArgs(wrap[2:])
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(wrap[len(wrap)-2])
		if err != nil {
			t.Fatal(err)
		}
		var plan landlockPlanFile
		if err := json.Unmarshal(raw, &plan); err != nil {
			t.Fatal(err)
		}
		want, version := "", landlockPlanVersion
		if on {
			want, version = "observer_default", landlockPlanVersionSeccomp
		}
		if host.SeccompProfile != want || plan.Seccomp != want || plan.Version != version {
			t.Fatalf("seccomp %v: host flag %q, plan %q version %d", on, host.SeccompProfile, plan.Seccomp, plan.Version)
		}
	}
}

// noteTestDashboard makes this test process the daemon whose dashboard
// listens on addr (the deny list needs a known dashboard address).
func noteTestDashboard(t *testing.T, addr string) {
	t.Helper()
	prev := resolvedDashboardListen()
	noteDashboardListen(addr)
	t.Cleanup(func() { noteDashboardListen(prev) })
}
