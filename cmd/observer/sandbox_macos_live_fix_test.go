//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals && !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox_apple_container && !sbo_omit_terminals_sandbox_mxc

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// sandbox_macos_live_fix_test.go holds the tests for the defects the macOS
// live run of 2026-10-22 found (D1 the relay, D2 the overall verdict, D3 the
// auto name). Everything runs on any host: the operating system is a seam.

// requireSandboxDrivers skips unless every named backend's driver is in this
// build.
func requireSandboxDrivers(t *testing.T, backends ...string) {
	t.Helper()
	for _, b := range backends {
		if _, ok := sandboxDriverRegs[b]; !ok {
			t.Skipf("the %s driver is not in this build", b)
		}
	}
}

// relayFixConfig is a sandbox-on config selecting components (none: no
// [components] block, as on every existing install).
func relayFixConfig(dbDir string, components ...string) config.Config {
	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(dbDir, "observer.db")
	cfg.Terminal.Sandbox.Enabled = true
	if len(components) > 0 {
		// A [components] block as the live Mac had it: a distro (every
		// driver is inactive in each) plus the driver opted in.
		cfg.Components.Distro = "developer"
		cfg.Components.Add = components
	}
	return cfg
}

// TestSandboxRelayOnOSFollowsTheSelectedDrivers (D1): the daemon serves the
// relay on macOS while a macOS driver is selected, on Windows while the MXC
// driver is, always on Linux, and never for a driver of another OS.
func TestSandboxRelayOnOSFollowsTheSelectedDrivers(t *testing.T) {
	requireSandboxDrivers(t, sandboxbackend.BackendSeatbelt, sandboxbackend.BackendAppleContainer, sandboxbackend.BackendMXCProcess)
	for _, tc := range []struct {
		name       string
		goos       string
		components []string
		want       bool
	}{
		{"linux always", "linux", nil, true},
		{"darwin with seatbelt selected", "darwin", []string{seatbeltComponent}, true},
		{"darwin with apple container selected", "darwin", []string{appleComponent}, true},
		{"darwin with both selected", "darwin", []string{seatbeltComponent, appleComponent}, true},
		{"darwin with no macOS driver", "darwin", nil, false},
		{"darwin with only the windows driver", "darwin", []string{mxcComponent}, false},
		{"windows with mxc selected", "windows", []string{mxcComponent}, true},
		{"windows without mxc", "windows", nil, false},
		{"windows with only a macOS driver", "windows", []string{seatbeltComponent}, false},
		{"another os", "freebsd", []string{seatbeltComponent, mxcComponent}, false},
	} {
		if got := sandboxRelayOnOS(tc.goos, relayFixConfig(t.TempDir(), tc.components...)); got != tc.want {
			t.Errorf("%s: relay served %v, want %v", tc.name, got, tc.want)
		}
	}
	// The drivers' registrations carry the platform (no side table).
	for backend, want := range map[string]string{
		sandboxbackend.BackendSeatbelt: "darwin", sandboxbackend.BackendAppleContainer: "darwin", sandboxbackend.BackendMXCProcess: "windows",
	} {
		if got := sandboxDriverRegs[backend].relayOS; got != want {
			t.Errorf("%s registers relayOS %q, want %q", backend, got, want)
		}
	}
}

// TestSandboxCLIRelayGateOnAMacDaemon (D1): with a macOS driver selected the
// daemon on a Mac serves the relay, so the CLI's "daemon is not running"
// refusal is not reached; without one it serves nothing and the refusal
// stands.
func TestSandboxCLIRelayGateOnAMacDaemon(t *testing.T) {
	if runtime.GOOS == "windows" || !localipc.Supported() {
		t.Skip("needs unix sockets")
	}
	requireSandboxDrivers(t, sandboxbackend.BackendSeatbelt)
	resetSandboxManaged(t)
	prevCfg, prevOS := sandboxRelayConfig, sandboxRelayGOOS
	sandboxRelayConfig = func(boot config.Config) config.Config { return boot }
	sandboxRelayGOOS = func() string { return "darwin" }
	t.Cleanup(func() { sandboxRelayConfig, sandboxRelayGOOS = prevCfg, prevOS })
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		components []string
		served     bool
	}{
		{"no macOS driver selected", nil, false},
		{"seatbelt selected", []string{seatbeltComponent}, true},
	} {
		obs, err := os.MkdirTemp("/tmp", "sbmac")
		if err != nil {
			t.Fatal(err)
		}
		cfg := relayFixConfig(obs, tc.components...)
		ctx, cancel := context.WithCancel(context.Background())
		startSandboxRelay(ctx, cfg, exe, slog.New(slog.DiscardHandler), sandboxRelayDeps{})
		gate := sandboxCLIRelayGate(sandboxObserverDirFor(cfg))
		cancel()
		_ = os.RemoveAll(obs)
		switch {
		case tc.served && gate != nil:
			t.Errorf("%s: the daemon serves the relay, yet the CLI refused: %v", tc.name, gate)
		case !tc.served && !errors.Is(gate, errSandboxCLINoDaemon):
			t.Errorf("%s: no relay is served, yet the CLI gate gave %v", tc.name, gate)
		}
	}
}

// overallRows renders backend rows for the overall verdict's tests.
func overallRows(rows ...dashapi.SandboxBackendAvail) []dashapi.SandboxBackendAvail { return rows }

// TestSandboxPlatformOverall (D2): the overall verdict follows the drivers
// the platform registers; Linux is unchanged.
func TestSandboxPlatformOverall(t *testing.T) {
	legacyOff := sandbox.Availability{Verdict: sandbox.VerdictUnsupportedPlatform, Backend: sandboxbackend.BackendBwrap, Reason: `bubblewrap sandboxing requires a Linux daemon (incl. WSL2); this daemon runs "darwin"`}
	bwrapOff := dashapi.SandboxBackendAvail{ID: sandboxbackend.BackendBwrap, Verdict: "unsupported_platform", Reason: "this backend does not run on macos"}
	inactive := func(id, comp string) dashapi.SandboxBackendAvail {
		return dashapi.SandboxBackendAvail{ID: id, Verdict: verdictModuleInactive, Reason: "select " + comp}
	}
	for _, tc := range []struct {
		name      string
		host      sandboxbackend.HostKind
		av        sandbox.Availability
		rows      []dashapi.SandboxBackendAvail
		available bool
		verdict   string
		backend   string
		reasonHas []string
	}{
		{
			name: "linux bwrap missing is unchanged", host: sandboxbackend.HostLinux,
			av:      sandbox.Availability{Verdict: sandbox.VerdictBackendMissing, Backend: sandboxbackend.BackendBwrap, Reason: "bwrap was not found on PATH; install bubblewrap"},
			rows:    overallRows(dashapi.SandboxBackendAvail{ID: sandboxbackend.BackendBwrap, Verdict: "backend_missing"}),
			verdict: sandbox.VerdictBackendMissing, backend: sandboxbackend.BackendBwrap, reasonHas: []string{"install bubblewrap"},
		},
		{
			name: "linux available is unchanged", host: sandboxbackend.HostLinux,
			av:        sandbox.Availability{Available: true, Verdict: sandbox.VerdictAvailable, Backend: sandboxbackend.BackendBwrap},
			rows:      overallRows(dashapi.SandboxBackendAvail{ID: sandboxbackend.BackendBwrap, Available: true}),
			available: true, verdict: sandbox.VerdictAvailable, backend: sandboxbackend.BackendBwrap,
		},
		{
			name: "wsl2 userns denied is unchanged", host: sandboxbackend.HostWSL2,
			av:      sandbox.Availability{Verdict: sandbox.VerdictUserNSDenied, Backend: sandboxbackend.BackendBwrap, Reason: "userns"},
			verdict: sandbox.VerdictUserNSDenied, backend: sandboxbackend.BackendBwrap, reasonHas: []string{"userns"},
		},
		{
			name: "darwin, seatbelt selected and chosen", host: sandboxbackend.HostMacOS,
			av:        sandbox.Availability{Available: true, Verdict: sandbox.VerdictAvailable, Backend: sandboxbackend.BackendSeatbelt},
			rows:      overallRows(inactive(sandboxbackend.BackendAppleContainer, appleComponent), bwrapOff, dashapi.SandboxBackendAvail{ID: sandboxbackend.BackendSeatbelt, Available: true, Beta: true}),
			available: true, verdict: sandbox.VerdictAvailable, backend: sandboxbackend.BackendSeatbelt,
		},
		{
			name: "darwin, seatbelt selected but beta, kept", host: sandboxbackend.HostMacOS,
			av:      sandbox.Availability{Verdict: "beta_not_chosen", Backend: sandboxbackend.BackendSeatbelt, Reason: "terminal_sandbox: seatbelt is available but not chosen"},
			rows:    overallRows(bwrapOff, dashapi.SandboxBackendAvail{ID: sandboxbackend.BackendSeatbelt, Available: true, Beta: true}),
			verdict: "beta_not_chosen", backend: sandboxbackend.BackendSeatbelt, reasonHas: []string{"seatbelt is available"},
		},
		{
			name: "darwin, seatbelt selected but not listed", host: sandboxbackend.HostMacOS, av: legacyOff,
			rows: overallRows(inactive(sandboxbackend.BackendAppleContainer, appleComponent), bwrapOff,
				dashapi.SandboxBackendAvail{ID: sandboxbackend.BackendSeatbelt, Verdict: "disabled_by_config", Reason: "seatbelt is not in [terminal.sandbox].backends"}),
			verdict: "disabled_by_config", backend: sandboxbackend.BackendSeatbelt,
			reasonHas: []string{"no sandbox backend is available on macos", "seatbelt (disabled_by_config)", "apple-container (module_inactive)"},
		},
		{
			name: "darwin, no macOS driver selected", host: sandboxbackend.HostMacOS, av: legacyOff,
			rows:    overallRows(inactive(sandboxbackend.BackendAppleContainer, appleComponent), bwrapOff, inactive(sandboxbackend.BackendSeatbelt, seatbeltComponent)),
			verdict: verdictModuleInactive, backend: sandboxbackend.BackendAppleContainer,
			reasonHas: []string{"apple-container (module_inactive): select " + appleComponent, "seatbelt (module_inactive): select " + seatbeltComponent},
		},
		{
			name: "windows, mxc selected and chosen", host: sandboxbackend.HostWindows,
			av:        sandbox.Availability{Available: true, Verdict: sandbox.VerdictAvailable, Backend: sandboxbackend.BackendMXCProcess},
			rows:      overallRows(bwrapOff, dashapi.SandboxBackendAvail{ID: sandboxbackend.BackendMXCProcess, Available: true}),
			available: true, verdict: sandbox.VerdictAvailable, backend: sandboxbackend.BackendMXCProcess,
		},
		{
			name: "windows without mxc", host: sandboxbackend.HostWindows,
			av:      sandbox.Availability{Verdict: sandbox.VerdictUnsupportedPlatform, Backend: sandboxbackend.BackendBwrap, Reason: "bubblewrap sandboxing requires a Linux daemon"},
			rows:    overallRows(bwrapOff, inactive(sandboxbackend.BackendMXCProcess, mxcComponent)),
			verdict: verdictModuleInactive, backend: sandboxbackend.BackendMXCProcess,
			reasonHas: []string{"no sandbox backend is available on windows", "mxc-process (module_inactive): select " + mxcComponent},
		},
		{
			name: "a host no row runs on", host: sandboxbackend.HostKind("plan9"), av: legacyOff,
			rows:    overallRows(bwrapOff),
			verdict: sandbox.VerdictUnsupportedPlatform, backend: sandboxbackend.BackendBwrap, reasonHas: []string{"no sandbox backend runs on plan9"},
		},
	} {
		got := sandboxPlatformOverall(tc.av, tc.rows, tc.host)
		if got.Available != tc.available || got.Verdict != tc.verdict || got.Backend != tc.backend {
			t.Errorf("%s: got %+v", tc.name, got)
			continue
		}
		for _, want := range tc.reasonHas {
			if !strings.Contains(got.Reason, want) {
				t.Errorf("%s: reason %q lacks %q", tc.name, got.Reason, want)
			}
		}
		if tc.host != sandboxbackend.HostLinux && tc.host != sandboxbackend.HostWSL2 && strings.Contains(got.Reason, "Linux daemon") {
			t.Errorf("%s: off Linux the overall still says %q", tc.name, got.Reason)
		}
	}
}

// TestSandboxCLIAutoNamesThePlatformRows (D3): "auto" is named by the
// host's own rows, so a refusal on a Mac names seatbelt and apple-container,
// not bwrap; Linux keeps bwrap.
func TestSandboxCLIAutoNamesThePlatformRows(t *testing.T) {
	for host, want := range map[sandboxbackend.HostKind]string{
		sandboxbackend.HostLinux:         sandboxbackend.BackendBwrap,
		sandboxbackend.HostWSL2:          sandboxbackend.BackendBwrap,
		sandboxbackend.HostMacOS:         sandboxbackend.BackendAppleContainer + " or " + sandboxbackend.BackendSeatbelt,
		sandboxbackend.HostWindows:       sandboxbackend.BackendMXCProcess,
		sandboxbackend.HostKind("plan9"): "no sandbox backend for plan9",
	} {
		if got := sandboxCLIAutoName(host); got != want {
			t.Errorf("%s: auto is named %q, want %q", host, got, want)
		}
	}
	if got, err := sandboxCLIBackend("auto"); err != nil || got != sandboxCLIAutoName(sandboxHostKind()) {
		t.Fatalf("auto resolves to %q %v", got, err)
	}
}
