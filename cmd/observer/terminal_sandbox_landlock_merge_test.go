//go:build !sbo_omit_terminals_sandbox_landlock && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxlandlock"
)

// terminal_sandbox_landlock_merge_test.go: the SBX-P3B merge fixes to the
// process_lite driver. F2: the exec step's self-test connects to the
// daemon's sockets (and an engine socket that exists) and refuses the
// launch unless the kernel denies each connect; the syscall is a seam, so
// these run on any kernel. F3: the TCP deny list is built from the listener
// config, never the model proxy's port.

// TestLandlockSelfTestRequiresEveryConnectDenied: EACCES and EPERM pass;
// a connection, ECONNREFUSED or ENOENT refuses the launch by name.
func TestLandlockSelfTestRequiresEveryConnectDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Landlock is a Linux driver; its socket paths are POSIX (Windows 11 Pro rerun 2026-10-25, D5 group 4)")
	}
	relay, attach := "/home/u/.observer/sandbox-relay/ipc", "/home/u/.observer/attach.sock"
	docker := "/run/user/1000/docker.sock"
	present := map[string]bool{relay: true, attach: true, docker: true}
	targets, err := landlockConnectTargets([]string{relay, attach}, landlockEngineSockets("/run/user/1000"), func(p string) bool { return present[p] })
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, tg := range targets {
		paths = append(paths, tg.path)
	}
	if !slices.Equal(paths, []string{relay, attach, docker}) {
		t.Fatalf("targets %v", paths)
	}
	cases := []struct {
		name    string
		answer  map[string]error
		refused string
	}{
		{"every connect denied with EACCES", map[string]error{relay: syscall.EACCES, attach: syscall.EACCES, docker: syscall.EACCES}, ""},
		{"EPERM counts as denied", map[string]error{relay: syscall.EPERM, attach: syscall.EACCES, docker: syscall.EPERM}, ""},
		{"the attach socket connected", map[string]error{relay: syscall.EACCES, attach: nil, docker: syscall.EACCES}, attach},
		{"the relay endpoint refused the connection, not the ruleset", map[string]error{relay: syscall.ECONNREFUSED, attach: syscall.EACCES, docker: syscall.EACCES}, relay},
		{"docker.sock reachable", map[string]error{relay: syscall.EACCES, attach: syscall.EACCES, docker: nil}, docker},
		{"a socket gone between the check and the connect", map[string]error{relay: syscall.ENOENT, attach: syscall.EACCES, docker: syscall.EACCES}, relay},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var tried []string
			err := landlockCheckConnects(targets, func(p string) error {
				tried = append(tried, p)
				return c.answer[p]
			})
			if c.refused == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if !slices.Equal(tried, paths) {
					t.Fatalf("connected to %v, want every target", tried)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.refused) {
				t.Fatalf("err %v, want a refusal naming %s", err, c.refused)
			}
		})
	}
}

// TestLandlockSelfTestNeedsADaemonSocket: a missing daemon socket is
// skipped, an engine socket that does not exist is not tried, and with no
// daemon socket at all the launch is refused (the right is unproven).
func TestLandlockSelfTestNeedsADaemonSocket(t *testing.T) {
	relay, attach := "/o/sandbox-relay/ipc", "/o/attach.sock"
	only := func(ps ...string) func(string) bool {
		return func(p string) bool { return slices.Contains(ps, p) }
	}
	targets, err := landlockConnectTargets([]string{relay, attach}, landlockEngineSockets(""), only(relay))
	if err != nil || len(targets) != 1 || targets[0].path != relay {
		t.Fatalf("attach socket absent: %v %v", targets, err)
	}
	if _, err := landlockConnectTargets([]string{relay, attach}, landlockEngineSockets(""), only("/run/docker.sock")); err == nil {
		t.Fatal("no daemon socket, yet the self-test had something to prove")
	}
	if got := landlockEngineSockets(""); !slices.Equal(got, []string{"/run/docker.sock", "/run/podman/podman.sock"}) {
		t.Fatalf("engine sockets without XDG_RUNTIME_DIR %v", got)
	}
}

// TestLandlockDenyListFromListenerConfig (audit SBX-P3B F3): every
// Observer listener the config switches on is denied, the dashboard at the
// address this process resolved (an --addr override included), never the
// model proxy's port.
func TestLandlockDenyListFromListenerConfig(t *testing.T) {
	t.Setenv("OBSERVER_DASHBOARD_ADDR", "")
	base := func() config.Config {
		c := config.Default()
		c.Dashboard.Addr = ""
		c.Ingest.OTel.Enabled = false
		c.Browser.Listener.Enabled = false
		c.MCPRelay.Enabled = false
		c.Observer.Process.ETW.Enabled = false
		c.Remote.Enabled = false
		return c
	}
	proxy := base().Proxy.Port
	cases := []struct {
		name string
		mut  func(*config.Config)
		dash string
		want []int
	}{
		{"nothing else on: the default dashboard", nil, "", []int{8081}},
		{"an --addr override", nil, "127.0.0.1:9090", []int{9090}},
		{"the configured dashboard address", func(c *config.Config) { c.Dashboard.Addr = "127.0.0.1:7070" }, "", []int{7070}},
		{"the OTLP receiver", func(c *config.Config) {
			c.Ingest.OTel.Enabled, c.Ingest.OTel.GRPCAddr, c.Ingest.OTel.HTTPAddr = true, "127.0.0.1:4317", "127.0.0.1:4318"
		}, "", []int{4317, 4318, 8081}},
		{"the OTLP receiver configured but off", func(c *config.Config) { c.Ingest.OTel.GRPCAddr = "127.0.0.1:4317" }, "", []int{8081}},
		{"browser ingest", func(c *config.Config) {
			c.Browser.Enabled, c.Browser.Listener.Enabled, c.Browser.Listener.ListenAddr = true, true, "127.0.0.1:8821"
		}, "", []int{8081, 8821}},
		{"the MCP relay listener", func(c *config.Config) { c.MCPRelay.Enabled, c.MCPRelay.Listen = true, "127.0.0.1:8830" }, "", []int{8081, 8830}},
		{"the process feed listener", func(c *config.Config) {
			c.Observer.Process.ETW.Enabled, c.Observer.Process.ETW.ListenAddr = true, "127.0.0.1:8823"
		}, "", []int{8081, 8823}},
		{"remote access binds", func(c *config.Config) {
			c.Remote.Enabled, c.Remote.BindAddr, c.Remote.TailscaleBackendAddr = true, "192.168.1.5:8443", "127.0.0.1:8444"
		}, "", []int{8081, 8443, 8444}},
		{"the model proxy's port is never denied", func(c *config.Config) {
			c.MCPRelay.Enabled, c.MCPRelay.Listen = true, fmt.Sprintf("127.0.0.1:%d", proxy)
		}, "", []int{8081}},
		{"a dashboard on the proxy port is not denied either", nil, fmt.Sprintf("127.0.0.1:%d", proxy), nil},
		{"a duplicate port once", func(c *config.Config) { c.MCPRelay.Enabled, c.MCPRelay.Listen = true, "127.0.0.1:8081" }, "", []int{8081}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base()
			if c.mut != nil {
				c.mut(&cfg)
			}
			got := landlockDeniedPorts(landlockListeners(cfg, c.dash), cfg.Proxy.Port)
			if !slices.Equal(got, c.want) {
				t.Fatalf("denied %v, want %v", got, c.want)
			}
			ranges, err := sandboxlandlock.AllowedPorts(got)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range got {
				if sandboxlandlock.Allows(ranges, p) {
					t.Fatalf("port %d is allowed by the ruleset", p)
				}
			}
			if !sandboxlandlock.Allows(ranges, cfg.Proxy.Port) {
				t.Fatal("the model proxy's port is not allowed")
			}
		})
	}
}

// TestLandlockDenyListFollowsTheResolvedDashboard: a dashboard address the
// daemon resolved after the driver was built (a --dashboard-addr flag) is
// the one denied at launch.
func TestLandlockDenyListFollowsTheResolvedDashboard(t *testing.T) {
	t.Setenv("OBSERVER_DASHBOARD_ADDR", "")
	prev := resolvedDashboardListen()
	t.Cleanup(func() { noteDashboardListen(prev) })
	cfg := config.Default()
	cfg.Dashboard.Addr = ""
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db") // no real records
	d := &landlockDriver{full: cfg}
	noteDashboardListen("127.0.0.1:9191")
	if got, err := d.deniedPorts(); err != nil || !slices.Contains(got, 9191) || slices.Contains(got, 8081) {
		t.Fatalf("denied %v (%v), want the resolved dashboard port 9191 and not the default", got, err)
	}
}

// TestLandlockCLIPlanDeniesTheDaemonsDashboard (cli-1b fixes-3, A): a
// sandboxed CLI launch builds its plan in its own process, where no
// dashboard address was resolved. With the daemon on a non-default port
// (a --dashboard-addr flag, or OBSERVER_DASHBOARD_ADDR only in the
// daemon's environment), the plan denies the port the daemon recorded,
// not this process's env, config or default; with no live record the
// launch is refused.
func TestLandlockCLIPlanDeniesTheDaemonsDashboard(t *testing.T) {
	t.Setenv("OBSERVER_DASHBOARD_ADDR", "")
	prev := resolvedDashboardListen()
	noteDashboardListen("") // this process is the CLI: nothing resolved
	t.Cleanup(func() { noteDashboardListen(prev) })
	cfg := config.Default()
	cfg.Dashboard.Addr = ""
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	d := &landlockDriver{full: cfg}

	if _, err := d.deniedPorts(); !errors.Is(err, errLandlockDashboardUnknown) {
		t.Fatalf("no record: err = %v, want the launch refused", err)
	}
	remove, err := writeDashboardListenRecord(cfg.Observer.DBPath, "127.0.0.1:9393")
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	got, err := d.deniedPorts()
	if err != nil || !slices.Contains(got, 9393) {
		t.Fatalf("denied %v (%v), want the daemon's recorded port 9393", got, err)
	}
	if slices.Contains(got, 8081) {
		t.Fatalf("denied %v: the CLI's default, not the daemon's port", got)
	}
	// The record of a daemon that is gone is not trusted.
	if _, err := landlockDashboardAddrs("", cfg.Observer.DBPath, func(int) bool { return false }); !errors.Is(err, errLandlockDashboardUnknown) {
		t.Fatalf("dead daemon's record: err = %v, want refused", err)
	}
}

// TestLandlockPlanDeniesAStandaloneDashboard (cli-1b fixes-4): a
// standalone `observer dashboard` records its own address (a per-process
// file that leaves the daemon's record alone), and a CLI-built plan denies
// it alongside the daemon's.
func TestLandlockPlanDeniesAStandaloneDashboard(t *testing.T) {
	t.Setenv("OBSERVER_DASHBOARD_ADDR", "")
	prev := resolvedDashboardListen()
	noteDashboardListen("")
	t.Cleanup(func() { noteDashboardListen(prev) })
	cfg := config.Default()
	cfg.Dashboard.Addr = ""
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	removeDaemon, err := writeDashboardListenRecord(cfg.Observer.DBPath, "127.0.0.1:9393")
	if err != nil {
		t.Fatal(err)
	}
	defer removeDaemon()
	removeStandalone, err := writeStandaloneDashboardListenRecord(cfg.Observer.DBPath, "127.0.0.1:9494")
	if err != nil {
		t.Fatal(err)
	}
	if rec, ok := readDashboardListenRecord(cfg.Observer.DBPath); !ok || rec.Addr != "127.0.0.1:9393" {
		t.Fatalf("the standalone record replaced the daemon's: %+v %v", rec, ok)
	}
	got, err := (&landlockDriver{full: cfg}).deniedPorts()
	if err != nil || !slices.Contains(got, 9393) || !slices.Contains(got, 9494) {
		t.Fatalf("denied %v (%v), want the daemon's 9393 and the standalone 9494", got, err)
	}
	removeStandalone()
	if got, _ := (&landlockDriver{full: cfg}).deniedPorts(); slices.Contains(got, 9494) {
		t.Fatalf("a removed standalone record still denied: %v", got)
	}
	// A standalone dashboard alone is enough to know a port.
	removeDaemon()
	if _, err := writeStandaloneDashboardListenRecord(cfg.Observer.DBPath, "127.0.0.1:9595"); err != nil {
		t.Fatal(err)
	}
	if got, err := (&landlockDriver{full: cfg}).deniedPorts(); err != nil || !slices.Contains(got, 9595) {
		t.Fatalf("denied %v (%v), want 9595", got, err)
	}
}

// TestLandlockPlanRefusesPortZero (cli-1b fixes-4): a dashboard on port 0
// listens on a port the operating system chose, which no record carries,
// so the Landlock launch is refused rather than built without that port.
func TestLandlockPlanRefusesPortZero(t *testing.T) {
	alive := func(int) bool { return true }
	dir := filepath.Join(t.TempDir(), "observer.db")
	for _, noted := range []string{"127.0.0.1:0", "[::1]:0"} {
		if _, err := landlockDashboardAddrs(noted, dir, alive); !errors.Is(err, errLandlockDashboardPortZero) {
			t.Errorf("%s: err = %v, want refused", noted, err)
		}
	}
	remove, err := writeDashboardListenRecord(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	if _, err := landlockDashboardAddrs("", dir, alive); !errors.Is(err, errLandlockDashboardPortZero) {
		t.Errorf("a recorded port 0: err = %v, want refused", err)
	}
	if got, err := landlockDashboardAddrs("127.0.0.1:8081", filepath.Join(t.TempDir(), "x.db"), alive); err != nil || len(got) != 1 {
		t.Errorf("a fixed port: %v %v", got, err)
	}
}
