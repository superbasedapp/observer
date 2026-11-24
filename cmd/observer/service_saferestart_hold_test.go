package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
	"github.com/marmutapp/superbased-observer/internal/service"
)

// service_saferestart_hold_test.go: the review fixes of lane sr-restart
// (fixup/restart-hold): the daemon's port and config resolved before
// anything else, refusals instead of guesses, the route hold lock, the
// daemon's own put-back and the put-back across processes.

// routeClaudeAt routes Claude Code at port the way `observer init` does.
func (f *fakeRestart) routeClaudeAt(port int) (string, []byte) {
	f.t.Helper()
	path := filepath.Join(f.home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"env":{"KEEP_ME":"1"},"model":"x"}`), 0o600); err != nil {
		f.t.Fatal(err)
	}
	reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: port, HomeDir: f.home, Writer: routeprov.WriterInit})
	if err != nil {
		f.t.Fatal(err)
	}
	if res := reg.RegisterClaudeCode(); res.Error != nil || !res.Added {
		f.t.Fatalf("route claude: %+v", res)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatal(err)
	}
	return path, b
}

// writePlist installs a LaunchAgent whose ProgramArguments are args.
func writePlist(t *testing.T, home string, args ...string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\"?>\n<plist version=\"1.0\"><dict>\n  <key>Label</key><string>" + service.LaunchdLabel + "</string>\n")
	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	for _, a := range args {
		b.WriteString("    <string>" + a + "</string>\n")
	}
	b.WriteString("  </array>\n</dict></plist>\n")
	p := service.LaunchAgentPath(home)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSafeRestartResolvesTheDaemonsPortAndConfig (finding 3): the proxy
// port and config come from the LaunchAgent's arguments, the systemd unit's,
// or the running daemon itself (a manual `observer start --port N`), and the
// environment is built for that config; the route on that port is taken off
// for the restart and put back.
func TestSafeRestartResolvesTheDaemonsPortAndConfig(t *testing.T) {
	const port = 19944
	cases := []struct {
		name   string
		setup  func(f *fakeRestart) string
		config bool
	}{
		{"launchd agent arguments", func(f *fakeRestart) string {
			f.manager = service.ManagerLaunchd
			alt := filepath.Join(f.home, "alt", "config.toml")
			writePlist(t, f.home, "/usr/local/bin/observer", "start", "--config", alt, "--port", strconv.Itoa(port))
			return alt
		}, true},
		{"systemd unit arguments", func(f *fakeRestart) string {
			alt := filepath.Join(f.home, "alt", "config.toml")
			unit := service.UnitPath(service.ScopeUser, f.home)
			if err := os.MkdirAll(filepath.Dir(unit), 0o700); err != nil {
				t.Fatal(err)
			}
			body := "[Service]\nExecStart=/usr/bin/observer start --config " + alt + " --port " + strconv.Itoa(port) + "\n"
			if err := os.WriteFile(unit, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			return alt
		}, true},
		{"a manual start on another port", func(f *fakeRestart) string {
			f.manager, f.installed, f.active = service.ManagerNone, false, false
			f.status = daemonStatus{Answers: true, StartedAt: "2026-11-23T10:00:00Z"}
			f.newStatus = daemonStatus{Answers: true, StartedAt: "2026-11-23T10:05:00Z"}
			f.daemonPort = port
			return ""
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeRestart(t)
			f.proxyPort = port
			want := c.setup(f)
			path, before := f.routeClaudeAt(port)
			f.during = func() {
				if safeRestartClaudeRouted(t, path) {
					t.Error("the route was still on while the daemon restarted")
				}
			}
			out, err := f.run(safeRestartOptions{})
			if err != nil {
				t.Fatalf("restart: %v\n%s", err, out)
			}
			if !strings.Contains(out, "off   claude-code") || !strings.Contains(out, ":"+strconv.Itoa(port)) {
				t.Fatalf("the route on :%d was not taken off:\n%s", port, out)
			}
			if after, _ := os.ReadFile(path); string(after) != string(before) {
				t.Fatalf("settings after the restart:\n%s\nwant\n%s", after, before)
			}
			if c.config && (len(f.configs) == 0 || f.configs[len(f.configs)-1] != want) {
				t.Fatalf("environments built for %q, want the daemon's config %q last", f.configs, want)
			}
		})
	}
}

// TestSafeRestartRefusesWhatItCannotTell (finding 3): a dashboard that
// answers while nothing answers on the resolved proxy port, and an
// organization posture that cannot be read, are refusals that change
// nothing, never an unprotected restart. A config with no proxy restarts.
func TestSafeRestartRefusesWhatItCannotTell(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(f *fakeRestart)
		refused string
	}{
		{"the dashboard answers, the proxy is elsewhere", func(f *fakeRestart) {
			f.proxyPort = 19966 // the daemon runs its proxy here; nothing tells the verb so
			f.status = daemonStatus{Answers: true, StartedAt: "a"}
			f.newStatus = daemonStatus{Answers: true, StartedAt: "b"}
		}, "nothing answers on the proxy port"},
		{"the organization's posture cannot be read", func(f *fakeRestart) {
			f.orgErr = errors.New("the governance state is locked")
		}, "could not read whether your organization maintains"},
		{"a config with no proxy restarts", func(f *fakeRestart) {
			f.proxyPort, f.noProxy = 19966, true
			f.status = daemonStatus{Answers: true, StartedAt: "a"}
			f.newStatus = daemonStatus{Answers: true, StartedAt: "b"}
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeRestart(t)
			c.setup(f)
			path, before := f.routeClaudeAt(f.proxyPort)
			out, err := f.run(safeRestartOptions{})
			if c.refused == "" {
				if err != nil || len(f.ran) != 1 {
					t.Fatalf("err %v ran %v\n%s", err, f.ran, out)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.refused) || !strings.Contains(err.Error(), "--keep-routes") {
				t.Fatalf("err = %v, want a refusal saying %q\n%s", err, c.refused, out)
			}
			if len(f.ran) != 0 {
				t.Fatalf("restarted %v despite the refusal", f.ran)
			}
			if after, _ := os.ReadFile(path); string(after) != string(before) {
				t.Fatal("the route changed despite the refusal")
			}
		})
	}
}

// TestRestartOrgPostureUnreadableConfigIsAnError (finding 3): the
// production posture read answers an error, never "not managed", when the
// config does not load, and the restart refuses on it.
func TestRestartOrgPostureUnreadableConfigIsAnError(t *testing.T) {
	f := newFakeRestart(t)
	broken := filepath.Join(f.home, "broken", "config.toml")
	if err := os.MkdirAll(filepath.Dir(broken), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(broken, []byte("[observer\nnot toml"), 0o600); err != nil {
		t.Fatal(err)
	}
	owns, err := restartOrgMaintainsRoutes(context.Background(), broken)
	if err == nil || owns {
		t.Fatalf("restartOrgMaintainsRoutes = %v, %v; want an error", owns, err)
	}
	path, before := f.routeClaude()
	var buf bytes.Buffer
	err = runSafeRestart(context.Background(), safeRestartOptions{out: &buf, timeout: time.Second}, func(p string) safeRestartEnv {
		e := f.env()
		e.orgMaintainsRoutes = func(ctx context.Context) (bool, error) { return restartOrgMaintainsRoutes(ctx, broken) }
		return e
	})
	if err == nil || !strings.Contains(err.Error(), "could not read whether your organization maintains") || len(f.ran) != 0 {
		t.Fatalf("err = %v ran %v\n%s", err, f.ran, buf.String())
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("the route changed despite the refusal")
	}
}

// TestSafeRestartLocksOutASecondRun (finding 5): while another run holds the
// route hold lock, a restart, stop and start each refuse and change nothing.
func TestSafeRestartLocksOutASecondRun(t *testing.T) {
	f := newFakeRestart(t)
	path, before := f.routeClaude()
	other, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: safeRestartTestPort, HomeDir: f.home})
	if err != nil {
		t.Fatal(err)
	}
	release, ok, err := other.LockRouteHold()
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	defer release()
	opts := safeRestartOptions{out: io.Discard, timeout: time.Second}
	for name, run := range map[string]func() error{
		"restart": func() error { _, err := f.run(safeRestartOptions{}); return err },
		"stop":    func() error { return runSafeStop(context.Background(), opts, f.envFor) },
		"start":   func() error { return runSafeStart(context.Background(), opts, f.envFor) },
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "another Observer command") {
			t.Fatalf("%s: err = %v, want the lock refusal", name, err)
		}
	}
	if len(f.ran) != 0 {
		t.Fatalf("ran %v while another run held the lock", f.ran)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("the route changed while another run held the lock")
	}
}

// TestServiceStopThenStartPutsBackQwenCode (finding 1): Qwen Code's removal
// leaves the default host in model.baseUrl. Across `observer service stop`
// and `start` (two processes) that is not a route "set meanwhile": the route
// goes back on.
func TestServiceStopThenStartPutsBackQwenCode(t *testing.T) {
	f := newFakeRestart(t)
	path := filepath.Join(f.home, ".qwen", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"model": {"name": "gpt-4o", "baseUrl": "https://api.openai.com/v1"}, "modelProviders": {"openai": [{"id": "gpt-4o", "baseUrl": "https://api.openai.com/v1", "envKey": "OPENAI_API_KEY"}]}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: safeRestartTestPort, HomeDir: f.home, Writer: routeprov.WriterInit})
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.RegisterQwenCode(); res.Error != nil || !res.Added {
		t.Fatalf("route qwen-code: %+v", res)
	}
	before, _ := os.ReadFile(path)
	if err := runSafeStop(context.Background(), safeRestartOptions{out: io.Discard, timeout: time.Second}, f.envFor); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if mid, _ := os.ReadFile(path); strings.Contains(string(mid), "127.0.0.1") {
		t.Fatal("the qwen-code route is still on after the stop")
	}
	f.active = false
	var buf bytes.Buffer
	if err := runSafeStart(context.Background(), safeRestartOptions{out: &buf, timeout: time.Second}, f.envFor); err != nil {
		t.Fatalf("start: %v\n%s", err, buf.String())
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) || !strings.Contains(buf.String(), "back  qwen-code") {
		t.Fatalf("qwen-code after start:\n%s\nwant\n%s\n%s", after, before, buf.String())
	}
}

// TestServiceStartWithoutAServiceManager (finding 4): with no service
// manager `observer service start` puts the routes back onto a proxy that
// already serves, and otherwise says to run `observer start` (whose daemon
// puts them back), never just "no service manager".
func TestServiceStartWithoutAServiceManager(t *testing.T) {
	for _, serving := range []bool{true, false} {
		t.Run("serving="+strconv.FormatBool(serving), func(t *testing.T) {
			f := newFakeRestart(t)
			path, before := f.routeClaude()
			if err := runSafeStop(context.Background(), safeRestartOptions{out: io.Discard, timeout: time.Second}, f.envFor); err != nil {
				t.Fatalf("stop: %v", err)
			}
			f.manager, f.installed, f.active, f.ran = service.ManagerNone, false, false, nil
			f.restarted = serving // a daemon started by hand serves the port again
			var buf bytes.Buffer
			err := runSafeStart(context.Background(), safeRestartOptions{out: &buf, timeout: time.Second}, f.envFor)
			after, _ := os.ReadFile(path)
			if serving {
				if err != nil || string(after) != string(before) {
					t.Fatalf("err %v\n%s\nwant\n%s", err, after, before)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "observer start") || !strings.Contains(err.Error(), "puts them back") {
				t.Fatalf("err = %v", err)
			}
			if safeRestartClaudeRouted(t, path) {
				t.Fatal("a route was put back onto a proxy that does not answer")
			}
		})
	}
}

// TestDaemonPutsBackAPendingHold (finding 4): the daemon puts back the routes
// a stop left off once its own proxy serves, waiting while a verb holds the
// route hold lock; a hold for another port is left alone.
func TestDaemonPutsBackAPendingHold(t *testing.T) {
	f := newFakeRestart(t)
	path, before := f.routeClaude()
	if err := runSafeStop(context.Background(), safeRestartOptions{out: io.Discard, timeout: time.Second}, f.envFor); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if safeRestartClaudeRouted(t, path) {
		t.Fatal("the route is still on after the stop")
	}
	newReg := func(port int) (*proxyroute.Registrar, error) {
		return proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: port, HomeDir: f.home})
	}

	// A daemon on another port leaves the hold alone.
	var stderr bytes.Buffer
	routeHoldPutBack{
		port: safeRestartTestPort + 1, registrar: newReg,
		serving: func(context.Context, int) bool { return true },
		wait:    func(context.Context, time.Duration) bool { return false },
		stdout:  io.Discard, stderr: &stderr,
	}.run(context.Background())
	if safeRestartClaudeRouted(t, path) || !strings.Contains(stderr.String(), "stay off") {
		t.Fatalf("another port's daemon touched the hold: %s", stderr.String())
	}

	// This port's daemon: its proxy is not up at first, and a verb holds
	// the lock for a while.
	verb, err := newReg(safeRestartTestPort)
	if err != nil {
		t.Fatal(err)
	}
	release, ok, err := verb.LockRouteHold()
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	serving, waits := false, 0
	var stdout bytes.Buffer
	routeHoldPutBack{
		port: safeRestartTestPort, registrar: newReg,
		serving: func(context.Context, int) bool { return serving },
		wait: func(context.Context, time.Duration) bool {
			waits++
			switch waits {
			case 2:
				serving = true
			case 4:
				if safeRestartClaudeRouted(t, path) {
					t.Error("the daemon put the route back while a verb held the lock")
				}
				release()
			}
			return waits < 20
		},
		stdout: &stdout, stderr: io.Discard,
	}.run(context.Background())
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("settings after the daemon's put-back:\n%s\nwant\n%s", after, before)
	}
	if !strings.Contains(stdout.String(), "back  claude-code") || waits < 4 {
		t.Fatalf("waits %d, output:\n%s", waits, stdout.String())
	}
	if _, err := os.Stat(filepath.Join(f.home, ".observer", proxyroute.RouteHoldFileName)); !os.IsNotExist(err) {
		t.Fatal("journal left behind")
	}
}

// TestDaemonProxyPortForReadsTheRestartReport: the daemon's proxy port comes
// from the restart dialog's report, and a body without one is no answer.
func TestDaemonProxyPortForReadsTheRestartReport(t *testing.T) {
	for _, c := range []struct {
		body string
		port int
		ok   bool
	}{
		{`{"available":true,"proxy_port":19988,"window_s":60}`, 19988, true},
		{`{"available":true}`, 0, false},
	} {
		port, ok := daemonProxyPortFromBody(strings.NewReader(c.body))
		if port != c.port || ok != c.ok {
			t.Fatalf("%s: %d %v", c.body, port, ok)
		}
	}
}
