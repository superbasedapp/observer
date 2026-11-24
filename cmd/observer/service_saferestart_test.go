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

// safeRestartTestPort is the proxy port of every fake daemon here.
const safeRestartTestPort = 18833

// fakeRestart is a scripted host: a service manager, a daemon that answers
// before and after the restart, and an AI tool home under t.TempDir().
type fakeRestart struct {
	t       *testing.T
	home    string
	manager service.RestartManager
	// before the restart
	installed, active bool
	pid               int
	status            daemonStatus
	serving           bool
	// after the restart
	newPID       int
	newStatus    daemonStatus
	servingAfter bool
	// facts
	inPlace, child, orgMaintains bool
	orgErr                       error
	live                         *fakeLiveClient
	// proxyPort is the port the fake proxy serves on; daemonPort is what
	// the daemon's dashboard reports (0: it reports none); noProxy is a
	// config with the proxy component off.
	proxyPort, daemonPort int
	noProxy               bool
	// configs is every config path the verb built an environment for.
	configs []string
	// actions
	restartErr error
	restarted  bool
	stopped    bool
	ran        []string
	// during runs inside the restart action (the daemon is down).
	during func()
	clock  time.Time
}

// envFor is the verbs' environment factory: it records the config path the
// verb resolved and returns the fake.
func (f *fakeRestart) envFor(configPath string) safeRestartEnv {
	f.configs = append(f.configs, configPath)
	return f.env()
}

// newFakeRestart is a systemd host running the daemon with a serving proxy,
// HOME pointed at a temp home whose config names safeRestartTestPort.
func newFakeRestart(t *testing.T) *fakeRestart {
	t.Helper()
	home := t.TempDir()
	setTestHome(t, home)
	cfg := filepath.Join(home, ".observer", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(home, ".observer", "observer.db")) + "\"\n\n" +
		"[observer.hooks]\nauto_register = false\n\n[proxy]\nport = " + strconv.Itoa(safeRestartTestPort) + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return &fakeRestart{
		t: t, home: home, manager: service.ManagerSystemd,
		installed: true, active: true, pid: 100, newPID: 200,
		serving: true, servingAfter: true, inPlace: true, proxyPort: safeRestartTestPort,
		live:  &fakeLiveClient{answered: true, drainAfter: -1},
		clock: time.Unix(1_800_000_000, 0),
	}
}

func (f *fakeRestart) env() safeRestartEnv {
	restart := func(what string) error {
		f.ran = append(f.ran, what)
		if f.during != nil {
			f.during()
		}
		f.restarted = f.restartErr == nil
		return f.restartErr
	}
	return safeRestartEnv{
		manager: func() service.RestartManager { return f.manager },
		unit: func(service.RestartManager, service.Scope) (bool, bool, int) {
			if f.restarted {
				return f.installed, true, f.newPID
			}
			return f.installed, f.active, f.pid
		},
		status: func(context.Context) daemonStatus {
			if f.restarted {
				return f.newStatus
			}
			return f.status
		},
		proxyServing: func(_ context.Context, port int) bool {
			if port != f.proxyPort {
				// Nothing listens on any other port.
				return false
			}
			if f.stopped && !f.restarted {
				return false
			}
			if f.restarted {
				return f.servingAfter
			}
			return f.serving
		},
		inPlace:            func() bool { return f.inPlace },
		daemonChild:        func(int) bool { return f.child },
		daemonPID:          func() int { return 0 },
		orgMaintainsRoutes: func(context.Context) (bool, error) { return f.orgMaintains, f.orgErr },
		daemonProxyPort: func(context.Context) (int, bool) {
			st := f.status
			if f.restarted {
				st = f.newStatus
			}
			return f.daemonPort, st.Answers && f.daemonPort > 0
		},
		proxyExpected: func() bool { return !f.noProxy },
		registrar: func(port int, dry bool) (*proxyroute.Registrar, error) {
			return proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: port, HomeDir: f.home, DryRun: dry})
		},
		liveRuns: f.live.client(),
		restartUnit: func(m service.RestartManager, _ service.Scope, startOnly bool, verb string) error {
			if verb == "restart" && startOnly {
				verb = "start"
			}
			if verb == "stop" {
				f.ran = append(f.ran, string(m)+" stop")
				f.stopped = f.restartErr == nil
				return f.restartErr
			}
			return restart(string(m) + " " + verb)
		},
		restartInPlace: func(context.Context) error { return restart("in_place") },
		guardSignals:   func(io.Writer) func() { return func() {} },
		sleep:          func(d time.Duration) { f.clock = f.clock.Add(d) },
		now:            func() time.Time { return f.clock },
	}
}

// routeClaude writes a Claude Code route to the fake proxy the way `observer
// init` does and returns the settings path and its bytes.
func (f *fakeRestart) routeClaude() (string, []byte) {
	f.t.Helper()
	path := filepath.Join(f.home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"env":{"KEEP_ME":"1"},"model":"x"}`), 0o600); err != nil {
		f.t.Fatal(err)
	}
	reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: safeRestartTestPort, HomeDir: f.home, Writer: routeprov.WriterInit})
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

func (f *fakeRestart) run(opts safeRestartOptions) (string, error) {
	f.t.Helper()
	var out bytes.Buffer
	opts.out = &out
	if opts.timeout == 0 {
		opts.timeout = 10 * time.Second
	}
	if opts.scope == "" {
		opts.scope = service.ScopeUser // what resolveScope gives the verbs
	}
	err := runSafeRestart(context.Background(), opts, f.envFor)
	return out.String(), err
}

func safeRestartClaudeRouted(t *testing.T, path string) bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(b), "ANTHROPIC_BASE_URL")
}

// TestSafeRestartTakesRoutesOffAndPutsThemBack: through systemd and through
// the daemon's in-place restart, the route is off while the daemon is down
// and comes back byte for byte once the new proxy answers.
func TestSafeRestartTakesRoutesOffAndPutsThemBack(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fakeRestart)
		ran   string
	}{
		{"systemd", func(*fakeRestart) {}, "systemd restart"},
		{"launchd", func(f *fakeRestart) { f.manager = service.ManagerLaunchd }, "launchd restart"},
		{"no service manager: in place", func(f *fakeRestart) {
			f.manager, f.installed, f.active = service.ManagerNone, false, false
			f.status = daemonStatus{Answers: true, StartedAt: "2026-11-23T10:00:00Z"}
			f.newStatus = daemonStatus{Answers: true, StartedAt: "2026-11-23T10:05:00Z"}
		}, "in_place"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeRestart(t)
			c.setup(f)
			path, before := f.routeClaude()
			f.during = func() {
				if safeRestartClaudeRouted(t, path) {
					t.Error("the route was still on while the daemon restarted")
				}
			}
			out, err := f.run(safeRestartOptions{})
			if err != nil {
				t.Fatalf("restart: %v\n%s", err, out)
			}
			if len(f.ran) != 1 || f.ran[0] != c.ran {
				t.Fatalf("ran %v, want [%s]", f.ran, c.ran)
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(before) {
				t.Fatalf("settings after the restart:\n%s\nwant\n%s", after, before)
			}
			for _, want := range []string{"off   claude-code", "Restarted. The proxy on :18833 answers again.", "back  claude-code", "exactly as it was"} {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			if _, err := os.Stat(filepath.Join(f.home, ".observer", proxyroute.RouteHoldFileName)); !os.IsNotExist(err) {
				t.Errorf("hold journal left behind: %v", err)
			}
		})
	}
}

// TestSafeRestartRefusals: each refusal changes nothing (no restart, the
// route stays on) and says why.
func TestSafeRestartRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fakeRestart)
		want  string
	}{
		{"inside a dashboard terminal", func(f *fakeRestart) { f.child = true }, "inside a session the Observer daemon started"},
		{"organization maintains the routes", func(f *fakeRestart) { f.orgMaintains = true }, "--keep-routes"},
		{"native Windows, no manager", func(f *fakeRestart) {
			f.manager, f.installed, f.active, f.inPlace = service.ManagerNone, false, false, false
			f.status = daemonStatus{Answers: true, StartedAt: "x"}
		}, "cannot restart itself in place"},
		{"nothing running", func(f *fakeRestart) {
			f.manager, f.installed, f.active, f.serving = service.ManagerNone, false, false, false
		}, "no Observer daemon is running"},
		{"a live sandboxed run", func(f *fakeRestart) { f.live.runs = oneCLIRun }, "claude-code on bwrap"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeRestart(t)
			c.setup(f)
			path, before := f.routeClaude()
			out, err := f.run(safeRestartOptions{liveRuns: serviceLiveRunChoice(false, false)})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to say %q\n%s", err, c.want, out)
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

// TestSafeRestartKeepRoutes: --keep-routes restarts with the route on, and is
// the way through on a machine whose organization maintains the routes.
func TestSafeRestartKeepRoutes(t *testing.T) {
	f := newFakeRestart(t)
	f.orgMaintains = true
	path, _ := f.routeClaude()
	f.during = func() {
		if !safeRestartClaudeRouted(t, path) {
			t.Error("--keep-routes took the route off")
		}
	}
	out, err := f.run(safeRestartOptions{keepRoutes: true})
	if err != nil || len(f.ran) != 1 || !strings.Contains(out, "--keep-routes: the proxy routes to :18833 stay on") {
		t.Fatalf("err %v ran %v\n%s", err, f.ran, out)
	}
}

// TestSafeRestartFailedRestartPutsRoutesBack: a restart the manager refused
// leaves the old daemon serving, so the route goes straight back on.
func TestSafeRestartFailedRestartPutsRoutesBack(t *testing.T) {
	f := newFakeRestart(t)
	f.restartErr = errors.New("unit failed")
	path, before := f.routeClaude()
	out, err := f.run(safeRestartOptions{})
	if err == nil || !strings.Contains(err.Error(), "unit failed") {
		t.Fatalf("err = %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) || !strings.Contains(out, "back  claude-code") {
		t.Fatalf("the route did not come back after a failed restart:\n%s", out)
	}
}

// TestSafeRestartNewDaemonNeverAnswers: the routes stay off (the tools reach
// their providers directly) and the journal keeps them; the next restart,
// with a daemon that answers, puts them back.
func TestSafeRestartNewDaemonNeverAnswers(t *testing.T) {
	f := newFakeRestart(t)
	f.servingAfter = false
	path, before := f.routeClaude()
	out, err := f.run(safeRestartOptions{timeout: 2 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "routes stay off") {
		t.Fatalf("err = %v\n%s", err, out)
	}
	if safeRestartClaudeRouted(t, path) {
		t.Fatal("the route was put back onto a proxy that does not answer")
	}

	// The operator fixes the daemon; the next restart finds the journal.
	f.restarted, f.servingAfter, f.ran, f.during = false, true, nil, nil
	out, err = f.run(safeRestartOptions{})
	if err != nil {
		t.Fatalf("second restart: %v\n%s", err, out)
	}
	if !strings.Contains(out, "An earlier restart was interrupted with 1 proxy route(s) off (claude-code)") {
		t.Errorf("the pending hold was not announced:\n%s", out)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("settings after recovery:\n%s\nwant\n%s", after, before)
	}
}

// TestSafeRestartDryRunChangesNothing: --dry-run names the mechanism and the
// route it would take off, and restarts nothing.
func TestSafeRestartDryRunChangesNothing(t *testing.T) {
	f := newFakeRestart(t)
	path, before := f.routeClaude()
	out, err := f.run(safeRestartOptions{dryRun: true})
	if err != nil || len(f.ran) != 0 {
		t.Fatalf("err %v ran %v", err, f.ran)
	}
	for _, want := range []string{"systemd restarts it", "would take off  claude-code", "Dry run: nothing was changed."} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("the dry run changed the route")
	}
}

// TestSafeRestartStartsAStoppedUnit: an installed unit that is not running is
// started; with no proxy there is nothing to take off.
func TestSafeRestartStartsAStoppedUnit(t *testing.T) {
	f := newFakeRestart(t)
	f.active, f.serving, f.servingAfter = false, false, false
	out, err := f.run(safeRestartOptions{})
	if err != nil || len(f.ran) != 1 || f.ran[0] != "systemd start" || !strings.Contains(out, "Started.") {
		t.Fatalf("err %v ran %v\n%s", err, f.ran, out)
	}
}

// TestSafeRestartNoProxyTakesNothingOff: a daemon with no proxy listener (a
// minimal edition) restarts without touching routes.
func TestSafeRestartNoProxyTakesNothingOff(t *testing.T) {
	f := newFakeRestart(t)
	f.serving, f.servingAfter = false, false
	path, before := f.routeClaude()
	out, err := f.run(safeRestartOptions{})
	if err != nil || len(f.ran) != 1 || !strings.Contains(out, "no route is taken off") {
		t.Fatalf("err %v ran %v\n%s", err, f.ran, out)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a route changed with no proxy running")
	}
}

// TestProcessDescendsFrom: this test process descends from its parent and
// not from an unrelated pid.
func TestProcessDescendsFrom(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc")
	}
	if !processDescendsFrom(os.Getpid(), os.Getppid()) {
		t.Error("the test process does not descend from its parent")
	}
	if processDescendsFrom(os.Getppid(), os.Getpid()) {
		t.Error("the parent descends from its child")
	}
}

// TestServiceStopAndStartHoldTheRoutes: `observer service stop` takes the
// route off before the daemon stops and `observer service start` puts it
// back once the proxy answers, byte for byte.
func TestServiceStopAndStartHoldTheRoutes(t *testing.T) {
	f := newFakeRestart(t)
	path, before := f.routeClaude()
	err := runSafeStop(context.Background(), safeRestartOptions{out: io.Discard, timeout: time.Second}, f.envFor)
	if err != nil || len(f.ran) != 1 || f.ran[0] != "systemd stop" {
		t.Fatalf("stop: err %v ran %v", err, f.ran)
	}
	if safeRestartClaudeRouted(t, path) {
		t.Fatal("the route is still on after the stop")
	}
	f.active = false
	var buf bytes.Buffer
	if err := runSafeStart(context.Background(), safeRestartOptions{out: &buf, timeout: time.Second}, f.envFor); err != nil {
		t.Fatalf("start: %v\n%s", err, buf.String())
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) || !strings.Contains(buf.String(), "back  claude-code") {
		t.Fatalf("the route did not come back on start:\n%s\nwant\n%s\n%s", after, before, buf.String())
	}
}

// TestServiceStopRefusesInsideADaemonSession: the stop would end the shell
// running it, so it changes nothing.
func TestServiceStopRefusesInsideADaemonSession(t *testing.T) {
	f := newFakeRestart(t)
	f.child = true
	path, before := f.routeClaude()
	if err := runSafeStop(context.Background(), safeRestartOptions{out: io.Discard}, f.envFor); err == nil || len(f.ran) != 0 {
		t.Fatalf("err %v ran %v", err, f.ran)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a refused stop changed the route")
	}
}
