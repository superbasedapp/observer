package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/service"
)

// fakeServiceProbe stands in for systemctl, /proc and the route registrars.
// It never execs anything: every systemctl call is recorded.
type fakeServiceProbe struct {
	active    bool
	pid       int
	exe       string
	exeErr    error
	listening bool
	clients   int
	sockErr   error
	routes    []string
	routesErr error
	ran       []string
}

func (f *fakeServiceProbe) probe() *serviceProbe {
	return &serviceProbe{
		run: func(c service.Command) error {
			f.ran = append(f.ran, strings.Join(c.Args, " "))
			if len(c.Args) > 1 && c.Args[len(c.Args)-2] == "try-restart" {
				f.pid++
			}
			return nil
		},
		show:    func(service.Scope) (bool, int, error) { return f.active, f.pid, nil },
		readExe: func(int) (string, error) { return f.exe, f.exeErr },
		proxySockets: func(int) (bool, int, error) {
			return f.listening, f.clients, f.sockErr
		},
		routes: func(string, int) ([]string, error) { return f.routes, f.routesErr },
	}
}

func (f *fakeServiceProbe) ranVerb(verb string) bool {
	for _, r := range f.ran {
		if strings.Contains(" "+r+" ", " "+verb+" ") {
			return true
		}
	}
	return false
}

// TestApplyServiceRefresh pins T-753, one case per decision row, through the
// action the cmd layer takes. The rc.3 roll's regression is the first case:
// `observer service install --now` over a unit still running the replaced
// binary used to run `systemctl start` (a no-op on an active unit) and print
// "Service enabled + started.".
func TestApplyServiceRefresh(t *testing.T) {
	const exe = "/home/u/.local/bin/observer"
	newLine := exe + " start"
	cases := []struct {
		name        string
		f           fakeServiceProbe
		r           serviceRefresh
		restarted   bool
		started     bool
		wantOut     []string
		wantMissing []string
	}{
		{
			name:      "install --now over a replaced binary, idle proxy (rc.3 regression)",
			f:         fakeServiceProbe{active: true, pid: 100, exe: exe + " (deleted)", listening: true},
			r:         serviceRefresh{startIfInactive: true},
			restarted: true, wantOut: []string{"Restarted the service onto this binary (was pid 100", "now pid 101", "no proxy route is active"},
			wantMissing: []string{"Service enabled + started."},
		},
		{
			name:      "upgrade, no proxy listener (minimal edition): restart even with a route file",
			f:         fakeServiceProbe{active: true, pid: 7, exe: exe + " (deleted)", routes: []string{"claude-code (x)"}},
			restarted: true, wantOut: []string{"no proxy listener"},
		},
		{
			name:    "upgrade, a proxy route is active: advise, never restart",
			f:       fakeServiceProbe{active: true, pid: 7, exe: exe + " (deleted)", listening: true, routes: []string{"claude-code (/home/u/.claude/settings.json)"}},
			wantOut: []string{"was NOT restarted", "a proxy route is active: claude-code", "observer service restart", "route off first", "daemon-restart-runbook"},
		},
		{
			name:    "upgrade, an open proxy connection: advise",
			f:       fakeServiceProbe{active: true, pid: 7, exe: exe + " (deleted)", listening: true, clients: 2},
			wantOut: []string{"was NOT restarted", "2 open connection(s) to the proxy"},
		},
		{
			name:    "upgrade, the route check failed: advise",
			f:       fakeServiceProbe{active: true, pid: 7, exe: exe + " (deleted)", listening: true, routesErr: errors.New("registrar unavailable")},
			wantOut: []string{"was NOT restarted", "could not be checked", "registrar unavailable"},
		},
		{
			name:    "upgrade, the socket table is unreadable: advise",
			f:       fakeServiceProbe{active: true, pid: 7, exe: exe + " (deleted)", sockErr: errors.New("cannot read /proc/net/tcp")},
			wantOut: []string{"was NOT restarted", "cannot read /proc/net/tcp"},
		},
		{
			name:    "running this binary already: no restart",
			f:       fakeServiceProbe{active: true, pid: 7, exe: exe, listening: true, routes: []string{"claude-code (x)"}},
			r:       serviceRefresh{oldExecStart: newLine},
			wantOut: []string{"already running this binary (pid 7)"},
		},
		{
			name:      "new ExecStart arguments, idle proxy: restart",
			f:         fakeServiceProbe{active: true, pid: 7, exe: exe, listening: true},
			r:         serviceRefresh{oldExecStart: exe + " start --port 9000"},
			restarted: true,
		},
		{
			name:      "a running binary at another path, idle proxy: restart onto this one",
			f:         fakeServiceProbe{active: true, pid: 7, exe: "/usr/lib/node_modules/@superbased/observer-linux-x64/bin/observer", listening: true},
			restarted: true,
		},
		{
			name: "stopped unit, install --now: enable + start",
			f:    fakeServiceProbe{}, r: serviceRefresh{startIfInactive: true}, started: true, wantOut: []string{"Service enabled + started."},
		},
		{
			name: "stopped unit, upgrade: left stopped",
			f:    fakeServiceProbe{}, wantOut: []string{"left stopped", "observer service start"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			f := c.f
			r := c.r
			r.scope, r.exe, r.port, r.w = service.ScopeUser, exe, 8820, &out
			if r.newExecStart == "" {
				r.newExecStart = newLine
			}
			if err := applyServiceRefresh(r, *f.probe()); err != nil {
				t.Fatal(err)
			}
			if got := f.ranVerb("try-restart"); got != c.restarted {
				t.Errorf("try-restart run = %v, want %v (ran %q)", got, c.restarted, f.ran)
			}
			if got := f.ranVerb("start"); got != c.started {
				t.Errorf("start run = %v, want %v (ran %q)", got, c.started, f.ran)
			}
			if f.ranVerb("restart") || f.ranVerb("stop") {
				t.Errorf("a plain restart / stop was run: %q (only try-restart is allowed)", f.ran)
			}
			for _, w := range c.wantOut {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output lacks %q:\n%s", w, out.String())
				}
			}
			for _, w := range c.wantMissing {
				if strings.Contains(out.String(), w) {
					t.Errorf("output still says %q:\n%s", w, out.String())
				}
			}
		})
	}
}

// TestServiceUpgradeKeepsArguments: `observer service upgrade` rewrites the
// unit for this binary with the arguments it was installed with, reloads
// systemd, and never starts a stopped unit; without a unit it refuses.
func TestServiceUpgradeKeepsArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd units are Linux-only")
	}
	home := t.TempDir()
	setTestHome(t, home)
	saved := systemdAvailable
	systemdAvailable = func() bool { return true }
	t.Cleanup(func() { systemdAvailable = saved })

	f := &fakeServiceProbe{}
	deps := serviceInstallDeps{
		exe:      "/new/bin/observer",
		pathDirs: func() []string { return []string{"/usr/bin", "/bin"} },
		linger:   func() string { return "" },
		probe:    f.probe(),
	}
	var out bytes.Buffer
	err := runServiceInstall(serviceInstallOptions{scope: service.ScopeUser, upgrade: true, stdout: &out, deps: deps})
	if err == nil || !strings.Contains(err.Error(), "service install --now") {
		t.Fatalf("upgrade without a unit: err = %v", err)
	}

	unitPath := service.UnitPath(service.ScopeUser, home)
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(home, "my cfg", "config.toml")
	old := service.RenderUnit(service.UnitOptions{ExecPath: "/old/bin/observer", Args: []string{"--config", cfg, "--port", "8899"}, Scope: service.ScopeUser})
	if err := os.WriteFile(unitPath, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runServiceInstall(serviceInstallOptions{scope: service.ScopeUser, upgrade: true, stdout: &out, deps: deps}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(unitPath)
	exe, args, ok := service.SplitExecStart(service.ExecStartLine(string(raw)))
	if !ok || exe != "/new/bin/observer" || strings.Join(args, "|") != "--config|"+cfg+"|--port|8899" {
		t.Fatalf("rewritten ExecStart: %q %q ok=%v\n%s", exe, args, ok, raw)
	}
	if !f.ranVerb("daemon-reload") || f.ranVerb("start") || f.ranVerb("enable") {
		t.Fatalf("systemctl calls %q: want daemon-reload only (a stopped unit stays stopped)", f.ran)
	}
	for _, w := range []string{"The unit ran /old/bin/observer; it now runs /new/bin/observer.", "left stopped"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("output lacks %q:\n%s", w, out.String())
		}
	}
}

// TestServiceInstallWithoutNowOnARunningUnit: plain `install` starts and
// restarts nothing, and no longer calls a running unit "not started".
func TestServiceInstallWithoutNowOnARunningUnit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd units are Linux-only")
	}
	setTestHome(t, t.TempDir())
	saved := systemdAvailable
	systemdAvailable = func() bool { return true }
	t.Cleanup(func() { systemdAvailable = saved })
	f := &fakeServiceProbe{active: true, pid: 42, exe: "/x/observer (deleted)", listening: true}
	var out bytes.Buffer
	err := runServiceInstall(serviceInstallOptions{scope: service.ScopeUser, stdout: &out, deps: serviceInstallDeps{
		exe: "/x/observer", pathDirs: func() []string { return nil }, linger: func() string { return "" }, probe: f.probe(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "not started") || !strings.Contains(out.String(), "running (pid 42)") || !strings.Contains(out.String(), "observer service install --now") {
		t.Fatalf("output:\n%s", out.String())
	}
	if f.ranVerb("start") || f.ranVerb("try-restart") || f.ranVerb("enable") {
		t.Fatalf("plain install ran %q", f.ran)
	}
}

func TestParseProcNetTCP(t *testing.T) {
	// 0x2274 = 8820. Rows: the listener, two clients' server-side sockets,
	// a client's own end (local ephemeral port, remote 8820: not counted),
	// a TIME_WAIT (06) and another port's listener.
	table := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2274 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1
   1: 0100007F:2274 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 2 1
   2: 0100007F:2274 0100007F:C351 01 00000000:00000000 00:00000000 00000000  1000        0 3 1
   3: 0100007F:C350 0100007F:2274 01 00000000:00000000 00:00000000 00000000  1000        0 4 1
   4: 0100007F:2274 0100007F:C352 06 00000000:00000000 00:00000000 00000000  1000        0 5 1
   5: 0100007F:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 6 1
`
	if l, e := parseProcNetTCP([]byte(table), 8820); !l || e != 2 {
		t.Fatalf("8820: listening=%v established=%d, want true 2", l, e)
	}
	if l, e := parseProcNetTCP([]byte(table), 8821); l || e != 0 {
		t.Fatalf("8821: listening=%v established=%d, want false 0", l, e)
	}
}

func TestParseSystemctlShow(t *testing.T) {
	cases := []struct {
		out    string
		active bool
		pid    int
	}{
		{"ActiveState=active\nMainPID=361984\n", true, 361984},
		{"MainPID=0\nActiveState=inactive\n", false, 0},
		{"ActiveState=activating\nMainPID=12\n", true, 12},
		{"ActiveState=failed\nMainPID=0\n", false, 0},
	}
	for _, c := range cases {
		if a, p := parseSystemctlShow(c.out); a != c.active || p != c.pid {
			t.Errorf("%q: %v %d, want %v %d", c.out, a, p, c.active, c.pid)
		}
	}
}
