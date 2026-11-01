package main

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/service"
)

// fakeLaunchd records launchctl calls; loaded decides `launchctl print`.
type fakeLaunchd struct {
	loaded bool
	calls  []string
}

func (f *fakeLaunchd) deps(home string) launchdDeps {
	return launchdDeps{
		home: home, uid: 501, exe: "/Users/dev/.local/bin/observer",
		pathDirs: func() []string { return []string{"/opt/homebrew/bin", "/usr/bin"} },
		run: func(c service.Command) error {
			f.calls = append(f.calls, c.Name+" "+strings.Join(c.Args, " "))
			return nil
		},
		quiet: func(c service.Command) error {
			if f.loaded {
				return nil
			}
			return errors.New("not loaded")
		},
		// launchctl print with no running process: no "pid =" line.
		output: func(c service.Command) (string, error) {
			if f.loaded {
				return "state = not running\n", nil
			}
			return "", errors.New("not loaded")
		},
		out: &bytes.Buffer{},
	}
}

func TestLaunchdInstallWritesTheAgentAndLoadsIt(t *testing.T) {
	home := t.TempDir()
	f := &fakeLaunchd{}
	var out bytes.Buffer
	err := runLaunchdInstall(serviceInstallOptions{scope: service.ScopeUser, now: true, port: 8821, stdout: &out}, f.deps(home))
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	raw, err := os.ReadFile(service.LaunchAgentPath(home))
	if err != nil {
		t.Fatal(err)
	}
	args, ok := service.LaunchAgentProgramArguments(string(raw))
	if !ok || strings.Join(args, " ") != "/Users/dev/.local/bin/observer start --port 8821" {
		t.Errorf("ProgramArguments = %v", args)
	}
	if !strings.Contains(string(raw), "/opt/homebrew/bin:/usr/bin") {
		t.Error("the agent's PATH is not the merged login PATH")
	}
	if len(f.calls) != 1 || !strings.HasPrefix(f.calls[0], "launchctl bootstrap gui/501 ") {
		t.Errorf("launchctl calls = %v, want one bootstrap", f.calls)
	}
}

func TestLaunchdInstallNeverRestartsALoadedAgent(t *testing.T) {
	home := t.TempDir()
	f := &fakeLaunchd{loaded: true}
	var out bytes.Buffer
	if err := runLaunchdInstall(serviceInstallOptions{scope: service.ScopeUser, now: true, stdout: &out}, f.deps(home)); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Errorf("a loaded agent was touched: %v", f.calls)
	}
	if !strings.Contains(out.String(), "route off first") {
		t.Errorf("output lacks the safe restart order:\n%s", out.String())
	}
}

func TestLaunchdUpgradeKeepsArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("launchd is macOS only; the case pins POSIX config paths (Windows 11 Pro rerun 2026-10-25, D5 group 4)")
	}
	home := t.TempDir()
	f := &fakeLaunchd{}
	if err := runLaunchdInstall(serviceInstallOptions{scope: service.ScopeUser, configPath: "/cfg.toml", stdout: &bytes.Buffer{}}, f.deps(home)); err != nil {
		t.Fatal(err)
	}
	d := f.deps(home)
	d.exe = "/Users/dev/new/observer"
	var out bytes.Buffer
	if err := runLaunchdInstall(serviceInstallOptions{scope: service.ScopeUser, upgrade: true, stdout: &out}, d); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(service.LaunchAgentPath(home))
	args, _ := service.LaunchAgentProgramArguments(string(raw))
	if strings.Join(args, " ") != "/Users/dev/new/observer start --config /cfg.toml" {
		t.Errorf("upgraded ProgramArguments = %v", args)
	}
	if !strings.Contains(out.String(), "it now runs /Users/dev/new/observer") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestLaunchdUpgradeWithoutAgent(t *testing.T) {
	f := &fakeLaunchd{}
	err := runLaunchdInstall(serviceInstallOptions{scope: service.ScopeUser, upgrade: true, stdout: &bytes.Buffer{}}, f.deps(t.TempDir()))
	if err == nil || !strings.Contains(err.Error(), "observer service install --now") {
		t.Fatalf("err = %v", err)
	}
}

func TestLaunchdLifecycleAndScope(t *testing.T) {
	home := t.TempDir()
	f := &fakeLaunchd{loaded: true}
	for verb, want := range map[string]string{
		"stop":    "launchctl kill SIGTERM gui/501/app.superbased.observer",
		"restart": "launchctl kickstart -k gui/501/app.superbased.observer",
		"status":  "launchctl print gui/501/app.superbased.observer",
		"start":   "launchctl kickstart gui/501/app.superbased.observer",
	} {
		f.calls = nil
		if err := runLaunchdLifecycle(verb, false, f.deps(home)); err != nil {
			t.Fatalf("%s: %v", verb, err)
		}
		if len(f.calls) != 1 || f.calls[0] != want {
			t.Errorf("%s ran %v, want %q", verb, f.calls, want)
		}
	}
	if err := runLaunchdLifecycle("start", true, f.deps(home)); !errors.Is(err, errLaunchdSystemScope) {
		t.Errorf("--system on macOS = %v, want errLaunchdSystemScope", err)
	}
	f.loaded = false
	if err := runLaunchdLifecycle("start", false, f.deps(home)); err == nil || !strings.Contains(err.Error(), "install it with") {
		t.Errorf("start with no agent = %v", err)
	}
}

func TestLaunchdUninstallRemovesThePlist(t *testing.T) {
	home := t.TempDir()
	f := &fakeLaunchd{}
	if err := runLaunchdInstall(serviceInstallOptions{scope: service.ScopeUser, stdout: &bytes.Buffer{}}, f.deps(home)); err != nil {
		t.Fatal(err)
	}
	f.loaded = true
	var out bytes.Buffer
	if err := runLaunchdUninstall(&out, false, f.deps(home)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(service.LaunchAgentPath(home)); !os.IsNotExist(err) {
		t.Error("the plist is still there")
	}
	if len(f.calls) != 1 || f.calls[0] != "launchctl bootout gui/501/app.superbased.observer" {
		t.Errorf("calls = %v", f.calls)
	}
}

// fakeDaemon is the agent's process for the stop escalation: it exits after
// the named launchctl/kill step, or never.
type fakeDaemon struct {
	exitOn string
	alive  bool
	clock  time.Time
}

// TestLaunchdStopEscalatesAndReports pins D-MU2: a daemon stuck in startup
// ignores SIGTERM; stop waits its bound, unloads the agent (bootout) so
// launchd does not restart it, kills it if needed, and reports each step.
// A process that survives everything is an error, never exit 0.
func TestLaunchdStopEscalatesAndReports(t *testing.T) {
	cases := []struct {
		name      string
		exitOn    string
		wantCalls []string
		wantErr   bool
		wantOut   []string
	}{
		{
			"exits on SIGTERM", "kill SIGTERM",
			[]string{"launchctl kill SIGTERM gui/501/app.superbased.observer"},
			false,
			[]string{"SIGTERM: pid 777 exited", "Stopped."},
		},
		{
			"stuck in startup", "bootout",
			[]string{"launchctl kill SIGTERM gui/501/app.superbased.observer", "launchctl bootout gui/501/app.superbased.observer"},
			false,
			[]string{"SIGTERM: pid 777 still running after 30s", "launchctl bootout: pid 777 exited", "unloaded"},
		},
		{
			"needs SIGKILL", "sigkill",
			[]string{"launchctl kill SIGTERM gui/501/app.superbased.observer", "launchctl bootout gui/501/app.superbased.observer", "kill -9 777"},
			false,
			[]string{"SIGKILL: pid 777 exited"},
		},
		{
			"never exits", "",
			[]string{"launchctl kill SIGTERM gui/501/app.superbased.observer", "launchctl bootout gui/501/app.superbased.observer", "kill -9 777"},
			true,
			[]string{"SIGKILL: pid 777 still running"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLaunchd{loaded: true}
			p := &fakeDaemon{exitOn: tc.exitOn, alive: true, clock: time.Unix(0, 0)}
			var out bytes.Buffer
			d := f.deps(t.TempDir())
			d.output = func(service.Command) (string, error) { return "state = running\n\tpid = 777\n", nil }
			inner := d.run
			d.run = func(c service.Command) error {
				err := inner(c)
				if tc.exitOn != "" && strings.Contains(strings.Join(c.Args, " "), tc.exitOn) {
					p.alive = false
				}
				return err
			}
			d.alive = func(pid int) bool { return pid == 777 && p.alive }
			d.kill = func(pid int) error {
				f.calls = append(f.calls, "kill -9 "+strconv.Itoa(pid))
				if tc.exitOn == "sigkill" {
					p.alive = false
				}
				return nil
			}
			d.sleep = func(dur time.Duration) { p.clock = p.clock.Add(dur) }
			d.now = func() time.Time { return p.clock }
			d.out = &out
			err := runLaunchdLifecycle("stop", false, d)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v\n%s", err, tc.wantErr, out.String())
			}
			if strings.Join(f.calls, "|") != strings.Join(tc.wantCalls, "|") {
				t.Errorf("calls = %v, want %v", f.calls, tc.wantCalls)
			}
			for _, w := range tc.wantOut {
				if !strings.Contains(out.String(), w) {
					t.Errorf("report lacks %q:\n%s", w, out.String())
				}
			}
		})
	}
}

// TestLaunchdStopCatchesARelaunch pins MACUSER merge M1: the old daemon
// exits non-zero (the stop watchdog or the startup guard) and KeepAlive
// starts a new one; stop re-reads the agent, unloads it and reports the new
// pid instead of printing "Stopped." while a daemon runs. A clean exit ends
// the watch at once.
func TestLaunchdStopCatchesARelaunch(t *testing.T) {
	cases := []struct {
		name      string
		after     []string // launchctl print once pid 777 is gone; the last repeats
		newExits  bool     // the relaunched pid 888 exits on bootout
		wantCalls []string
		wantErr   bool
		wantOut   []string
		notOut    string
	}{
		{
			"relaunched, then unloaded",
			[]string{"state = spawn scheduled\n\tlast exit code = 1\n", "state = running\n\tpid = 888\n"},
			true,
			[]string{"launchctl kill SIGTERM gui/501/app.superbased.observer", "launchctl bootout gui/501/app.superbased.observer"},
			false,
			[]string{"launchd started a new daemon (pid 888) after pid 777 exited", "launchctl bootout: pid 888 exited", "unloaded"},
			"Stopped.",
		},
		{
			"relaunched pid survives",
			[]string{"state = running\n\tpid = 888\n"},
			false,
			[]string{"launchctl kill SIGTERM gui/501/app.superbased.observer", "launchctl bootout gui/501/app.superbased.observer", "kill -9 888"},
			true,
			[]string{"SIGKILL: pid 888 still running"},
			"Stopped.",
		},
		{
			"clean exit",
			[]string{"state = not running\n\tlast exit code = 0\n"},
			false,
			[]string{"launchctl kill SIGTERM gui/501/app.superbased.observer"},
			false,
			[]string{"SIGTERM: pid 777 exited", "Stopped."},
			"new daemon",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLaunchd{loaded: true}
			oldAlive, newAlive, booted, polls := true, true, false, 0
			clock := time.Unix(0, 0)
			var out bytes.Buffer
			d := f.deps(t.TempDir())
			d.output = func(service.Command) (string, error) {
				switch {
				case oldAlive:
					return "state = running\n\tpid = 777\n", nil
				case booted:
					return "", errors.New("not loaded")
				}
				p := tc.after[min(polls, len(tc.after)-1)]
				polls++
				return p, nil
			}
			inner := d.run
			d.run = func(c service.Command) error {
				err := inner(c)
				switch strings.Join(c.Args, " ") {
				case "kill SIGTERM gui/501/app.superbased.observer":
					oldAlive = false
				case "bootout gui/501/app.superbased.observer":
					booted = true
					if tc.newExits {
						newAlive = false
					}
				}
				return err
			}
			d.alive = func(pid int) bool {
				return (pid == 777 && oldAlive) || (pid == 888 && newAlive && !oldAlive)
			}
			d.kill = func(pid int) error {
				f.calls = append(f.calls, "kill -9 "+strconv.Itoa(pid))
				return nil
			}
			d.sleep = func(dur time.Duration) { clock = clock.Add(dur) }
			d.now = func() time.Time { return clock }
			d.out = &out
			err := runLaunchdLifecycle("stop", false, d)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v\n%s", err, tc.wantErr, out.String())
			}
			if strings.Join(f.calls, "|") != strings.Join(tc.wantCalls, "|") {
				t.Errorf("calls = %v, want %v", f.calls, tc.wantCalls)
			}
			for _, w := range tc.wantOut {
				if !strings.Contains(out.String(), w) {
					t.Errorf("report lacks %q:\n%s", w, out.String())
				}
			}
			if strings.Contains(out.String(), tc.notOut) {
				t.Errorf("report says %q:\n%s", tc.notOut, out.String())
			}
			if tc.name == "clean exit" && clock.Sub(time.Unix(0, 0)) >= 15*time.Second {
				t.Errorf("a clean exit waited the whole watch (%s)", clock.Sub(time.Unix(0, 0)))
			}
		})
	}
}
