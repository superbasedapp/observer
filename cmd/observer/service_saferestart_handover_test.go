package main

import (
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/service"
)

// service_saferestart_handover_test.go: L-168 (ii). When the running daemon
// hands its proxy socket to its own in-place restart, `observer service
// restart` uses that restart and takes no route off: the port keeps
// answering, so a routed session is never refused and nothing in its config
// changes. Under a service manager it does so only while the daemon runs
// exactly the installed unit's command.

// handoverFake is a fake host whose daemon answers on its dashboard and
// offers the hand-over.
func handoverFake(t *testing.T) *fakeRestart {
	t.Helper()
	f := newFakeRestart(t)
	f.status = daemonStatus{Answers: true, StartedAt: "2026-11-24T10:00:00Z"}
	f.newStatus = daemonStatus{Answers: true, StartedAt: "2026-11-24T10:05:00Z"}
	f.handover = true
	f.runningInvocation = service.InvocationDigest("/usr/bin/observer", []string{"--no-open"})
	f.unitInvocation = f.runningInvocation
	return f
}

func TestSafeRestartHandsTheProxyOver(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fakeRestart)
	}{
		{"systemd runs the unit's own command", func(*fakeRestart) {}},
		{"launchd runs the agent's own command", func(f *fakeRestart) { f.manager = service.ManagerLaunchd }},
		{"no service manager", func(f *fakeRestart) {
			f.manager, f.installed, f.active = service.ManagerNone, false, false
			f.unitInvocation = ""
		}},
		{"a managed node whose organization maintains the routes", func(f *fakeRestart) { f.orgMaintains = true }},
		{"the organization's posture cannot be read", func(f *fakeRestart) { f.orgErr = os.ErrPermission }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := handoverFake(t)
			c.setup(f)
			path, before := f.routeClaude()
			f.during = func() {
				if !safeRestartClaudeRouted(t, path) {
					t.Error("the route was taken off although the port keeps answering")
				}
			}
			out, err := f.run(safeRestartOptions{})
			if err != nil {
				t.Fatalf("restart: %v\n%s", err, out)
			}
			if len(f.ran) != 1 || f.ran[0] != "in_place" {
				t.Fatalf("ran %v, want [in_place]\n%s", f.ran, out)
			}
			if after, _ := os.ReadFile(path); string(after) != string(before) {
				t.Fatalf("the settings changed:\n%s\nwant\n%s", after, before)
			}
			for _, want := range []string{"hands its proxy's listening socket to the new process", "stay on", "kept answering throughout"} {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, "off   claude-code") {
				t.Errorf("a route was reported off:\n%s", out)
			}
		})
	}
}

// TestSafeRestartUsesTheManagerWhenTheUnitChanged: a unit rewritten since
// the daemon started (`observer service upgrade`) takes effect only through
// the manager's restart, so the hand-over is not used, the routes come off
// as before, and the output says why.
func TestSafeRestartUsesTheManagerWhenTheUnitChanged(t *testing.T) {
	for _, unit := range []string{service.InvocationDigest("/opt/new/observer", []string{"--no-open"}), ""} {
		f := handoverFake(t)
		f.unitInvocation = unit
		path, before := f.routeClaude()
		f.during = func() {
			if safeRestartClaudeRouted(t, path) {
				t.Error("the route was still on while systemd restarted the daemon")
			}
		}
		out, err := f.run(safeRestartOptions{})
		if err != nil {
			t.Fatalf("restart: %v\n%s", err, out)
		}
		if len(f.ran) != 1 || f.ran[0] != "systemd restart" {
			t.Fatalf("ran %v, want [systemd restart]\n%s", f.ran, out)
		}
		if !strings.Contains(out, "differs from the installed systemd service's") {
			t.Errorf("the output does not say why the hand-over was not used:\n%s", out)
		}
		if after, _ := os.ReadFile(path); string(after) != string(before) {
			t.Fatalf("the route did not come back:\n%s", after)
		}
	}
}

// TestSafeRestartWithoutHandoverIsUnchanged: a daemon that predates the
// report restarts exactly as before (the route hold).
func TestSafeRestartWithoutHandoverIsUnchanged(t *testing.T) {
	f := handoverFake(t)
	f.handover = false
	path, _ := f.routeClaude()
	f.during = func() {
		if safeRestartClaudeRouted(t, path) {
			t.Error("the route was still on while the daemon restarted")
		}
	}
	out, err := f.run(safeRestartOptions{})
	if err != nil || len(f.ran) != 1 || f.ran[0] != "systemd restart" || !strings.Contains(out, "off   claude-code") {
		t.Fatalf("err %v ran %v\n%s", err, f.ran, out)
	}
}
