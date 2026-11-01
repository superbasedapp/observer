package service

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// fakeProc is a process that exits after a given action (or never).
type fakeProc struct {
	exitOn  string // action after which the process exits; "" never
	alive   bool
	actions []string
	clock   time.Time
}

func (f *fakeProc) deps() StopDeps {
	return StopDeps{
		Alive: func() bool { return f.alive },
		Do: func(a string) error {
			f.actions = append(f.actions, a)
			if a == f.exitOn {
				f.alive = false
			}
			if a == "bootout" {
				return errors.New("boot-out failed")
			}
			return nil
		},
		Sleep: func(d time.Duration) { f.clock = f.clock.Add(d) },
		Now:   func() time.Time { return f.clock },
		Poll:  time.Second,
	}
}

func TestEscalateStopTable(t *testing.T) {
	cases := []struct {
		name        string
		alive       bool
		exitOn      string
		wantActions []string
		wantExited  bool
	}{
		{"not running", false, "", nil, true},
		{"exits on SIGTERM", true, "sigterm", []string{"sigterm"}, true},
		{"stuck in startup, bootout ends it", true, "bootout", []string{"sigterm", "bootout"}, true},
		{"needs SIGKILL", true, "sigkill", []string{"sigterm", "bootout", "sigkill"}, true},
		{"never exits", true, "", []string{"sigterm", "bootout", "sigkill"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeProc{alive: tc.alive, exitOn: tc.exitOn, clock: time.Unix(0, 0)}
			rep := EscalateStop(LaunchdStopSteps, f.deps())
			if !slices.Equal(f.actions, tc.wantActions) {
				t.Errorf("actions = %v, want %v", f.actions, tc.wantActions)
			}
			if rep.Exited != tc.wantExited {
				t.Errorf("Exited = %v, want %v", rep.Exited, tc.wantExited)
			}
			if len(rep.Steps) != len(tc.wantActions) {
				t.Fatalf("steps = %d, want %d", len(rep.Steps), len(tc.wantActions))
			}
			for i, s := range rep.Steps {
				if s.Exited != (tc.wantExited && i == len(rep.Steps)-1) {
					t.Errorf("step %d exited = %v", i, s.Exited)
				}
				if !s.Exited && s.Waited < LaunchdStopSteps[i].Bound {
					t.Errorf("step %d gave up after %s, bound %s", i, s.Waited, LaunchdStopSteps[i].Bound)
				}
			}
		})
	}
}

func TestParseLaunchdPID(t *testing.T) {
	out := "gui/501/app.superbased.observer = {\n\tactive count = 1\n\tpath = /Users/u/Library/LaunchAgents/app.superbased.observer.plist\n\tstate = running\n\tpid = 4242\n}\n"
	if got := ParseLaunchdPID(out); got != 4242 {
		t.Errorf("pid = %d, want 4242", got)
	}
	if got := ParseLaunchdPID("state = not running\n"); got != 0 {
		t.Errorf("no pid = %d, want 0", got)
	}
}

// TestWatchRelaunch pins the M1 watch row by row: a new pid is reported, a
// clean last exit or an unloaded agent ends the watch at once, and the old
// pid still listed, or nothing at all, waits out the bound.
func TestWatchRelaunch(t *testing.T) {
	cases := []struct {
		name     string
		prints   []string // "" is an error (not loaded); the last one repeats
		want     int
		wantWait time.Duration
	}{
		{"relaunched", []string{"state = spawn scheduled\nlast exit code = 1\n", "state = running\npid = 888\n"}, 888, time.Second},
		{"clean exit", []string{"state = not running\nlast exit code = 0\n"}, 0, 0},
		{"not loaded", []string{""}, 0, 0},
		{"old pid still listed", []string{"state = running\npid = 777\n"}, 0, LaunchdRelaunchWatch},
		{"failed, never restarted", []string{"state = not running\nlast exit code = 1\n"}, 0, LaunchdRelaunchWatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := time.Unix(0, 0)
			i := 0
			got := WatchRelaunch(777, LaunchdRelaunchWatch, RelaunchDeps{
				Print: func() (string, error) {
					p := tc.prints[min(i, len(tc.prints)-1)]
					i++
					if p == "" {
						return "", errors.New("not loaded")
					}
					return p, nil
				},
				Sleep: func(d time.Duration) { clock = clock.Add(d) },
				Now:   func() time.Time { return clock },
				Poll:  time.Second,
			})
			if got != tc.want {
				t.Errorf("pid = %d, want %d", got, tc.want)
			}
			if waited := clock.Sub(time.Unix(0, 0)); waited != tc.wantWait {
				t.Errorf("waited %s, want %s", waited, tc.wantWait)
			}
		})
	}
}

func TestParseLaunchdLastExit(t *testing.T) {
	for out, want := range map[string]int{"\tlast exit code = 1\n": 1, "last exit code = 0": 0} {
		if got, ok := ParseLaunchdLastExit(out); !ok || got != want {
			t.Errorf("%q: %d %v, want %d", out, got, ok, want)
		}
	}
	for _, out := range []string{"last exit code = (never exited)\n", "state = running\n"} {
		if _, ok := ParseLaunchdLastExit(out); ok {
			t.Errorf("%q parsed as an exit code", out)
		}
	}
}
