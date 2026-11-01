package main

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/service"
)

// TestLaunchdStopNeverKillsAReusedPID pins MACUSER merge L1: SIGKILL goes
// only to the process whose start time the stop read first. A pid reused by
// another process counts as the daemon gone, and a SIGKILL step that finds
// the identity changed is skipped and reported.
func TestLaunchdStopNeverKillsAReusedPID(t *testing.T) {
	t.Run("reused during the SIGTERM wait", func(t *testing.T) {
		f := &fakeLaunchd{loaded: true}
		clock := time.Unix(0, 0)
		var out bytes.Buffer
		d := f.deps(t.TempDir())
		calls := 0
		d.output = func(service.Command) (string, error) {
			calls++
			if calls == 1 {
				return "state = running\n\tpid = 777\n", nil
			}
			return "state = not running\n\tlast exit code = 0\n", nil
		}
		d.alive = func(int) bool { return true } // the pid stays in use: another process holds it
		d.ident = func(int) (string, bool) {
			if clock.Sub(time.Unix(0, 0)) >= 2*time.Second {
				return "start-2", true
			}
			return "start-1", true
		}
		d.kill = func(pid int) error { f.calls = append(f.calls, "kill -9 "+strconv.Itoa(pid)); return nil }
		d.sleep = func(dur time.Duration) { clock = clock.Add(dur) }
		d.now = func() time.Time { return clock }
		d.out = &out
		if err := runLaunchdLifecycle("stop", false, d); err != nil {
			t.Fatalf("stop: %v\n%s", err, out.String())
		}
		for _, c := range f.calls {
			if strings.HasPrefix(c, "kill -9") || strings.HasPrefix(c, "launchctl bootout") {
				t.Errorf("a reused pid was escalated against: %v", f.calls)
			}
		}
	})
	t.Run("identity changes right before SIGKILL", func(t *testing.T) {
		f := &fakeLaunchd{loaded: true}
		clock := time.Unix(0, 0)
		var out bytes.Buffer
		d := f.deps(t.TempDir())
		reads := 0
		d.ident = func(int) (string, bool) {
			reads++ // 1: recorded, 2: the first liveness check, 3: the SIGKILL check
			if reads >= 3 {
				return "start-2", true
			}
			return "start-1", true
		}
		d.alive = func(int) bool { return true }
		d.kill = func(pid int) error { f.calls = append(f.calls, "kill -9 "+strconv.Itoa(pid)); return nil }
		d.sleep = func(dur time.Duration) { clock = clock.Add(dur) }
		d.now = func() time.Time { return clock }
		d.out = &out
		rep := escalateLaunchdStop(d, "gui/501/app.superbased.observer", 777, []service.StopStep{{Action: "sigkill", Bound: 5 * time.Second}})
		if len(f.calls) != 0 {
			t.Errorf("SIGKILL sent to a pid that is no longer the daemon: %v", f.calls)
		}
		if !rep.Exited || !strings.Contains(out.String(), "no longer the daemon") {
			t.Errorf("report %+v:\n%s", rep, out.String())
		}
	})
}
