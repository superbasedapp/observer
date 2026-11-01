package service

import (
	"bufio"
	"strconv"
	"strings"
	"time"
)

// StopStep is one rung of the stop escalation (D-MU2): an action, then a
// bounded wait for the process to exit.
type StopStep struct {
	// Action names what the step does ("sigterm", "bootout", "sigkill").
	Action string
	// Bound is how long to wait for the process to exit after the action.
	Bound time.Duration
}

// LaunchdStopSteps is the ordered escalation `observer service stop` walks
// on macOS. SIGTERM first: the daemon drains and exits 0, which KeepAlive
// (SuccessfulExit=false) leaves stopped. Its own shutdown watchdog forces
// the exit 20s into a stop, so the first wait covers that plus slack. A
// daemon still alive after it (stuck before its signal handling, the
// D-MU2 report) is unloaded with bootout, so launchd does not restart it,
// and only then killed outright.
var LaunchdStopSteps = []StopStep{
	{Action: "sigterm", Bound: 30 * time.Second},
	{Action: "bootout", Bound: 10 * time.Second},
	{Action: "sigkill", Bound: 5 * time.Second},
}

// StopDeps are the side effects EscalateStop drives.
type StopDeps struct {
	// Alive reports whether the process is still running.
	Alive func() bool
	// Do performs one step's action.
	Do func(action string) error
	// Sleep and Now drive the wait; poll is the interval between checks.
	Sleep func(time.Duration)
	Now   func() time.Time
	Poll  time.Duration
}

// StopStepResult records what one step did.
type StopStepResult struct {
	Action string
	Err    error
	// Waited is how long the step waited after its action.
	Waited time.Duration
	// Exited reports that the process was gone at the end of the step.
	Exited bool
}

// StopReport is the whole escalation's outcome.
type StopReport struct {
	Steps []StopStepResult
	// Exited reports that the process is gone.
	Exited bool
}

// EscalateStop walks steps top-down: it performs a step's action, waits up
// to its bound for the process to exit, and moves to the next step only
// while the process is still alive. A failed action still waits (launchctl
// can fail on a process that is exiting anyway) and the next step runs.
func EscalateStop(steps []StopStep, d StopDeps) StopReport {
	poll := d.Poll
	if poll <= 0 {
		poll = 200 * time.Millisecond
	}
	var rep StopReport
	if !d.Alive() {
		rep.Exited = true
		return rep
	}
	for _, s := range steps {
		res := StopStepResult{Action: s.Action, Err: d.Do(s.Action)}
		start := d.Now()
		for {
			if !d.Alive() {
				res.Exited = true
				break
			}
			if d.Now().Sub(start) >= s.Bound {
				break
			}
			d.Sleep(poll)
		}
		res.Waited = d.Now().Sub(start)
		rep.Steps = append(rep.Steps, res)
		if res.Exited {
			rep.Exited = true
			return rep
		}
	}
	return rep
}

// ParseLaunchdPID returns the "pid = N" value of `launchctl print` output,
// or 0 when the service has no running process.
func ParseLaunchdPID(out string) int {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != "pid" {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// LaunchdRelaunchWatch is how long `observer service stop` keeps reading the
// agent's state after the daemon it stopped has exited (MACUSER merge M1).
// The plist's KeepAlive {SuccessfulExit=false} restarts a daemon that exits
// non-zero, which the stop watchdog and the startup stop guard both do, and
// launchd waits up to its 10s throttle interval before the restart, so the
// watch covers that plus slack.
const LaunchdRelaunchWatch = 15 * time.Second

// LaunchdRelaunchStopSteps is the escalation for a daemon launchd started
// in place of the one a stop just ended: unload the agent first, so launchd
// does not restart it again, then kill it.
var LaunchdRelaunchStopSteps = []StopStep{
	{Action: "bootout", Bound: 10 * time.Second},
	{Action: "sigkill", Bound: 5 * time.Second},
}

// RelaunchDeps are the reads WatchRelaunch drives.
type RelaunchDeps struct {
	// Print returns `launchctl print` output for the agent; an error means
	// the agent is not loaded.
	Print func() (string, error)
	// Sleep and Now drive the wait; Poll is the interval between reads.
	Sleep func(time.Duration)
	Now   func() time.Time
	Poll  time.Duration
}

// WatchRelaunch reads the agent's state for up to bound after oldPID exited
// and returns the pid of a daemon launchd started in its place, or 0 when
// none started: the agent is not loaded, the last exit was 0 (KeepAlive
// SuccessfulExit=false leaves that stopped), or the bound passed with no new
// process.
func WatchRelaunch(oldPID int, bound time.Duration, d RelaunchDeps) int {
	poll := d.Poll
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	start := d.Now()
	for {
		out, err := d.Print()
		if err != nil {
			return 0
		}
		pid := ParseLaunchdPID(out)
		if pid != 0 && pid != oldPID {
			return pid
		}
		if code, ok := ParseLaunchdLastExit(out); pid == 0 && ok && code == 0 {
			return 0
		}
		if d.Now().Sub(start) >= bound {
			return 0
		}
		d.Sleep(poll)
	}
}

// ParseLaunchdLastExit returns the "last exit code = N" value of `launchctl
// print` output, and false when there is none or it is not a number (for
// example "(never exited)").
func ParseLaunchdLastExit(out string) (int, bool) {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.TrimSpace(k) != "last exit code" {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		return n, err == nil
	}
	return 0, false
}
