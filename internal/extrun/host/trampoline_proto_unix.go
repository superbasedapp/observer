//go:build unix

package host

import (
	"encoding/json"
	"strings"
)

// The trampoline side of the protocol (trampoline.go): only Unix systems
// start a trampoline.

const (
	// The fds of the payload and status pipes in the trampoline.
	trampolinePayloadFD = 3
	trampolineStatusFD  = 4
)

// The trampoline's own exit codes, used only when it never reached the
// program (the status pipe says why).
const (
	trampExitPayload = 120
	trampExitCgroup  = 121
	trampExitRlimit  = 122
	trampExitStart   = 123
	trampExitExec    = 127
)

// modeSupervise is the not-contained rung's helper: it stays alive as the
// child subreaper of the program, so a process that leaves the process
// group is still re-parented to it and swept when the program exits or the
// run is killed. It starts the program through a second, exec-mode
// trampoline, so the caps still hold from the program's first instruction
// and the supervisor itself is not bound by them.
const modeSupervise = "supervise"

// isTrampolineStart reports whether args and the environment lookup name a
// trampoline start.
func isTrampolineStart(args []string, getenv func(string) string) bool {
	return len(args) >= 2 && args[1] == trampolineArg && getenv(trampolineEnv) == "1"
}

// encodeStatus renders one status line.
func encodeStatus(m trampolineStatus) []byte {
	b, _ := json.Marshal(m)
	return append(b, '\n')
}

// oneLine trims an error to a single short line for the status pipe.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// cgroupIsSafe reports whether a run may start in the cgroup v2 path run
// when the daemon lives in the path daemon: run must be a real cgroup
// (never the root, which is everyone's ancestor), and neither the daemon's
// own cgroup nor one of its ancestors, so a cgroup.kill of the run can never
// reach the daemon. An empty daemon path (unknown) only rules out the root.
func cgroupIsSafe(run, daemon string) bool {
	run = strings.TrimSuffix(run, "/")
	if run == "" {
		return false
	}
	daemon = strings.TrimSuffix(daemon, "/")
	if daemon == "" {
		return true
	}
	return run != daemon && !strings.HasPrefix(daemon+"/", run+"/")
}
