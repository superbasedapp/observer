//go:build unix

package host

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// TrampolineDispatch must be the first call in main of every binary that
// runs external programs through this package. In a normal start it marks
// the trampoline as offered and returns ok=false. In a trampoline start it
// does the trampoline's work and returns the exit code (ok=true) only when
// it failed; on success the process has become the program and never
// returns.
func TrampolineDispatch(args []string) (int, bool) {
	if !isTrampolineStart(args, os.Getenv) {
		trampolineInstalled.Store(true)
		return 0, false
	}
	return runTrampoline(), true
}

// runTrampoline reads the payload and runs the mode it names.
func runTrampoline() int {
	status := os.NewFile(trampolineStatusFD, "extrun-status")
	if status != nil {
		syscall.CloseOnExec(trampolineStatusFD)
	}
	report := func(m trampolineStatus) {
		if status != nil {
			_, _ = status.Write(encodeStatus(m))
		}
	}
	fail := func(stage string, err error, code int) int {
		report(trampolineStatus{Ev: evError, Stage: stage, Err: oneLine(err.Error())})
		return code
	}
	report(trampolineStatus{Ev: evStarted})
	p, err := readPayload()
	if err != nil {
		return fail("payload", err, trampExitPayload)
	}
	if p.Mode == modeSupervise {
		return supervise(p, status, report, fail)
	}
	return execProgram(p, report, fail)
}

// readPayload reads and checks the payload on fd 3, then closes it.
func readPayload() (trampolinePayload, error) {
	var p trampolinePayload
	f := os.NewFile(trampolinePayloadFD, "extrun-payload")
	if f == nil {
		return p, fmt.Errorf("no payload fd")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16<<20))
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, err
	}
	if p.V != trampolineVersion {
		return p, fmt.Errorf("payload version %d, want %d", p.V, trampolineVersion)
	}
	if p.Path == "" || len(p.Argv) == 0 {
		return p, fmt.Errorf("payload names no program")
	}
	return p, nil
}

// execProgram is the exec mode: join, set the rlimits, report, exec.
func execProgram(p trampolinePayload, report func(trampolineStatus), fail func(string, error, int) int) int {
	ready := trampolineStatus{Ev: evReady}
	if p.CgroupJoin != "" {
		if err := joinCgroup(p.CgroupJoin); err != nil {
			return fail("cgroup_join", err, trampExitCgroup)
		}
	}
	ready.Cgroup, ready.Memory, ready.Pids = cgroupCarries(p.MemoryBytes, p.PidsMax)
	if p.NotUnder != "" && !cgroupIsSafe(ready.Cgroup, p.NotUnder) {
		return fail("cgroup_safety", fmt.Errorf("the run's cgroup %q is the daemon's own (%q) or one of its ancestors", ready.Cgroup, p.NotUnder), trampExitCgroup)
	}
	set := func(res int, v int64) error {
		lim := unix.Rlimit{Cur: uint64(v), Max: uint64(v)}
		return unix.Setrlimit(res, &lim)
	}
	if p.CPUSeconds > 0 {
		if err := set(unix.RLIMIT_CPU, p.CPUSeconds); err != nil {
			return fail("rlimit_cpu", err, trampExitRlimit)
		}
		ready.CPU = extrun.MechRlimitCPU
	}
	if p.FileBytes > 0 {
		if err := set(unix.RLIMIT_FSIZE, p.FileBytes); err != nil {
			return fail("rlimit_fsize", err, trampExitRlimit)
		}
		ready.Fsize = extrun.MechRlimitFsize
	}
	if p.MemoryBytes > 0 && ready.Memory == "" && rlimitDataHolds {
		if err := set(unix.RLIMIT_DATA, p.MemoryBytes); err != nil {
			return fail("rlimit_data", err, trampExitRlimit)
		}
		ready.Memory = extrun.MechRlimitData
	}
	report(ready)
	err := syscall.Exec(p.Path, p.Argv, p.Env) //nolint:gosec // G204: the path is absolute, checked and hashed by extrun.Runner before the payload was written
	return fail("exec", err, trampExitExec)
}
