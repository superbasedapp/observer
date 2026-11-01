//go:build linux

package host

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// procRoot is where the process table is read. A var so a test can point it
// at a fixture tree.
var procRoot = "/proc"

// trampolineSupported: Linux applies the per-process caps before exec
// through the trampoline.
const trampolineSupported = true

// platformCaps is what Linux plans before a run: wall time and output caps
// for the whole run; memory (RLIMIT_DATA), CPU (RLIMIT_CPU) and the child
// count (polled from /proc) best effort, and the file size (RLIMIT_FSIZE)
// enforced, all set before exec by the trampoline. The run itself reports
// what it actually got (appliedCaps): a cgroup raises memory and children to
// enforced, a missing trampoline lowers the rlimit caps to not enforced.
func platformCaps() map[extrun.Cap]extrun.CapState {
	return map[extrun.Cap]extrun.CapState{
		extrun.CapWall:     extrun.CapEnforced,
		extrun.CapStdout:   extrun.CapEnforced,
		extrun.CapStderr:   extrun.CapEnforced,
		extrun.CapMemory:   extrun.CapBestEffort,
		extrun.CapChildren: extrun.CapBestEffort,
		extrun.CapCPU:      extrun.CapBestEffort,
		extrun.CapFileSize: extrun.CapEnforced,
	}
}

// childrenApplied: a cgroup's pids.max holds the cap over tasks (processes
// and threads); without it the group is polled from /proc, counting
// processes.
func childrenApplied(ready trampolineStatus) extrun.CapApplied {
	if ready.Pids == extrun.MechCgroup {
		return extrun.CapApplied{Mechanism: extrun.MechCgroup, Unit: extrun.UnitTasks}
	}
	return extrun.CapApplied{Mechanism: extrun.MechPoll, Unit: extrun.UnitProcesses}
}

// linuxGroup is a unixGroup whose members can be counted from /proc.
type linuxGroup struct {
	unixGroup
}

// count returns how many live processes other than the leader are in the
// group. Zombies are not counted.
func (g linuxGroup) count() (int, bool) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, false
	}
	n := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == g.pid {
			continue
		}
		data, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "stat"))
		if err != nil {
			continue
		}
		if st, ok := parseProcStat(data); ok && st.pgrp == g.pid && st.alive() {
			n++
		}
	}
	return n, true
}

// procStat is what the runner reads from one /proc/<pid>/stat line.
type procStat struct {
	state byte
	ppid  int
	pgrp  int
	// start is the process start time in clock ticks since boot; 0 when the
	// line was too short to carry it.
	start uint64
}

// alive is false for a zombie or a dead process.
func (s procStat) alive() bool { return s.state != 'Z' && s.state != 'X' }

// parseProcStat reads a /proc/<pid>/stat line: "pid (comm) state ppid pgrp
// session tty tpgid flags minflt cminflt majflt cmajflt utime stime cutime
// cstime priority nice threads itrealvalue starttime ...". comm may hold
// spaces and parentheses, so the fields are read after the LAST ")".
func parseProcStat(data []byte) (procStat, bool) {
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return procStat{}, false
	}
	fields := bytes.Fields(data[i+1:])
	if len(fields) < 3 || len(fields[0]) != 1 {
		return procStat{}, false
	}
	ppid, err1 := strconv.Atoi(string(fields[1]))
	pgrp, err2 := strconv.Atoi(string(fields[2]))
	if err1 != nil || err2 != nil {
		return procStat{}, false
	}
	st := procStat{state: fields[0][0], ppid: ppid, pgrp: pgrp}
	if len(fields) > 19 {
		st.start, _ = strconv.ParseUint(string(fields[19]), 10, 64)
	}
	return st, true
}

// parseStat reads the state and process group (the fields the group count
// needs).
func parseStat(data []byte) (pgrp int, state byte, ok bool) {
	st, ok := parseProcStat(data)
	return st.pgrp, st.state, ok
}
