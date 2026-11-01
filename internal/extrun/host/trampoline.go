package host

import (
	"bufio"
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
)

// The trampoline (roadmap F0-2 follow-ups, JSP-12 finding 1): caps are
// applied BEFORE the program's first instruction, never after it started.
// The executor does not start the program itself; it starts the binary it
// is linked into (the observer binary in production, the test binary in
// tests) in its trampoline mode. The trampoline joins the run's cgroup when
// asked, sets the per-process rlimits, reports what it applied on a status
// pipe, and then replaces itself with the program through execve, so the
// program inherits every limit from its first instruction.
//
// A binary offers the trampoline by calling TrampolineDispatch first thing
// in main (before any other work); until it does, the executor runs
// programs directly and reports the per-process caps as not enforced.
//
// The protocol: argv[1] is trampolineArg and the environment holds
// trampolineEnv; fd 3 carries one JSON payload from the executor and is
// closed after it is read; fd 4 is the status pipe, close-on-exec, so it
// reaches EOF at the moment execve succeeds. Each status message is one
// JSON line.

const (
	// trampolineArg is argv[1] of a trampoline start.
	trampolineArg = "__sbo_extrun_trampoline__"
	// trampolineEnv is set (to "1") in a trampoline start's environment; the
	// program never sees it (the trampoline execs with the payload's
	// environment only).
	trampolineEnv = "SBO_EXTRUN_TRAMPOLINE"
	// trampolineVersion guards a payload written by a different build of
	// the same binary name (an upgrade while a run starts).
	trampolineVersion = 1
)

// The trampoline modes.
const (
	// modeExec applies the caps and execs the program.
	modeExec = "exec"
)

// trampolinePayload is what the executor sends on fd 3.
type trampolinePayload struct {
	V    int      `json:"v"`
	Mode string   `json:"mode"`
	Path string   `json:"path"`
	Argv []string `json:"argv"`
	Env  []string `json:"env"`
	// CgroupJoin is a per-run cgroup directory the executor created; the
	// trampoline writes its own pid to cgroup.procs before anything else.
	CgroupJoin string `json:"cgroup_join,omitempty"`
	// NotUnder, when set, is the daemon's own cgroup v2 path: the trampoline
	// refuses to start the program when its own cgroup is that one or one
	// of its ancestors, so a later cgroup.kill can never reach the daemon.
	NotUnder string `json:"not_under,omitempty"`
	// MemoryBytes and PidsMax are the caps the run's cgroup should carry.
	// The trampoline reads its own cgroup back: when memory.max equals
	// MemoryBytes and memory.swap.max is 0, the memory cap is the cgroup's
	// and RLIMIT_DATA is not set; otherwise RLIMIT_DATA is the fallback.
	MemoryBytes int64 `json:"memory_bytes,omitempty"`
	PidsMax     int64 `json:"pids_max,omitempty"`
	// CPUSeconds and FileBytes become RLIMIT_CPU and RLIMIT_FSIZE.
	CPUSeconds int64 `json:"cpu_seconds,omitempty"`
	FileBytes  int64 `json:"file_bytes,omitempty"`
}

// The status message kinds.
const (
	// evStarted is the trampoline's first word, written before it reads
	// its payload or joins a cgroup: the trampoline itself is running, so
	// a later silent death is its own, not its launcher's.
	evStarted = "started"
	evReady   = "ready"
	evError   = "error"
	evExit    = "exit"
)

// trampolineStatus is one status line.
type trampolineStatus struct {
	Ev string `json:"ev"`
	// Cgroup is the cgroup v2 path (relative to the v2 mount) the program
	// starts in, on Linux.
	Cgroup string `json:"cgroup,omitempty"`
	// The mechanism that holds each cap, from the extrun Mech vocabulary;
	// empty when the trampoline applied nothing for it.
	Memory string `json:"memory,omitempty"`
	Pids   string `json:"pids,omitempty"`
	CPU    string `json:"cpu,omitempty"`
	Fsize  string `json:"fsize,omitempty"`
	// Stage and Err describe an evError.
	Stage string `json:"stage,omitempty"`
	Err   string `json:"err,omitempty"`
	// Code, Signal and Swept describe a supervisor's evExit.
	Code   int    `json:"code,omitempty"`
	Signal string `json:"signal,omitempty"`
	Swept  int    `json:"swept,omitempty"`
}

// trampolineInstalled is set by TrampolineDispatch: the binary offers the
// trampoline mode.
var trampolineInstalled atomic.Bool

// TrampolineInstalled reports whether this binary called TrampolineDispatch,
// so the executor may start it in trampoline mode.
func TrampolineInstalled() bool { return trampolineInstalled.Load() }

// statusLog collects the status lines of one trampoline start. Safe for
// concurrent use: the reader goroutine appends while the executor reads.
type statusLog struct {
	mu        sync.Mutex
	msgs      []trampolineStatus
	done      chan struct{}
	readyCh   chan struct{}
	readyOnce sync.Once
}

func newStatusLog() *statusLog {
	return &statusLog{done: make(chan struct{}), readyCh: make(chan struct{})}
}

// read consumes r until EOF. Lines that do not decode are ignored. readyCh
// closes at the first ready message or at EOF, whichever comes first.
func (l *statusLog) read(r io.Reader) {
	defer close(l.done)
	defer l.readyOnce.Do(func() { close(l.readyCh) })
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		var m trampolineStatus
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		l.mu.Lock()
		l.msgs = append(l.msgs, m)
		l.mu.Unlock()
		if m.Ev == evReady {
			l.readyOnce.Do(func() { close(l.readyCh) })
		}
	}
}

// last returns the most recent message of kind ev.
func (l *statusLog) last(ev string) (trampolineStatus, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.msgs) - 1; i >= 0; i-- {
		if l.msgs[i].Ev == ev {
			return l.msgs[i], true
		}
	}
	return trampolineStatus{}, false
}

// failure returns a one-line start error when the trampoline reported one
// and never reached the program.
func (l *statusLog) failure() string {
	if _, ok := l.last(evReady); ok {
		if e, ok := l.last(evError); ok && e.Stage == "exec" {
			return "trampoline: exec: " + e.Err
		}
		return ""
	}
	if e, ok := l.last(evError); ok {
		return "trampoline: " + e.Stage + ": " + e.Err
	}
	return ""
}

// encodePayload renders the payload.
func encodePayload(p trampolinePayload) []byte {
	b, _ := json.Marshal(p)
	return b
}
