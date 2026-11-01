package extrun

import "time"

// Cap names one resource cap.
type Cap string

// The closed cap vocabulary, in report order.
const (
	CapWall     Cap = "wall"
	CapStdout   Cap = "stdout_bytes"
	CapStderr   Cap = "stderr_bytes"
	CapMemory   Cap = "memory"
	CapChildren Cap = "children"
	// CapCPU is CPU time, in whole seconds.
	CapCPU Cap = "cpu"
	// CapFileSize is the largest file the program may write, in bytes.
	CapFileSize Cap = "file_size"
)

// The closed mechanism vocabulary: what actually holds a cap on one run.
// An executor names the mechanism in CapApplied; the run record carries it.
const (
	MechTimer       = "wall_timer"
	MechPipe        = "pipe_cap"
	MechCgroup      = "cgroup_v2"
	MechRlimitData  = "rlimit_data"
	MechRlimitCPU   = "rlimit_cpu"
	MechRlimitFsize = "rlimit_fsize"
	MechPoll        = "poll"
	MechJob         = "job_object"
	MechJobCPU      = "job_cpu_time"
)

// The closed unit vocabulary of a cap's limit. The child-process cap is the
// one cap whose unit differs by mechanism: a cgroup's pids.max counts tasks
// (processes and threads, the program included), a Windows job's
// ActiveProcessLimit counts processes (the program included), and the
// polling fallback counts processes (the program included).
const (
	UnitSeconds   = "seconds"
	UnitBytes     = "bytes"
	UnitTasks     = "tasks"
	UnitProcesses = "processes"
)

// CapState says how a cap is held on this run. It is a closed vocabulary.
type CapState string

// The closed cap-state vocabulary.
const (
	// CapOff: the cap was not requested.
	CapOff CapState = "off"
	// CapEnforced: the executor holds the cap for the whole run.
	CapEnforced CapState = "enforced"
	// CapBestEffort: the executor applies the cap, but a program can get
	// past it briefly (applied just after start, or polled).
	CapBestEffort CapState = "best_effort"
	// CapNotEnforced: this OS or executor cannot hold the cap; it is
	// reported, never claimed.
	CapNotEnforced CapState = "not_enforced"
)

// Platform says, as data, which caps an executor enforces on its OS when a
// cap is requested. A cap missing from Caps is not enforced.
type Platform struct {
	GOOS string
	Caps map[Cap]CapState
	// ChildrenUnit is the unit the child-process cap is counted in on this
	// OS when nothing better is known before the run (UnitTasks or
	// UnitProcesses). Empty means UnitProcesses.
	ChildrenUnit string
}

// CapResult is one cap on one run: its limit (seconds for wall and CPU,
// bytes for output, memory and file size, a count for children, in Unit)
// and how it is held. Mechanism names what held it on this run; it is empty
// before the run and for a cap that is off or not enforced.
type CapResult struct {
	Cap       Cap
	Limit     int64
	State     CapState
	Unit      string
	Mechanism string
}

// CapApplied is what an executor reports it actually applied for one cap
// on one run. It replaces the planned state, so an executor can report a
// cap held more strongly than the platform default (a cgroup was available)
// or more weakly (no trampoline). A zero Limit keeps the planned limit; an
// empty Unit keeps the planned unit.
type CapApplied struct {
	State     CapState
	Mechanism string
	Unit      string
	Limit     int64
}

// The defaults applied to a zero Wall, StdoutBytes or StderrBytes. Wall and
// output caps are always on: a run with no time or output bound is never
// what a caller means.
const (
	DefaultWall        = 2 * time.Minute
	DefaultStdoutBytes = 8 << 20
	DefaultStderrBytes = 1 << 20
)

// capRow is one row of the cap table: the cap, how to read its limit from
// Limits, and its unit (empty for children: the platform names it).
type capRow struct {
	cap   Cap
	limit func(Limits) int64
	unit  string
}

// capTable is walked in order for the cap report.
var capTable = []capRow{
	{CapWall, func(l Limits) int64 { return int64(l.Wall / time.Second) }, UnitSeconds},
	{CapStdout, func(l Limits) int64 { return l.StdoutBytes }, UnitBytes},
	{CapStderr, func(l Limits) int64 { return l.StderrBytes }, UnitBytes},
	{CapMemory, func(l Limits) int64 { return l.MemoryBytes }, UnitBytes},
	{CapChildren, func(l Limits) int64 { return int64(l.Children) }, ""},
	{CapCPU, func(l Limits) int64 { return CPUSeconds(l.CPU) }, UnitSeconds},
	{CapFileSize, func(l Limits) int64 { return l.FileBytes }, UnitBytes},
}

// CPUSeconds rounds a CPU-time cap up to whole seconds (the unit
// RLIMIT_CPU takes); a cap below one second becomes one second, never zero
// (which would mean off).
func CPUSeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Second - 1) / time.Second)
}

// ResolveLimits validates l and fills the defaults. ok is false when any
// value is negative.
func ResolveLimits(l Limits) (Limits, bool) {
	if l.Wall < 0 || l.StdoutBytes < 0 || l.StderrBytes < 0 || l.MemoryBytes < 0 || l.Children < 0 || l.CPU < 0 || l.FileBytes < 0 {
		return l, false
	}
	if l.Wall == 0 {
		l.Wall = DefaultWall
	}
	if l.StdoutBytes == 0 {
		l.StdoutBytes = DefaultStdoutBytes
	}
	if l.StderrBytes == 0 {
		l.StderrBytes = DefaultStderrBytes
	}
	return l, true
}

// PlanCaps reports every cap for already resolved limits on platform p, in
// table order. A cap with a zero limit is off; a requested cap takes the
// platform's state, and not_enforced when the platform does not name it.
// Wall is reported in whole seconds; a sub-second wall rounds down there,
// the executor still uses the exact duration.
func PlanCaps(l Limits, p Platform) []CapResult {
	out := make([]CapResult, 0, len(capTable))
	for _, row := range capTable {
		limit := row.limit(l)
		requested := limit > 0 || (row.cap == CapWall && l.Wall > 0)
		state := CapOff
		if requested {
			state = p.Caps[row.cap]
			if state == "" || state == CapOff {
				state = CapNotEnforced
			}
		}
		unit := row.unit
		if row.cap == CapChildren {
			unit = p.ChildrenUnit
			if unit == "" {
				unit = UnitProcesses
			}
		}
		out = append(out, CapResult{Cap: row.cap, Limit: limit, State: state, Unit: unit})
	}
	return out
}

// applyApplied replaces the planned row of every cap the executor reports
// it applied. A cap that is off stays off: an executor never turns on a cap
// the caller did not ask for.
func applyApplied(caps []CapResult, applied map[Cap]CapApplied) []CapResult {
	if len(applied) == 0 {
		return caps
	}
	for i, c := range caps {
		a, ok := applied[c.Cap]
		if !ok || c.State == CapOff || a.State == CapOff {
			continue
		}
		if a.State == "" {
			a.State = MechanismState(a.Mechanism)
		}
		caps[i].State = a.State
		caps[i].Mechanism = a.Mechanism
		if a.State == CapNotEnforced {
			caps[i].Mechanism = ""
		}
		if a.Unit != "" {
			caps[i].Unit = a.Unit
		}
		if a.Limit > 0 {
			caps[i].Limit = a.Limit
		}
	}
	return caps
}

// mechanismStates is how strongly each mechanism holds its cap, as data.
// A per-process limit (an rlimit) is best effort for the run as a whole,
// because every process the program starts gets its own budget; a limit
// over the whole run (a cgroup, a job object, the wall timer, the pipe cap)
// is enforced. RLIMIT_FSIZE is enforced: it bounds each file, and every
// process inherits it. The job's CPU time is best effort: Windows enforces
// it late (JSP-12: 8 s for a 1 s limit).
var mechanismStates = map[string]CapState{
	MechTimer:       CapEnforced,
	MechPipe:        CapEnforced,
	MechCgroup:      CapEnforced,
	MechJob:         CapEnforced,
	MechRlimitFsize: CapEnforced,
	MechRlimitData:  CapBestEffort,
	MechRlimitCPU:   CapBestEffort,
	MechPoll:        CapBestEffort,
	MechJobCPU:      CapBestEffort,
}

// MechanismState is how strongly mech holds a cap; an empty or unknown
// mechanism holds nothing (not_enforced).
func MechanismState(mech string) CapState {
	if s, ok := mechanismStates[mech]; ok {
		return s
	}
	return CapNotEnforced
}
