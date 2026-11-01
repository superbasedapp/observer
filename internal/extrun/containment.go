package extrun

import "strings"

// Rung names one row of the ordered containment table (roadmap F0-2
// follow-ups; security plan section 8.6, revision 2.4 and 2.5 [JSP-12]):
// what keeps everything a program starts from outliving its run. It is a
// closed vocabulary; the run record names the rung used.
type Rung string

// The closed rung vocabulary.
const (
	// RungJobObject: a Windows job object with KILL_ON_JOB_CLOSE, the
	// program started suspended and resumed only inside it, and the job
	// always terminated after the program exits. Contained.
	RungJobObject Rung = "job_object"
	// RungCgroup: a per-run cgroup v2 joined before exec, killed with
	// cgroup.kill, with pids.max, memory.max and memory.swap.max = 0 when
	// the controllers are there. Contained.
	RungCgroup Rung = "cgroup_v2"
	// RungPIDNamespace: the isolation component's pid namespace
	// (--unshare-pid with --die-with-parent): when its first process dies
	// the kernel kills every process in it. Contained.
	RungPIDNamespace Rung = "pid_namespace"
	// RungProcessGroup: the program's own process group, killed as a whole,
	// plus a subreaper sweep where the OS has one. NOT contained: a
	// grandchild that calls setsid leaves the group, and one that also
	// clears its environment escaped the spike's sweep.
	RungProcessGroup Rung = "process_group"
	// RungProcess: the program alone (an OS with neither process groups nor
	// job objects). NOT contained.
	RungProcess Rung = "process"
)

// ContainmentFacts is what the executor knows, before a run, about the
// mechanisms it could use. The executor resolves these at the boundary; the
// table below never looks at an OS or tool name.
type ContainmentFacts struct {
	// JobObject: the executor runs every program in a job object.
	JobObject bool
	// Cgroup: a per-run cgroup v2 can be made (a delegated subtree is
	// writable, or a transient systemd scope with Delegate=yes can be
	// started) and the trampoline can join it before exec.
	Cgroup bool
	// PIDNamespace: the plan was wrapped by an isolation provider that runs
	// it in its own pid namespace tied to the launcher's life.
	PIDNamespace bool
	// ProcessGroup: the OS has process groups.
	ProcessGroup bool
}

// containmentRow is one row of the containment table: the first row whose
// when holds is the rung, and a rung that fails at start falls through to
// the next row that holds.
type containmentRow struct {
	rung      Rung
	contained bool
	label     string
	when      func(ContainmentFacts) bool
}

// containmentTable is walked top-down.
var containmentTable = []containmentRow{
	{RungJobObject, true, "contained (job object)", func(f ContainmentFacts) bool { return f.JobObject }},
	{RungCgroup, true, "contained (per-run cgroup v2)", func(f ContainmentFacts) bool { return f.Cgroup }},
	{RungPIDNamespace, true, "contained (isolation pid namespace)", func(f ContainmentFacts) bool { return f.PIDNamespace }},
	{RungProcessGroup, false, "not contained (process group kill only, no sweep)", func(f ContainmentFacts) bool { return f.ProcessGroup }},
	{RungProcess, false, "not contained (the program alone)", func(ContainmentFacts) bool { return true }},
}

// ContainmentRungs returns every rung whose condition holds, in table
// order. The first is the one to use; the rest are the fallbacks when it
// cannot be set up at start. The list always ends with a rung that needs
// nothing, so it is never empty.
func ContainmentRungs(f ContainmentFacts) []Rung {
	var out []Rung
	for _, row := range containmentTable {
		if row.when(f) {
			out = append(out, row.rung)
		}
	}
	return out
}

// RungContained reports whether a rung contains the run, and its label for
// the run record and the Scanners tab. The label claims only what the rung
// itself does; ContainmentLabel names what a finished run actually got.
func RungContained(r Rung) (bool, string) {
	for _, row := range containmentTable {
		if row.rung == r {
			return row.contained, row.label
		}
	}
	return false, "not contained (unknown mechanism)"
}

// labelOverride is one row of the label table: a finished run on rung whose
// when holds gets label instead of the rung's own. It never changes whether
// the rung is contained.
type labelOverride struct {
	rung  Rung
	label string
	when  func(Containment) bool
}

// labelOverrides is walked top-down. The process-group rung claims a sweep
// only when a subreaper supervisor actually ran and reported it (Linux with
// the trampoline); without a supervisor, or on macOS, the label says the
// group kill was all that was done (decision log P-018 item d).
var labelOverrides = []labelOverride{
	{RungProcessGroup, "not contained (process group kill and subreaper sweep)", func(c Containment) bool { return c.Supervised }},
}

// ContainmentLabel reports whether the run's rung contains it and the label
// that says exactly what was done on this run.
func ContainmentLabel(c Containment) (bool, string) {
	contained, label := RungContained(c.Rung)
	for _, o := range labelOverrides {
		if o.rung == c.Rung && o.when(c) {
			return contained, o.label
		}
	}
	return contained, label
}

// The closed cgroup-source vocabulary: where a run's cgroup came from.
const (
	// CgroupSourceConfigured: a per-run child of a writable cgroup v2
	// directory the operator configured (for example a service unit with
	// Delegate=yes).
	CgroupSourceConfigured = "configured_parent"
	// CgroupSourceUserScope: a transient systemd user scope with
	// Delegate=yes, started per run; needs no root (JSP-12 laptop half).
	CgroupSourceUserScope = "systemd_user_scope"
	// CgroupSourceSystemScope: the same as a system scope, for a daemon
	// running as root under systemd.
	CgroupSourceSystemScope = "systemd_system_scope"
)

// RungSkip is a rung that was tried and could not be set up, and why.
type RungSkip struct {
	Rung   Rung
	Reason string
}

// Containment is the run record's containment block.
type Containment struct {
	// Rung is the mechanism used; Contained and Label come from the table.
	Rung      Rung
	Contained bool
	Label     string
	// CgroupSource, CgroupPath, Delegated and Controllers describe a
	// RungCgroup run: where the cgroup came from, its path under the cgroup
	// v2 mount, whether its subtree was delegated to the runner's user (the
	// directory is owned by it), and which controllers it had (systemd 245
	// delegates only memory and pids to a user).
	CgroupSource string
	CgroupPath   string
	Delegated    bool
	Controllers  []string
	// Skipped lists the rungs above this one that were tried and failed.
	Skipped []RungSkip
	// Survivors counts processes still running the run's own executable
	// (found by executable identity, never by pids the program reported)
	// that started during the run and were alive after the final kill.
	Survivors int
	// Swept counts processes the subreaper sweep or the cgroup kill ended
	// after the program itself had exited.
	Swept int
	// Supervised is true when a subreaper supervisor held the run and
	// reported its sweep (the process-group rung on Linux with the
	// trampoline). The label claims a sweep only then.
	Supervised bool
}

// pidNamespaceFlags are the launcher arguments that, together, put the
// wrapped program in its own pid namespace that dies with the launcher
// (bwrap's spelling, the one isolation launcher today).
var pidNamespaceFlags = []struct{ any []string }{
	{any: []string{"--unshare-pid", "--unshare-all"}},
	{any: []string{"--die-with-parent"}},
}

// PIDNamespacer is an optional interface of an IsolationProvider that says
// whether its wrapped plans run in their own pid namespace tied to the
// launcher's life.
type PIDNamespacer interface {
	PIDNamespace() bool
}

// WrappedInPIDNamespace reports whether an isolation provider put the
// wrapped plan in its own pid namespace that dies with the launcher. A
// provider that implements PIDNamespacer answers for itself; otherwise the
// wrapped launcher's arguments before the "--" separator must carry every
// row of pidNamespaceFlags.
func WrappedInPIDNamespace(prov IsolationProvider, wrapped Plan) bool {
	if pn, ok := prov.(PIDNamespacer); ok {
		return pn.PIDNamespace()
	}
	args := wrapped.Args
	for i, a := range args {
		if a == "--" {
			args = args[:i]
			break
		}
	}
	for _, row := range pidNamespaceFlags {
		found := false
		for _, a := range args {
			for _, want := range row.any {
				if a == want || strings.HasPrefix(a, want+"=") {
					found = true
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}
