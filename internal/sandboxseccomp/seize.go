package sandboxseccomp

import (
	"fmt"
	"strconv"
	"strings"
)

// seize.go is the strace opt-in (lane ptrace, PT-96, operator ruling
// 2026-11-10): [terminal.sandbox].seccomp_allow_seize, off by default and
// turned on only from the dashboard, lifts PTRACE_SEIZE and nothing else, so
// `strace <cmd>` works inside a sandboxed terminal with strace 6.14 and later
// (whose startup check takes the filter's EPERM on a seize of itself for
// support and then seizes the child it starts). PTRACE_ATTACH stays denied,
// and every other row of observer_default is unchanged: the requests strace's
// seize mode makes on its own tracee (PTRACE_INTERRUPT, PTRACE_SETOPTIONS,
// PTRACE_GETREGSET, PTRACE_GET_SYSCALL_INFO, PTRACE_PEEKDATA, PTRACE_SYSCALL,
// PTRACE_DETACH) were never denied, and process_vm_readv stays denied (strace
// falls back to PTRACE_PEEKDATA on its EPERM). TestSeccompKernelSeizeRequests
// measures each of them under the seize profile.
//
// The lift is fail closed on containment: it takes effect only when a seize
// cannot reach a process outside the sandbox, decided at launch from one of
// two grounds (seizeGrounds). The ground that applied is the profile's id, so
// the run records it (terminal_run.seccomp), and the host helper checks it
// again before the box starts (CheckSeizeGround). With neither ground the
// launch keeps observer_default and says why. No kernel setting is changed.

// The profiles that lift PTRACE_SEIZE, one per containment ground. Their
// rows are identical; the id is the ground the launch recorded.
const (
	// ProfileObserverSeizePIDNS: the sandbox runs in a pid namespace of its
	// own, so a seize can name no process outside it.
	ProfileObserverSeizePIDNS ProfileID = "observer_seize_pidns"
	// ProfileObserverSeizeYama: Yama's ptrace_scope is 1 or more, so the
	// kernel limits a seize to the tracer's own descendants.
	ProfileObserverSeizeYama ProfileID = "observer_seize_yama"
)

// SeizeGround is the containment ground a seize profile rests on.
type SeizeGround string

// The closed SeizeGround vocabulary. The zero value means no ground held.
const (
	SeizeGroundPIDNamespace SeizeGround = "pid_namespace"
	SeizeGroundYama         SeizeGround = "yama"
)

// YamaScopePath is where the kernel publishes Yama's ptrace scope. It is
// read, never written.
const YamaScopePath = "/proc/sys/kernel/yama/ptrace_scope"

// ParseYamaScope reads the file's text: one integer, 0 to 3. Anything else
// (a missing Yama, garbage) is not known, which no ground accepts.
func ParseYamaScope(text string) (scope int, ok bool) {
	n, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || n < 0 || n > 3 {
		return 0, false
	}
	return n, true
}

// SeizeFacts is what the containment table reads, all decided at launch.
type SeizeFacts struct {
	// OptIn is [terminal.sandbox].seccomp_allow_seize.
	OptIn bool
	// OwnPIDNamespace: a layer of the run's stack declares that the agent
	// runs in a pid namespace of its own (the registry's grounded field).
	OwnPIDNamespace bool
	// YamaScope is kernel.yama.ptrace_scope as read at launch; YamaKnown is
	// false when it could not be read.
	YamaScope int
	YamaKnown bool
}

// seizeGround is one row of the containment table.
type seizeGround struct {
	ground  SeizeGround
	profile ProfileID
	holds   func(SeizeFacts) bool
	// lost says why the ground does not hold (CheckSeizeGround).
	lost func(SeizeFacts) string
}

// seizeGrounds is the containment table, walked top down; the first row
// that holds decides the profile. A pid namespace of its own comes first:
// it holds whatever the host's Yama setting is.
var seizeGrounds = []seizeGround{
	{
		ground: SeizeGroundPIDNamespace, profile: ProfileObserverSeizePIDNS,
		holds: func(f SeizeFacts) bool { return f.OwnPIDNamespace },
		lost:  func(SeizeFacts) string { return "the sandbox command does not give the run a pid namespace of its own" },
	},
	{
		ground: SeizeGroundYama, profile: ProfileObserverSeizeYama,
		holds: func(f SeizeFacts) bool { return f.YamaKnown && f.YamaScope >= 1 },
		lost:  func(f SeizeFacts) string { return "Yama ptrace_scope " + yamaWords(f) },
	},
}

// yamaWords names the Yama reading in a refusal.
func yamaWords(f SeizeFacts) string {
	if !f.YamaKnown {
		return "could not be read (" + YamaScopePath + ")"
	}
	return "reads " + strconv.Itoa(f.YamaScope)
}

// SeizeDecision is the profile a launch gets.
type SeizeDecision struct {
	Profile ProfileID
	// Ground is the containment ground the lift rests on ("" when the
	// default profile applies).
	Ground SeizeGround
	// Refusal says why PTRACE_SEIZE stays denied although the opt-in is on
	// ("" when the opt-in is off or the lift applies).
	Refusal string
}

// DecideSeize is the launch's choice: observer_default when the opt-in is
// off, the seize profile of the first ground that holds, else
// observer_default with the reason.
func DecideSeize(f SeizeFacts) SeizeDecision {
	if !f.OptIn {
		return SeizeDecision{Profile: ProfileObserverDefault}
	}
	for _, g := range seizeGrounds {
		if g.holds(f) {
			return SeizeDecision{Profile: g.profile, Ground: g.ground}
		}
	}
	return SeizeDecision{
		Profile: ProfileObserverDefault,
		Refusal: "strace stays blocked (PTRACE_SEIZE denied): this sandbox shares the host's process list and Yama ptrace_scope " + yamaWords(f) + ", so a seize could reach a process outside the sandbox",
	}
}

// SeizeGroundOf names the ground a profile rests on; false for a profile
// that does not lift PTRACE_SEIZE.
func SeizeGroundOf(id ProfileID) (SeizeGround, bool) {
	for _, g := range seizeGrounds {
		if g.profile == id {
			return g.ground, true
		}
	}
	return "", false
}

// CheckSeizeGround is the host helper's second look, just before the box
// starts: a seize profile whose ground does not hold is refused (the launch
// fails closed rather than lifting PTRACE_SEIZE without its ground). Any
// other profile passes. OptIn is not read: the launch already decided.
func CheckSeizeGround(id ProfileID, f SeizeFacts) error {
	for _, g := range seizeGrounds {
		if g.profile != id {
			continue
		}
		if g.holds(f) {
			return nil
		}
		return fmt.Errorf("sandboxseccomp: profile %s lifts PTRACE_SEIZE on the ground %s, but %s; the launch is refused", id, g.ground, g.lost(f))
	}
	return nil
}

// seizeRows returns rows with PTRACE_SEIZE taken off the ptrace row, which
// then denies PTRACE_ATTACH alone. Every other row is copied as is.
func seizeRows(rows []Rule) []Rule {
	out := make([]Rule, len(rows))
	copy(out, rows)
	for i, r := range out {
		if r.Syscall != "ptrace" {
			continue
		}
		out[i].Arg0In = []uint32{ptraceAttach}
		out[i].Reason = "attaching to a process that already exists with PTRACE_ATTACH; PTRACE_SEIZE is allowed by [terminal.sandbox].seccomp_allow_seize on the containment ground the profile names (a pid namespace of the sandbox's own, or Yama ptrace_scope 1 or more), so strace on a child it starts works on every release"
	}
	return out
}
