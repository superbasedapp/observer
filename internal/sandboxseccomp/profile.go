package sandboxseccomp

import "fmt"

// Action is what a decision row answers.
type Action string

// The closed Action vocabulary.
const (
	// ActionAllow lets the syscall run.
	ActionAllow Action = "allow"
	// ActionErrno fails the syscall with EPERM, so the tool sees an
	// ordinary permission error and degrades instead of dying.
	ActionErrno Action = "errno_eperm"
	// ActionKill ends the whole process (SECCOMP_RET_KILL_PROCESS). Used
	// only for a foreign architecture and the x32 ABI, where the syscall
	// numbers of the table do not apply.
	ActionKill Action = "kill_process"
)

// ProfileID names a profile.
type ProfileID string

// ProfileObserverDefault is the default profile: the deny list below.
const ProfileObserverDefault ProfileID = "observer_default"

// Rule is one row of a profile: a syscall by its kernel name, the action,
// and, for an argument-filtered row, the values of the low 32 bits of
// argument 0 the action applies to (any other value is allowed).
type Rule struct {
	Syscall string
	Action  Action
	// Arg0In, when set, limits the row to these argument 0 values (the low
	// 32 bits; a value with high bits set is also refused, which only
	// over-denies, never under-denies).
	Arg0In []uint32
	// Archs, when set, limits the row to these architectures (a syscall
	// the other architecture's table does not have).
	Archs []string
	// Reason says why the row exists.
	Reason string
	// Grounding says how the row compares with Docker's default profile
	// (moby profiles/seccomp/default.json), the reference for "a container
	// workload never needs it".
	Grounding string
}

// ptrace request values (linux/ptrace.h): attaching to a process that
// already exists. PTRACE_TRACEME (a debugger tracing the child it started,
// as gdb and delve do) stays allowed. PTRACE_SEIZE is denied on any target:
// the filter sees only the pid, so it cannot tell a child the tracer just
// started from a process that was there before. Decision (audit N2-A7, lane
// FU4): keep the deny. Measured (TestSeccompKernelDecisions): strace on a
// child it starts (`strace <cmd>`) works with strace releases before 6.14,
// which probe PTRACE_SEIZE on a forked child at start and, when it is
// refused, have the child call PTRACE_TRACEME instead. strace 6.14 and
// later fails under the filter, because its startup check seizes strace
// itself, takes that EPERM for support and then seizes the child it starts.
// `strace -p <pid>` (attaching to a process that already exists) fails on
// every release. The opt-in [terminal.sandbox].seccomp_allow_seize (lane
// ptrace, PT-96) lifts PTRACE_SEIZE alone, only on a containment ground
// decided at launch (seize.go); PTRACE_ATTACH stays denied there too.
const (
	ptraceAttach = 0x10
	ptraceSeize  = 0x4206
)

// The groundings, so each row reads like the others.
const (
	groundDockerBlocked = "blocked by Docker's default profile"
	groundDockerCap     = "allowed by Docker's default profile only with a capability a sandboxed agent never holds"
	groundDockerIOUring = "removed from Docker's default profile in moby 25 (io_uring CVE class)"
	groundDockerPtrace  = "Docker allows ptrace on kernels 4.8 and later; denied here only for attaching to an existing process"
	groundDockerPeer    = "Docker allows it on kernels 4.8 and later, like ptrace; denied here with the ptrace row, as another route to a process that already exists"
)

// profiles is the profile table. Rows are walked top down; a syscall
// appears at most once per profile (validate). The two seize profiles are
// the default rows with only PTRACE_SEIZE lifted (seize.go).
var profiles = map[ProfileID][]Rule{
	ProfileObserverDefault:    defaultRows,
	ProfileObserverSeizePIDNS: seizeRows(defaultRows),
	ProfileObserverSeizeYama:  seizeRows(defaultRows),
}

// defaultRows are observer_default's rows.
var defaultRows = []Rule{
	{Syscall: "kexec_load", Action: ActionErrno, Reason: "loads a new kernel", Grounding: groundDockerBlocked},
	{Syscall: "kexec_file_load", Action: ActionErrno, Reason: "loads a new kernel", Grounding: groundDockerBlocked},
	{Syscall: "init_module", Action: ActionErrno, Reason: "loads a kernel module", Grounding: groundDockerBlocked},
	{Syscall: "finit_module", Action: ActionErrno, Reason: "loads a kernel module", Grounding: groundDockerBlocked},
	{Syscall: "delete_module", Action: ActionErrno, Reason: "unloads a kernel module", Grounding: groundDockerBlocked},
	{Syscall: "bpf", Action: ActionErrno, Reason: "eBPF programs and maps, a large kernel attack surface", Grounding: groundDockerCap},
	{Syscall: "perf_event_open", Action: ActionErrno, Reason: "performance counters, a side channel and kernel attack surface", Grounding: groundDockerCap},
	{Syscall: "userfaultfd", Action: ActionErrno, Reason: "user page-fault handling, a common exploit primitive", Grounding: groundDockerCap},
	{Syscall: "keyctl", Action: ActionErrno, Reason: "the kernel keyring is not namespaced", Grounding: groundDockerBlocked},
	{Syscall: "add_key", Action: ActionErrno, Reason: "the kernel keyring is not namespaced", Grounding: groundDockerBlocked},
	{Syscall: "request_key", Action: ActionErrno, Reason: "the kernel keyring is not namespaced", Grounding: groundDockerBlocked},
	{Syscall: "ptrace", Action: ActionErrno, Arg0In: []uint32{ptraceAttach, ptraceSeize}, Reason: "attaching to a process that already exists (process_lite shares the host's pid namespace); PTRACE_TRACEME (gdb, delve, and strace releases before 6.14 on a child they start, which fall back to it) and requests on a traced child stay allowed; PTRACE_SEIZE is denied on any pid, so strace -p fails with EPERM on every release and strace 6.14 and later fails even on a child it starts (its startup check seizes itself)", Grounding: groundDockerPtrace},
	// The non-ptrace routes into a process that already exists (audit
	// N2-A7): reading or writing its memory, and copying a descriptor out
	// of it. The kernel checks them with the same ptrace access test, so
	// Landlock's scoping (process_lite) and the pid namespace (bwrap)
	// already stop them reaching a host process; the rows keep the filter
	// consistent with the ptrace row. A profiler that reads its own
	// child's memory (py-spy, lldb) gets EPERM.
	{Syscall: "process_vm_readv", Action: ActionErrno, Reason: "reads another process's memory without ptrace", Grounding: groundDockerPeer},
	{Syscall: "process_vm_writev", Action: ActionErrno, Reason: "writes another process's memory without ptrace", Grounding: groundDockerPeer},
	{Syscall: "pidfd_getfd", Action: ActionErrno, Reason: "copies a descriptor out of another process (a credential socket, an open secret file)", Grounding: groundDockerPeer},
	// The mount rows deny the mount syscalls in every namespace, also
	// inside a user namespace the agent creates. User namespaces
	// themselves (clone and unshare with CLONE_NEWUSER, clone3, setns)
	// stay allowed. Decision (audit N2-A8, lane FU4): Chromium's and
	// Electron's own sandbox (Playwright, Puppeteer, headless browser
	// tests) needs a user namespace but no mount, so denying user
	// namespaces would break them, while a nested bwrap (Claude Code's
	// own sandbox, any tool that runs bwrap) needs mount and fails under
	// the filter either way: an expected outcome, recorded in the live
	// matrix. The cost is Docker's largest remaining closed surface
	// (userns); bwrap's box and process_lite's Landlock scope keep a
	// nested namespace away from the host's mounts.
	{Syscall: "mount", Action: ActionErrno, Reason: "changes the mount table the sandbox was built from; also denied inside a nested user namespace, so a nested bwrap fails", Grounding: groundDockerCap},
	{Syscall: "umount2", Action: ActionErrno, Reason: "would remove a mask or a read-only bind", Grounding: groundDockerCap},
	{Syscall: "pivot_root", Action: ActionErrno, Reason: "changes the root the sandbox was built on", Grounding: groundDockerCap},
	{Syscall: "fsopen", Action: ActionErrno, Reason: "the new mount API", Grounding: groundDockerCap},
	{Syscall: "fsconfig", Action: ActionErrno, Reason: "the new mount API", Grounding: groundDockerCap},
	{Syscall: "fsmount", Action: ActionErrno, Reason: "the new mount API", Grounding: groundDockerCap},
	{Syscall: "fspick", Action: ActionErrno, Reason: "the new mount API", Grounding: groundDockerCap},
	{Syscall: "move_mount", Action: ActionErrno, Reason: "the new mount API", Grounding: groundDockerCap},
	{Syscall: "open_tree", Action: ActionErrno, Reason: "the new mount API", Grounding: groundDockerCap},
	{Syscall: "open_tree_attr", Action: ActionErrno, Reason: "the new mount API", Grounding: groundDockerCap},
	{Syscall: "mount_setattr", Action: ActionErrno, Reason: "the new mount API (would flip a read-only bind writable)", Grounding: groundDockerCap},
	{Syscall: "swapon", Action: ActionErrno, Reason: "host memory administration", Grounding: groundDockerBlocked},
	{Syscall: "swapoff", Action: ActionErrno, Reason: "host memory administration", Grounding: groundDockerBlocked},
	{Syscall: "reboot", Action: ActionErrno, Reason: "host administration", Grounding: groundDockerBlocked},
	{Syscall: "open_by_handle_at", Action: ActionErrno, Reason: "opens a file by handle, bypassing the mount view (the shocker escape)", Grounding: groundDockerBlocked},
	{Syscall: "name_to_handle_at", Action: ActionErrno, Reason: "the handle half of open_by_handle_at", Grounding: groundDockerBlocked},
	{Syscall: "clock_settime", Action: ActionErrno, Reason: "sets the host clock", Grounding: groundDockerCap},
	{Syscall: "clock_adjtime", Action: ActionErrno, Reason: "adjusts the host clock", Grounding: groundDockerCap},
	{Syscall: "settimeofday", Action: ActionErrno, Reason: "sets the host clock", Grounding: groundDockerCap},
	{Syscall: "acct", Action: ActionErrno, Reason: "host process accounting", Grounding: groundDockerCap},
	{Syscall: "quotactl", Action: ActionErrno, Reason: "host disk quotas", Grounding: groundDockerCap},
	{Syscall: "quotactl_fd", Action: ActionErrno, Reason: "host disk quotas", Grounding: groundDockerCap},
	{Syscall: "lookup_dcookie", Action: ActionErrno, Reason: "profiling interface, kernel attack surface", Grounding: groundDockerCap},
	{Syscall: "io_uring_setup", Action: ActionErrno, Reason: "io_uring bypasses syscall filtering and is a large attack surface; libuv and others fall back on EPERM", Grounding: groundDockerIOUring},
	{Syscall: "io_uring_enter", Action: ActionErrno, Reason: "io_uring", Grounding: groundDockerIOUring},
	{Syscall: "io_uring_register", Action: ActionErrno, Reason: "io_uring", Grounding: groundDockerIOUring},
	{Syscall: "iopl", Action: ActionErrno, Archs: []string{ArchAMD64}, Reason: "raw I/O port access", Grounding: groundDockerCap},
	{Syscall: "ioperm", Action: ActionErrno, Archs: []string{ArchAMD64}, Reason: "raw I/O port access", Grounding: groundDockerCap},
	{Syscall: "uselib", Action: ActionErrno, Archs: []string{ArchAMD64}, Reason: "obsolete a.out loader", Grounding: groundDockerBlocked},
}

// Profiles returns the profile ids, the default first.
func Profiles() []ProfileID {
	return []ProfileID{ProfileObserverDefault, ProfileObserverSeizePIDNS, ProfileObserverSeizeYama}
}

// Rules returns a copy of a profile's rows.
func Rules(id ProfileID) ([]Rule, bool) {
	rs, ok := profiles[id]
	if !ok {
		return nil, false
	}
	return append([]Rule(nil), rs...), true
}

// appliesTo reports whether a row is part of the program on goarch.
func (r Rule) appliesTo(goarch string) bool {
	if len(r.Archs) == 0 {
		return true
	}
	for _, a := range r.Archs {
		if a == goarch {
			return true
		}
	}
	return false
}

// validate checks a profile's rows against an architecture: known actions,
// a number for every syscall, no syscall twice (an argument-filtered row
// allows what it does not match, so a second row for the same number would
// never be reached).
func validate(rs []Rule, goarch string, spec archSpec) error {
	seen := map[string]bool{}
	for _, r := range rs {
		switch r.Action {
		case ActionErrno, ActionKill, ActionAllow:
		default:
			return fmt.Errorf("sandboxseccomp: row %s: unknown action %q", r.Syscall, r.Action)
		}
		if r.Reason == "" || r.Grounding == "" {
			return fmt.Errorf("sandboxseccomp: row %s: a row needs its reason and grounding", r.Syscall)
		}
		for _, a := range r.Archs {
			if _, ok := archs[a]; !ok {
				return fmt.Errorf("sandboxseccomp: row %s: unknown architecture %q", r.Syscall, a)
			}
		}
		if !r.appliesTo(goarch) {
			continue
		}
		if _, ok := spec.nr[r.Syscall]; !ok {
			return fmt.Errorf("sandboxseccomp: row %s: no syscall number on %s", r.Syscall, goarch)
		}
		if seen[r.Syscall] {
			return fmt.Errorf("sandboxseccomp: row %s appears twice", r.Syscall)
		}
		seen[r.Syscall] = true
	}
	return nil
}
