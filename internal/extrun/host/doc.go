// Package host is the impure boundary of internal/extrun: the production
// Executor (os/exec with the per-OS process group or job object), the file
// inspector and hasher, and NewRunner, which wires them together with the
// toolresolve resolver built by toolresolve/host.NewEnv (so the command
// wrapping shim exclusion is always on).
//
// What each OS holds, as reported in extrun.Platform:
//
//   - Linux: the program starts in its own process group (Setpgid); on
//     timeout, cancel or a cap the whole group gets SIGKILL, and it gets it
//     again after a normal exit so no background child outlives the run.
//     Wall time and output caps are enforced. The per-process caps are set
//     BEFORE exec by the trampoline (trampoline.go): the binary this package
//     is linked into re-executes itself in its trampoline mode, sets
//     RLIMIT_CPU, RLIMIT_FSIZE and, when no cgroup carries memory,
//     RLIMIT_DATA, and only then execs the program. RLIMIT_AS and
//     RLIMIT_NPROC are never used (JSP-12). Memory by RLIMIT_DATA and CPU by
//     RLIMIT_CPU are best effort (each process gets its own budget); the
//     file size cap is enforced. Child processes are counted from /proc
//     every PollInterval and the group is killed above the cap (best
//     effort: a burst between two polls gets through until the next poll).
//     A binary that never called TrampolineDispatch runs programs directly,
//     and the record reports those caps as not enforced.
//   - macOS and the other Unix systems: the same process group kill, wall
//     time and output caps, and the trampoline's RLIMIT_CPU and
//     RLIMIT_FSIZE; memory and child caps are not enforced.
//   - Windows: the program starts suspended, is put in a job object and is
//     only then resumed, so every cap is enforced from its first
//     instruction. The job's limits come from a pure table (jobplan.go):
//     KILL_ON_JOB_CLOSE and DIE_ON_UNHANDLED_EXCEPTION always, the memory
//     limit, the active-process limit (processes, the program included: the
//     number as given, where Linux's pids.max counts tasks) and the job's
//     user-time limit when requested; BREAKAWAY_OK and SILENT_BREAKAWAY_OK
//     never, so a child that asks to break away is refused. On timeout,
//     cancel or a cap, and always after the program exits, the job is
//     terminated with TerminateJobObject, and the processes still in it are
//     counted as survivors. The job's CPU limit acts late (JSP-12: 8 s for
//     a 1 s limit), so it is best effort and the wall cap is the timeliness
//     guarantee; there is no file-size cap. A child over the process cap
//     fails to start rather than killing the run. This file set
//     cross-builds, vets and lints here; the job rows have not been run on
//     Windows through this code (the JSP-12 laptop run used the spike's
//     winjob.exe).
//
// Containment (extrun.ContainmentRungs, walked top-down; the run record
// names the rung used and the rungs that failed before it):
//
//  1. Linux, a per-run cgroup v2: a child of the operator's configured
//     parent (Executor.CgroupParent), else a transient systemd scope with
//     Delegate=yes started per run (a user scope needs no root; systemd 245
//     delegates only memory and pids). The trampoline joins it before exec
//     and refuses a cgroup that is the daemon's own or one of its
//     ancestors. Caps: memory.max with memory.swap.max = 0, pids.max
//     (counting tasks, threads included). The kill is cgroup.kill.
//  2. The isolation provider's pid namespace (bwrap --unshare-pid with
//     --die-with-parent): killing the launcher ends the namespace.
//  3. The process group plus, on Linux with the trampoline, a supervisor:
//     this binary in its supervise mode, the child subreaper of the program,
//     which sweeps every process re-parented to it when the program exits
//     or the run is stopped. Labelled "not contained".
//  4. Windows: the job object (always first there).
//
// After the final kill the executor looks for survivors by executable
// identity (device and inode of the program and the launcher, the same
// across namespaces) among this user's processes started during the run,
// and reports them. A process that escaped and still holds the output pipes
// marks the run Leftover. Ledger row SHR-1 in docs/security.md records
// these limits.
package host
