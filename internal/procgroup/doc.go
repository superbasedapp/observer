// Package procgroup starts a child process in its own process group and
// ends the whole group, so a child that forks helpers of its own cannot
// leave them running after a deadline.
//
// Set puts the child in a new process group before it starts. Terminate
// sends SIGTERM to the group, waits up to a grace period for it to exit and
// SIGKILLs whatever is left. On Windows there is no POSIX process group: Set
// does nothing and Terminate kills the child process itself, so a
// grandchild is not reaped there.
//
// The org server's external insight harness (internal/orgserver/harness),
// the reference pi agent (cmd/observer-org-pi-agent) and the benchmark
// runner (cmd/observer) share it. It imports only os/exec, syscall and
// time.
package procgroup
