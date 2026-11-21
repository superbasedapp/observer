// Package sandboxseccomp is the syscall filter of the lightweight sandbox
// rows (gap G16, lane N2): a profile table, a decision table derived from it
// per architecture, and a classic BPF assembler, all in pure Go (no CGO, no
// libseccomp). The bwrap row hands the program to `bwrap --seccomp <fd>`;
// the process_lite row loads it itself after no_new_privs. Both read it back
// from /proc/<pid>/status; the cmd seams own that I/O.
//
// The one profile, ProfileObserverDefault, is "default-deny-where-safe": a
// DENY list of syscalls a coding agent never needs and that widen the attack
// surface, each answered with EPERM so a tool degrades instead of dying.
// Only a foreign architecture (and, on amd64, the x32 ABI) kills the
// process. An allow-list profile is out of scope (RK-32).
//
// Syscall numbers are per architecture (sysnum.go); a test pins both tables
// against golang.org/x/sys/unix. The package's own tests carry a BPF
// interpreter that runs every decision row against synthetic seccomp_data,
// so each row is proven without a kernel.
//
// The package is pure: no database/sql, net/http, os/exec or fsnotify
// (imports_test.go pins it).
package sandboxseccomp
