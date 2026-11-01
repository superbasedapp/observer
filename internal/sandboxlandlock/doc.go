// Package sandboxlandlock is the pure planner of the `process_lite` sandbox
// row (sandbox plan v2 sections 4.1 and 13 P3, lane SBX-P3B; beta, register
// entry LIN-1): Landlock alone, no namespaces, for Linux hosts that block
// unprivileged user namespaces (bwrap's userns_denied).
//
// It decides everything and does nothing: the Landlock ABI table (abi.go),
// the probe ladder over injected facts (probe.go), the ruleset mirrored from
// the run's bind plan (rules.go) and the TCP allow-list of every port but
// Observer's own (ports.go). The real landlock_create_ruleset,
// landlock_add_rule and landlock_restrict_self calls, the self-test and the
// exec live in cmd/observer (terminal_sandbox_landlock_linux.go).
//
// What the row gives and does not give is stated in docs/security.md row
// SBX-BE-17: the filesystem is an allow-list (only the workspace, the
// tool's state, the run's temp and socket dirs are writable; the observer
// directory, the daemon's relay endpoint and the attach socket are not
// reachable, the latter two because ABI 9 handles connecting to a unix
// socket path), TCP is an allow-list of every port except Observer's own,
// UDP is unrestricted below ABI 10, and there is no PID namespace, private
// /proc or private network.
//
// The package is pure: no database/sql, net, net/http, os, os/exec, syscall
// or fsnotify, and no observer-internal import (imports_test.go pins it).
package sandboxlandlock
