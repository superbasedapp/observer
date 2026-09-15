// Package sshforward owns the lifecycle of the instance switcher's SSH local
// port forwards (docs/plans/ssh-remote-profiles-plan-2026-08-27.md §12 D2).
//
// # What it does
//
// An "instance" is a remote machine that runs its OWN Observer install. This
// package opens `ssh -N -L 127.0.0.1:<local>:127.0.0.1:<dashboard_port>` to
// that machine so the operator's browser can reach the REMOTE dashboard on
// this machine's loopback, and it closes the forward again on request or at
// daemon exit.
//
// # What it is NOT
//
// It is not a tunnel manager and it must never become one. Everything about a
// forward except the local port is read from an operator-authored
// [[terminal.ssh.profiles]] entry: the destination host, the remote port, the
// key, the jump host. A caller supplies a profile NAME and nothing else — the
// same authorization shape termsvc.LaunchSSH uses — so a request can choose
// WHICH configured machine to reach and can never nominate a new one, a new
// port, or a new direction. Only -L is composed; never -R, never -D, never -w.
//
// It also does NOT proxy the remote dashboard. Observer opens the forward and
// hands back a loopback port; the browser talks to the remote daemon directly
// through it, so the REMOTE install's own auth posture is what governs there.
// Nothing about this node's session or capability class is lent to it.
//
// # Host keys
//
// A -N child has no terminal and nobody to answer an unknown-host prompt, so
// the composed argv sets BatchMode=yes while leaving StrictHostKeyChecking=ask
// untouched. The practical effect is that an unknown host is REFUSED, never
// auto-accepted. Rather than surface that as an opaque ssh failure, Connect
// pre-flights known_hosts and returns ErrHostKeyUnknown with the honest fix
// ("open an SSH terminal to this profile once and accept the host key"). The
// pre-flight is a better ERROR MESSAGE, not the enforcement: ssh itself remains
// the thing that refuses, so a pre-flight that cannot reach a verdict lets the
// attempt proceed rather than guessing.
//
// # Module shape
//
// CLAUDE.md "Module Boundaries" #1: no database/sql, no net/http, no fsnotify,
// and no observer-internal import beyond the pure sshprofile package — pinned
// by imports_test.go. Process spawning, port allocation, the readiness probe
// and the known-hosts check are all injected seams with OS-backed defaults in
// spawn.go, following internal/termsession's Spawner precedent.
package sshforward
