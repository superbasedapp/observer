//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// spawnDetached starts a GUI application as a fully DETACHED POSIX process and
// returns its os.Process. It is the one exec seam of the GUI launch path
// (docs/plans/ide-desktop-launch-plan-2026-09-03.md §2.4); everything above it
// — resolution, argv composition, the wrap decision — is pure.
//
// Setsid puts the child in its OWN session and process group, which is what
// makes the launch survive the daemon: a SIGHUP or SIGINT delivered to the
// daemon's session never reaches the operator's editor, and the app is not
// reaped when the daemon's controlling terminal goes away. It is the exact
// opposite of the PTY path's contract (a terminal child MUST die with its
// daemon) — do not "unify" the two spawn paths.
//
// Stdio is wired to /dev/null EXPLICITLY rather than left nil. Leaving the
// fields nil produces the same child-visible result, but os/exec then opens the
// null device itself and only closes those descriptors in cmd.Wait() — which
// this path never calls (it reaps through os.Process.Wait, since the caller
// holds a Process, not a Cmd). Opening and closing them here keeps the daemon's
// descriptor count flat across launches. The child must not share the daemon's
// own streams either way: a GUI app has no use for them, and inheriting a pipe
// that closes on daemon exit can kill it.
//
// The darwin case needs no separate file: `open -a <App>` is an ordinary exec
// here; open(1) is EXPECTED (per Apple's open(1) documentation) to hand the
// caller's environment to the application it launches on a cold start — which
// is what the child-env wrap relies on. NOT live-verified (plan §9.6: no darwin
// run this session); the launch also records open(1)'s own pid/exit, not the app's.
func spawnDetached(argv []string, dir string, env []string) (*os.Process, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("gui spawn: empty argv")
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("gui spawn: open %s: %w", os.DevNull, err)
	}
	defer func() { _ = null.Close() }() // the child has its own descriptors after Start

	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 — argv is server-derived (registry row + resolved binary + validated dir)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = null, null, null
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("gui spawn %s: %w", argv[0], err)
	}
	return cmd.Process, nil
}
