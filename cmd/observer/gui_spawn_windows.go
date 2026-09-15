//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// spawnDetached starts a GUI application as a fully DETACHED Windows process
// and returns its os.Process. It is the one exec seam of the GUI launch path
// (docs/plans/ide-desktop-launch-plan-2026-09-03.md §2.4); everything above it
// — resolution, argv composition, the wrap decision — is pure.
//
// Three deliberate choices, each of which is load-bearing:
//
//   - DETACHED_PROCESS: the child gets NO console. Without it a
//     console-subsystem launcher inherits the daemon's console (or, under a
//     service, none at all) and a stray console window can flash on the
//     operator's desktop.
//   - CREATE_NEW_PROCESS_GROUP: the child is not in the daemon's process group,
//     so a Ctrl-C / Ctrl-Break delivered to the daemon's console never reaches
//     the IDE the operator is working in.
//   - NO JOB OBJECT. The daemon puts its PTY children in a kill-on-close job
//     (internal/jobobject) precisely so a terminal cannot outlive the daemon.
//     A GUI launch is the OPPOSITE contract: the operator's editor must survive
//     a daemon restart, so it is deliberately never added to that job. This is
//     the single most important difference between the two spawn paths — do not
//     "unify" them.
//
// Stdio is wired to NUL EXPLICITLY rather than left nil. Leaving the fields nil
// produces the same child-visible result, but os/exec then opens the null
// device itself and only closes those handles in cmd.Wait() — which this path
// never calls (it reaps through os.Process.Wait, since the caller holds a
// Process, not a Cmd). Opening and closing them here keeps the daemon's handle
// count flat across launches. The child must not share the daemon's own streams
// either way: a GUI app has no use for them, and inheriting a pipe that closes
// on daemon exit can kill it.
func spawnDetached(argv []string, dir string, env []string) (*os.Process, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("gui spawn: empty argv")
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("gui spawn: open %s: %w", os.DevNull, err)
	}
	defer func() { _ = null.Close() }() // the child has its own handles after Start

	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 — argv is server-derived (registry row + resolved binary + validated dir)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = null, null, null
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("gui spawn %s: %w", argv[0], err)
	}
	return cmd.Process, nil
}
