//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// defaultSetupOS is the macOS and Linux half of `observer setup`. There is no
// per-user Path or sign-in entry to own here (a shell profile and
// `observer service install` cover those), so those seams stay nil and the
// commands say so; launching and stopping the daemon work the same way.
func defaultSetupOS() setupOS {
	return setupOS{
		spawnDetached: spawnDetachedUnix,
		stopPID:       stopPIDUnix,
		link: func(target, alias string) error {
			return os.Symlink(filepath.Base(target), alias)
		},
	}
}

// spawnDetachedUnix starts argv in its own session (so closing the terminal
// does not stop it), its output appended to logPath.
func spawnDetachedUnix(argv []string, logPath string) error {
	if len(argv) == 0 {
		return errors.New("empty argv")
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // the daemon log beside the operator's own database
	if err != nil {
		return err
	}
	defer func() { _ = logf.Close() }()
	null, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = null.Close() }()
	fmt.Fprintf(logf, "\n--- %s started by observer setup launch ---\n", time.Now().Format(time.RFC3339))
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- argv[0] is this binary, the rest fixed
	cmd.Stdin, cmd.Stdout, cmd.Stderr = null, logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// stopPIDUnix sends SIGTERM (the daemon drains and exits cleanly) and waits
// for the process to go.
func stopPIDUnix(pid int, timeout time.Duration) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("pid %d did not exit within %s", pid, timeout)
}
