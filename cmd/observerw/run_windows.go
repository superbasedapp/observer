//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// run starts the observer.exe that sits beside this program with args, no
// console window and no visible output, waits for it and returns its exit
// code. Output has nowhere to go from a windowless program, so it is
// discarded; `observer setup launch` writes the daemon's own log file.
func run(args []string) int {
	self, err := os.Executable()
	if err != nil {
		return 2
	}
	target := filepath.Join(filepath.Dir(self), "observer.exe")
	cmd := exec.Command(target, args...) //nolint:gosec // G204/G702: the sibling observer.exe, arguments passed through unchanged
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		return 2
	}
	return 0
}
