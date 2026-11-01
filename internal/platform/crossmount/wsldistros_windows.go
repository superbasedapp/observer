//go:build windows

package crossmount

import (
	"context"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// runWSLList runs the running-distro list with no console window (the
// daemon has none to share) and returns its standard output.
func runWSLList(ctx context.Context, exe string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, exe, "--list", "--running", "--quiet") // #nosec G204 -- fixed system path and fixed arguments
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd.Output()
}

// wslExePath is wsl.exe in the System32 directory the Windows API reports
// (GetSystemDirectory), never %SystemRoot% from the environment (FU-209).
// A test binary never runs wsl.exe (runningWSLDistros' testBinaryGuard).
func wslExePath() string {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return wslExeIn("")
	}
	return wslExeIn(dir)
}
