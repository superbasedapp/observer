//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/marmutapp/superbased-observer/internal/setup"
)

// defaultSetupOS is the Windows half of `observer setup`: HKCU\Environment
// for the per-user Path, HKCU\...\Run for start at sign-in (no elevation for
// either), detached process start with no console, and hard links.
func defaultSetupOS() setupOS {
	return setupOS{
		readUserPath:  readUserPathWindows,
		writeUserPath: writeUserPathWindows,
		readRun:       readRunWindows,
		writeRun:      writeRunWindows,
		deleteRun:     deleteRunWindows,
		spawnDetached: spawnDetachedWindows,
		stopPID:       stopPIDWindows,
		link:          os.Link,
	}
}

const userEnvKey = `Environment`

func readUserPathWindows() (string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, userEnvKey, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer func() { _ = k.Close() }()
	// GetStringValue returns a REG_EXPAND_SZ value unexpanded, which is
	// what must be written back so %USERPROFILE%-style entries survive.
	v, _, err := k.GetStringValue("Path")
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	return v, err
}

func writeUserPathWindows(value string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, userEnvKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	// Keep the value's existing type; a fresh value is REG_EXPAND_SZ like
	// the one Windows itself creates.
	_, typ, gerr := k.GetStringValue("Path")
	if gerr == nil && typ == registry.SZ {
		err = k.SetStringValue("Path", value)
	} else {
		err = k.SetExpandStringValue("Path", value)
	}
	if err != nil {
		return err
	}
	broadcastEnvironmentChange()
	return nil
}

// broadcastEnvironmentChange tells Explorer (and so every terminal opened
// from now on) that the user environment changed, the same WM_SETTINGCHANGE
// [Environment]::SetEnvironmentVariable sends. Best-effort with a short
// timeout so a hung window cannot stall setup.
func broadcastEnvironmentChange() {
	const (
		hwndBroadcast   = 0xffff
		wmSettingChange = 0x001A
		smtoAbortIfHung = 0x0002
	)
	user32 := windows.NewLazySystemDLL("user32.dll")
	proc := user32.NewProc("SendMessageTimeoutW")
	env, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}
	var result uintptr
	_, _, _ = proc.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)), smtoAbortIfHung, 5000, uintptr(unsafe.Pointer(&result)))
}

func readRunWindows() (string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, setup.RunKeyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue(setup.RunValueName)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	return v, err
}

func writeRunWindows(value string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, setup.RunKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	return k.SetStringValue(setup.RunValueName, value)
}

func deleteRunWindows() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, setup.RunKeyPath, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	if err := k.DeleteValue(setup.RunValueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

// spawnDetachedWindows starts argv with no console window and no shared
// process group, its output appended to logPath. The same flags as the GUI
// launch path (gui_spawn_windows.go) plus CREATE_NO_WINDOW, and no job
// object: the daemon must outlive the process that started it.
func spawnDetachedWindows(argv []string, logPath string) error {
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
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// stopPIDWindows ends a process and waits for it to exit so its binary can be
// deleted. Windows has no SIGTERM for a console-less process; the database
// is SQLite in WAL mode, which recovers from an abrupt stop.
func stopPIDWindows(pid int, timeout time.Duration) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid)) //nolint:gosec // a pid from the start lock
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := windows.TerminateProcess(h, 1); err != nil {
		return err
	}
	ev, err := windows.WaitForSingleObject(h, uint32(timeout/time.Millisecond))
	if err != nil {
		return err
	}
	if ev != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("pid %d did not exit within %s", pid, timeout)
	}
	return nil
}
