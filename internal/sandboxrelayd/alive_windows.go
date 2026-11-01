//go:build windows

package sandboxrelayd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// alive_windows.go is the run liveness lock on native Windows: an
// exclusive LockFileEx byte-range lock the helper holds for its whole
// life. The kernel drops it when the helper's handle closes, which happens
// when the process ends in any way (TerminateProcess included), the same
// guarantee flock gives on unix. The handle is opened with every share
// mode so the daemon can probe it and the file can be renamed into place
// while locked; it is not inheritable, so the box the helper starts never
// holds it.

// openShared opens or creates path with every share mode.
func openShared(path string, create bool) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	disp := uint32(windows.OPEN_EXISTING)
	if create {
		disp = windows.CREATE_NEW
	}
	return windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, disp,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

// lockNB tries an exclusive lock on the first byte without waiting.
func lockNB(h windows.Handle) error {
	var ol windows.Overlapped
	return windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
}

func holdAlive(dir, runID string) (func(), error) {
	if err := MkdirAllOwned(dir); err != nil {
		return nil, fmt.Errorf("sandboxrelayd.HoldRun: %w", err)
	}
	final := filepath.Join(dir, runID+aliveSuffix)
	tmp := filepath.Join(dir, "."+runID+aliveSuffix)
	_ = os.Remove(tmp)
	h, err := openShared(tmp, true)
	if err != nil {
		return nil, fmt.Errorf("sandboxrelayd.HoldRun: %w", err)
	}
	fail := func(err error) (func(), error) {
		_ = windows.CloseHandle(h)
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("sandboxrelayd.HoldRun: %w", err)
	}
	if err := lockNB(h); err != nil {
		return fail(err)
	}
	// The lock file is the token user's even when the helper is elevated
	// (owned.go, B2).
	if err := OwnRecord(tmp); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fail(err)
	}
	return func() {
		_ = os.Remove(final)
		_ = windows.CloseHandle(h)
	}, nil
}

func probeAlive(path string) helperState {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return helperUnknown
	}
	h, err := openShared(path, false)
	if err != nil {
		return helperUnknown
	}
	f := os.NewFile(uintptr(h), path)
	defer func() { _ = f.Close() }()
	if !privateFile(path, f, fi) {
		return helperUnknown
	}
	err = lockNB(h)
	switch {
	case err == nil:
		var ol windows.Overlapped
		_ = windows.UnlockFileEx(h, 0, 1, 0, &ol)
		return helperGone
	case errors.Is(err, windows.ERROR_LOCK_VIOLATION):
		return helperHeld
	}
	return helperUnknown
}

// dropAlive is not offered on Windows: no helper there keeps its container
// through a daemon hangup (re-adoption is Linux only).
func dropAlive(string) {}
