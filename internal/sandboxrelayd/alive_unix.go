//go:build unix

package sandboxrelayd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// holdAlive makes <dir>/<runID>.alive locked: created under a temporary
// name (exclusively, never through a link), locked, then renamed into
// place. The descriptor is close-on-exec, so the box the helper starts
// never inherits the lock.
func holdAlive(dir, runID string) (func(), error) {
	if err := MkdirAllOwned(dir); err != nil {
		return nil, fmt.Errorf("sandboxrelayd.HoldRun: %w", err)
	}
	final := filepath.Join(dir, runID+aliveSuffix)
	tmp := filepath.Join(dir, "."+runID+aliveSuffix)
	_ = os.Remove(tmp)                                                           //nolint:gosec // G703: under the 0700 runs dir; runID passed ValidRunID
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600) //nolint:gosec // G703: under the 0700 runs dir; runID passed ValidRunID
	if err != nil {
		return nil, fmt.Errorf("sandboxrelayd.HoldRun: %w", err)
	}
	fail := func(err error) (func(), error) {
		_ = f.Close()
		_ = os.Remove(tmp) //nolint:gosec // G703: under the 0700 runs dir; runID passed ValidRunID
		return nil, fmt.Errorf("sandboxrelayd.HoldRun: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // G115: a descriptor number
		return fail(err)
	}
	if err := OwnRecord(tmp); err != nil { // owned.go: a no-op off Windows, kept so every site is the same
		return fail(err)
	}
	if err := os.Rename(tmp, final); err != nil { //nolint:gosec // G703: under the 0700 runs dir; runID passed ValidRunID
		return fail(err)
	}
	heldAlive.Lock()
	heldAlive.files[final] = f
	heldAlive.Unlock()
	return func() {
		heldAlive.Lock()
		delete(heldAlive.files, final)
		heldAlive.Unlock()
		_ = os.Remove(final) //nolint:gosec // G703: under the 0700 runs dir; runID passed ValidRunID
		_ = f.Close()
	}, nil
}

// heldAlive is the lock files this process holds through holdAlive, by
// final path, so DropRunLock can release one without removing it.
var heldAlive = struct {
	sync.Mutex
	files map[string]*os.File
}{files: map[string]*os.File{}}

// dropAlive closes the descriptor that holds path's lock, which releases
// the lock and leaves the file.
func dropAlive(path string) {
	heldAlive.Lock()
	f := heldAlive.files[path]
	delete(heldAlive.files, path)
	heldAlive.Unlock()
	if f != nil {
		_ = f.Close()
	}
}

// probeAlive tries the lock without waiting: taken means nobody held it.
func probeAlive(path string) helperState {
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return helperUnknown
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() || !ownedByMe(fi) {
		return helperUnknown
	}
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // G115: a descriptor number
	switch {
	case err == nil:
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:gosec // G115: a descriptor number
		return helperGone
	case errors.Is(err, syscall.EWOULDBLOCK):
		return helperHeld
	}
	return helperUnknown
}
