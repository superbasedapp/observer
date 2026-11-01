//go:build windows

package dblease

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// available is true on windows: LockFileEx with LOCKFILE_FAIL_IMMEDIATELY
// is the non-blocking exclusive lock (lane sec-deps4, ledger SECP-8: one
// dependency scan at a time per machine held only on unix before).
const available = true

// tryAcquireFile opens (creating if needed) the lock file at path and
// takes a non-blocking exclusive byte-range lock on its first byte.
// ERROR_LOCK_VIOLATION means another handle (this process or another)
// holds it: a normal "not acquired" result, not an error. As with flock,
// the lock belongs to the open handle, and windows drops it when the
// handle closes or the process exits, so a lease is never stranded.
func tryAcquireFile(path string) (release func(), acquired bool, err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644) //nolint:gosec // G304: path is built from the operator's own DB dir + a fixed lease name, never request data.
	if err != nil {
		return noop, false, fmt.Errorf("dblease: open lock file %s: %w", path, err)
	}
	h := windows.Handle(f.Fd())
	ol := new(windows.Overlapped)
	if lerr := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol); lerr != nil {
		_ = f.Close()
		if errors.Is(lerr, windows.ERROR_LOCK_VIOLATION) || errors.Is(lerr, windows.ERROR_IO_PENDING) {
			return noop, false, nil
		}
		return noop, false, fmt.Errorf("dblease: LockFileEx %s: %w", path, lerr)
	}
	released := false
	release = func() {
		if released {
			return
		}
		released = true
		_ = windows.UnlockFileEx(h, 0, 1, 0, ol)
		_ = f.Close()
	}
	return release, true, nil
}
