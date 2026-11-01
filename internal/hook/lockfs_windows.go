//go:build windows

package hook

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// lockCreateHeld reports whether an O_EXCL create of a settings lock file
// failed because the lock is held. On Windows a create of a name whose
// previous file is still being deleted (another holder released it while a
// third process had it open), or is open without delete sharing, fails with
// ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION, not "exists". Those are
// the lock being held or released, so the caller waits; before, they took
// the fail-open branch and the write ran unserialized, losing entries of
// hook_checksums.json under concurrent writers (Windows 11 Pro live run,
// PT-02).
func lockCreateHeld(err error) bool {
	return errors.Is(err, os.ErrExist) || errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

// removeLockFile removes a released lock file. A waiting contender that
// has the file open for a moment makes the delete fail with a sharing
// violation on Windows; the remove is retried briefly so the lock is never
// left behind for every other writer to time out on.
func removeLockFile(p string) {
	for i := 0; i < 100; i++ {
		err := os.Remove(p)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
