//go:build !windows

package hook

import (
	"errors"
	"os"
)

// lockCreateHeld reports whether an O_EXCL create of a settings lock file
// failed because the lock is held (lockfs_windows.go has the Windows
// errors that mean the same).
func lockCreateHeld(err error) bool { return errors.Is(err, os.ErrExist) }

// removeLockFile removes a released lock file.
func removeLockFile(p string) { _ = os.Remove(p) }
