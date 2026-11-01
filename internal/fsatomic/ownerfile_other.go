//go:build !windows

package fsatomic

import "os"

// createOwnerOnly is an exclusive create with mode 0600.
func createOwnerOnly(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the caller names its own state file.
}

// isOwnerOnlyFile reads the open file's owner and permission bits (fstat).
func isOwnerOnlyFile(f *os.File) (bool, error) {
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	uid, known := fileOwnerUID(fi)
	return posixOwnerOnly(fi.Mode(), uid, known, os.Getuid()), nil
}

// posixOwnerOnly is the POSIX rule: the owner is self (when the platform
// reports an owner) and no group or other bit is set.
func posixOwnerOnly(mode os.FileMode, owner uint32, ownerKnown bool, self int) bool {
	if mode.Perm()&0o077 != 0 {
		return false
	}
	if !ownerKnown {
		return true
	}
	return self >= 0 && uint64(owner) == uint64(self)
}
