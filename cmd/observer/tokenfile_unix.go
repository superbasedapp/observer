//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// ensureTokenFilePrivate enforces the local listener token file's ownership
// and mode (P3-27): a file another account owns is refused, and group or other
// permission bits on a file of ours are removed before the token is used.
func ensureTokenFilePrivate(path string, info os.FileInfo) error {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("token file %s is owned by another account; refusing to use it", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil { //nolint:gosec // G703: writes under the user's own local state with the user's own rights
			return fmt.Errorf("token file %s is readable by other accounts and could not be made private: %w", path, err)
		}
	}
	return nil
}
