//go:build unix

package fsatomic

import (
	"os"
	"syscall"
)

// fileOwnerUID is the owner uid fstat reported.
func fileOwnerUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
