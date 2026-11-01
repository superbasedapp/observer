//go:build unix

package diag

import (
	"os"
	"syscall"
)

// ownedByRoot reports whether fi's owner is uid 0. known is false when the
// platform's stat carries no owner.
func ownedByRoot(fi os.FileInfo) (root, known bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, false
	}
	return st.Uid == 0, true
}
