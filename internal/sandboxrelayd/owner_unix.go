//go:build unix

package sandboxrelayd

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByMe reports whether fi belongs to this process's user.
func ownedByMe(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// privateFile reports whether an opened record is this user's and no group
// or other may write it.
func privateFile(_ string, _ *os.File, fi fs.FileInfo) bool {
	return fi.Mode().Perm()&0o022 == 0 && ownedByMe(fi)
}

// privateDir reports the same for a record's directory.
func privateDir(_ string, fi fs.FileInfo) bool {
	return fi.Mode().Perm()&0o022 == 0 && ownedByMe(fi)
}

// oNoFollow refuses to open through a final symlink.
const oNoFollow = syscall.O_NOFOLLOW

// oNonblock opens a guest-writable path without blocking: a FIFO swapped in
// for a file returns at once instead of waiting for a writer.
const oNonblock = syscall.O_NONBLOCK

// clearNonblock puts an opened regular file back in blocking mode.
func clearNonblock(f *os.File) {
	rc, err := f.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) { _ = syscall.SetNonblock(int(fd), false) }) //nolint:gosec // G115: a descriptor number
}
