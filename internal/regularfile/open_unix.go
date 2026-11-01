//go:build unix

package regularfile

import (
	"os"
	"syscall"
)

// openForRead opens path read-only and non-blocking: a FIFO that replaced a
// regular file after Read's stat opens at once instead of waiting
// for a writer, and the descriptor stat that follows refuses it. O_NONBLOCK
// changes nothing for a regular file.
func openForRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

// openNoFollow is openForRead that also refuses a symlink at the leaf
// (O_NOFOLLOW: the open fails, ELOOP on Linux and macOS). ReadNoFollow's
// Lstat is not needed here; the descriptor stat that follows decides.
func openNoFollow(path string, _ os.FileInfo) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
