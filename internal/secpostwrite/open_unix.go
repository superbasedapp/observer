//go:build !windows

package secpostwrite

import (
	"os"
	"syscall"
)

// openNoFollow opens path read-only refusing a symlink in the last
// component (O_NOFOLLOW).
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
