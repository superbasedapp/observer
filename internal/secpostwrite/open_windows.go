//go:build windows

package secpostwrite

import "os"

// openNoFollow opens path read-only. Windows has no O_NOFOLLOW; the Lstat
// symlink refusal and the same-file check after open carry the guarantee.
func openNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}
