//go:build unix

package cloudcred

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// openNoFollow is the O_NOFOLLOW open flag: the kernel itself refuses a
// symlinked credential file even if it is swapped in after the Lstat check.
const openNoFollow = syscall.O_NOFOLLOW

// checkOwner refuses a credential path owned by anyone other than this process
// user (root is accepted, since a root-owned 0600 file is readable only by a
// process already running as root). A foreign-owned file or directory means
// somebody else controls the bytes we would trust.
func checkOwner(path string, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil // unknown stat shape: the mode check is the guarantee
	}
	uid := os.Getuid()
	if uid < 0 {
		return nil
	}
	if int(st.Uid) != uid && st.Uid != 0 {
		return fmt.Errorf("cloudcred: %s is owned by uid %d, not this process's uid %d", path, st.Uid, uid)
	}
	return nil
}

// checkOwnerFile re-verifies ownership on the OPEN handle (fstat), closing the
// window between the path Lstat and the open.
func checkOwnerFile(path string, _ *os.File, fi fs.FileInfo) error {
	return checkOwner(path, fi)
}

// fileFallbackSecure reports whether this platform build's file fallback
// (fileStore) has verified owner+symlink protections sufficient to trust with
// cloud credentials when the OS keychain is unavailable. Unix does: every
// read/write refuses a symlinked path via O_NOFOLLOW (openNoFollow, closing
// the Lstat-to-open TOCTOU window at the kernel level) and verifies POSIX
// ownership on both the path and the open handle (checkOwner /
// checkOwnerFile). That meets the CI-P2 contract, so Open() (cred.go) selects
// fileStore here instead of failing closed. See fileFallbackSecure in
// cred_other.go for the non-unix (fails-closed) counterpart.
func fileFallbackSecure() bool { return true }
