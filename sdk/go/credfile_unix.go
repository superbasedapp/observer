//go:build !windows

package superbased

import (
	"io"
	"os"
	"syscall"
)

// readOwnerOnlyFile reads at most limit bytes of path under the credential
// file rules (contract destination.md section 6): no symlink, a regular file,
// no group or other permission bits, owned by this user.
func readOwnerOnlyFile(path string, limit int64) ([]byte, string) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, "cannot read the SDK credential file: " + errText(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, "the SDK credential file is a symlink; refused"
	}
	if !fi.Mode().IsRegular() {
		return nil, "the SDK credential file is not a regular file; refused"
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, "the SDK credential file is readable by other users; refused (chmod 600)"
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return nil, "the SDK credential file is owned by another user; refused"
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, "cannot read the SDK credential file: " + errText(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, "cannot read the SDK credential file: " + errText(err)
	}
	return raw, ""
}

func errText(err error) string {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err.Error()
	}
	return err.Error()
}
