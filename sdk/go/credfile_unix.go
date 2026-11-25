//go:build !windows

package superbased

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// readOwnerOnlyFile reads at most limit bytes of path under the credential
// file rules (contract destination.md section 6): no symlink, a regular file,
// no group or other permission bits, owned by this user.
func readOwnerOnlyFile(path string, limit int64) ([]byte, string) {
	raw, problem, _ := readOwnerOnly(path, limit)
	return raw, problem
}

// readOwnerOnly is readOwnerOnlyFile with the refused rule's reason
// (credential-file-cases.json reasons; "" for an I/O error).
func readOwnerOnly(path string, limit int64) ([]byte, string, string) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, "cannot read the SDK credential file: " + errText(err), ""
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, "the SDK credential file is a symlink; refused", reasonSymlink
	}
	if !fi.Mode().IsRegular() {
		return nil, "the SDK credential file is not a regular file; refused", reasonNotRegular
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, "the SDK credential file is readable by other users; refused (chmod 600)", reasonMode
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != processUID() {
		return nil, "the SDK credential file is owned by another user; refused", reasonOwner
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, "cannot read the SDK credential file: " + errText(err), ""
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, "cannot read the SDK credential file: " + errText(err), ""
	}
	return raw, "", ""
}

func errText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// readSDKHeldFile reads the SDK-held credential file under the same unix
// rules as the machine's file: (bytes, problem, reason, missing). missing is
// true (and problem "") when there is no file at path.
func readSDKHeldFile(path, _ string, limit int64) ([]byte, string, string, bool) {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, "", "", true
	}
	raw, problem, reason := readOwnerOnly(path, limit)
	return raw, problem, reason, false
}
