package fsatomic

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Owner-only credential files (R-160): the one owner of how Observer
// creates a file only its own user may read, on every OS. On POSIX that is
// an exclusive create with mode 0600. On Windows permission bits mean
// nothing (the file would inherit the profile directory's ACL, which an
// administrator or a roaming-profile policy may have widened), so the file
// is created with a protected DACL that grants full access to the token
// user and SYSTEM only, and no inherited ACE reaches it (ownerfile_windows.go).
// The browser ingest token, the remote pairing secret's hash, the process
// bridge token and the MXC run's config file are created this way.

// CreateOwnerOnly creates path exclusively (an existing path fails with an
// error matching fs.ErrExist, so a file planted at path is never written
// through) and returns it open for writing, readable by this user only.
func CreateOwnerOnly(path string) (*os.File, error) {
	f, err := createOwnerOnly(path)
	if err != nil {
		return nil, fmt.Errorf("fsatomic.CreateOwnerOnly: %w", err)
	}
	return f, nil
}

// CreateTempOwnerOnly is os.CreateTemp with CreateOwnerOnly's access: a new
// file in dir whose name is pattern with its last "*" (or, without one, its
// end) replaced by a random string.
func CreateTempOwnerOnly(dir, pattern string) (*os.File, error) {
	if strings.ContainsRune(pattern, filepath.Separator) || strings.ContainsRune(pattern, '/') {
		return nil, fmt.Errorf("fsatomic.CreateTempOwnerOnly: pattern %q contains a path separator", pattern)
	}
	prefix, suffix := pattern, ""
	if i := strings.LastIndex(pattern, "*"); i >= 0 {
		prefix, suffix = pattern[:i], pattern[i+1:]
	}
	for try := 0; try < 100; try++ {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, fmt.Errorf("fsatomic.CreateTempOwnerOnly: %w", err)
		}
		f, err := createOwnerOnly(filepath.Join(dir, prefix+hex.EncodeToString(b[:])+suffix))
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("fsatomic.CreateTempOwnerOnly: %w", err)
		}
		return f, nil
	}
	return nil, fmt.Errorf("fsatomic.CreateTempOwnerOnly: no free name for %q in %s", pattern, dir)
}

// IsOwnerOnly reports whether the file at path is this user's and readable
// by this user only. It opens path and judges the open file
// (FileIsOwnerOnly); a caller that goes on to read the file should open it
// itself and call FileIsOwnerOnly on that handle, so the file it reads is
// the file that was judged.
func IsOwnerOnly(path string) (bool, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the caller names its own state file.
	if err != nil {
		return false, fmt.Errorf("fsatomic.IsOwnerOnly: %w", err)
	}
	defer func() { _ = f.Close() }()
	ok, err := isOwnerOnlyFile(f)
	if err != nil {
		return false, fmt.Errorf("fsatomic.IsOwnerOnly: %w", err)
	}
	return ok, nil
}

// FileIsOwnerOnly reports whether the open file f is this user's and
// readable by this user only, read from the handle itself (WINFIX4 audit
// finding 5), so a file swapped in between an open and a check by path, or
// a file another account planted with a user and SYSTEM DACL, is refused:
// on POSIX the owner uid is this process's and no group or other permission
// bit is set (fstat); on Windows the owner is the token user and the DACL
// is protected with every entry allowing only that user or SYSTEM
// (GetSecurityInfo on the handle).
func FileIsOwnerOnly(f *os.File) (bool, error) {
	ok, err := isOwnerOnlyFile(f)
	if err != nil {
		return false, fmt.Errorf("fsatomic.FileIsOwnerOnly: %w", err)
	}
	return ok, nil
}
