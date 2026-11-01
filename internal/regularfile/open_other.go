//go:build !unix && !windows

package regularfile

import (
	"fmt"
	"os"
)

// openForRead opens path read-only. Off unix and Windows (plan9, js,
// wasip1) there is no named pipe that a plain open blocks on at a settings
// path; Read still stats the open descriptor and refuses anything that is
// not a regular file.
func openForRead(path string) (*os.File, error) {
	return os.Open(path)
}

// openNoFollow opens path read-only for ReadNoFollow on an OS with neither
// O_NOFOLLOW nor a reparse-point open flag. A plain open follows a link, so
// this is best effort only: the open descriptor must compare os.SameFile
// with ReadNoFollow's Lstat. Where the OS loads a file's identity lazily at
// compare time, that check sees what is at the path then, not what the
// Lstat saw; the descriptor stat in readOpen still refuses anything that is
// not a regular file.
func openNoFollow(path string, lfi os.FileInfo) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	ofi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if lfi == nil || !os.SameFile(lfi, ofi) {
		_ = f.Close()
		return nil, &refusal{msg: fmt.Sprintf("%s changed while it was opened", path), kind: ErrNotRegular}
	}
	return f, nil
}
