package regularfile

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrNotRegular is wrapped by Read's refusal of a path that is not a
// regular file (a FIFO, a device, a directory), at the stat or on the open
// descriptor.
var ErrNotRegular = errors.New("not a regular file")

// ErrTooLarge is wrapped by Read's refusal of a file larger than the cap,
// at the stat or after reading one byte past it.
var ErrTooLarge = errors.New("larger than the cap")

// Read is the one capped regular-file read of a vendor settings file. It
// refuses anything that is not a regular file (a FIFO, a device, a
// directory) and anything larger than maxBytes, without reading it: the path
// is stat'ed first (a symlink is followed, a dotfile manager's link to a
// regular file is fine), then opened non-blocking where the OS has FIFOs
// (openForRead) and stat'ed again on the open descriptor, so a file swapped
// to a FIFO between the two can neither hang the read nor be read. At most
// maxBytes+1 bytes are read, so a file that grew past the cap after the stat
// is refused too. A missing file is an error wrapping os.ErrNotExist; the
// two refusals wrap ErrNotRegular and ErrTooLarge.
func Read(path string, maxBytes int64) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, notRegular(path)
	}
	if fi.Size() > maxBytes {
		return nil, tooLarge(path, maxBytes)
	}
	f, err := openForRead(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, _, err := readOpen(f, path, maxBytes)
	return b, err
}

// ReadNoFollow is Read for a file that must be the file itself, never a
// link to one: an administrator's file whose owner the caller checks
// (internal/hook readManagedHooksFile). The path is Lstat'ed first only to
// refuse a link, a FIFO or a device without opening it; the verdict is the
// open descriptor's, and what the open guarantees is per OS (openNoFollow):
//
//   - unix: O_RDONLY|O_NONBLOCK|O_NOFOLLOW, so a symlink at the leaf fails
//     the open and a FIFO opens at once;
//   - Windows: CreateFile with FILE_FLAG_OPEN_REPARSE_POINT, so a symbolic
//     link, junction or other reparse point opens as itself and is refused
//     on the handle's own attributes (there is no FIFO to block on);
//   - any other OS: best effort, a plain open compared os.SameFile with the
//     Lstat.
//
// The descriptor is stat'ed and must be a regular file within maxBytes, and
// at most maxBytes+1 bytes are read. The descriptor's FileInfo is returned
// with the bytes, so a caller's mode or owner check that reads that
// FileInfo judges the file that was read, not a path stat a swap can
// outdate. A missing file (one removed between the Lstat and the open
// included) is an error wrapping os.ErrNotExist; the refusals wrap
// ErrNotRegular (a link included) and ErrTooLarge.
func ReadNoFollow(path string, maxBytes int64) ([]byte, os.FileInfo, error) {
	lfi, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !lfi.Mode().IsRegular() {
		return nil, nil, notRegular(path)
	}
	if lfi.Size() > maxBytes {
		return nil, nil, tooLarge(path, maxBytes)
	}
	f, err := openNoFollow(path, lfi)
	if err != nil {
		// A link swapped in after the Lstat fails the no-follow open (ELOOP
		// on Linux and macOS; refused on the handle on Windows): name it as
		// the refusal it is.
		if again, lerr := os.Lstat(path); lerr == nil && !again.Mode().IsRegular() {
			return nil, nil, notRegular(path)
		}
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	return readOpen(f, path, maxBytes)
}

// readOpen is the descriptor half of both reads: the open file must be a
// regular file within maxBytes, and at most maxBytes+1 bytes are read.
func readOpen(f *os.File, path string, maxBytes int64) ([]byte, os.FileInfo, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, notRegular(path)
	}
	if fi.Size() > maxBytes {
		return nil, nil, tooLarge(path, maxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, nil, tooLarge(path, maxBytes)
	}
	return b, fi, nil
}

func notRegular(path string) error {
	return &refusal{msg: fmt.Sprintf("%s is not a regular file", path), kind: ErrNotRegular}
}

func tooLarge(path string, maxBytes int64) error {
	return &refusal{msg: fmt.Sprintf("%s is larger than %d bytes", path, maxBytes), kind: ErrTooLarge}
}

// refusal is one of Read's refusals: its message as it has always read, and
// the sentinel it wraps for errors.Is.
type refusal struct {
	msg  string
	kind error
}

func (e *refusal) Error() string { return e.msg }
func (e *refusal) Unwrap() error { return e.kind }
