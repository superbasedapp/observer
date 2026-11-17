package secassesssvc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"time"
)

// A second process can write the run record (a standalone dashboard answers
// validate, import and delete-data while the daemon's reconcile pass records an
// end), and a read-modify-write of one file is a lost update unless the writers
// take turns. The in-process mutex covers one process; this lock file covers
// the others. It is a plain create-exclusive file beside the record, held only
// across one read-modify-write (milliseconds), taken over when its owner died
// and left it (older than lockStale), and given up on after lockWait: a write
// that cannot take its turn fails loudly instead of overwriting.
const (
	lockSuffix = ".lock"
	lockWait   = 5 * time.Second
	lockStale  = 30 * time.Second
	lockPoll   = 15 * time.Millisecond
)

// ErrLockBusy is returned when another process holds the run record's lock for
// longer than a write waits.
var ErrLockBusy = errors.New("secassesssvc: the run record is being written by another process")

// lockRecord takes the cross-process lock of the run record and returns the
// function that releases it. A keep-nothing store needs none.
func (s *Store) lockRecord() (func(), error) {
	if s.path == "" {
		return func() {}, nil
	}
	path := s.path + lockSuffix
	deadline := time.Now().Add(lockWait)
	for {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_, _ = f.WriteString(strconv.Itoa(os.Getpid()))
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("%w: %w", ErrLockBusy, err)
		}
		if info, serr := os.Stat(path); serr == nil && time.Since(info.ModTime()) > lockStale {
			_ = os.Remove(path) // the owner died holding it
			continue
		}
		if time.Now().After(deadline) {
			return nil, ErrLockBusy
		}
		time.Sleep(lockPoll)
	}
}
