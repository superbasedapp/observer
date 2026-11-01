package secposture

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
)

// maxSeenBytes caps the seen mark file: a decimal uint64 and a newline.
const maxSeenBytes = 32

// RaiseDirty appends one byte to the project's dirty marker, so its size
// (the counter) grows by one. Two writers of one kind (the hook, before a
// write-capable or shell call proceeds, and the daemon, when it learns of
// a write) append without a lock: O_APPEND writes of one byte never
// interleave. There is no fsync on the hook path (revision 2.4 [JSP-2]:
// 12 microseconds p99 to raise; an fsync'd raise costs 1.65 ms on WSL and
// 2.19 ms on Windows).
func RaiseDirty(l Layout, rootHash string) error {
	path := l.DirtyPath(rootHash)
	if path == "" {
		return errors.New("secposture.RaiseDirty: no path for the project hash")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
			return fmt.Errorf("secposture.RaiseDirty: %w", mkErr)
		}
		f, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	}
	if err != nil {
		return fmt.Errorf("secposture.RaiseDirty: %w", err)
	}
	if _, err := f.Write([]byte{'.'}); err != nil {
		_ = f.Close()
		return fmt.Errorf("secposture.RaiseDirty: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("secposture.RaiseDirty: %w", err)
	}
	return nil
}

// ReadDirty returns the project's dirty counter: the marker's size. A
// missing marker is 0 (no activity yet).
func ReadDirty(l Layout, rootHash string) (uint64, error) {
	path := l.DirtyPath(rootHash)
	if path == "" {
		return 0, errors.New("secposture.ReadDirty: no path for the project hash")
	}
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("secposture.ReadDirty: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return 0, errors.New("secposture.ReadDirty: marker is not a regular file")
	}
	return uint64(fi.Size()), nil
}

// ReadSeen returns the highest posture sequence this project's hooks
// accepted. A missing mark is 0; a malformed one is an error (the caller
// reads it as unknown, never as 0).
func ReadSeen(l Layout, rootHash string) (uint64, error) {
	path := l.SeenPath(rootHash)
	if path == "" {
		return 0, errors.New("secposture.ReadSeen: no path for the project hash")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("secposture.ReadSeen: %w", err)
	}
	if len(raw) > maxSeenBytes {
		return 0, errors.New("secposture.ReadSeen: mark too large")
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("secposture.ReadSeen: %w", err)
	}
	return n, nil
}

// seenWrite is how the hook path writes the seen mark: atomically (a
// reader never sees half a number) and without fsync, like the dirty
// marker. A crash may lose the last raise; that only narrows the rollback
// window the mark guards, never widens what verifies.
var seenWrite = fsatomic.Options{TempPattern: ".sec-seen-*.tmp", Fsync: false}

// RaiseSeen records seq as the project's seen mark when it is above the
// current one (the mark never goes down). Concurrent hooks may race; the
// loser leaves a lower but still valid mark, which only narrows the
// rollback window it guards, never widens what verifies.
func RaiseSeen(l Layout, rootHash string, seq uint64) error {
	path := l.SeenPath(rootHash)
	if path == "" {
		return errors.New("secposture.RaiseSeen: no path for the project hash")
	}
	if cur, err := ReadSeen(l, rootHash); err == nil && cur >= seq {
		return nil
	}
	data := []byte(strconv.FormatUint(seq, 10) + "\n")
	if err := fsatomic.WriteFile(path, data, seenWrite); err != nil {
		return fmt.Errorf("secposture.RaiseSeen: %w", err)
	}
	return nil
}

// DirtySince lists the project root hashes whose dirty marker was raised at
// or after since (its modification time): projects the hook saw activity
// in, which the posture writer signs even before their session is
// ingested.
func DirtySince(l Layout, since time.Time) ([]string, error) {
	if since.IsZero() {
		since = time.Unix(0, 1)
	}
	return hashesIn(l.join(DirtyDirName), "", since)
}

// DirtyHealth is the dirty-marker directory's health for doctor (section
// 4.11): whether it exists and is writable by its owner, how many markers
// it holds, how many were raised since a time, and how many cannot be
// read as a counter.
type DirtyHealth struct {
	Dir        string
	Exists     bool
	Writable   bool
	Markers    int
	Recent     int
	Unreadable int
}

// ReadDirtyHealth inspects the dirty-marker directory. It never writes.
func ReadDirtyHealth(l Layout, since time.Time) (DirtyHealth, error) {
	h := DirtyHealth{Dir: l.join(DirtyDirName)}
	if h.Dir == "" {
		return h, errors.New("secposture.ReadDirtyHealth: no security directory")
	}
	fi, err := os.Stat(h.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return h, nil
	}
	if err != nil {
		return h, fmt.Errorf("secposture.ReadDirtyHealth: %w", err)
	}
	h.Exists = fi.IsDir()
	h.Writable = h.Exists && fi.Mode().Perm()&0o200 != 0
	entries, err := os.ReadDir(h.Dir)
	if err != nil {
		return h, fmt.Errorf("secposture.ReadDirtyHealth: %w", err)
	}
	for _, e := range entries {
		if !validHash(e.Name()) {
			continue
		}
		h.Markers++
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			h.Unreadable++
			continue
		}
		if !info.ModTime().Before(since) {
			h.Recent++
		}
	}
	return h, nil
}
