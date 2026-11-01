package winrelaysvc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/winrelay"
)

// Journal appends bypass records to one file, rotating it to a single older
// generation (winrelay.JournalRotated) at its size cap. Safe for concurrent
// use by the relay's handlers.
type Journal struct {
	path     string
	maxBytes int64
	mu       sync.Mutex
}

// NewJournal returns a journal writing path, rotating at maxBytes (<= 0 is
// winrelay.DefaultJournalMaxBytes).
func NewJournal(path string, maxBytes int64) *Journal {
	if maxBytes <= 0 {
		maxBytes = winrelay.DefaultJournalMaxBytes
	}
	return &Journal{path: path, maxBytes: maxBytes}
}

// Path is the journal file.
func (j *Journal) Path() string { return j.path }

// errNotRegular refuses a journal path that is a link, a directory or a
// device: the relay writes only a regular file it created.
var errNotRegular = errors.New("winrelaysvc: the bypass journal is not a regular file")

// Append writes one record. Any error means the record was not written; the
// caller then refuses the fail-open forward.
func (j *Journal) Append(e winrelay.Entry) error {
	line, err := winrelay.Encode(e)
	if err != nil {
		return fmt.Errorf("winrelaysvc.Journal.Append: encode: %w", err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return fmt.Errorf("winrelaysvc.Journal.Append: %w", err)
	}
	fi, err := os.Lstat(j.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return fmt.Errorf("winrelaysvc.Journal.Append: %w", err)
	case !fi.Mode().IsRegular():
		return errNotRegular
	case fi.Size()+int64(len(line)) > j.maxBytes:
		if err := os.Rename(j.path, j.path+".1"); err != nil {
			return fmt.Errorf("winrelaysvc.Journal.Append: rotate: %w", err)
		}
	}
	f, err := os.OpenFile(j.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) //nolint:gosec // G304: the relay's own journal path
	if err != nil {
		return fmt.Errorf("winrelaysvc.Journal.Append: %w", err)
	}
	// Re-check on the descriptor: a link swapped in after the Lstat above is
	// refused instead of followed (the record is then not written and the
	// forward is refused).
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return errNotRegular
	}
	if after, err := os.Lstat(j.path); err != nil || !after.Mode().IsRegular() {
		_ = f.Close()
		return errNotRegular
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return fmt.Errorf("winrelaysvc.Journal.Append: %w", err)
	}
	// The record must be on disk before the request leaves: a bypass whose
	// record a crash or a power loss drops would be a silent one.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("winrelaysvc.Journal.Append: sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("winrelaysvc.Journal.Append: %w", err)
	}
	return nil
}
