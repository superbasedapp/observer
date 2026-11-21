package osvdb

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
	"time"
)

// MaxViewRecordBytes caps one record RecordReader returns (records are a
// few KB; the largest seen are tens of KB).
const MaxViewRecordBytes = 1 << 20

// Errors of RecordReader.Record.
var (
	// ErrEcosystemNotInstalled: the store holds no verified export for the
	// ecosystem (or the name is not one it could hold).
	ErrEcosystemNotInstalled = errors.New("osvdb: ecosystem database not installed")
	// ErrRecordNotFound: the export holds no record of that id (or the id
	// is not a valid record id).
	ErrRecordNotFound = errors.New("osvdb: record not found")
	// ErrRecordTooLarge: the record is over MaxViewRecordBytes.
	ErrRecordTooLarge = errors.New("osvdb: record too large")
)

// RecordReader reads single OSV records out of the store's installed
// exports (osv-scalibr/<Ecosystem>/all.zip) for a view (the dashboard's
// finding drawer). It only reads the local store: there is no network
// path. One zip directory is kept per ecosystem and dropped when the file's
// modification time or size changes (a refresh renamed a new export in).
//
// The cached directory does NOT hold the file open between reads: each
// read opens the file, reads and closes it. On Windows an open handle
// (opened without FILE_SHARE_DELETE, as Go opens files) would make the
// refresh's rename over all.zip fail, so a view must never pin the file.
// A record read across a concurrent replacement fails its CRC-32 check
// (archive/zip verifies it) instead of returning mixed bytes.
//
// It is safe for concurrent use. Close drops the cached directories.
type RecordReader struct {
	store Store
	mu    sync.Mutex
	zips  map[string]*cachedExport
}

// cachedExport is one ecosystem's zip directory and the file identity it
// was read from.
type cachedExport struct {
	r       *zip.Reader
	modTime time.Time
	size    int64
}

// NewRecordReader returns a reader over the store's installed exports.
func NewRecordReader(s Store) *RecordReader {
	return &RecordReader{store: s, zips: map[string]*cachedExport{}}
}

// Record returns the raw JSON of record id from the ecosystem's installed
// export: ErrEcosystemNotInstalled when the store records no verified
// export for it (the ecosystem must be one Installed names: a name never
// reaches the file system otherwise), ErrRecordNotFound when the export
// holds no such record or id is not a valid record id (ValidID), and
// ErrRecordTooLarge over MaxViewRecordBytes.
func (rr *RecordReader) Record(eco, id string) ([]byte, error) {
	if !ValidEcosystem(eco) {
		return nil, ErrEcosystemNotInstalled
	}
	if !ValidID(id) {
		return nil, ErrRecordNotFound
	}
	installed, err := rr.store.Installed()
	if err != nil {
		return nil, fmt.Errorf("osvdb.RecordReader: %w", err)
	}
	if _, ok := installed[eco]; !ok {
		return nil, ErrEcosystemNotInstalled
	}
	zr, err := rr.export(eco)
	if err != nil {
		return nil, err
	}
	f, err := zr.Open(EntryName(id))
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrInvalid) {
		return nil, ErrRecordNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("osvdb.RecordReader: %w", err)
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err == nil && st.Size() > MaxViewRecordBytes {
		return nil, ErrRecordTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxViewRecordBytes+1))
	if err != nil {
		return nil, fmt.Errorf("osvdb.RecordReader: %w", err)
	}
	if len(b) > MaxViewRecordBytes {
		return nil, ErrRecordTooLarge
	}
	return b, nil
}

// export returns the ecosystem's cached zip directory, re-reading it when
// the file changed.
func (rr *RecordReader) export(eco string) (*zip.Reader, error) {
	path := rr.store.zipPath("osv-scalibr", eco)
	st, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrEcosystemNotInstalled
	}
	if err != nil {
		return nil, fmt.Errorf("osvdb.RecordReader: %w", err)
	}
	rr.mu.Lock()
	defer rr.mu.Unlock()
	if c, ok := rr.zips[eco]; ok && c.modTime.Equal(st.ModTime()) && c.size == st.Size() {
		return c.r, nil
	}
	delete(rr.zips, eco)
	ra := &reopenReaderAt{path: path}
	// The directory is read through one handle (a 220 MB export's central
	// directory is tens of MB), closed before returning.
	h, err := os.Open(path) //nolint:gosec // G304: the store's own export path; eco passed ValidEcosystem and Installed.
	if err != nil {
		return nil, fmt.Errorf("osvdb.RecordReader: %w", err)
	}
	ra.setHandle(h)
	zr, err := zip.NewReader(ra, st.Size())
	ra.setHandle(nil)
	_ = h.Close()
	if err != nil {
		return nil, fmt.Errorf("osvdb.RecordReader: %w", err)
	}
	rr.zips[eco] = &cachedExport{r: zr, modTime: st.ModTime(), size: st.Size()}
	return zr, nil
}

// Close drops every cached directory (no file is held open).
func (rr *RecordReader) Close() error {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rr.zips = map[string]*cachedExport{}
	return nil
}

// reopenReaderAt is an io.ReaderAt over a file path that opens the file
// for each read (or uses the handle set while the directory is read), so
// nothing holds the file open between reads.
type reopenReaderAt struct {
	path string
	mu   sync.Mutex
	h    *os.File
}

func (r *reopenReaderAt) setHandle(h *os.File) {
	r.mu.Lock()
	r.h = h
	r.mu.Unlock()
}

// ReadAt reads len(p) bytes at off.
func (r *reopenReaderAt) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	h := r.h
	r.mu.Unlock()
	if h != nil {
		return h.ReadAt(p, off)
	}
	f, err := os.Open(r.path) //nolint:gosec // G304: the export path export() built.
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	return f.ReadAt(p, off)
}
