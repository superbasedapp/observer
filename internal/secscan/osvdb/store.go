package osvdb

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// MaxExportBytes caps one ecosystem's download (npm is about 220 MB).
const MaxExportBytes = 1 << 30

// The body download's deadlines: a server that stops sending for
// DefaultBodyIdle, or a download that runs past DefaultBodyTotal, is cut
// off, so a slow server cannot hold the store lock (and with it every
// other refresh in this process) for longer than that. The total is sized
// for npm's ~220 MB export at about 1 Mbit/s.
const (
	DefaultBodyIdle  = 60 * time.Second
	DefaultBodyTotal = 45 * time.Minute
)

// ErrBodyStalled is the failure of a body download that passed a deadline.
var ErrBodyStalled = errors.New("the download stalled or ran past its deadline")

// Meta is what the remote says about one export.
type Meta struct {
	// LastModified is the object's Last-Modified header, verbatim.
	LastModified string
	// CRC32C is the base64 CRC32C from x-goog-hash; "" when absent.
	CRC32C string
	// Size is the Content-Length, -1 when unknown.
	Size int64
}

// Remote reaches the exports. Production: internal/secscan/osvnet.
type Remote interface {
	// Head returns one export's metadata without its body.
	Head(ctx context.Context, eco string) (Meta, error)
	// Get streams one export.
	Get(ctx context.Context, eco string) (Meta, io.ReadCloser, error)
}

// Epoch is one ecosystem's record.
type Epoch struct {
	Ecosystem    string    `json:"ecosystem"`
	LastModified string    `json:"last_modified"`
	CRC32C       string    `json:"crc32c"`
	Size         int64     `json:"size"`
	FetchedAt    time.Time `json:"fetched_at"`
	// CheckedAt is the last time the remote was asked (a refresh that found
	// nothing new moves it, not FetchedAt).
	CheckedAt time.Time `json:"checked_at"`
	// LastError is the last refresh failure, "" after a success.
	LastError string `json:"last_error,omitempty"`
}

// String is the epoch as findings and scan runs record it.
func (e Epoch) String() string {
	if e.LastModified == "" && e.CRC32C == "" {
		return ""
	}
	return e.LastModified + " crc32c=" + e.CRC32C
}

// Installed reports whether a verified export is on disk for the record.
func (e Epoch) Installed() bool { return e.CRC32C != "" && !e.FetchedAt.IsZero() }

// Store is the database directory. The zero value is unusable; use Open.
type Store struct {
	dir string
	mu  *sync.Mutex
	// bodyIdle and bodyTotal are the body download's deadlines.
	bodyIdle, bodyTotal time.Duration
}

var storeLocks sync.Map // dir -> *sync.Mutex: one refresh per directory per process

// Open returns the store at dir (created 0700 on first refresh).
func Open(dir string) Store {
	m, _ := storeLocks.LoadOrStore(dir, &sync.Mutex{})
	return Store{dir: dir, mu: m.(*sync.Mutex), bodyIdle: DefaultBodyIdle, bodyTotal: DefaultBodyTotal}
}

// WithBodyDeadlines returns the store with other body download deadlines
// (tests); a zero value keeps the default.
func (s Store) WithBodyDeadlines(idle, total time.Duration) Store {
	if idle > 0 {
		s.bodyIdle = idle
	}
	if total > 0 {
		s.bodyTotal = total
	}
	return s
}

// Dir is the directory osvlocal takes as LocalPath, and the directory
// osv-scanner takes as OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY.
func (s Store) Dir() string { return s.dir }

func (s Store) zipPath(sub, eco string) string { return filepath.Join(s.dir, sub, eco, "all.zip") }
func (s Store) epochsPath() string             { return filepath.Join(s.dir, "epochs.json") }

// Epochs reads the records. A missing file is no records.
func (s Store) Epochs() (map[string]Epoch, error) {
	b, err := os.ReadFile(s.epochsPath())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Epoch{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("osvdb.Epochs: %w", err)
	}
	var list []Epoch
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("osvdb.Epochs: %w", err)
	}
	out := map[string]Epoch{}
	for _, e := range list {
		out[e.Ecosystem] = e
	}
	return out, nil
}

// Installed returns the epoch string of every ecosystem whose export is on
// disk and recorded, for depscan.ChildRequest.Epochs.
func (s Store) Installed() (map[string]string, error) {
	eps, err := s.Epochs()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for eco, e := range eps {
		if !e.Installed() {
			continue
		}
		if _, err := os.Stat(s.zipPath("osv-scalibr", eco)); err == nil {
			out[eco] = e.String()
		}
	}
	return out, nil
}

func (s Store) writeEpochs(m map[string]Epoch) error {
	list := make([]Epoch, 0, len(m))
	for _, e := range m {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Ecosystem < list[j].Ecosystem })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.epochsPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.epochsPath())
}

// Report is what one refresh did.
type Report struct {
	// Changed are the ecosystems whose export was replaced (a rescan is
	// due for every project that uses them).
	Changed []string
	// Unchanged were current already.
	Unchanged []string
	// Failed maps an ecosystem to its failure; its previous file stays.
	Failed map[string]string
}

// Refresh brings each ecosystem's export up to date through remote.
func (s Store) Refresh(ctx context.Context, remote Remote, ecos []string, now time.Time) (Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep := Report{Failed: map[string]string{}}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return rep, fmt.Errorf("osvdb.Refresh: %w", err)
	}
	eps, err := s.Epochs()
	if err != nil {
		eps = map[string]Epoch{}
	}
	for _, eco := range ecos {
		if ctx.Err() != nil {
			break
		}
		cur := eps[eco]
		cur.Ecosystem = eco
		changed, next, err := s.refreshOne(ctx, remote, eco, cur, now)
		if err != nil {
			cur.LastError = err.Error()
			cur.CheckedAt = now
			eps[eco] = cur
			rep.Failed[eco] = err.Error()
			continue
		}
		eps[eco] = next
		if changed {
			rep.Changed = append(rep.Changed, eco)
		} else {
			rep.Unchanged = append(rep.Unchanged, eco)
		}
	}
	if err := s.writeEpochs(eps); err != nil {
		return rep, fmt.Errorf("osvdb.Refresh: %w", err)
	}
	return rep, ctx.Err()
}

func (s Store) refreshOne(ctx context.Context, remote Remote, eco string, cur Epoch, now time.Time) (bool, Epoch, error) {
	head, err := remote.Head(ctx, eco)
	if err != nil {
		return false, cur, err
	}
	if head.CRC32C == "" {
		return false, cur, errors.New("the export carries no CRC32C; refusing an unverifiable download")
	}
	if cur.Installed() && head.CRC32C == cur.CRC32C {
		if _, err := os.Stat(s.zipPath("osv-scalibr", eco)); err == nil {
			cur.CheckedAt, cur.LastError = now, ""
			return false, cur, nil
		}
	}
	getCtx, cancel := context.WithTimeout(ctx, s.bodyTotal)
	defer cancel()
	meta, body, err := remote.Get(getCtx, eco)
	if err != nil {
		return false, cur, err
	}
	wd := newWatchdog(body, cancel, s.bodyIdle)
	defer wd.stop()
	if meta.CRC32C == "" {
		return false, cur, errors.New("the export carries no CRC32C; refusing an unverifiable download")
	}
	final := s.zipPath("osv-scalibr", eco)
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return false, cur, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(final), "all.zip.*.part")
	if err != nil {
		return false, cur, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(wd, MaxExportBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if wd.fired() || errors.Is(getCtx.Err(), context.DeadlineExceeded) {
		return false, cur, fmt.Errorf("download: %w", ErrBodyStalled)
	}
	if err != nil {
		return false, cur, fmt.Errorf("download: %w", err)
	}
	if n > MaxExportBytes {
		return false, cur, fmt.Errorf("the export is larger than %d bytes", MaxExportBytes)
	}
	if meta.Size >= 0 && n != meta.Size {
		return false, cur, fmt.Errorf("short download: %d of %d bytes", n, meta.Size)
	}
	got := CRC32CString(h.Sum32())
	if got != meta.CRC32C {
		return false, cur, fmt.Errorf("CRC32C mismatch: got %s, the bucket says %s", got, meta.CRC32C)
	}
	zr, err := zip.OpenReader(tmpName)
	if err != nil {
		return false, cur, fmt.Errorf("not a zip archive: %w", err)
	}
	_ = zr.Close()
	// The osv-scanner copy is made BEFORE either file is replaced: a copy
	// that fails (a full disk) leaves both old files and the old epoch
	// record, never the new export under the old record. Only the two
	// renames, in one directory tree, follow.
	scanner := s.zipPath("osv-scanner", eco)
	part, err := s.stageScanner(tmpName, scanner)
	if err != nil {
		return false, cur, fmt.Errorf("osv-scanner copy: %w", err)
	}
	defer os.Remove(part)
	if err := os.Rename(tmpName, final); err != nil {
		return false, cur, err
	}
	next := Epoch{Ecosystem: eco, LastModified: meta.LastModified, CRC32C: meta.CRC32C, Size: n, FetchedAt: now, CheckedAt: now}
	if err := os.Rename(part, scanner); err != nil {
		// The SCALIBR file is already the new export; the osv-scanner one
		// is removed rather than left older than the record, so that
		// driver finds no database ("not scanned") until the next refresh.
		_ = os.Remove(scanner)
		next.LastError = "osv-scanner copy: " + err.Error()
	}
	return true, next, nil
}

// stageScanner puts the verified export where osv-scanner will read it,
// under a temporary name beside dst: a hard link, or a copy where the
// filesystem refuses one. The caller renames it into place.
func (s Store) stageScanner(src, dst string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	part := dst + ".part"
	_ = os.Remove(part)
	if err := linkFile(src, part); err == nil {
		return part, nil
	}
	if err := copyFile(src, part); err != nil {
		_ = os.Remove(part)
		return "", err
	}
	return part, nil
}

// linkFile is the hard-link step of stageScanner (a variable so a test can
// make it fail).
var linkFile = os.Link

// copyFile is the copy step of stageScanner (a variable so a test can make
// it fail).
var copyFile = func(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// watchdog reads a download body and cuts it off when no byte arrives for
// idle: it cancels the request's context and closes the body, which
// unblocks a pending Read.
type watchdog struct {
	r      io.ReadCloser
	idle   time.Duration
	timer  *time.Timer
	mu     sync.Mutex
	isDone bool
	hit    bool
}

func newWatchdog(r io.ReadCloser, cancel context.CancelFunc, idle time.Duration) *watchdog {
	w := &watchdog{r: r, idle: idle}
	w.timer = time.AfterFunc(idle, func() {
		w.mu.Lock()
		if w.isDone {
			w.mu.Unlock()
			return
		}
		w.hit = true
		w.mu.Unlock()
		cancel()
		_ = r.Close()
	})
	return w
}

func (w *watchdog) Read(p []byte) (int, error) {
	n, err := w.r.Read(p)
	if n > 0 {
		w.mu.Lock()
		if !w.isDone && !w.hit {
			w.timer.Reset(w.idle)
		}
		w.mu.Unlock()
	}
	return n, err
}

func (w *watchdog) fired() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hit
}

func (w *watchdog) stop() {
	w.mu.Lock()
	w.isDone = true
	w.mu.Unlock()
	w.timer.Stop()
	_ = w.r.Close()
}

// CRC32CString encodes a CRC32C the way x-goog-hash does: base64 of the
// big-endian 4 bytes.
func CRC32CString(sum uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], sum)
	return base64.StdEncoding.EncodeToString(b[:])
}

// LinkInto hard-links each named ecosystem's SCALIBR export into dst, in
// the store's own layout (dst/osv-scalibr/<eco>/all.zip), for a reader
// that cannot see the store's directory: the isolated scan child, since the
// isolation engine never binds ~/.observer. Nothing is copied (about 300 MB
// a scan): a filesystem that refuses a link is an error, and the caller
// then refuses the scan (isolation_refused, lane SEC-DEPS3 item 5), never
// running the child unisolated on a host that has a provider. An ecosystem with no export
// on disk is skipped (the child reports it not scanned).
func (s Store) LinkInto(dst string, ecos []string) error {
	for _, eco := range ecos {
		src := s.zipPath("osv-scalibr", eco)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		to := filepath.Join(dst, "osv-scalibr", eco, "all.zip")
		if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
			return fmt.Errorf("osvdb.LinkInto: %w", err)
		}
		if err := linkFile(src, to); err != nil {
			return fmt.Errorf("osvdb.LinkInto: %w", err)
		}
	}
	return nil
}
