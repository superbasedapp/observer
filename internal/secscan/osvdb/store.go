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

// Epoch is one ecosystem's record. LastModified, CRC32C and Size always
// describe the upstream BASE object (the full export last installed); an
// incremental update moves Watermark, DeltaRecords and FetchedAt only.
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
	// Watermark: records modified after it are not in the local file. Zero
	// means no incremental update is possible yet (a full download is due,
	// and a remote with no per-record listing never sets it).
	Watermark time.Time `json:"watermark,omitzero"`
	// BaseFetchedAt is when the full export was last installed.
	BaseFetchedAt time.Time `json:"base_fetched_at,omitzero"`
	// DeltaRecords counts the records applied on top of the base.
	DeltaRecords int `json:"delta_records,omitempty"`
	// DeltaFailures counts consecutive failed incremental updates; at
	// MaxDeltaFailures the next refresh downloads the full export.
	DeltaFailures int `json:"delta_failures,omitempty"`
	// Source names where the installed base came from: "" for the OSV
	// bucket (SourceUpstream), else the SourcedRemote's SourceFeed,
	// SourceImport or SourceOrgMirror.
	Source string `json:"source,omitempty"`
}

// SourcedRemote is a Remote that names its source (Epoch.Source): the
// content-channel sets (the signed mirror, an imported set, the org
// mirror). The OSV bucket's remote is not one, so its epochs read as they
// always did.
type SourcedRemote interface {
	OSVSource() string
}

// String is the epoch as findings and scan runs record it: the base
// object's Last-Modified and CRC32C, plus " delta=<watermark>" (RFC 3339
// with nanoseconds, UTC) once records were applied on top of it, and
// " source=<source>" for a base that did not come from the OSV bucket, so a
// finding names the exact data it was matched against and where it came
// from.
func (e Epoch) String() string {
	if e.LastModified == "" && e.CRC32C == "" {
		return ""
	}
	s := e.LastModified + " crc32c=" + e.CRC32C
	if e.DeltaRecords > 0 && !e.Watermark.IsZero() {
		s += " delta=" + e.Watermark.UTC().Format(time.RFC3339Nano)
	}
	if e.Source != "" {
		s += " source=" + e.Source
	}
	return s
}

// Installed reports whether a verified export is on disk for the record.
func (e Epoch) Installed() bool { return e.CRC32C != "" && !e.FetchedAt.IsZero() }

// Store is the database directory. The zero value is unusable; use Open.
type Store struct {
	dir string
	mu  *sync.Mutex
	// bodyIdle and bodyTotal are the body download's deadlines.
	bodyIdle, bodyTotal time.Duration
	// deltaTotal bounds one ecosystem's incremental update.
	deltaTotal time.Duration
}

var storeLocks sync.Map // dir -> *sync.Mutex: one refresh per directory per process

// Open returns the store at dir (created 0700 on first refresh).
func Open(dir string) Store {
	m, _ := storeLocks.LoadOrStore(dir, &sync.Mutex{})
	return Store{dir: dir, mu: m.(*sync.Mutex), bodyIdle: DefaultBodyIdle, bodyTotal: DefaultBodyTotal, deltaTotal: DefaultDeltaTotal}
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
	// Incremental maps an ecosystem updated record by record to the number
	// of records applied; such an ecosystem is also in Changed.
	Incremental map[string]int
}

// Refresh brings each ecosystem's export up to date through remote. A
// remote that is also a DeltaRemote is asked for the changed records
// whenever the rebase rules allow (see rebaseRules); otherwise, and when
// a rebase is due, the full export is checked and downloaded as before.
func (s Store) Refresh(ctx context.Context, remote Remote, ecos []string, now time.Time) (Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep := Report{Failed: map[string]string{}, Incremental: map[string]int{}}
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
		out, next, err := s.refreshEco(ctx, remote, eco, cur, now)
		if err != nil {
			next.LastError = err.Error()
			next.CheckedAt = now
			eps[eco] = next
			rep.Failed[eco] = err.Error()
			continue
		}
		eps[eco] = next
		switch {
		case out.applied > 0:
			rep.Changed = append(rep.Changed, eco)
			rep.Incremental[eco] = out.applied
		case out.changed:
			rep.Changed = append(rep.Changed, eco)
		default:
			rep.Unchanged = append(rep.Unchanged, eco)
		}
	}
	if err := s.writeEpochs(eps); err != nil {
		return rep, fmt.Errorf("osvdb.Refresh: %w", err)
	}
	return rep, ctx.Err()
}

// refreshFull is the full-export path: the export's metadata first, the
// body only when its CRC32C differs from the installed base's. The body
// comes from Get, or, when the remote is a LocalRemote, from a hard link
// (a copy where the link is refused) of a file already on this disk; both
// pass the same checks (size, CRC32C, zip directory) before the same two
// renames.
func (s Store) refreshFull(ctx context.Context, remote Remote, eco string, cur Epoch, now time.Time) (bool, Epoch, error) {
	head, err := remote.Head(ctx, eco)
	if err != nil {
		return false, cur, err
	}
	if head.CRC32C == "" {
		return false, cur, errors.New("the export carries no CRC32C; refusing an unverifiable download")
	}
	final := s.zipPath("osv-scalibr", eco)
	if cur.Installed() && head.CRC32C == cur.CRC32C {
		if _, err := os.Stat(final); err == nil {
			cur.CheckedAt, cur.LastError = now, ""
			// An export installed before incremental updates (or by a
			// remote with no per-record listing) IS the upstream object
			// the metadata names, so it can take a watermark without a
			// download.
			if dr, ok := remote.(DeltaRemote); ok && cur.Watermark.IsZero() && cur.DeltaRecords == 0 {
				cur.Watermark = baseWatermark(ctx, dr, eco, head.LastModified)
				if cur.BaseFetchedAt.IsZero() {
					cur.BaseFetchedAt = cur.FetchedAt
				}
			}
			return false, cur, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return false, cur, err
	}
	var got fetched
	if lr, ok := remote.(LocalRemote); ok {
		got, err = s.linkLocal(ctx, lr, eco, filepath.Dir(final))
	} else {
		got, err = s.download(ctx, remote, eco, filepath.Dir(final))
	}
	if got.tmp != "" {
		defer os.Remove(got.tmp)
	}
	if err != nil {
		return false, cur, err
	}
	meta, n := got.meta, got.n
	if meta.CRC32C == "" {
		return false, cur, errors.New("the export carries no CRC32C; refusing an unverifiable download")
	}
	if n > MaxExportBytes {
		return false, cur, fmt.Errorf("the export is larger than %d bytes", MaxExportBytes)
	}
	if meta.Size >= 0 && n != meta.Size {
		return false, cur, fmt.Errorf("short download: %d of %d bytes", n, meta.Size)
	}
	if got.crc != meta.CRC32C {
		return false, cur, fmt.Errorf("CRC32C mismatch: got %s, the source says %s", got.crc, meta.CRC32C)
	}
	if err := checkZip(got.tmp, -1); err != nil {
		return false, cur, err
	}
	next := Epoch{Ecosystem: eco, LastModified: meta.LastModified, CRC32C: meta.CRC32C, Size: n, FetchedAt: now, CheckedAt: now, BaseFetchedAt: now}
	if sr, ok := remote.(SourcedRemote); ok {
		next.Source = sr.OSVSource()
	}
	next.LastError, err = s.install(got.tmp, eco)
	if err != nil {
		return false, cur, err
	}
	if dr, ok := remote.(DeltaRemote); ok {
		next.Watermark = baseWatermark(ctx, dr, eco, meta.LastModified)
	}
	return true, next, nil
}

// fetched is a verified-to-be candidate export under a temporary name.
type fetched struct {
	tmp  string
	meta Meta
	n    int64
	crc  string
}

// download streams the export into a temporary file in dir, computing its
// size and CRC32C as it arrives, under the body deadlines.
func (s Store) download(ctx context.Context, remote Remote, eco, dir string) (fetched, error) {
	var out fetched
	getCtx, cancel := context.WithTimeout(ctx, s.bodyTotal)
	defer cancel()
	meta, body, err := remote.Get(getCtx, eco)
	if err != nil {
		return out, err
	}
	out.meta = meta
	wd := newWatchdog(body, cancel, s.bodyIdle)
	defer wd.stop()
	if meta.CRC32C == "" {
		return out, errors.New("the export carries no CRC32C; refusing an unverifiable download")
	}
	tmp, err := os.CreateTemp(dir, "all.zip.*.part")
	if err != nil {
		return out, err
	}
	out.tmp = tmp.Name()
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(wd, MaxExportBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if wd.fired() || errors.Is(getCtx.Err(), context.DeadlineExceeded) {
		return out, fmt.Errorf("download: %w", ErrBodyStalled)
	}
	if err != nil {
		return out, fmt.Errorf("download: %w", err)
	}
	out.n, out.crc = n, CRC32CString(h.Sum32())
	return out, nil
}

// linkLocal puts the LocalRemote's file under a temporary name in dir: a
// hard link, or a copy where the filesystem refuses one (design B3: the
// mirrored export is not kept twice). Its size and CRC32C are then read
// from the linked file, so the same checks as a download apply.
func (s Store) linkLocal(ctx context.Context, lr LocalRemote, eco, dir string) (fetched, error) {
	var out fetched
	path, meta, err := lr.LocalExport(ctx, eco)
	if err != nil {
		return out, err
	}
	out.meta = meta
	f, err := os.CreateTemp(dir, "all.zip.*.part")
	if err != nil {
		return out, err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	if err := linkFile(path, name); err != nil {
		if err := copyFile(path, name); err != nil {
			_ = os.Remove(name)
			return out, fmt.Errorf("local export: %w", err)
		}
	}
	out.tmp = name
	out.n, out.crc, err = fileCRC32C(name)
	if err != nil {
		return out, fmt.Errorf("local export: %w", err)
	}
	return out, nil
}

// fileCRC32C reads a file's size and base64 CRC32C.
func fileCRC32C(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	n, err := io.Copy(h, io.LimitReader(f, MaxExportBytes+1))
	if err != nil {
		return 0, "", err
	}
	return n, CRC32CString(h.Sum32()), nil
}

// checkZip opens the candidate's zip directory; want >= 0 also requires
// exactly that many entries.
func checkZip(path string, want int) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("not a zip archive: %w", err)
	}
	got := len(zr.File)
	_ = zr.Close()
	if want >= 0 && got != want {
		return fmt.Errorf("the merged export holds %d entries, %d were written", got, want)
	}
	return nil
}

// install puts a verified candidate in place for both engines. The
// osv-scanner copy is made BEFORE either file is replaced: a copy that
// fails (a full disk) leaves both old files and the old epoch record,
// never the new export under the old record (err). Only the two renames,
// in one directory tree, follow; a failed second rename leaves the SCALIBR
// file new and removes the osv-scanner one, so that driver finds no
// database ("not scanned") until the next refresh (note, recorded as the
// epoch's LastError).
func (s Store) install(tmp, eco string) (note string, err error) {
	scanner := s.zipPath("osv-scanner", eco)
	part, err := s.stageScanner(tmp, scanner)
	if err != nil {
		return "", fmt.Errorf("osv-scanner copy: %w", err)
	}
	defer os.Remove(part)
	if err := os.Rename(tmp, s.zipPath("osv-scalibr", eco)); err != nil {
		return "", err
	}
	if err := os.Rename(part, scanner); err != nil {
		_ = os.Remove(scanner)
		return "osv-scanner copy: " + err.Error(), nil
	}
	return "", nil
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
	return s.linkLayout("osv-scalibr", dst, ecos)
}

func (s Store) linkLayout(sub, dst string, ecos []string) error {
	for _, eco := range ecos {
		src := s.zipPath(sub, eco)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		to := filepath.Join(dst, sub, eco, "all.zip")
		if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
			return fmt.Errorf("osvdb.LinkInto: %w", err)
		}
		if err := linkFile(src, to); err != nil {
			return fmt.Errorf("osvdb.LinkInto: %w", err)
		}
	}
	return nil
}
