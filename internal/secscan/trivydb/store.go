package trivydb

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// store.go is the installed database: generation directories under one
// root, each holding db/trivy.db and db/metadata.json (the layout Trivy's
// --cache-dir reads), and state.json naming the generation in use. A
// refresh unpacks into a new generation and only then rewrites state.json
// (atomically, by rename), so the last known good database stays in use
// until a new one is complete; older generations are removed afterwards.

// RefreshEvery is the cadence of the database check after the accept.
const RefreshEvery = 6 * time.Hour

// Unpack caps.
const (
	// MaxDBBytes caps trivy.db unpacked (1,691,385,856 bytes on
	// 2026-11-04).
	MaxDBBytes      = 6 << 30
	maxMetadataSize = 64 << 10
	maxTarEntries   = 64
	stateFile       = "state.json"
	genPrefix       = "gen-"
)

// The two files a generation holds.
const (
	DBFile       = "trivy.db"
	MetadataFile = "metadata.json"
)

// Store is the installed database's root directory (outside ~/.observer:
// the isolated run binds a generation read-only).
type Store struct {
	Root string
}

// State is the store's record (state.json).
type State struct {
	// Generation is the directory in use ("" when none is installed).
	Generation string `json:"generation,omitempty"`
	// ManifestDigest and LayerDigest identify the artifact the generation
	// came from; LayerBytes is its compressed size.
	ManifestDigest string `json:"manifest_digest,omitempty"`
	LayerDigest    string `json:"layer_digest,omitempty"`
	LayerBytes     int64  `json:"layer_bytes,omitempty"`
	// DBBytes is what the generation takes on disk.
	DBBytes int64 `json:"db_bytes,omitempty"`
	// UpdatedAt and NextUpdate are the database's own metadata.
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
	NextUpdate time.Time `json:"next_update,omitempty"`
	// FetchedAt is when the generation was downloaded; CheckedAt when the
	// manifest was last asked (successfully or not).
	FetchedAt time.Time `json:"fetched_at,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
	// LastError is the last refresh's fixed reason ("" after a success);
	// the installed generation stays in use.
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitempty"`
}

// Installed reports whether a generation is in use.
func (st State) Installed() bool {
	return st.Generation != "" && digestRE.MatchString(st.LayerDigest)
}

// Epoch is what a run and its findings record: the artifact's manifest
// digest (short) and the database's build time.
func (st State) Epoch() string {
	if !st.Installed() {
		return ""
	}
	d := strings.TrimPrefix(st.ManifestDigest, "sha256:")
	if len(d) > 12 {
		d = d[:12]
	}
	return "trivy-db@sha256:" + d + "/" + st.UpdatedAt.UTC().Format(time.RFC3339)
}

// Age is how old the installed database is at now (zero when none).
func (st State) Age(now time.Time) time.Duration {
	if !st.Installed() || st.UpdatedAt.IsZero() {
		return 0
	}
	return now.Sub(st.UpdatedAt)
}

// Due reports whether a refresh may ask the registry at now: always when
// nothing is installed; otherwise at most every RefreshEvery after the
// last check, and not before the database's own NextUpdate.
func Due(st State, now time.Time) bool {
	if !st.Installed() {
		return st.LastErrorAt.IsZero() || now.Sub(st.LastErrorAt) >= time.Minute
	}
	if now.Sub(st.CheckedAt) < RefreshEvery {
		return false
	}
	return st.NextUpdate.IsZero() || !now.Before(st.NextUpdate)
}

func (s Store) statePath() string { return filepath.Join(s.Root, stateFile) }

// State reads the store's record; a missing or unreadable record, or one
// whose generation is not on disk, reads nothing installed (the fetch
// fields are kept).
func (s Store) State() State {
	var st State
	f, err := os.Open(s.statePath())
	if err != nil {
		return State{}
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil || json.Unmarshal(b, &st) != nil {
		return State{}
	}
	if st.Generation != "" {
		if !validGeneration(st.Generation) {
			st.Generation = ""
		} else if fi, err := os.Stat(filepath.Join(s.Root, st.Generation, "db", DBFile)); err != nil || !fi.Mode().IsRegular() {
			st.Generation = ""
		}
	}
	return st
}

func validGeneration(g string) bool {
	if !strings.HasPrefix(g, genPrefix) || len(g) != len(genPrefix)+12 {
		return false
	}
	for _, c := range g[len(genPrefix):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// DBDir is the installed generation's db directory ("" when none).
func (s Store) DBDir(st State) string {
	if !st.Installed() {
		return ""
	}
	return filepath.Join(s.Root, st.Generation, "db")
}

func (s Store) writeState(st State) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Root, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Root, ".tmp-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(name, s.statePath())
	}
	if werr != nil {
		_ = os.Remove(name)
	}
	return werr
}

// Fetcher is the download (Client in production).
type Fetcher interface {
	Manifest(ctx context.Context) (Manifest, error)
	Layer(ctx context.Context, m Manifest, w io.Writer) error
}

// The refresh's fixed failure reasons (State.LastError).
const (
	ReasonManifest = "manifest_unavailable"
	ReasonLayer    = "layer_download_failed"
	ReasonUnpack   = "layer_unreadable"
	ReasonDisk     = "store_write_failed"
)

// RefreshError is a refresh that did not install a new generation; Reason
// is the fixed reason, Err the cause.
type RefreshError struct {
	Reason string
	Err    error
}

// Error renders the reason and the cause.
func (e *RefreshError) Error() string { return "trivydb: " + e.Reason + ": " + e.Err.Error() }

// Unwrap returns the cause.
func (e *RefreshError) Unwrap() error { return e.Err }

// Refresh asks the registry for the tag's manifest and, when its layer is
// not the installed one, downloads, verifies and unpacks it into a new
// generation and switches to it. It records the check either way; a
// failure keeps the installed generation and records its reason. changed
// reports a new generation.
func (s Store) Refresh(ctx context.Context, f Fetcher, now time.Time) (State, bool, error) {
	st := s.State()
	fail := func(reason string, err error) (State, bool, error) {
		st.CheckedAt, st.LastError, st.LastErrorAt = now.UTC(), reason, now.UTC()
		_ = s.writeState(st)
		return st, false, &RefreshError{Reason: reason, Err: err}
	}
	if err := os.MkdirAll(s.Root, 0o700); err != nil {
		return st, false, &RefreshError{Reason: ReasonDisk, Err: err}
	}
	m, err := f.Manifest(ctx)
	if err != nil {
		return fail(ReasonManifest, err)
	}
	if st.Installed() && st.LayerDigest == m.Layer.Digest {
		st.ManifestDigest, st.CheckedAt, st.LastError, st.LastErrorAt = m.Digest, now.UTC(), "", time.Time{}
		return st, false, s.writeState(st)
	}
	layer, err := os.CreateTemp(s.Root, ".tmp-layer-*")
	if err != nil {
		return fail(ReasonDisk, err)
	}
	layerPath := layer.Name()
	defer func() { _ = os.Remove(layerPath) }()
	err = f.Layer(ctx, m, layer)
	if cerr := layer.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fail(ReasonLayer, err)
	}
	gen := genPrefix + strings.TrimPrefix(m.Layer.Digest, "sha256:")[:12]
	tmpDir, err := os.MkdirTemp(s.Root, ".tmp-gen-*")
	if err != nil {
		return fail(ReasonDisk, err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	meta, dbBytes, err := unpack(layerPath, filepath.Join(tmpDir, "db"))
	if err != nil {
		var re *RefreshError
		if errors.As(err, &re) {
			return fail(re.Reason, re.Err)
		}
		return fail(ReasonUnpack, err)
	}
	final := filepath.Join(s.Root, gen)
	if gen == st.Generation {
		// The same layer prefix as the generation in use (a 48-bit
		// collision or a state.json that lost its digest): keep it.
		return fail(ReasonDisk, errors.New("the new generation's directory is the one in use"))
	}
	_ = os.RemoveAll(final)
	if err := os.Rename(tmpDir, final); err != nil {
		return fail(ReasonDisk, err)
	}
	next := State{
		Generation: gen, ManifestDigest: m.Digest, LayerDigest: m.Layer.Digest, LayerBytes: m.Layer.Size, DBBytes: dbBytes,
		UpdatedAt: meta.UpdatedAt.UTC(), NextUpdate: meta.NextUpdate.UTC(), FetchedAt: now.UTC(), CheckedAt: now.UTC(),
	}
	if err := s.writeState(next); err != nil {
		_ = os.RemoveAll(final)
		return fail(ReasonDisk, err)
	}
	s.removeOtherGenerations(gen)
	return next, true, nil
}

// removeOtherGenerations removes every generation but keep, best effort (a
// generation a running scan holds open on Windows stays until the next
// refresh).
func (s Store) removeOtherGenerations(keep string) {
	ents, err := os.ReadDir(s.Root)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if n != keep && e.IsDir() && (validGeneration(n) || strings.HasPrefix(n, ".tmp-gen-")) {
			_ = os.RemoveAll(filepath.Join(s.Root, n))
		}
	}
}

// Metadata is the database's metadata.json.
type Metadata struct {
	Version    int       `json:"Version"`
	NextUpdate time.Time `json:"NextUpdate"`
	UpdatedAt  time.Time `json:"UpdatedAt"`
}

// MetadataVersion is the database schema the driver reads (trivy-db:2).
const MetadataVersion = 2

// unpack extracts trivy.db and metadata.json (regular files at the
// archive's root, each once) from the gzip tar layer into dir, under the
// caps; any other entry is skipped, a link or a second copy refused.
func unpack(layerPath, dir string) (Metadata, int64, error) {
	f, err := os.Open(layerPath)
	if err != nil {
		return Metadata{}, 0, err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return Metadata{}, 0, err
	}
	defer func() { _ = gz.Close() }()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Metadata{}, 0, &RefreshError{Reason: ReasonDisk, Err: err}
	}
	tr := tar.NewReader(gz)
	limits := map[string]int64{DBFile: MaxDBBytes, MetadataFile: maxMetadataSize}
	got := map[string]int64{}
	for i := 0; ; i++ {
		if i >= maxTarEntries {
			return Metadata{}, 0, errors.New("too many entries")
		}
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Metadata{}, 0, err
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		limit, wanted := limits[name]
		if !wanted {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return Metadata{}, 0, fmt.Errorf("%s is not a regular file", name)
		}
		if _, dup := got[name]; dup {
			return Metadata{}, 0, fmt.Errorf("%s appears twice", name)
		}
		if h.Size < 0 || h.Size > limit {
			return Metadata{}, 0, fmt.Errorf("%s is %d bytes, cap %d", name, h.Size, limit)
		}
		n, err := writeCapped(filepath.Join(dir, name), tr, limit)
		if err != nil {
			return Metadata{}, 0, err
		}
		got[name] = n
	}
	if _, ok := got[DBFile]; !ok {
		return Metadata{}, 0, errors.New("the layer holds no trivy.db")
	}
	if _, ok := got[MetadataFile]; !ok {
		return Metadata{}, 0, errors.New("the layer holds no metadata.json")
	}
	b, err := os.ReadFile(filepath.Join(dir, MetadataFile))
	if err != nil {
		return Metadata{}, 0, err
	}
	var meta Metadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return Metadata{}, 0, fmt.Errorf("metadata.json: %w", err)
	}
	if meta.Version != MetadataVersion || meta.UpdatedAt.IsZero() {
		return Metadata{}, 0, fmt.Errorf("metadata.json: version %d, updated %s", meta.Version, meta.UpdatedAt)
	}
	return meta, got[DBFile] + got[MetadataFile], nil
}

func writeCapped(p string, r io.Reader, limit int64) (int64, error) {
	out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, &RefreshError{Reason: ReasonDisk, Err: err}
	}
	n, err := io.Copy(out, io.LimitReader(r, limit+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, &RefreshError{Reason: ReasonDisk, Err: err}
	}
	if n > limit {
		return n, fmt.Errorf("%s is over %d bytes", filepath.Base(p), limit)
	}
	return n, nil
}

// LinkInto makes the installed generation reachable as cacheDir/db, the
// path Trivy's --cache-dir reads: a symlink to the generation's db
// directory (so an isolated run that binds the generation read-only reads
// it through the link), else hard links of its two files. It returns the
// generation's db directory, the run's read-only program directory.
func (s Store) LinkInto(st State, cacheDir string) (string, error) {
	src := s.DBDir(st)
	if src == "" {
		return "", errors.New("trivydb.LinkInto: no database is installed")
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", fmt.Errorf("trivydb.LinkInto: %w", err)
	}
	dst := filepath.Join(cacheDir, "db")
	if err := os.Symlink(src, dst); err == nil {
		return src, nil
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return "", fmt.Errorf("trivydb.LinkInto: %w", err)
	}
	for _, n := range []string{DBFile, MetadataFile} {
		if err := os.Link(filepath.Join(src, n), filepath.Join(dst, n)); err != nil {
			return "", fmt.Errorf("trivydb.LinkInto: %w", err)
		}
	}
	return src, nil
}
