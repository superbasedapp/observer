//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_osv_content.go presents an installed security.osv_export set
// (from the org mirror, the SuperBased feed or a `db import` directory) to
// osvdb as a Remote. A published set carries, per ecosystem, a base
// "<eco>.zip" and, when the publisher cut one, a cumulative delta
// "<eco>.delta.zip" whose signed entry (content.DeltaOf) names the base's
// digest, the records it drops and the record count of the result (static
// feed mirroring plan section 6.2). With a delta the remote presents the
// MERGED export (osvdb.MergeExportZip, raw copies), built once per (base,
// delta) pair into a cache file beside the content root with a small
// sidecar, so Head never merges twice; with no delta it presents the base
// as installed. It never makes a request of its own.

// osvMergedDir is the merged-export cache directory, beside the content
// root.
const osvMergedDir = "osv-merged"

// osvMergedSidecarV is the sidecar's format version.
const osvMergedSidecarV = 1

// osvMirrorEntryName is the artifact name of one ecosystem's base export in
// the security.osv_export kind: "<ecosystem>.zip", the ecosystem spelled by
// osvdb.ExportArtifact, the one rule the publisher signs with ("npm.zip",
// "GitHub-Actions.zip": the feed serves no name with a space).
func osvMirrorEntryName(eco string) string { return osvdb.ExportArtifact(eco) }

// osvDeltaEntryName is the artifact name of one ecosystem's cumulative
// delta (osvdb.DeltaArtifact).
func osvDeltaEntryName(eco string) string { return osvdb.DeltaArtifact(eco) }

// osvMergedSidecar describes one merged export.
type osvMergedSidecar struct {
	V           int    `json:"v"`
	BaseSHA256  string `json:"base_sha256"`
	DeltaSHA256 string `json:"delta_sha256"`
	CRC32C      string `json:"crc32c"`
	Size        int64  `json:"size"`
	Records     int    `json:"records"`
	IssuedAt    string `json:"issued_at"`
}

// osvContentRemote is an osvdb.Remote (and osvdb.LocalRemote) over an
// installed security.osv_export set.
type osvContentRemote struct {
	l contentchan.Loaded
	// cacheDir holds the merged exports; "" means a store without one.
	cacheDir string
	// source is where the set came from (osvdb.SourceOrgMirror,
	// SourceFeed or SourceImport): the epoch records it, errors name it.
	source string
	// merges counts merges this value ran (tests).
	merges *int
}

// osvSourceWords names each content-channel source in errors and status
// lines.
var osvSourceWords = map[string]string{
	osvdb.SourceOrgMirror: "the org mirror",
	osvdb.SourceFeed:      "the superbased signed mirror",
	osvdb.SourceImport:    "the imported set",
	osvdb.SourceUpstream:  "the OSV bucket",
}

// osvSourceName is source in words.
func osvSourceName(source string) string {
	if w, ok := osvSourceWords[source]; ok {
		return w
	}
	return source
}

// newOSVContentRemote returns the remote over l, installed in st, for
// source (osvdb.SourceOrgMirror, SourceFeed or SourceImport), and removes
// merged exports the set no longer names.
func newOSVContentRemote(st contentchan.Store, l contentchan.Loaded, source string) osvContentRemote {
	r := osvContentRemote{l: l, cacheDir: filepath.Join(filepath.Dir(st.Root), osvMergedDir), source: source, merges: new(int)}
	r.pruneMerged()
	return r
}

// osvExportView is what one ecosystem presents.
type osvExportView struct {
	path string
	meta osvdb.Meta
	// sha is the signed digest of path ("" for a merged export, whose
	// inputs were checked before the merge and whose CRC32C osvdb checks).
	sha string
}

// deltaFor returns eco's delta entry, if the set carries one.
func (r osvContentRemote) deltaFor(eco string) (content.Entry, bool) {
	name := osvDeltaEntryName(eco)
	for _, e := range r.l.Manifest.Entries {
		if e.Name == name && e.Delta != nil && !content.IsRevoked(r.l.Manifest, e.SHA256) {
			return e, true
		}
	}
	return content.Entry{}, false
}

// Serves implements osvdb.ServingRemote: the set holds an ecosystem when
// its manifest lists that ecosystem's base, unrevoked. A set published
// before an ecosystem joined the store (every feed manifest before GitHub
// Actions) does not hold it, so that ecosystem alone falls through to the
// next source of the order.
func (r osvContentRemote) Serves(eco string) bool {
	name := osvMirrorEntryName(eco)
	if name == "" {
		return false
	}
	for _, e := range r.l.Manifest.Entries {
		if e.Name == name && !content.IsRevoked(r.l.Manifest, e.SHA256) {
			return true
		}
	}
	return false
}

// view resolves eco to the file osvdb is handed.
func (r osvContentRemote) view(eco string) (osvExportView, error) {
	if r.l.Freshness == content.Unknown {
		return osvExportView{}, fmt.Errorf("%s's OSV exports are past their age floor", osvSourceName(r.source))
	}
	if !r.Serves(eco) {
		return osvExportView{}, fmt.Errorf("%s does not hold the %s export", osvSourceName(r.source), eco)
	}
	bp, be, err := r.l.ArtifactPath(osvMirrorEntryName(eco))
	if err != nil {
		return osvExportView{}, err
	}
	de, ok := r.deltaFor(eco)
	if !ok {
		crc, err := fileCRC32C(bp)
		if err != nil {
			return osvExportView{}, err
		}
		return osvExportView{path: bp, sha: be.SHA256, meta: osvdb.Meta{LastModified: r.l.Manifest.IssuedAt, CRC32C: crc, Size: be.SizeBytes}}, nil
	}
	return r.merged(eco, bp, be, de)
}

// merged returns the merged export of eco, building it when the cache does
// not hold this (base, delta) pair.
func (r osvContentRemote) merged(eco, basePath string, be, de content.Entry) (osvExportView, error) {
	if r.cacheDir == "" {
		return osvExportView{}, errors.New("no cache directory for a merged OSV export")
	}
	if de.Delta.Base != be.Name || !strings.EqualFold(de.Delta.BaseSHA256, be.SHA256) {
		return osvExportView{}, fmt.Errorf("the %s delta does not name the installed base", eco)
	}
	zipPath, sidePath := r.mergedPaths(eco)
	if sc, ok := readOSVSidecar(sidePath); ok && strings.EqualFold(sc.BaseSHA256, be.SHA256) && strings.EqualFold(sc.DeltaSHA256, de.SHA256) {
		if fi, err := os.Lstat(zipPath); err == nil && fi.Mode().IsRegular() && fi.Size() == sc.Size {
			return osvExportView{path: zipPath, meta: osvdb.Meta{LastModified: sc.IssuedAt, CRC32C: sc.CRC32C, Size: sc.Size}}, nil
		}
	}
	deltaPath, _, err := r.l.ArtifactPath(de.Name)
	if err != nil {
		return osvExportView{}, err
	}
	// The inputs are checked against their signed digests before a byte is
	// merged: a file changed after install is refused here.
	for _, in := range []struct {
		path string
		e    content.Entry
	}{{basePath, be}, {deltaPath, de}} {
		_, sum, err := fileCRC32CAndSHA256(in.path)
		if err != nil {
			return osvExportView{}, err
		}
		if sum != strings.ToLower(in.e.SHA256) {
			return osvExportView{}, fmt.Errorf("the installed %s does not match its digest", in.e.Name)
		}
	}
	sc, err := r.buildMerged(eco, basePath, deltaPath, de, zipPath, sidePath)
	if err != nil {
		return osvExportView{}, err
	}
	return osvExportView{path: zipPath, meta: osvdb.Meta{LastModified: sc.IssuedAt, CRC32C: sc.CRC32C, Size: sc.Size}}, nil
}

// mergedPaths are eco's cache file and sidecar.
func (r osvContentRemote) mergedPaths(eco string) (string, string) {
	return filepath.Join(r.cacheDir, eco+".merged.zip"), filepath.Join(r.cacheDir, eco+".merged.json")
}

// buildMerged merges base and delta into a temporary file, checks the
// record count against the signed entry, and renames it over the cache
// file (a new inode: a copy osvdb hard-linked earlier is never changed),
// then writes the sidecar.
func (r osvContentRemote) buildMerged(eco, basePath, deltaPath string, de content.Entry, zipPath, sidePath string) (osvMergedSidecar, error) {
	var sc osvMergedSidecar
	if err := os.MkdirAll(r.cacheDir, 0o700); err != nil {
		return sc, err
	}
	base, err := zip.OpenReader(basePath)
	if err != nil {
		return sc, fmt.Errorf("the %s base is not a zip: %w", eco, err)
	}
	defer func() { _ = base.Close() }()
	delta, err := zip.OpenReader(deltaPath)
	if err != nil {
		return sc, fmt.Errorf("the %s delta is not a zip: %w", eco, err)
	}
	defer func() { _ = delta.Close() }()
	drop := make(map[string]bool, len(de.Delta.Drop))
	for _, n := range de.Delta.Drop {
		drop[n] = true
	}
	tmp, err := os.CreateTemp(r.cacheDir, ".tmp-"+eco+"-*.zip")
	if err != nil {
		return sc, err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	cw := &countWriter{w: io.MultiWriter(tmp, h)}
	stats, err := osvdb.MergeExportZip(&base.Reader, &delta.Reader, drop, cw)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return sc, fmt.Errorf("merge %s: %w", eco, err)
	}
	if stats.Total != de.Delta.Records {
		return sc, fmt.Errorf("the merged %s export has %d records, the signed entry says %d", eco, stats.Total, de.Delta.Records)
	}
	if r.merges != nil {
		*r.merges++
	}
	// The old sidecar is removed first, so a crash before the new one is
	// written leaves no sidecar (the next call merges again), never a stale
	// sidecar vouching for a new file.
	_ = os.Remove(sidePath)
	if err := os.Rename(name, zipPath); err != nil {
		return sc, err
	}
	ok = true
	sc = osvMergedSidecar{
		V: osvMergedSidecarV, BaseSHA256: strings.ToLower(de.Delta.BaseSHA256), DeltaSHA256: strings.ToLower(de.SHA256),
		CRC32C: osvdb.CRC32CString(h.Sum32()), Size: cw.n, Records: stats.Total, IssuedAt: r.l.Manifest.IssuedAt,
	}
	b, err := json.Marshal(sc)
	if err != nil {
		return sc, err
	}
	if err := writeDepsFile(sidePath, b); err != nil {
		return sc, err
	}
	return sc, nil
}

// countWriter counts the bytes written through it.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// readOSVSidecar reads a merged export's sidecar.
func readOSVSidecar(path string) (osvMergedSidecar, bool) {
	b, err := readDepsFile(path, 4096)
	if err != nil {
		return osvMergedSidecar{}, false
	}
	var sc osvMergedSidecar
	if json.Unmarshal(b, &sc) != nil || sc.V != osvMergedSidecarV {
		return osvMergedSidecar{}, false
	}
	return sc, true
}

// pruneMerged removes the cache's merged exports (and stray temporaries)
// that the set does not name with the same base and delta: a new base or
// delta makes the old merge stale.
func (r osvContentRemote) pruneMerged() {
	if r.cacheDir == "" {
		return
	}
	ents, err := os.ReadDir(r.cacheDir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, ".tmp-") {
			_ = os.Remove(filepath.Join(r.cacheDir, n))
			continue
		}
		eco, isSide := strings.CutSuffix(n, ".merged.json")
		if !isSide {
			eco, _ = strings.CutSuffix(n, ".merged.zip")
		}
		if eco == n {
			continue
		}
		if r.mergedCurrent(eco) {
			continue
		}
		_ = os.Remove(filepath.Join(r.cacheDir, n))
	}
}

// mergedCurrent reports whether eco's cached sidecar names the set's
// current base and delta.
func (r osvContentRemote) mergedCurrent(eco string) bool {
	de, ok := r.deltaFor(eco)
	if !ok {
		return false
	}
	_, sidePath := r.mergedPaths(eco)
	sc, ok := readOSVSidecar(sidePath)
	return ok && strings.EqualFold(sc.BaseSHA256, de.Delta.BaseSHA256) && strings.EqualFold(sc.DeltaSHA256, de.SHA256)
}

// OSVSource implements osvdb.SourcedRemote: the epoch records where the
// base came from.
func (r osvContentRemote) OSVSource() string { return r.source }

// Head implements osvdb.Remote.
func (r osvContentRemote) Head(_ context.Context, eco string) (osvdb.Meta, error) {
	v, err := r.view(eco)
	if err != nil {
		return osvdb.Meta{}, err
	}
	return v.meta, nil
}

// Get implements osvdb.Remote: the file streamed, a base checked against
// its signed sha256 at the end of the read (osvdb checks the CRC32C of
// either).
func (r osvContentRemote) Get(_ context.Context, eco string) (osvdb.Meta, io.ReadCloser, error) {
	v, err := r.view(eco)
	if err != nil {
		return osvdb.Meta{}, nil, err
	}
	f, err := os.Open(v.path) //nolint:gosec // G304: a file of the node's own content store
	if err != nil {
		return osvdb.Meta{}, nil, err
	}
	if v.sha == "" {
		return v.meta, f, nil
	}
	return v.meta, newDigestReader(f, v.sha), nil
}

// The content remote hands osvdb its installed (or merged) files to link
// (design B3), and names the ecosystems it holds.
var (
	_ osvdb.LocalRemote   = osvContentRemote{}
	_ osvdb.ServingRemote = osvContentRemote{}
)

// LocalExport implements osvdb.LocalRemote: the installed base's path, its
// sha256 checked against the signed entry, or the merged export's path,
// with the Meta Head reports. osvdb hard-links the file into its store
// instead of streaming a second copy (static feed mirroring plan, B3, G6)
// and checks its size and CRC32C.
func (r osvContentRemote) LocalExport(_ context.Context, eco string) (string, osvdb.Meta, error) {
	v, err := r.view(eco)
	if err != nil {
		return "", osvdb.Meta{}, err
	}
	if v.sha != "" {
		_, sum, err := fileCRC32CAndSHA256(v.path)
		if err != nil {
			return "", osvdb.Meta{}, err
		}
		if sum != strings.ToLower(v.sha) {
			return "", osvdb.Meta{}, errors.New("the installed OSV export does not match its digest")
		}
	}
	return v.path, v.meta, nil
}
