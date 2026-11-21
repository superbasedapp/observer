package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// osvosexport.go is the `vendorsign osvosexport` verb, the daily publisher
// of the security.osv_os_export content kind (OS and CI vulnerability
// scanning plan, docs/plans/os-and-ci-vulnerability-scanning-plan-2026-11-04.md
// sections 6.4 and 6.6.1, spike JSP-OS). It cuts one STRIPPED file per row
// of osvdb.OSReleases (the one release table) out of its distribution's
// live whole OSV export, then publishes each file exactly as osvexport
// publishes an ecosystem: a base plus a cumulative delta over it, signed
// with the content-feed key, so a node rebuilds a release's file with
// osvdb.MergeExportZip. The bucket's own per-release exports are never
// read: they stopped updating in October 2024.
//
// Input, one directory per distribution, named by the release table's Base
// as the OSV bucket spells it ("Red Hat", "Rocky Linux"):
//
//	<in>/<Base>/all.zip      the whole upstream export as fetched
//	<in>/<Base>/source.json  {"object","last_modified","crc32c","md5","generation"}
//
// State, owned by this tool and never shared with osvexport's (the kind
// file marks it):
//
//	<state>/kind                     security.osv_os_export
//	<state>/stripped/<Artifact>.zip  today's stripped file of each release
//	<state>/base/<Artifact>.zip      the current base of each release
//	<state>/state.json, manifest.json as osvexport
//
// Output:
//
//	<out>/security.osv_os_export/manifest.json + <Artifact>.zip + <Artifact>.delta.zip
//
// with the names osvdb.OSRelease.ExportArtifact and DeltaArtifact give.
//
// Stripping: a record is kept for a release when any of its affected
// entries is one the release keeps (osvdb.OSRelease.Keep), and in the kept
// record every other affected entry is dropped; every other field and the
// field order are kept, and the record is written compact. Records are
// read in entry-name order and written with a fixed time, so the same
// export always gives the same bytes. Memory: the whole export is read one
// record at a time; one zip writer per release of the distribution is open
// while it is read. A release with no record (a release too new to have
// any) is left out of the manifest, never published as an empty base.

const (
	// osvOSSourceLabel and osvOSLicense describe the stripped files' bytes.
	// The records are the distributions' own advisories, each under its
	// publisher's terms, so no single licence is asserted here.
	osvOSSourceLabel = "osv.dev export bucket, stripped per release by SuperBased"
	osvOSLicense     = "NOASSERTION"
	// osvOSStrippedDir is the state subdirectory of today's stripped files.
	osvOSStrippedDir = "stripped"
	// osvOSMaxRecord caps one record of a whole export (records are a few
	// KB; a kernel record listing every version is a few hundred KB).
	osvOSMaxRecord = 64 << 20
)

// osvOSSet is the security.osv_os_export kind, keyed by
// osvdb.OSRelease.Artifact.
var osvOSSet = osvSetSpec{
	verb: "osvosexport", kind: content.OSVOSExport, sourceLabel: osvOSSourceLabel, license: osvOSLicense,
	baseName: func(key string) string {
		if r, ok := osvdb.ReleaseByArtifact(key); ok {
			return r.ExportArtifact()
		}
		return ""
	},
	deltaName: func(key string) string {
		if r, ok := osvdb.ReleaseByArtifact(key); ok {
			return r.DeltaArtifact()
		}
		return ""
	},
}

func runOSVOSExport(args []string, out *os.File) error {
	o, err := parseOSVExportFlags(osvOSSet.verb, "input directory: <Base>/all.zip + <Base>/source.json per distribution (Debian, Ubuntu, Alpine, Red Hat, Rocky Linux)", args)
	if err != nil {
		return err
	}
	res, err := buildOSVOSExport(o)
	if err != nil {
		return err
	}
	printOSVExport(out, res)
	return nil
}

// osvOSReleasesByBase groups the release table by distribution base, each
// group in table order.
func osvOSReleasesByBase() map[string][]osvdb.OSRelease {
	out := map[string][]osvdb.OSRelease{}
	for _, r := range osvdb.OSReleases {
		out[r.Base] = append(out[r.Base], r)
	}
	return out
}

// buildOSVOSExport strips every distribution directory under o.In into its
// releases' files, then publishes them through publishOSVSet. A directory
// that is no distribution of the release table, a whole export that fails
// its checksums or holds no record, or a record that is not a JSON object
// refuses the run; a failure leaves the state and the last output as they
// were.
func buildOSVOSExport(o osvExportOptions) (osvExportResult, error) {
	spec := osvOSSet
	if err := checkOSVOptions(spec.verb, o); err != nil {
		return osvExportResult{}, err
	}
	// Claim the state first, so a strip never writes into another kind's
	// state directory.
	if err := claimOSVState(o.State, spec); err != nil {
		return osvExportResult{}, err
	}
	dirs, err := os.ReadDir(o.In)
	if err != nil {
		return osvExportResult{}, fmt.Errorf("vendorsign %s: %w", spec.verb, err)
	}
	byBase := osvOSReleasesByBase()
	var bases []string
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		if _, ok := byBase[d.Name()]; !ok {
			known := make([]string, 0, len(byBase))
			for b := range byBase {
				known = append(known, b)
			}
			sort.Strings(known)
			return osvExportResult{}, fmt.Errorf("vendorsign %s: %q is not a distribution of the release table (known: %s)", spec.verb, d.Name(), strings.Join(known, ", "))
		}
		bases = append(bases, d.Name())
	}
	if len(bases) == 0 {
		return osvExportResult{}, fmt.Errorf("vendorsign %s: no distribution directory in %s", spec.verb, o.In)
	}
	work := filepath.Join(o.State, osvOSStrippedDir)
	if err := os.MkdirAll(work, 0o700); err != nil {
		return osvExportResult{}, fmt.Errorf("vendorsign %s: %w", spec.verb, err)
	}
	var inputs []osvInput
	var omitted []string
	for _, base := range bases {
		whole, err := checkOSVInput(spec.verb, filepath.Join(o.In, base), base, "distribution")
		if err != nil {
			return osvExportResult{}, err
		}
		stripped, err := stripOSVReleases(whole.path, byBase[base], work)
		if err != nil {
			return osvExportResult{}, fmt.Errorf("vendorsign %s: %s: %w", spec.verb, base, err)
		}
		for _, s := range stripped {
			if s.records == 0 {
				omitted = append(omitted, s.rel.Artifact)
				continue
			}
			inputs = append(inputs, osvInput{key: s.rel.Artifact, path: s.path, sum: s.sum, src: whole.src})
		}
	}
	if len(inputs) == 0 {
		return osvExportResult{}, fmt.Errorf("vendorsign %s: no release of %s holds a record; nothing to publish", spec.verb, strings.Join(bases, ", "))
	}
	res, err := publishOSVSet(o, spec, inputs)
	if err != nil {
		return osvExportResult{}, err
	}
	sort.Strings(omitted)
	res.Omitted = omitted
	return res, nil
}

// osvStripped is one release's stripped file.
type osvStripped struct {
	rel     osvdb.OSRelease
	path    string
	sum     osvFileSum
	records int
}

// stripOSVReleases reads the whole export at wholePath once, in entry-name
// order, and writes each release's stripped file to <work>/<Artifact>.zip
// (temp + rename). A release with no record gets no file (a stale one is
// removed) and records 0. The files are this run's scratch: only
// publishOSVSet reads them, and a run that fails publishes nothing.
func stripOSVReleases(wholePath string, rels []osvdb.OSRelease, work string) ([]osvStripped, error) {
	zr, err := zip.OpenReader(wholePath)
	if err != nil {
		return nil, fmt.Errorf("%s does not open as a zip: %w", osvExportFile, err)
	}
	defer func() { _ = zr.Close() }()
	files, err := sortedFlatRecords(&zr.Reader)
	if err != nil {
		return nil, err
	}

	writers := make([]*osvStripWriter, len(rels))
	defer func() {
		for _, w := range writers {
			if w != nil {
				w.abort()
			}
		}
	}()
	for i, r := range rels {
		w, err := newOSVStripWriter(filepath.Join(work, r.ExportArtifact()))
		if err != nil {
			return nil, err
		}
		writers[i] = w
	}
	needles := make([][]byte, len(rels))
	for i, r := range rels {
		needles[i] = []byte(r.Ecosystem)
	}

	var raw, joined, compact bytes.Buffer
	records := 0
	for _, f := range files {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		records++
		if f.UncompressedSize64 > osvOSMaxRecord {
			return nil, fmt.Errorf("record %s is %d bytes, over %d", f.Name, f.UncompressedSize64, osvOSMaxRecord)
		}
		raw.Reset()
		if err := readZipEntry(f, &raw); err != nil {
			return nil, fmt.Errorf("record %s: %w", f.Name, err)
		}
		data := raw.Bytes()
		// A release's ecosystem string must appear in the record for any
		// entry to be kept, so a record naming none is never parsed (OSV
		// writes these plain-ASCII strings unescaped).
		var want []int
		for i, n := range needles {
			if bytes.Contains(data, n) {
				want = append(want, i)
			}
		}
		if len(want) == 0 {
			continue
		}
		rec, err := splitOSVRecord(data)
		if err != nil {
			return nil, fmt.Errorf("record %s: %w", f.Name, err)
		}
		for _, i := range want {
			out, ok, err := rec.strip(rels[i], &joined, &compact)
			if err != nil {
				return nil, fmt.Errorf("record %s: %w", f.Name, err)
			}
			if !ok {
				continue
			}
			if err := writers[i].add(f.Name, out); err != nil {
				return nil, err
			}
		}
	}
	if records == 0 {
		return nil, fmt.Errorf("%s holds no record", osvExportFile)
	}

	out := make([]osvStripped, 0, len(rels))
	for i, r := range rels {
		w := writers[i]
		writers[i] = nil
		s := osvStripped{rel: r, path: w.final, records: w.records}
		if w.records == 0 {
			w.abort()
			if err := os.Remove(w.final); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("remove stale %s: %w", w.final, err)
			}
			out = append(out, s)
			continue
		}
		sum, err := w.finish()
		if err != nil {
			return nil, err
		}
		s.sum = sum
		out = append(out, s)
	}
	return out, nil
}

// sortedFlatRecords is a flat OSV export's entries in name order (the order
// every verb reads records in, so its output is the same bytes for the same
// export). A nested, path-like or repeated name is refused.
func sortedFlatRecords(zr *zip.Reader) ([]*zip.File, error) {
	files := slices.Clone(zr.File)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	for i, f := range files {
		if f.Name == "" || strings.ContainsAny(f.Name, `/\`) || strings.HasPrefix(f.Name, "-") || f.Name == "." || f.Name == ".." {
			return nil, fmt.Errorf("entry %q is not a flat record name", f.Name)
		}
		if i > 0 && files[i-1].Name == f.Name {
			return nil, fmt.Errorf("entry %q repeats", f.Name)
		}
	}
	return files, nil
}

// readZipEntry decompresses one entry into buf, at most osvOSMaxRecord
// bytes.
func readZipEntry(f *zip.File, buf *bytes.Buffer) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	n, err := io.Copy(buf, io.LimitReader(rc, osvOSMaxRecord+1))
	if err != nil {
		return err
	}
	if n > osvOSMaxRecord {
		return fmt.Errorf("over %d bytes", osvOSMaxRecord)
	}
	return nil
}

// osvRecordParts is one OSV record split into its top-level fields, in
// their order, with the affected array split into its entries and each
// entry's package ecosystem read.
type osvRecordParts struct {
	keys [][]byte
	vals []json.RawMessage
	// aff is the index of the "affected" field, -1 when there is none.
	aff      int
	affected []json.RawMessage
	ecos     []string
	// names are the entries' package names (osvshards keys on them).
	names []string
}

// splitOSVRecord splits one record. It refuses anything but a single JSON
// object with distinct keys whose "affected" field, when present, is an
// array of objects.
func splitOSVRecord(data []byte) (osvRecordParts, error) {
	p := osvRecordParts{aff: -1}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return p, fmt.Errorf("not JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return p, errors.New("not a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return p, fmt.Errorf("not JSON: %w", err)
		}
		key, ok := t.(string)
		if !ok {
			return p, errors.New("not a JSON object")
		}
		if seen[key] {
			return p, fmt.Errorf("field %q repeats", key)
		}
		seen[key] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return p, fmt.Errorf("field %q: %w", key, err)
		}
		kb, err := json.Marshal(key)
		if err != nil {
			return p, err
		}
		if key == "affected" {
			p.aff = len(p.keys)
			if err := json.Unmarshal(v, &p.affected); err != nil {
				return p, fmt.Errorf("affected is not an array: %w", err)
			}
			p.ecos = make([]string, len(p.affected))
			p.names = make([]string, len(p.affected))
			for i, a := range p.affected {
				var e struct {
					Package struct {
						Ecosystem string `json:"ecosystem"`
						Name      string `json:"name"`
					} `json:"package"`
				}
				if err := json.Unmarshal(a, &e); err != nil {
					return p, fmt.Errorf("affected[%d]: %w", i, err)
				}
				p.ecos[i] = e.Package.Ecosystem
				p.names[i] = e.Package.Name
			}
		}
		p.keys = append(p.keys, kb)
		p.vals = append(p.vals, v)
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return p, errors.New("not a JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return p, errors.New("trailing data after the record")
	}
	return p, nil
}

// strip writes into compact the record as release r keeps it: every field
// in its order, the affected array reduced to the entries r keeps, written
// compact. ok is false when r keeps no entry. The returned bytes live in
// compact until its next use.
func (p osvRecordParts) strip(r osvdb.OSRelease, joined, compact *bytes.Buffer) ([]byte, bool, error) {
	if p.aff < 0 {
		return nil, false, nil
	}
	var kept []int
	for i, eco := range p.ecos {
		if r.Keep(eco) {
			kept = append(kept, i)
		}
	}
	if len(kept) == 0 {
		return nil, false, nil
	}
	out, err := p.withAffected(kept, joined, compact)
	return out, err == nil, err
}

// withAffected writes into compact the record with its affected array
// reduced to the entries at kept (in that order), every other field in its
// order, written compact (osvosexport's per-release strip and osvshards'
// per-prefix strip). The returned bytes live in compact until its next use.
func (p osvRecordParts) withAffected(kept []int, joined, compact *bytes.Buffer) ([]byte, error) {
	joined.Reset()
	joined.WriteByte('{')
	for i := range p.keys {
		if i > 0 {
			joined.WriteByte(',')
		}
		joined.Write(p.keys[i])
		joined.WriteByte(':')
		if i != p.aff {
			joined.Write(p.vals[i])
			continue
		}
		joined.WriteByte('[')
		for j, k := range kept {
			if j > 0 {
				joined.WriteByte(',')
			}
			joined.Write(p.affected[k])
		}
		joined.WriteByte(']')
	}
	joined.WriteByte('}')
	compact.Reset()
	if err := json.Compact(compact, joined.Bytes()); err != nil {
		return nil, fmt.Errorf("stripped record is not JSON: %w", err)
	}
	return compact.Bytes(), nil
}

// osvStripWriter streams one release's stripped zip to a temp file beside
// its final path, hashing the bytes as they are written.
type osvStripWriter struct {
	final   string
	tmp     *os.File
	h       hash.Hash
	n       *byteCounter
	zw      *zip.Writer
	records int
}

// byteCounter counts the bytes written through it.
type byteCounter struct{ n int64 }

func (c *byteCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

func newOSVStripWriter(final string) (*osvStripWriter, error) {
	tmp, err := os.CreateTemp(filepath.Dir(final), "."+filepath.Base(final)+".*.part")
	if err != nil {
		return nil, err
	}
	w := &osvStripWriter{final: final, tmp: tmp, h: sha256.New(), n: &byteCounter{}}
	w.zw = zip.NewWriter(io.MultiWriter(tmp, w.h, w.n))
	return w, nil
}

// add writes one record, deflated, with the fixed time every published zip
// of the publisher carries.
func (w *osvStripWriter) add(name string, data []byte) error {
	dst, err := w.zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: osvDeltaModTime})
	if err != nil {
		return fmt.Errorf("write %s: %w", w.final, err)
	}
	if _, err := dst.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", w.final, err)
	}
	w.records++
	return nil
}

// finish closes the zip, syncs and renames it into place, and returns its
// digest and size.
func (w *osvStripWriter) finish() (osvFileSum, error) {
	fail := func(err error) (osvFileSum, error) {
		w.abort()
		return osvFileSum{}, fmt.Errorf("write %s: %w", w.final, err)
	}
	if err := w.zw.Close(); err != nil {
		return fail(err)
	}
	if err := w.tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := w.tmp.Close(); err != nil {
		return fail(err)
	}
	if err := os.Chmod(w.tmp.Name(), 0o600); err != nil {
		return fail(err)
	}
	if err := os.Rename(w.tmp.Name(), w.final); err != nil {
		return fail(err)
	}
	return osvFileSum{sha256: hex.EncodeToString(w.h.Sum(nil)), size: w.n.n}, nil
}

// abort drops the temp file (a no-op once finish renamed it).
func (w *osvStripWriter) abort() {
	_ = w.tmp.Close()
	_ = os.Remove(w.tmp.Name())
}
