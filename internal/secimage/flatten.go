package secimage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// outerEntry is one entry of the image tar: where its data starts.
type outerEntry struct {
	off, size int64
	typ       byte
	link      string
}

// maxOuterLinks bounds the in-archive symlink chain of a layer path (a
// legacy `docker save` links a repeated layer to its first copy).
const maxOuterLinks = 8

// zstdMaxMemory bounds the zstd decoder's window and buffers.
const zstdMaxMemory = 128 << 20

// counter counts bytes read and fails once a budget is spent.
type counter struct {
	r     io.Reader
	n     int64
	limit int64 // 0: no limit
	err   error
}

func (c *counter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.limit > 0 && c.n > c.limit {
		return n, c.err
	}
	return n, err
}

// Flatten reads a `docker save` or OCI-layout tar of size bytes from r and
// writes the allow-listed files of the flattened root filesystem to dst
// (package doc). It reads the outer tar twice through r (an index pass,
// then each layer by offset) and never holds a layer in memory.
func Flatten(r io.ReaderAt, size int64, dst Sink, lim Limits) (Result, error) {
	res := Result{Compression: map[string]int{}}
	if size < 0 || (lim.MaxInputBytes > 0 && size > lim.MaxInputBytes) {
		return res, refuse(ReasonCapExceeded, "image is %d bytes, cap %d", size, lim.MaxInputBytes)
	}
	idx, err := indexOuter(r, size, lim)
	if err != nil {
		return res, err
	}
	layers, digest, format, err := readManifest(r, idx, lim)
	if err != nil {
		return res, err
	}
	res.Format, res.Digest, res.Layers = format, digest, len(layers)
	if lim.MaxLayers > 0 && len(layers) > lim.MaxLayers {
		return res, refuse(ReasonCapExceeded, "%d layers, cap %d", len(layers), lim.MaxLayers)
	}
	locs := make([]outerEntry, len(layers))
	for i, l := range layers {
		e, ok := resolveOuter(idx, l)
		if !ok {
			return res, refuse(ReasonLayerMissing, "layer %d (%s) is not in the archive", i, l)
		}
		locs[i] = e
	}
	fl := &flattener{dst: dst, lim: lim, res: &res, owner: map[string]int{}, refusedWanted: map[string]bool{}}
	for i, e := range locs {
		if err := fl.layer(r, i, e); err != nil {
			return res, err
		}
	}
	return fl.finish()
}

// seekCounter is the index pass's reader: it tracks the absolute offset
// and lets the tar reader seek over entry data instead of reading it (a
// layer is never read in the index pass).
type seekCounter struct {
	s *io.SectionReader
	n int64
}

func (c *seekCounter) Read(p []byte) (int, error) {
	n, err := c.s.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *seekCounter) Seek(off int64, whence int) (int64, error) {
	pos, err := c.s.Seek(off, whence)
	if err == nil {
		c.n = pos
	}
	return pos, err
}

// indexOuter records where each entry of the image tar starts.
func indexOuter(r io.ReaderAt, size int64, lim Limits) (map[string]outerEntry, error) {
	cr := &seekCounter{s: io.NewSectionReader(r, 0, size)}
	tr := tar.NewReader(cr)
	idx := map[string]outerEntry{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, refuse(ReasonCorrupt, "image tar: %v", err)
		}
		if lim.MaxOuterEntries > 0 && len(idx) >= lim.MaxOuterEntries {
			return nil, refuse(ReasonCapExceeded, "more than %d entries in the image tar", lim.MaxOuterEntries)
		}
		name, ok := cleanRel(h.Name, lim.MaxPathLen)
		if !ok {
			continue // never referenced: a manifest path is cleaned the same way
		}
		if _, dup := idx[name]; dup {
			return nil, refuse(ReasonCorrupt, "image tar names %s twice", name)
		}
		idx[name] = outerEntry{off: cr.n, size: h.Size, typ: h.Typeflag, link: h.Linkname}
	}
	return idx, nil
}

// resolveOuter returns the regular entry name points at, following the
// archive's own symlinks (never the filesystem's) inside the archive.
func resolveOuter(idx map[string]outerEntry, name string) (outerEntry, bool) {
	for range maxOuterLinks {
		e, ok := idx[name]
		if !ok {
			return outerEntry{}, false
		}
		switch e.typ {
		case tar.TypeReg: // the reader turns the old TypeRegA into TypeReg
			return e, true
		case tar.TypeSymlink:
			target := e.link
			if !strings.HasPrefix(target, "/") {
				target = path.Join(path.Dir(name), target)
			}
			next, ok := cleanRel(target, 0)
			if !ok {
				return outerEntry{}, false
			}
			name = next
		default:
			return outerEntry{}, false
		}
	}
	return outerEntry{}, false
}

// readDoc reads one small regular entry.
func readDoc(r io.ReaderAt, idx map[string]outerEntry, name string, lim Limits) ([]byte, bool, error) {
	e, ok := resolveOuter(idx, name)
	if !ok {
		return nil, false, nil
	}
	max := lim.MaxDocBytes
	if max <= 0 {
		max = 4 << 20
	}
	if e.size > max {
		return nil, true, refuse(ReasonCapExceeded, "%s is %d bytes, cap %d", name, e.size, max)
	}
	b := make([]byte, e.size)
	if n, err := r.ReadAt(b, e.off); n < len(b) {
		return nil, true, refuse(ReasonCorrupt, "%s: %v", name, err)
	}
	return b, true, nil
}

// readManifest returns the layer paths in order, the manifest digest and
// the format: manifest.json (docker save, and Docker 25+ beside its OCI
// layout) first, else index.json.
func readManifest(r io.ReaderAt, idx map[string]outerEntry, lim Limits) ([]string, string, string, error) {
	b, ok, err := readDoc(r, idx, "manifest.json", lim)
	if err != nil {
		return nil, "", "", err
	}
	if ok {
		var m []struct{ Layers []string }
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, "", "", refuse(ReasonNotAnImage, "manifest.json: %v", err)
		}
		switch {
		case len(m) == 0:
			return nil, "", "", refuse(ReasonNotAnImage, "manifest.json names no image")
		case len(m) > 1:
			return nil, "", "", refuse(ReasonMultipleImages, "manifest.json names %d images; save one", len(m))
		}
		layers := make([]string, 0, len(m[0].Layers))
		for _, l := range m[0].Layers {
			c, ok := cleanRel(l, lim.MaxPathLen)
			if !ok || strings.HasPrefix(l, "/") {
				return nil, "", "", refuse(ReasonUnsafe, "manifest.json layer path %q", l)
			}
			layers = append(layers, c)
		}
		return layers, sha256Digest(b), "docker-save", nil
	}
	b, ok, err = readDoc(r, idx, "index.json", lim)
	if err != nil {
		return nil, "", "", err
	}
	if !ok {
		return nil, "", "", refuse(ReasonNotAnImage, "neither manifest.json nor index.json")
	}
	// An index may point at a nested index (one platform's); two levels.
	for range 2 {
		var ix struct {
			Manifests []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
			} `json:"manifests"`
			Layers []struct {
				Digest string `json:"digest"`
			} `json:"layers"`
		}
		if err := json.Unmarshal(b, &ix); err != nil {
			return nil, "", "", refuse(ReasonNotAnImage, "OCI index: %v", err)
		}
		switch {
		case len(ix.Manifests) == 0:
			return nil, "", "", refuse(ReasonNotAnImage, "OCI index names no manifest")
		case len(ix.Manifests) > 1:
			return nil, "", "", refuse(ReasonMultipleImages, "OCI index names %d manifests; save one platform", len(ix.Manifests))
		}
		blob, ok := blobPath(ix.Manifests[0].Digest)
		if !ok {
			return nil, "", "", refuse(ReasonUnsafe, "OCI digest %q", ix.Manifests[0].Digest)
		}
		mb, found, err := readDoc(r, idx, blob, lim)
		if err != nil {
			return nil, "", "", err
		}
		if !found {
			return nil, "", "", refuse(ReasonLayerMissing, "manifest blob %s is not in the archive", blob)
		}
		if sha256Digest(mb) != ix.Manifests[0].Digest {
			return nil, "", "", refuse(ReasonCorrupt, "manifest blob %s does not match its digest", blob)
		}
		var m struct {
			Manifests []json.RawMessage `json:"manifests"`
			Layers    []struct {
				Digest string `json:"digest"`
			} `json:"layers"`
		}
		if err := json.Unmarshal(mb, &m); err != nil {
			return nil, "", "", refuse(ReasonNotAnImage, "OCI manifest: %v", err)
		}
		if len(m.Manifests) > 0 {
			b = mb
			continue
		}
		layers := make([]string, 0, len(m.Layers))
		for _, l := range m.Layers {
			p, ok := blobPath(l.Digest)
			if !ok {
				return nil, "", "", refuse(ReasonUnsafe, "OCI layer digest %q", l.Digest)
			}
			layers = append(layers, p)
		}
		return layers, ix.Manifests[0].Digest, "oci-layout", nil
	}
	return nil, "", "", refuse(ReasonNotAnImage, "OCI index nested too deep")
}

func sha256Digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// blobPath maps an OCI digest to its blob path; only sha256 with a 64-hex
// value is accepted.
func blobPath(d string) (string, bool) {
	alg, h, ok := strings.Cut(d, ":")
	if !ok || alg != "sha256" || len(h) != 64 {
		return "", false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return "blobs/sha256/" + h, true
}

// cleanRel cleans an archive path: "./" and leading "/" trimmed, then
// refused (false) when it holds a NUL or a ".." segment, is empty, or is
// longer than maxLen (0: no cap). Layer entries are checked with
// cleanLayer, which also refuses absolute paths.
func cleanRel(name string, maxLen int) (string, bool) {
	if (maxLen > 0 && len(name) > maxLen) || strings.ContainsRune(name, 0) {
		return "", false
	}
	n := strings.TrimLeft(name, "/")
	for _, seg := range strings.Split(n, "/") {
		if seg == ".." {
			return "", false
		}
	}
	c := path.Clean(n)
	if c == "." || c == "" || strings.HasPrefix(c, "../") {
		return "", false
	}
	return c, true
}

// cleanLayer is cleanRel for a layer entry: an absolute path is refused
// too (layer paths are relative to the image root).
func cleanLayer(name string, maxLen int) (string, bool) {
	if strings.HasPrefix(name, "/") {
		return "", false
	}
	return cleanRel(name, maxLen)
}

// flattener is one Flatten's state.
type flattener struct {
	dst Sink
	lim Limits
	res *Result
	// owner: extracted path -> the layer that wrote it.
	owner map[string]int
	// refusedWanted: allow-listed paths whose latest entry was unusable.
	refusedWanted map[string]bool
	written       int64
	decompressed  int64
}

// layer applies one layer.
func (f *flattener) layer(r io.ReaderAt, li int, e outerEntry) error {
	sec := io.NewSectionReader(r, e.off, e.size)
	rd, kind, closeFn, err := decompressor(sec)
	if err != nil {
		return refuse(ReasonCorrupt, "layer %d: %v", li, err)
	}
	if closeFn != nil {
		defer closeFn()
	}
	f.res.Compression[kind]++
	limit := int64(0)
	if f.lim.MaxRatio > 0 {
		limit = max(f.lim.RatioFloor, e.size*f.lim.MaxRatio)
	}
	capErr := refuse(ReasonCapExceeded, "layer %d passed the decompression ratio cap", li)
	if f.lim.MaxDecompressedBytes > 0 {
		left := f.lim.MaxDecompressedBytes - f.decompressed
		if left <= 0 {
			return refuse(ReasonCapExceeded, "the image passed the decompressed size cap")
		}
		if limit == 0 || left < limit {
			limit = left
			capErr = refuse(ReasonCapExceeded, "the image passed the decompressed size cap")
		}
	}
	dc := &counter{r: rd, limit: limit, err: capErr}
	defer func() {
		f.res.CompressedBytes += e.size
		f.res.DecompressedBytes += dc.n
		f.decompressed += dc.n
	}()
	tr := tar.NewReader(dc)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			var ce *Error
			if errors.As(err, &ce) {
				return err
			}
			return refuse(ReasonCorrupt, "layer %d: %v", li, err)
		}
		f.res.EntriesWalked++
		if f.lim.MaxEntries > 0 && f.res.EntriesWalked > f.lim.MaxEntries {
			return refuse(ReasonCapExceeded, "more than %d layer entries", f.lim.MaxEntries)
		}
		if err := f.entry(tr, li, h); err != nil {
			return err
		}
	}
}

// entry applies one layer entry.
func (f *flattener) entry(tr *tar.Reader, li int, h *tar.Header) error {
	if c := strings.TrimPrefix(h.Name, "./"); c == "" || c == "." {
		return nil // the layer's root directory
	}
	p, ok := cleanLayer(h.Name, f.lim.MaxPathLen)
	if !ok {
		f.res.Refused++
		return nil
	}
	dir, base := path.Split(p)
	dir = strings.TrimSuffix(dir, "/")
	switch {
	case base == ".wh..wh..opq":
		f.res.OpaqueWhiteouts++
		return f.removeLower(dir, li, true)
	case strings.HasPrefix(base, ".wh."):
		f.res.Whiteouts++
		return f.removeLower(path.Join(dir, strings.TrimPrefix(base, ".wh.")), li, false)
	}
	// Overlay semantics: any entry at p replaces what a lower layer had
	// there; a non-directory also hides everything a lower layer had
	// beneath p (a directory replaced by a file or a link).
	if err := f.replaceLower(p, li, h.Typeflag != tar.TypeDir); err != nil {
		return err
	}
	if !Wanted(p) {
		return nil
	}
	delete(f.refusedWanted, p)
	switch h.Typeflag {
	case tar.TypeReg: // the reader turns the old TypeRegA into TypeReg
		return f.write(p, tr, h.Size, li)
	case tar.TypeSymlink:
		// Never followed. An os-release link is expected (finish copies
		// usr/lib/os-release); a package database must be a regular file.
		if isPackageDB(p) {
			f.refusedWanted[p] = true
		}
		if strings.HasPrefix(h.Linkname, "/") {
			return nil // absolute targets are relative to the image root, never the host
		}
		if _, ok := cleanRel(path.Join(dir, h.Linkname), 0); !ok { //nolint:gosec // G305: only checks whether the link target stays inside the root; nothing is written through it
			f.res.Refused++ // the link leaves the root
		}
		return nil
	case tar.TypeLink:
		target, ok := cleanLayer(h.Linkname, f.lim.MaxPathLen)
		if !ok {
			f.res.Refused++
			f.refusedWanted[p] = true
			return nil
		}
		if _, have := f.owner[target]; !have {
			f.refusedWanted[p] = true // its target was not extracted
			return nil
		}
		return f.copy(target, p, li)
	default:
		f.res.Refused++
		if isPackageDB(p) {
			f.refusedWanted[p] = true
		}
		return nil
	}
}

func (f *flattener) write(p string, r io.Reader, size int64, li int) error {
	if size < 0 || (f.lim.MaxEntryBytes > 0 && size > f.lim.MaxEntryBytes) {
		return refuse(ReasonCapExceeded, "%s is %d bytes, cap %d", p, size, f.lim.MaxEntryBytes)
	}
	if f.lim.MaxOutputBytes > 0 && f.written+size > f.lim.MaxOutputBytes {
		return refuse(ReasonCapExceeded, "extracted files passed %d bytes", f.lim.MaxOutputBytes)
	}
	w, err := f.dst.Create(p)
	if err != nil {
		return refuse(ReasonOutputFailed, "%s: %v", p, err)
	}
	n, err := io.CopyN(w, r, size)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		var ce *Error
		if errors.As(err, &ce) {
			return err
		}
		if n < size {
			return refuse(ReasonCorrupt, "%s: %v", p, err)
		}
		return refuse(ReasonOutputFailed, "%s: %v", p, err)
	}
	f.written += size
	f.owner[p] = li
	return nil
}

// copy writes a hard link's content: the target was extracted, by this
// layer or a lower one.
func (f *flattener) copy(from, to string, li int) error {
	if from == to {
		f.owner[to] = li
		return nil
	}
	size := f.lim.MaxEntryBytes
	if size <= 0 {
		size = 512 << 20
	}
	if err := copyWithin(f.dst, from, to, size); err != nil {
		return refuse(ReasonOutputFailed, "%s: %v", to, err)
	}
	f.owner[to] = li
	return nil
}

// removeLower applies a whiteout of layer li: the files a LOWER layer
// wrote at p and beneath it (or, for an opaque whiteout, only beneath the
// directory p) are removed. Files of layer li itself stay.
func (f *flattener) removeLower(p string, li int, opaque bool) error {
	for k, l := range f.owner {
		if l >= li {
			continue
		}
		hit := k == p || strings.HasPrefix(k, p+"/")
		if opaque {
			hit = p == "" || strings.HasPrefix(k, p+"/")
		}
		if !hit {
			continue
		}
		if err := f.dst.Remove(k); err != nil {
			return refuse(ReasonOutputFailed, "%s: %v", k, err)
		}
		delete(f.owner, k)
		f.res.RemovedByWhiteout++
	}
	for k := range f.refusedWanted {
		if k == p || strings.HasPrefix(k, p+"/") || (opaque && p == "") {
			delete(f.refusedWanted, k)
		}
	}
	return nil
}

// replaceLower removes what lower layers wrote at p (and beneath it when
// subtree), before layer li's entry at p takes its place.
func (f *flattener) replaceLower(p string, li int, subtree bool) error {
	for k, l := range f.owner {
		if l >= li || !(k == p || (subtree && strings.HasPrefix(k, p+"/"))) {
			continue
		}
		if err := f.dst.Remove(k); err != nil {
			return refuse(ReasonOutputFailed, "%s: %v", k, err)
		}
		delete(f.owner, k)
	}
	if subtree {
		for k := range f.refusedWanted {
			if strings.HasPrefix(k, p+"/") {
				delete(f.refusedWanted, k)
			}
		}
	}
	return nil
}

func (f *flattener) finish() (Result, error) {
	have := map[string]bool{}
	for k := range f.owner {
		have[k] = true
	}
	if err := finishOSRelease(f.dst, have, f.res); err != nil {
		return *f.res, err
	}
	for k := range have {
		f.res.Files = append(f.res.Files, k)
	}
	sort.Strings(f.res.Files)
	for k := range f.refusedWanted {
		f.res.RefusedWanted = append(f.res.RefusedWanted, k)
	}
	sort.Strings(f.res.RefusedWanted)
	return *f.res, nil
}

// decompressor sniffs a layer's compression from its magic bytes.
func decompressor(r *io.SectionReader) (io.Reader, string, func(), error) {
	var magic [4]byte
	n, _ := r.ReadAt(magic[:], 0)
	switch {
	case n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		g, err := gzip.NewReader(r)
		if err != nil {
			return nil, "", nil, err
		}
		return g, "gzip", func() { _ = g.Close() }, nil
	case n == 4 && bytes.Equal(magic[:], []byte{0x28, 0xb5, 0x2f, 0xfd}):
		z, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(zstdMaxMemory), zstd.WithDecoderLowmem(true))
		if err != nil {
			return nil, "", nil, err
		}
		return z, "zstd", z.Close, nil
	default:
		return r, "none", nil, nil
	}
}
