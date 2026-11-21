package secimage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// The archives these tests read are built here, in Go: no real image sits
// in testdata (size, licence, and the fixture rule that testdata carries no
// environment).

// tent is one tar entry.
type tent struct {
	name string
	typ  byte
	body string
	link string
	size int64 // for zero-filled bodies (bombs); body is ignored when set
}

func reg(name, body string) tent   { return tent{name: name, typ: tar.TypeReg, body: body} }
func sym(name, target string) tent { return tent{name: name, typ: tar.TypeSymlink, link: target} }

func hard(name, target string) tent      { return tent{name: name, typ: tar.TypeLink, link: target} }
func dirent(name string) tent            { return tent{name: name, typ: tar.TypeDir} }
func zeros(name string, size int64) tent { return tent{name: name, typ: tar.TypeReg, size: size} }

// tarOf writes entries as an uncompressed tar.
func tarOf(t testing.TB, entries ...tent) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: 0o644}
		if e.typ == tar.TypeDir {
			h.Mode = 0o755
		}
		if e.typ == tar.TypeReg {
			h.Size = int64(len(e.body))
			if e.size > 0 {
				h.Size = e.size
			}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if e.size > 0 {
				chunk := make([]byte, 1<<16)
				for left := e.size; left > 0; {
					n := min(left, int64(len(chunk)))
					if _, err := tw.Write(chunk[:n]); err != nil {
						t.Fatal(err)
					}
					left -= n
				}
			} else if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gz(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zst(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// dockerSave builds a legacy `docker save` tar: manifest.json naming
// <i>/layer.tar per layer, plus extra outer entries.
func dockerSave(t testing.TB, layers [][]byte, extra ...tent) []byte {
	t.Helper()
	var names []string
	var entries []tent
	for i, l := range layers {
		n := fmt.Sprintf("%d/layer.tar", i)
		names = append(names, n)
		entries = append(entries, reg(n, string(l)))
	}
	m, _ := json.Marshal([]map[string]any{{"Config": "config.json", "RepoTags": []string{"test:latest"}, "Layers": names}})
	entries = append(entries, reg("config.json", "{}"), reg("manifest.json", string(m)))
	return tarOf(t, append(entries, extra...)...)
}

// manifestTar builds a tar with a hand-written manifest.json.
func manifestTar(t testing.TB, manifest string, entries ...tent) []byte {
	t.Helper()
	return tarOf(t, append(entries, reg("manifest.json", manifest))...)
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// ociLayout builds an OCI layout tar: index.json -> manifest blob -> layer
// blobs; it returns the tar and the manifest digest.
func ociLayout(t testing.TB, layers [][]byte) ([]byte, string) {
	t.Helper()
	var entries []tent
	var ls []map[string]any
	for _, l := range layers {
		d := digestOf(l)
		ls = append(ls, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": d, "size": len(l)})
		entries = append(entries, reg("blobs/sha256/"+d[len("sha256:"):], string(l)))
	}
	cfg := []byte("{}")
	entries = append(entries, reg("blobs/sha256/"+digestOf(cfg)[7:], string(cfg)))
	mb, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"digest": digestOf(cfg), "size": len(cfg)}, "layers": ls,
	})
	md := digestOf(mb)
	entries = append(entries, reg("blobs/sha256/"+md[7:], string(mb)))
	ix, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []map[string]any{{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": md, "size": len(mb)}}})
	entries = append(entries, reg("oci-layout", `{"imageLayoutVersion":"1.0.0"}`), reg("index.json", string(ix)))
	return tarOf(t, entries...), md
}

// flatten runs Flatten into a fresh run directory.
func flatten(t testing.TB, img []byte, lim Limits) (Result, string, error) {
	t.Helper()
	dir := t.TempDir()
	run := filepath.Join(dir, "run")
	if err := os.Mkdir(run, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := NewDirSink(run)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	res, err := Flatten(bytes.NewReader(img), int64(len(img)), s, lim)
	return res, run, err
}

// filesIn lists the regular files under dir, relative, slash-separated.
func filesIn(t testing.TB, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			t.Errorf("%s is a symlink; the reader must never write one", p)
		}
		if d.Type().IsRegular() {
			r, _ := filepath.Rel(dir, p)
			out = append(out, filepath.ToSlash(r))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

const (
	debianOSRelease = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\n"
	alpineOSRelease = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\n"
	dpkgStatus      = "Package: libc6\nStatus: install ok installed\nSource: glibc\nVersion: 2.36-9+deb12u2\nArchitecture: amd64\n\n"
)
