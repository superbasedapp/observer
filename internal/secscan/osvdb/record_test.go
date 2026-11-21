package osvdb

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeExport writes dir/osv-scalibr/<eco>/all.zip with name->body entries.
func writeExport(t *testing.T, s Store, eco string, entries map[string]string) string {
	t.Helper()
	path := s.zipPath("osv-scalibr", eco)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	// Written aside and renamed in, the way the store installs an export.
	tmp := path + ".part"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename over the export (is it held open?): %v", err)
	}
	return path
}

func installedStore(t *testing.T, ecos ...string) Store {
	t.Helper()
	s := Open(t.TempDir())
	m := map[string]Epoch{}
	for _, e := range ecos {
		m[e] = Epoch{Ecosystem: e, LastModified: "Mon, 02 Nov 2026 00:00:00 GMT", CRC32C: "AAAAAA==", FetchedAt: time.Now()}
	}
	if err := os.MkdirAll(s.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.writeEpochs(m); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestRecordReader: a record is read by its own id from the installed
// export; an absent id, an invalid id, an ecosystem with no verified
// export and a name that could climb out of the store all refuse.
func TestRecordReader(t *testing.T) {
	s := installedStore(t, "npm")
	writeExport(t, s, "npm", map[string]string{"GHSA-aaaa-bbbb-cccc.json": `{"id":"GHSA-aaaa-bbbb-cccc"}`})
	// An export on disk with no epoch record is not installed.
	writeExport(t, s, "PyPI", map[string]string{"PYSEC-1.json": `{"id":"PYSEC-1"}`})
	rr := NewRecordReader(s)
	defer rr.Close()

	got, err := rr.Record("npm", "GHSA-aaaa-bbbb-cccc")
	if err != nil || string(got) != `{"id":"GHSA-aaaa-bbbb-cccc"}` {
		t.Fatalf("record: %q %v", got, err)
	}
	cases := []struct {
		name, eco, id string
		want          error
	}{
		{"absent id", "npm", "GHSA-zzzz-zzzz-zzzz", ErrRecordNotFound},
		{"invalid id", "npm", "../epochs", ErrRecordNotFound},
		{"dotdot id", "npm", "..", ErrRecordNotFound},
		{"no epoch", "PyPI", "PYSEC-1", ErrEcosystemNotInstalled},
		{"unknown ecosystem", "Hex", "X-1", ErrEcosystemNotInstalled},
		{"traversal ecosystem", "../osv-scalibr/npm", "GHSA-aaaa-bbbb-cccc", ErrEcosystemNotInstalled},
		{"separator ecosystem", `npm\..`, "GHSA-aaaa-bbbb-cccc", ErrEcosystemNotInstalled},
	}
	for _, c := range cases {
		if _, err := rr.Record(c.eco, c.id); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

// TestRecordReaderSeesReplacement: the cached directory is dropped when a
// refresh renames a new export in, and the reader never holds the file
// open (the rename succeeds on Windows too).
func TestRecordReaderSeesReplacement(t *testing.T) {
	s := installedStore(t, "npm")
	writeExport(t, s, "npm", map[string]string{"GHSA-1.json": `{"id":"GHSA-1","v":1}`})
	rr := NewRecordReader(s)
	defer rr.Close()
	if b, err := rr.Record("npm", "GHSA-1"); err != nil || !strings.Contains(string(b), `"v":1`) {
		t.Fatalf("first: %q %v", b, err)
	}
	writeExport(t, s, "npm", map[string]string{
		"GHSA-1.json": `{"id":"GHSA-1","v":2,"pad":"` + strings.Repeat("x", 64) + `"}`,
		"GHSA-2.json": `{"id":"GHSA-2"}`,
	})
	if b, err := rr.Record("npm", "GHSA-1"); err != nil || !strings.Contains(string(b), `"v":2`) {
		t.Fatalf("after replacement: %q %v", b, err)
	}
	if _, err := rr.Record("npm", "GHSA-2"); err != nil {
		t.Fatalf("new record: %v", err)
	}
}

// TestRecordReaderSizeCap: a record over MaxViewRecordBytes is refused.
func TestRecordReaderSizeCap(t *testing.T) {
	s := installedStore(t, "npm")
	writeExport(t, s, "npm", map[string]string{"GHSA-big.json": `{"id":"GHSA-big","x":"` + strings.Repeat("a", MaxViewRecordBytes) + `"}`})
	rr := NewRecordReader(s)
	if _, err := rr.Record("npm", "GHSA-big"); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("big record: %v", err)
	}
}
