package osvdb

import (
	"archive/zip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExportRecordsAndFlat(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "osv-scalibr", "Go", "all.zip")
	if err := os.MkdirAll(filepath.Dir(zp), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(zp)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for id, body := range map[string]string{"GO-1": `{"id":"GO-1"}`, "GHSA-2": `{"id":"GHSA-2"}`} {
		w, err := zw.Create(EntryName(id))
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
	_ = f.Close()
	got, err := ExportRecords(dir, "Go", []string{"GO-1", "GHSA-2", "CVE-3", "../x", "GO-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got["GO-1"]) != `{"id":"GO-1"}` {
		t.Fatalf("records: %v", got)
	}
	if _, err := ExportRecords(dir, "npm", []string{"x"}); !errors.Is(err, ErrEcosystemNotInstalled) {
		t.Fatalf("missing export: %v", err)
	}
	flat := t.TempDir()
	if err := WriteFlatRecords(flat, got); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(flat, "GHSA-2.json")); err != nil || string(b) != `{"id":"GHSA-2"}` {
		t.Fatalf("flat: %q %v", b, err)
	}
	if err := WriteFlatRecords(flat, map[string][]byte{"../evil": nil}); err == nil {
		t.Fatal("an invalid id was written")
	}
}
