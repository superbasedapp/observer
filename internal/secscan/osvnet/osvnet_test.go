package osvnet

import (
	"archive/zip"
	"bytes"
	"context"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

func TestAllowListRefusesOtherHosts(t *testing.T) {
	c := New(Options{})
	for _, u := range []string{"https://example.com/x", "http://" + BucketHost + "/npm/all.zip", "https://api.osv.dev.evil.test/"} {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		if _, err := c.HTTPClient().Do(req); err == nil {
			t.Errorf("%s must be refused", u)
		}
	}
	if _, err := c.exportURL("../../etc"); err == nil {
		t.Error("a path-shaped ecosystem must be refused")
	}
}

func TestRefreshThroughLane(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("a.json")
	_, _ = w.Write([]byte("{}"))
	_ = zw.Close()
	body := buf.Bytes()
	crc := osvdb.CRC32CString(crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)))
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.URL.Path != "/crates.io/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Goog-Hash", "crc32c="+crc+",md5=xxxx")
		w.Header().Set("Last-Modified", "Tue, 20 Oct 2026 11:25:00 GMT")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	c := New(Options{BucketURL: srv.URL})
	s := osvdb.Open(t.TempDir())
	rep, err := s.Refresh(context.Background(), c, []string{"crates.io", "npm"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Changed) != 1 || rep.Changed[0] != "crates.io" || rep.Failed["npm"] == "" {
		t.Fatalf("report %+v", rep)
	}
	if paths[0] != "HEAD /crates.io/all.zip" {
		t.Fatalf("the lane must ask for metadata first: %v", paths)
	}
}

// TestGitHubActionsThroughLane: the GitHub Actions ecosystem's name holds a
// space; the lane escapes it (%20) in the export, the listing and a record
// URL, the store keeps it as one directory element, and a feed file name
// with a space is refused (the feed serves osvdb.ExportArtifact's name).
func TestGitHubActionsThroughLane(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("GHSA-mrrh-fwg8-r2c3.json")
	_, _ = w.Write([]byte(`{"id":"GHSA-mrrh-fwg8-r2c3"}`))
	_ = zw.Close()
	body := buf.Bytes()
	crc := osvdb.CRC32CString(crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)))
	var raw []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw = append(raw, r.Method+" "+r.URL.EscapedPath())
		switch r.URL.EscapedPath() {
		case "/GitHub%20Actions/all.zip":
			w.Header().Set("X-Goog-Hash", "crc32c="+crc+",md5=xxxx")
			w.Header().Set("Last-Modified", "Tue, 03 Nov 2026 11:25:00 GMT")
			_, _ = w.Write(body)
		case "/GitHub%20Actions/GHSA-mrrh-fwg8-r2c3.json":
			_, _ = w.Write([]byte(`{"id":"GHSA-mrrh-fwg8-r2c3"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(Options{BucketURL: srv.URL})
	dir := t.TempDir()
	s := osvdb.Open(dir)
	rep, err := s.Refresh(context.Background(), c, []string{"GitHub Actions"}, time.Now())
	if err != nil || len(rep.Changed) != 1 {
		t.Fatalf("refresh %+v %v (requests %v)", rep, err, raw)
	}
	if _, err := os.Stat(filepath.Join(dir, "osv-scalibr", "GitHub Actions", "all.zip")); err != nil {
		t.Fatalf("the export is not stored under its own name: %v", err)
	}
	if inst, _ := s.Installed(); inst["GitHub Actions"] == "" {
		t.Fatalf("installed %v", inst)
	}
	if _, err := c.Record(context.Background(), "GitHub Actions", "GHSA-mrrh-fwg8-r2c3"); err != nil {
		t.Fatalf("record: %v (requests %v)", err, raw)
	}
	if u, err := c.objectURL("GitHub Actions", "modified_id.csv"); err != nil || !strings.HasSuffix(u, "/GitHub%20Actions/modified_id.csv") {
		t.Fatalf("listing URL %q %v", u, err)
	}
	if _, err := c.feedFileURL("security.osv_export", "GitHub Actions.zip"); err == nil {
		t.Fatal("a feed file name with a space must be refused")
	}
	if u, err := c.feedFileURL("security.osv_export", osvdb.ExportArtifact("GitHub Actions")); err != nil || !strings.HasSuffix(u, "/security.osv_export/GitHub-Actions.zip") {
		t.Fatalf("feed URL %q %v", u, err)
	}
}
