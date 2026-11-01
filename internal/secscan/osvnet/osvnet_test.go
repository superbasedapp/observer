package osvnet

import (
	"archive/zip"
	"bytes"
	"context"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
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
