package webcloud

import (
	"io/fs"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestStaffHandlerServesSPA pins the staff embed: client routes get
// staff.html, embedded assets are served, a missing asset is a 404, and the
// staff bundle carries none of the portal's entry.
func TestStaffHandlerServesSPA(t *testing.T) {
	h := StaffHandler()
	for _, path := range []string{"/", "/orgs", "/orgs/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "/staff.html"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("GET %s = %d %q, want the staff index", path, rec.Code, rec.Header().Get("Content-Type"))
		}
		if !strings.Contains(rec.Body.String(), "/staff/assets/") {
			t.Fatalf("GET %s: the index does not load /staff/ assets", path)
		}
	}
	sub, err := fs.Sub(staffDistFS, "dist-staff")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(sub, "assets")
	if err != nil || len(entries) == 0 {
		t.Fatalf("embedded dist-staff/assets empty (err=%v): run the staff build", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/assets/"+entries[0].Name(), nil))
	if rec.Code != 200 || strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("asset = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/assets/missing-chunk.js", nil))
	if rec.Code != 404 {
		t.Fatalf("missing asset = %d, want 404", rec.Code)
	}
	if _, err := sub.Open("index.html"); err == nil {
		t.Fatal("dist-staff carries the portal's index.html")
	}
}
