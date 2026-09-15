package webcloud

import (
	"io/fs"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEmbeddedDistPresent is the wiring assertion from the divergence plan's
// W7 first task (E10): the portal SPA must actually be embedded in the binary.
// A build made from a tree where webcloud/dist was never built (or was
// gitignored away) would otherwise compile fine and serve 500s for every
// portal route — this pins that failure to a loud test instead of a deploy.
func TestEmbeddedDistPresent(t *testing.T) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		t.Fatalf("embedded dist missing entirely: %v", err)
	}
	f, err := sub.Open("index.html")
	if err != nil {
		t.Fatalf("embedded dist has no index.html — run the webcloud build before shipping: %v", err)
	}
	_ = f.Close()

	// index.html must reference at least one fingerprinted asset that is also
	// embedded — an index without its assets is a half-built dist.
	entries, err := fs.ReadDir(sub, "assets")
	if err != nil || len(entries) == 0 {
		t.Fatalf("embedded dist/assets empty or missing (err=%v) — half-built SPA", err)
	}
}

// TestHandlerServesSPARoutes pins the Handler contract: the root and unknown
// client-side routes serve index.html; embedded static assets serve directly.
func TestHandlerServesSPARoutes(t *testing.T) {
	h := Handler()

	for _, path := range []string{"/", "/privacy", "/usage/nested/route"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 {
			t.Fatalf("GET %s = %d, want 200 (SPA fallback)", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("GET %s Content-Type = %q, want text/html (index fallback)", path, ct)
		}
	}

	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	entries, err := fs.ReadDir(sub, "assets")
	if err != nil || len(entries) == 0 {
		t.Fatalf("no embedded assets to probe (err=%v)", err)
	}
	assetPath := "/assets/" + entries[0].Name()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", assetPath, nil))
	if rec.Code != 200 {
		t.Fatalf("GET %s = %d, want 200 (embedded asset)", assetPath, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
		t.Fatalf("GET %s served as HTML — asset route fell through to the SPA fallback", assetPath)
	}
}
