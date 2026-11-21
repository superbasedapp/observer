//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestSecuritySBOMRoute: 404 compiled out, not selected, unknown project
// and no inventory; a stored inventory downloads as CycloneDX.
func TestSecuritySBOMRoute(t *testing.T) {
	s, root := newTestServer(t)
	hash := secposture.ProjectRootHash(root)
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleSecuritySBOM(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	if w := get("/api/security/sbom?project=" + hash); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "component_not_installed") {
		t.Fatalf("no seam: %d %s", w.Code, w.Body)
	}
	have := false
	var asked string
	s.opts.SecurityProjectSBOM = func(_ context.Context, r string) ([]byte, bool, error) {
		asked = r
		if !have {
			return nil, false, nil
		}
		return []byte(`{"bomFormat":"CycloneDX"}`), true, nil
	}
	s.comps.svc = scannerSnapSvc{snap: componentstate.Snapshot{Configured: true}}
	s.opts.SecuritySelected = scannerRule()
	if w := get("/api/security/sbom?project=" + hash); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "not_selected") {
		t.Fatalf("not selected: %d %s", w.Code, w.Body)
	}
	s.opts.SecuritySelected = scannerRule("security.deps")
	cases := []struct {
		name, path, code string
		status           int
	}{
		{"no project", "/api/security/sbom", "no_project", http.StatusBadRequest},
		{"unknown project", "/api/security/sbom?project=nope", "unknown_project", http.StatusNotFound},
		{"no inventory", "/api/security/sbom?project=" + hash, "no_inventory", http.StatusNotFound},
	}
	for _, c := range cases {
		if w := get(c.path); w.Code != c.status || !strings.Contains(w.Body.String(), c.code) {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body)
		}
	}
	have = true
	w := get("/api/security/sbom?project=" + hash)
	if w.Code != http.StatusOK || asked != root || w.Body.String() != `{"bomFormat":"CycloneDX"}` {
		t.Fatalf("download: %d %s asked %q", w.Code, w.Body, asked)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/vnd.cyclonedx+json" {
		t.Errorf("content type %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, ".sbom.cdx.json") {
		t.Errorf("disposition %q", cd)
	}
}

// TestSecuritySBOMFileName: one case per shape.
func TestSecuritySBOMFileName(t *testing.T) {
	for in, want := range map[string]string{
		"my-app":   "my-app.sbom.cdx.json",
		"a b/c\"d": "a_b_c_d.sbom.cdx.json",
		"..":       "project.sbom.cdx.json",
		"":         "project.sbom.cdx.json",
	} {
		if got := securitySBOMFileName(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
