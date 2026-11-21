//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// TestHandleSecurityScannersTrivyDB (lane OS-2 T): the Trivy database
// accept answers 404 unless the Trivy image driver and what it needs are
// selected, or in a build whose seam carries no accept; GET reads the
// image driver's state with the confirm token; only a POST carrying it
// records; GET /api/security/scanners carries the same state.
func TestHandleSecurityScannersTrivyDB(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	accepted := false
	status := func(context.Context) (dashapi.ScannerDBStatus, error) {
		return dashapi.ScannerDBStatus{Image: &dashapi.ScannerImageStatus{
			Driver: "trivy", Default: "scalibr", Choices: []string{"scalibr", "trivy"}, ScalibrCompiled: true, TrivyCompiled: true,
			Trivy: &dashapi.ScannerTrivyImageStatus{Selected: true, DB: dashapi.ScannerTrivyDBStatus{Accepted: accepted, ApproxDownloadMB: 140, ApproxDiskMB: 1700, Source: "ghcr.io"}},
		}}, nil
	}
	seam := &dashapi.ScannerDB{Status: status, AcceptTrivyDB: func(context.Context) error { accepted = true; return nil }}
	all := scannerRule("security.deps", "security.scan.osv", "security.scan.trivy", "security.scan.image.trivy")
	srv := func(seam *dashapi.ScannerDB, rule func(componentstate.Snapshot, string) bool) *Server {
		s := &Server{opts: Options{ConfigPath: cfg, ScannerDB: seam, SecuritySelected: rule}}
		s.comps.svc = scannerSnapSvc{snap: componentstate.Snapshot{Configured: true}}
		return s
	}
	get := func(s *Server) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleSecurityScannersTrivyDB(w, httptest.NewRequest(http.MethodGet, "/api/security/scanners/trivydb", nil))
		return w
	}
	if w := get(srv(seam, scannerRule("security.deps", "security.scan.trivy"))); w.Code != http.StatusNotFound {
		t.Fatalf("not selected: %d", w.Code)
	}
	if w := get(srv(&dashapi.ScannerDB{Status: status}, all)); w.Code != http.StatusNotFound {
		t.Fatalf("no accept in the seam: %d", w.Code)
	}
	s := srv(seam, all)
	w := get(s)
	var resp struct {
		Status       dashapi.ScannerImageStatus `json:"status"`
		ConfirmToken string                     `json:"confirm_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK || resp.ConfirmToken == "" || resp.Status.Trivy == nil || resp.Status.Trivy.DB.Accepted {
		t.Fatalf("GET %d %s %v", w.Code, w.Body, err)
	}
	post := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/security/scanners/trivydb", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(remoteConfirmHeader, token)
		r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: resp.ConfirmToken})
		w := httptest.NewRecorder()
		s.handleSecurityScannersTrivyDB(w, r)
		return w
	}
	if w := post("wrong"); w.Code != http.StatusForbidden || accepted {
		t.Fatalf("a POST without the token must not record: %d", w.Code)
	}
	if w := post(resp.ConfirmToken); w.Code != http.StatusOK || !accepted {
		t.Fatalf("POST %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	s.handleSecurityScanners(w, httptest.NewRequest(http.MethodGet, "/api/security/scanners", nil))
	var card struct {
		Image *dashapi.ScannerImageStatus `json:"image"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &card); err != nil || card.Image == nil || card.Image.Driver != "trivy" || card.Image.Trivy == nil || !card.Image.Trivy.DB.Accepted {
		t.Fatalf("scanners card image %s %v", w.Body, err)
	}
}
