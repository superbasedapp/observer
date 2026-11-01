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

// TestHandleSecurityScannersDB is the operator's ruling PT-19 (2) on the
// dashboard: the Scanners card's database accept answers 404 unless a
// dependency driver is selected, reads the state with the confirm token,
// and records the accept only on a POST carrying it; GET
// /api/security/scanners carries the same state for the card.
func TestHandleSecurityScannersDB(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	accepted := false
	seam := &dashapi.ScannerDB{
		Status: func(context.Context) (dashapi.ScannerDBStatus, error) {
			st := dashapi.ScannerDBStatus{Accepted: accepted, ApproxMB: 300, Source: "osv-vulnerabilities.storage.googleapis.com", Text: "about 300 MB"}
			if !accepted {
				st.Blocked = "database_not_accepted"
			}
			return st, nil
		},
		Accept: func(context.Context) error { accepted = true; return nil },
	}
	// Not selected: 404, nothing recorded.
	off := &Server{opts: Options{ConfigPath: cfg, ScannerDB: seam, SecuritySelected: scannerRule("security.deps")}}
	off.comps.svc = scannerSnapSvc{snap: componentstate.Snapshot{Configured: true}}
	w := httptest.NewRecorder()
	off.handleSecurityScannersDB(w, httptest.NewRequest(http.MethodGet, "/api/security/scanners/db", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("not selected: %d", w.Code)
	}
	none := &Server{opts: Options{ConfigPath: cfg, SecuritySelected: scannerRule("security.deps", "security.scan.osv")}}
	none.comps.svc = scannerSnapSvc{snap: componentstate.Snapshot{Configured: true}}
	w = httptest.NewRecorder()
	none.handleSecurityScannersDB(w, httptest.NewRequest(http.MethodGet, "/api/security/scanners/db", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("no seam: %d", w.Code)
	}

	s := &Server{opts: Options{ConfigPath: cfg, ScannerDB: seam, SecuritySelected: scannerRule("security.deps", "security.scan.osv")}}
	s.comps.svc = scannerSnapSvc{snap: componentstate.Snapshot{Configured: true}}
	w = httptest.NewRecorder()
	s.handleSecurityScannersDB(w, httptest.NewRequest(http.MethodGet, "/api/security/scanners/db", nil))
	if w.Code != http.StatusOK || accepted {
		t.Fatalf("GET %d %s", w.Code, w.Body)
	}
	var resp struct {
		Status       dashapi.ScannerDBStatus `json:"status"`
		ConfirmToken string                  `json:"confirm_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.ConfirmToken == "" || resp.Status.Accepted || resp.Status.ApproxMB != 300 || resp.Status.Source == "" {
		t.Fatalf("GET body %s %v", w.Body, err)
	}
	post := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/security/scanners/db", strings.NewReader(`{"accept":true}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(remoteConfirmHeader, token)
		r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: resp.ConfirmToken})
		w := httptest.NewRecorder()
		s.handleSecurityScannersDB(w, r)
		return w
	}
	if w := post("wrong"); w.Code != http.StatusForbidden || accepted {
		t.Fatalf("a POST without the token must not record: %d", w.Code)
	}
	if w := post(resp.ConfirmToken); w.Code != http.StatusOK || !accepted {
		t.Fatalf("POST %d %s", w.Code, w.Body)
	}
	// The card's read carries the state.
	w = httptest.NewRecorder()
	s.handleSecurityScanners(w, httptest.NewRequest(http.MethodGet, "/api/security/scanners", nil))
	var card struct {
		DB *dashapi.ScannerDBStatus `json:"db"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &card); err != nil || card.DB == nil || !card.DB.Accepted {
		t.Fatalf("scanners card db %s %v", w.Body, err)
	}
}
