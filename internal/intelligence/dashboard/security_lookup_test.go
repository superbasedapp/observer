//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// TestHandleSecurityLookup (lane RM-2, plan section 13.10): the package
// lookup posture answers 404 unless a dependency driver is selected or in a
// seam that carries none; GET reads it with the confirm token; only a PUT
// carrying the token, with a well-formed body naming known fields only,
// reaches the writer; a writer's refusal is a 409 with its words.
func TestHandleSecurityLookup(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	mode := ""
	var got []dashapi.PackageLookupChange
	seam := &dashapi.ScannerDB{
		Status: func(context.Context) (dashapi.ScannerDBStatus, error) { return dashapi.ScannerDBStatus{}, nil },
		Lookup: func(context.Context) (dashapi.PackageLookupStatus, error) {
			return dashapi.PackageLookupStatus{Mode: mode, RemoteHosts: []string{"superbased.app", "shards.superbased.app"}}, nil
		},
		SetLookup: func(_ context.Context, ch dashapi.PackageLookupChange) error {
			if ch.Mode != nil && *ch.Mode == "remote" && !ch.AcceptRemote {
				return errors.New("needs its own consent")
			}
			got = append(got, ch)
			if ch.Mode != nil {
				mode = *ch.Mode
			}
			return nil
		},
	}
	srv := func(seam *dashapi.ScannerDB, rule func(componentstate.Snapshot, string) bool) *Server {
		s := &Server{opts: Options{ConfigPath: cfg, ScannerDB: seam, SecuritySelected: rule}}
		s.comps.svc = scannerSnapSvc{snap: componentstate.Snapshot{Configured: true}}
		return s
	}
	all := scannerRule("security.deps", "security.scan.scalibr")
	get := func(s *Server) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleSecurityLookup(w, httptest.NewRequest(http.MethodGet, "/api/security/lookup", nil))
		return w
	}
	if w := get(srv(seam, scannerRule("security.deps"))); w.Code != http.StatusNotFound {
		t.Fatalf("no driver selected: %d", w.Code)
	}
	if w := get(srv(&dashapi.ScannerDB{Status: seam.Status}, all)); w.Code != http.StatusNotFound {
		t.Fatalf("no lookup in the seam: %d", w.Code)
	}
	s := srv(seam, all)
	w := get(s)
	var resp struct {
		Status       dashapi.PackageLookupStatus `json:"status"`
		ConfirmToken string                      `json:"confirm_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK || resp.ConfirmToken == "" || len(resp.Status.RemoteHosts) != 2 {
		t.Fatalf("GET %d %s %v", w.Code, w.Body, err)
	}
	put := func(token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/api/security/lookup", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(remoteConfirmHeader, token)
		r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: resp.ConfirmToken})
		w := httptest.NewRecorder()
		s.handleSecurityLookup(w, r)
		return w
	}
	if w := put("wrong", `{"mode":"remote","accept_remote":true}`); w.Code != http.StatusForbidden || len(got) != 0 {
		t.Fatalf("a PUT without the token reached the writer: %d", w.Code)
	}
	for name, body := range map[string]string{
		"unknown field": `{"mode":"remote","accept":true}`,
		"two objects":   `{"mode":"local"}{"mode":"remote"}`,
		"not json":      `mode=remote`,
		"empty":         ``,
	} {
		if w := put(resp.ConfirmToken, body); w.Code != http.StatusBadRequest || len(got) != 0 {
			t.Fatalf("%s: %d (writer calls %d)", name, w.Code, len(got))
		}
	}
	if w := put(resp.ConfirmToken, `{"mode":"remote"}`); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "own consent") {
		t.Fatalf("a refused change: %d %s", w.Code, w.Body)
	}
	w = put(resp.ConfirmToken, `{"mode":"remote","accept_remote":true}`)
	if w.Code != http.StatusOK || len(got) != 1 || !got[0].AcceptRemote || mode != "remote" {
		t.Fatalf("PUT %d %s %+v", w.Code, w.Body, got)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Status.Mode != "remote" {
		t.Fatalf("PUT answer %s", w.Body)
	}
	r := httptest.NewRequest(http.MethodDelete, "/api/security/lookup", nil)
	w = httptest.NewRecorder()
	s.handleSecurityLookup(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE %d", w.Code)
	}
}
