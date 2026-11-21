//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestHandleSecurityReachSource (3b-src): the Go source check's route
// answers 404 without a selected driver or the seam; GET reads the state
// with the confirm token; only a PUT carrying the token with a well-formed
// body reaches the opt-in writer; only a POST with the token starts a run.
func TestHandleSecurityReachSource(t *testing.T) {
	s, root := newTestServer(t)
	hash := secposture.ProjectRootHash(root)
	var changes []dashapi.ReachSourceChange
	runs := 0
	refuseRun := false
	seam := &dashapi.ScannerDB{
		Status: func(context.Context) (dashapi.ScannerDBStatus, error) { return dashapi.ScannerDBStatus{}, nil },
		ReachSource: func(_ context.Context, r string) (dashapi.ReachSourceStatus, error) {
			return dashapi.ReachSourceStatus{Project: r, Compiled: true, OptedIn: len(changes) > 0 && changes[len(changes)-1].Enabled, Running: runs > 0}, nil
		},
		SetReachSource: func(_ context.Context, r string, ch dashapi.ReachSourceChange) error {
			if r != root {
				return errors.New("wrong project")
			}
			changes = append(changes, ch)
			return nil
		},
		RunReachSource: func(context.Context, string) error {
			if refuseRun {
				return errors.New("this project is not opted in to the Go source check")
			}
			runs++
			return nil
		},
	}
	s.opts.ScannerDB = seam
	s.opts.SecuritySelected = scannerRule("security.deps", "security.scan.osv")
	s.comps.svc = scannerSnapSvc{snap: componentstate.Snapshot{Configured: true}}

	w := httptest.NewRecorder()
	s.handleSecurityReachSource(w, httptest.NewRequest(http.MethodGet, "/api/security/reach/go-source?project="+hash, nil))
	var resp struct {
		dashapi.ReachSourceStatus
		ConfirmToken string `json:"confirm_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK || resp.ConfirmToken == "" || resp.Project != root {
		t.Fatalf("GET %d %s %v", w.Code, w.Body, err)
	}
	send := func(method, path, token, body string, h http.HandlerFunc) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path+"?project="+hash, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(remoteConfirmHeader, token)
		r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: resp.ConfirmToken})
		w := httptest.NewRecorder()
		h(w, r)
		return w
	}
	optin, run := s.handleSecurityReachSource, s.handleSecurityReachSourceRun
	if w := send(http.MethodPut, "/api/security/reach/go-source", "wrong", `{"enabled":true}`, optin); w.Code != http.StatusForbidden || len(changes) != 0 {
		t.Fatalf("a PUT without the token reached the writer: %d", w.Code)
	}
	for name, body := range map[string]string{"unknown field": `{"enabled":true,"all":true}`, "two objects": `{}{}`, "not json": `enabled=1`, "empty": ``} {
		if w := send(http.MethodPut, "/api/security/reach/go-source", resp.ConfirmToken, body, optin); w.Code != http.StatusBadRequest || len(changes) != 0 {
			t.Fatalf("%s: %d", name, w.Code)
		}
	}
	if w := send(http.MethodPut, "/api/security/reach/go-source", resp.ConfirmToken, `{"enabled":true,"allow_unisolated":true}`, optin); w.Code != http.StatusOK || len(changes) != 1 || !changes[0].AllowUnisolated {
		t.Fatalf("PUT %d %s %+v", w.Code, w.Body, changes)
	}
	if w := send(http.MethodPost, "/api/security/reach/go-source/run", "wrong", `{}`, run); w.Code != http.StatusForbidden || runs != 0 {
		t.Fatalf("a run without the token started: %d", w.Code)
	}
	if w := send(http.MethodGet, "/api/security/reach/go-source/run", resp.ConfirmToken, ``, run); w.Code != http.StatusMethodNotAllowed || runs != 0 {
		t.Fatalf("a GET started a run: %d", w.Code)
	}
	if w := send(http.MethodPost, "/api/security/reach/go-source/run", resp.ConfirmToken, `{}`, run); w.Code != http.StatusAccepted || runs != 1 {
		t.Fatalf("POST run %d %s", w.Code, w.Body)
	}
	refuseRun = true
	if w := send(http.MethodPost, "/api/security/reach/go-source/run", resp.ConfirmToken, `{}`, run); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "not opted in") {
		t.Fatalf("a refused run: %d %s", w.Code, w.Body)
	}

	// Gates: no driver selected, no seam.
	s.opts.SecuritySelected = scannerRule("security.deps")
	w = httptest.NewRecorder()
	s.handleSecurityReachSource(w, httptest.NewRequest(http.MethodGet, "/api/security/reach/go-source?project="+hash, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("no driver selected: %d", w.Code)
	}
	s.opts.ScannerDB, s.opts.SecuritySelected = &dashapi.ScannerDB{}, scannerRule("security.deps", "security.scan.osv")
	w = httptest.NewRecorder()
	s.handleSecurityReachSource(w, httptest.NewRequest(http.MethodGet, "/api/security/reach/go-source?project="+hash, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("no seam: %d", w.Code)
	}
}
