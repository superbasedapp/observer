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

// TestHandleSecurityArtifacts (M3L-2 item 4, ruling 2026-11-05): the
// artifact folders route answers 404 unless a dependency driver is
// selected or the seam carries it; it needs a known project; GET lists the
// folders with the confirm token; only a PUT carrying the token, with a
// well-formed body naming known fields only, reaches the writer, with the
// project's root; a writer's refusal is a 409 with its words.
func TestHandleSecurityArtifacts(t *testing.T) {
	s, root := newTestServer(t)
	hash := secposture.ProjectRootHash(root)
	on := false
	var gotRoot string
	var changes []dashapi.ArtifactChange
	seam := &dashapi.ScannerDB{
		Status: func(context.Context) (dashapi.ScannerDBStatus, error) { return dashapi.ScannerDBStatus{}, nil },
		Artifacts: func(_ context.Context, r string) (dashapi.ArtifactFolders, error) {
			gotRoot = r
			return dashapi.ArtifactFolders{Project: r, DriverCompiled: true, Folders: []dashapi.ArtifactFolder{
				{Dir: "bin", Default: true, Present: true, Enabled: on, Summary: "2 ELF executables"},
			}}, nil
		},
		SetArtifact: func(_ context.Context, r string, ch dashapi.ArtifactChange) error {
			if ch.Dir == "nope" {
				return errors.New("nope: not a folder of the project")
			}
			gotRoot = r
			changes = append(changes, ch)
			on = ch.Enabled
			return nil
		},
	}
	s.opts.ScannerDB = seam
	s.opts.SecuritySelected = scannerRule("security.deps", "security.scan.scalibr")
	s.comps.svc = scannerSnapSvc{snap: componentstate.Snapshot{Configured: true}}

	get := func(target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleSecurityArtifacts(w, httptest.NewRequest(http.MethodGet, target, nil))
		return w
	}
	if w := get("/api/security/artifacts"); w.Code != http.StatusBadRequest {
		t.Fatalf("no project: %d", w.Code)
	}
	if w := get("/api/security/artifacts?project=deadbeef"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown project: %d", w.Code)
	}
	w := get("/api/security/artifacts?project=" + hash)
	var resp struct {
		dashapi.ArtifactFolders
		ConfirmToken string `json:"confirm_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK || resp.ConfirmToken == "" || len(resp.Folders) != 1 || resp.Folders[0].Enabled {
		t.Fatalf("GET %d %s %v", w.Code, w.Body, err)
	}
	if gotRoot == "" {
		t.Fatal("the seam did not receive the project's root")
	}
	put := func(token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/api/security/artifacts?project="+hash, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(remoteConfirmHeader, token)
		r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: resp.ConfirmToken})
		w := httptest.NewRecorder()
		s.handleSecurityArtifacts(w, r)
		return w
	}
	if w := put("wrong", `{"dir":"bin","enabled":true}`); w.Code != http.StatusForbidden || len(changes) != 0 {
		t.Fatalf("a PUT without the token reached the writer: %d", w.Code)
	}
	for name, body := range map[string]string{
		"unknown field": `{"dir":"bin","enabled":true,"all":true}`,
		"two objects":   `{"dir":"bin"}{"dir":"dist"}`,
		"no folder":     `{"enabled":true}`,
		"not json":      `dir=bin`,
		"empty":         ``,
	} {
		if w := put(resp.ConfirmToken, body); w.Code != http.StatusBadRequest || len(changes) != 0 {
			t.Fatalf("%s: %d (writer calls %d)", name, w.Code, len(changes))
		}
	}
	if w := put(resp.ConfirmToken, `{"dir":"nope","enabled":true}`); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "not a folder") {
		t.Fatalf("a refused change: %d %s", w.Code, w.Body)
	}
	w = put(resp.ConfirmToken, `{"dir":"bin","enabled":true}`)
	if w.Code != http.StatusOK || len(changes) != 1 || changes[0].Dir != "bin" || !changes[0].Enabled || !on {
		t.Fatalf("PUT %d %s %+v", w.Code, w.Body, changes)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.Folders) != 1 || !resp.Folders[0].Enabled {
		t.Fatalf("PUT answer %s", w.Body)
	}
	w = httptest.NewRecorder()
	s.handleSecurityArtifacts(w, httptest.NewRequest(http.MethodDelete, "/api/security/artifacts?project="+hash, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE %d", w.Code)
	}
}

// TestHandleSecurityArtifactsGate: 404 with no driver selected and with a
// seam that carries no artifact functions.
func TestHandleSecurityArtifactsGate(t *testing.T) {
	s, root := newTestServer(t)
	hash := secposture.ProjectRootHash(root)
	full := &dashapi.ScannerDB{
		Artifacts:   func(context.Context, string) (dashapi.ArtifactFolders, error) { return dashapi.ArtifactFolders{}, nil },
		SetArtifact: func(context.Context, string, dashapi.ArtifactChange) error { return nil },
	}
	s.comps.svc = scannerSnapSvc{snap: componentstate.Snapshot{Configured: true}}
	req := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleSecurityArtifacts(w, httptest.NewRequest(http.MethodGet, "/api/security/artifacts?project="+hash, nil))
		return w
	}
	s.opts.ScannerDB, s.opts.SecuritySelected = full, scannerRule("security.deps")
	if w := req(); w.Code != http.StatusNotFound {
		t.Fatalf("no driver selected: %d", w.Code)
	}
	s.opts.ScannerDB, s.opts.SecuritySelected = &dashapi.ScannerDB{}, scannerRule("security.deps", "security.scan.scalibr")
	if w := req(); w.Code != http.StatusNotFound {
		t.Fatalf("no artifact seam: %d", w.Code)
	}
}
