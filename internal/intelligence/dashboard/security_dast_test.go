//go:build !sbo_omit_security && !sbo_omit_security_dast

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// fakeDAST is a stand-in for the cmd seam: it records what it was asked.
type fakeDAST struct {
	selected, accepted bool
	runs               []string
	runRoot            string
	accepts            int
}

func (f *fakeDAST) seam() *dashapi.SecurityDAST {
	return &dashapi.SecurityDAST{
		State: func(context.Context) dashapi.DASTState {
			return dashapi.DASTState{Selected: f.selected, Accepted: f.accepted, AcceptText: "accept text"}
		},
		Candidates: func(_ context.Context, root string) []dashapi.DASTCandidate {
			return []dashapi.DASTCandidate{{URL: "http://localhost:5173/", Name: "npm run dev (vite)", Source: "package.json", Listening: "yes"}}
		},
		LastRuns: func(context.Context, string) []dashapi.DASTOriginRun {
			return []dashapi.DASTOriginRun{{Origin: "http://localhost:5173", At: "2026-11-13T10:00:00Z", Outcome: "complete", Findings: 2}}
		},
		Accept: func(context.Context) error { f.accepts++; f.accepted = true; return nil },
		Run: func(_ context.Context, root, url string, _ bool) (dashapi.DASTRunResult, error) {
			f.runs = append(f.runs, url)
			f.runRoot = root
			return dashapi.DASTRunResult{Target: url, Outcome: "complete", Requests: 7, Checks: 17, Findings: 2, New: 1}, nil
		},
	}
}

// TestSecurityDASTRoutes: 404 compiled out and not selected; the GET lists
// a known project's candidates and last runs; the run refuses before the
// accept, refuses a URL that is not a dev server on this machine and an
// unknown project, and runs against the dashboard's own project root.
func TestSecurityDASTRoutes(t *testing.T) {
	s, root := newTestServer(t)
	hash := secposture.ProjectRootHash(root)
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleSecurityDAST(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	body := func(url string) string {
		b, _ := json.Marshal(map[string]any{"project": hash, "url": url})
		return string(b)
	}

	// No seam: compiled out.
	if w := get("/api/security/dast"); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "component_not_installed") {
		t.Fatalf("no seam: %d %s", w.Code, w.Body)
	}
	fake := &fakeDAST{}
	s.opts.SecurityDAST = fake.seam()
	// Not selected: every route 404, nothing runs.
	if w := get("/api/security/dast"); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "not_selected") {
		t.Fatalf("not selected GET: %d %s", w.Code, w.Body)
	}
	if w := securityPost(s.handleSecurityDASTRun, "/api/security/dast/run", body("http://localhost:5173/"), true); w.Code != http.StatusNotFound || len(fake.runs) != 0 {
		t.Fatalf("not selected run: %d %s", w.Code, w.Body)
	}
	if w := securityPost(s.handleSecurityDASTAccept, "/api/security/dast/accept", `{}`, true); w.Code != http.StatusNotFound || fake.accepts != 0 {
		t.Fatalf("not selected accept: %d %s", w.Code, w.Body)
	}

	fake.selected = true
	w := get("/api/security/dast?project=" + hash)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", w.Code, w.Body)
	}
	var view securityDASTView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.State.Selected || view.State.Accepted || view.ConfirmToken == "" || view.Project == nil ||
		len(view.Project.Candidates) != 1 || view.Project.Candidates[0].Listening != "yes" || len(view.Project.LastRuns) != 1 {
		t.Fatalf("GET body: %s", w.Body)
	}
	if w := get("/api/security/dast?project=nope"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown project GET: %d", w.Code)
	}

	// Not accepted: the run refuses.
	if w := securityPost(s.handleSecurityDASTRun, "/api/security/dast/run", body("http://localhost:5173/"), true); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "not_accepted") || len(fake.runs) != 0 {
		t.Fatalf("not accepted run: %d %s", w.Code, w.Body)
	}
	// The accept needs the confirm token.
	if w := securityPost(s.handleSecurityDASTAccept, "/api/security/dast/accept", `{}`, false); w.Code != http.StatusForbidden || fake.accepts != 0 {
		t.Fatalf("accept without token: %d", w.Code)
	}
	if w := securityPost(s.handleSecurityDASTAccept, "/api/security/dast/accept", `{}`, true); w.Code != http.StatusOK || fake.accepts != 1 {
		t.Fatalf("accept: %d %s", w.Code, w.Body)
	}

	cases := []struct {
		name   string
		body   string
		token  bool
		status int
	}{
		{"no confirm token", body("http://localhost:5173/"), false, http.StatusForbidden},
		{"a remote host", body("http://example.com:80/"), true, http.StatusBadRequest},
		{"a LAN address", body("http://192.168.1.2:3000/"), true, http.StatusBadRequest},
		{"no port", body("http://localhost/"), true, http.StatusBadRequest},
		{"unknown project", `{"project":"nope","url":"http://localhost:5173/"}`, true, http.StatusNotFound},
		{"bad body", `{`, true, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if w := securityPost(s.handleSecurityDASTRun, "/api/security/dast/run", c.body, c.token); w.Code != c.status || len(fake.runs) != 0 {
				t.Fatalf("%d %s (runs %v)", w.Code, w.Body, fake.runs)
			}
		})
	}

	w = securityPost(s.handleSecurityDASTRun, "/api/security/dast/run", body("http://localhost:5173/"), true)
	if w.Code != http.StatusOK || len(fake.runs) != 1 || fake.runRoot != root {
		t.Fatalf("run: %d %s root %q", w.Code, w.Body, fake.runRoot)
	}
	var res dashapi.DASTRunResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil || res.Findings != 2 || res.New != 1 || res.Outcome != "complete" {
		t.Fatalf("run body: %s %v", w.Body, err)
	}
}

// TestSecurityDASTErrRows: one case per refusal row, plus the fallback.
func TestSecurityDASTErrRows(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{dashapi.ErrDASTNotSelected, http.StatusNotFound, "not_selected"},
		{dashapi.ErrDASTNotAccepted, http.StatusConflict, "not_accepted"},
		{dashapi.ErrDASTBadTarget, http.StatusBadRequest, "bad_target"},
		{dashapi.ErrDASTBusy, http.StatusConflict, "busy"},
		{context.DeadlineExceeded, http.StatusInternalServerError, "failed"},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		writeSecurityDASTErr(w, c.err)
		if w.Code != c.status || !strings.Contains(w.Body.String(), `"`+c.code+`"`) {
			t.Errorf("%v: %d %s", c.err, w.Code, w.Body)
		}
	}
}
