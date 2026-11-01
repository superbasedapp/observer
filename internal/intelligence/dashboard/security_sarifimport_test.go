//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// sarifSnapSvc serves one component snapshot.
type sarifSnapSvc struct {
	ComponentsService
	snap componentstate.Snapshot
}

func (f sarifSnapSvc) State(context.Context) (componentstate.Snapshot, error) { return f.snap, nil }

// sarifRule selects only the ids named, under a configured block.
func sarifRule(ids ...string) func(componentstate.Snapshot, string) bool {
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	return func(snap componentstate.Snapshot, id string) bool { return snap.Configured && set[id] }
}

// TestHandleSecurityImportSARIF is the SARIF upload (lane SEC-P4 decision
// 13): 404 unless security.scan.sarif-import and security.code are both
// selected or with no seam; GET mints the confirm token and returns the
// picker and the cap; a POST without the token, with a body over the cap,
// with an unknown tool or an unknown project records nothing; a file the
// adapter refuses answers 400; a good upload reaches the seam with the
// project's root and the file's exact bytes.
func TestHandleSecurityImportSARIF(t *testing.T) {
	ctx := context.Background()
	database, err := openTestDB(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	root := "/work/app"
	if _, err := database.ExecContext(ctx, `INSERT INTO projects (root_path, created_at) VALUES (?, ?)`, root, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	type call struct{ root, tool, data string }
	var calls []call
	seam := &dashapi.SARIFImport{
		Tools:    []dashapi.SARIFImportTool{{ID: "gosec", Label: "gosec"}, {ID: "other", Label: "Another tool"}},
		MaxBytes: 256,
		Import: func(_ context.Context, root, tool string, data []byte) (any, error) {
			if strings.Contains(string(data), `"bad"`) {
				return nil, fmt.Errorf("%w: not a SARIF 2.1.0 log", dashapi.ErrSARIFImportInput)
			}
			if strings.Contains(string(data), `"broken"`) {
				return nil, errors.New("store: disk I/O error at /home/u/.observer/observer.db")
			}
			calls = append(calls, call{root, tool, string(data)})
			return map[string]int{"findings": 1}, nil
		},
	}
	server := func(seam *dashapi.SARIFImport, ids ...string) *Server {
		s := &Server{opts: Options{DB: database, SARIFImport: seam, SecuritySelected: sarifRule(ids...)}}
		s.comps.svc = sarifSnapSvc{snap: componentstate.Snapshot{Configured: true}}
		return s
	}
	get := func(s *Server) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleSecurityImportSARIF(w, httptest.NewRequest(http.MethodGet, "/api/security/import-sarif", nil))
		return w
	}
	for name, s := range map[string]*Server{
		"no seam":           server(nil, "security.code", "security.scan.sarif-import"),
		"driver only":       server(seam, "security.scan.sarif-import"),
		"parent only":       server(seam, "security.code"),
		"nothing selected":  server(seam),
		"no component rule": {opts: Options{DB: database, SARIFImport: seam}},
	} {
		if w := get(s); w.Code != http.StatusNotFound {
			t.Errorf("%s: GET %d, want 404", name, w.Code)
		}
	}

	s := server(seam, "security.code", "security.scan.sarif-import")
	w := get(s)
	var resp struct {
		Tools        []dashapi.SARIFImportTool `json:"tools"`
		MaxBytes     int                       `json:"max_bytes"`
		ConfirmToken string                    `json:"confirm_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK || resp.ConfirmToken == "" || len(resp.Tools) != 2 || resp.MaxBytes != 256 {
		t.Fatalf("GET %d %s %v", w.Code, w.Body, err)
	}
	hash := secposture.ProjectRootHash(root)
	post := func(token, ctype, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/security/import-sarif", strings.NewReader(body))
		r.Header.Set("Content-Type", ctype)
		r.Header.Set(remoteConfirmHeader, token)
		r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: resp.ConfirmToken})
		w := httptest.NewRecorder()
		s.handleSecurityImportSARIF(w, r)
		return w
	}
	file := `{"version":"2.1.0","runs":[]}`
	body := func(project, tool, sarif string) string {
		return fmt.Sprintf(`{"project":%q,"tool":%q,"sarif":%s}`, project, tool, sarif)
	}
	for _, c := range []struct {
		name, token, ctype, body string
		want                     int
	}{
		{"no token", "wrong", "application/json", body(hash, "gosec", file), http.StatusForbidden},
		{"not json", resp.ConfirmToken, "text/plain", body(hash, "gosec", file), http.StatusUnsupportedMediaType},
		{"over the cap", resp.ConfirmToken, "application/json", body(hash, "gosec", `{"pad":"`+strings.Repeat("x", 300)+`"}`), http.StatusRequestEntityTooLarge},
		{"over the cap and the envelope", resp.ConfirmToken, "application/json", body(hash, "gosec", `{"pad":"`+strings.Repeat("x", 8<<10)+`"}`), http.StatusRequestEntityTooLarge},
		{"no file", resp.ConfirmToken, "application/json", `{"project":"` + hash + `","tool":"gosec"}`, http.StatusBadRequest},
		{"unknown tool", resp.ConfirmToken, "application/json", body(hash, "nmap", file), http.StatusBadRequest},
		{"unknown project", resp.ConfirmToken, "application/json", body(secposture.ProjectRootHash("/elsewhere"), "gosec", file), http.StatusNotFound},
		{"refused by the adapter", resp.ConfirmToken, "application/json", body(hash, "gosec", `{"bad":1}`), http.StatusBadRequest},
		{"a node error", resp.ConfirmToken, "application/json", body(hash, "gosec", `{"broken":1}`), http.StatusInternalServerError},
	} {
		w := post(c.token, c.ctype, c.body)
		if w.Code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, w.Code, w.Body, c.want)
		}
		if c.want == http.StatusInternalServerError && strings.Contains(w.Body.String(), "/home/u") {
			t.Errorf("%s: a node error leaked its text: %s", c.name, w.Body)
		}
	}
	if len(calls) != 0 {
		t.Fatalf("a refused upload reached the import: %+v", calls)
	}
	if w := post(resp.ConfirmToken, "application/json", body(hash, "gosec", file)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"findings":1`) {
		t.Fatalf("good upload %d %s", w.Code, w.Body)
	}
	if len(calls) != 1 || calls[0] != (call{root, "gosec", file}) {
		t.Fatalf("the import got %+v, want the root, the tool and the file's bytes", calls)
	}
}
