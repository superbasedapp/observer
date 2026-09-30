package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/shellwrap"
	"github.com/marmutapp/superbased-observer/internal/shellwrapsvc"
)

// fakeShellWrap records calls; it never touches a file.
type fakeShellWrap struct {
	applied  []shellwrapsvc.Request
	disabled []bool
}

func (f *fakeShellWrap) Status(context.Context) (shellwrap.Status, error) {
	return shellwrap.Status{GOOS: "linux", ShimDir: "/h/.observer/shims"}, nil
}

func (f *fakeShellWrap) Apply(_ context.Context, req shellwrapsvc.Request) (shellwrapsvc.Outcome, error) {
	f.applied = append(f.applied, req)
	return shellwrapsvc.Outcome{DryRun: req.DryRun}, nil
}

func (f *fakeShellWrap) Disable(_ context.Context, dry bool) (shellwrapsvc.Outcome, error) {
	f.disabled = append(f.disabled, dry)
	return shellwrapsvc.Outcome{DryRun: dry}, nil
}

func shellWrapServer(t *testing.T, svc ShellWrapService) *Server {
	t.Helper()
	dir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(dir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	s, err := New(Options{DB: database, ConfigPath: filepath.Join(dir, "config.toml"), ShellWrap: svc})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func shellWrapToken(t *testing.T, s *Server) (string, *http.Cookie) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/shell-wrap/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Token  string           `json:"confirm_token"`
		Status shellwrap.Status `json:"status"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Token == "" || body.Status.ShimDir == "" {
		t.Fatalf("status body %+v", body)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			return body.Token, c
		}
	}
	t.Fatal("no confirm cookie")
	return "", nil
}

func shellWrapPost(s *Server, path, body, token string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set(remoteConfirmHeader, token)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func TestShellWrapRoutes(t *testing.T) {
	fake := &fakeShellWrap{}
	s := shellWrapServer(t, fake)
	tok, ck := shellWrapToken(t, s)

	if rr := shellWrapPost(s, "/api/shell-wrap/apply", `{"tools":["claude-code"]}`, "", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("apply without the confirm token: %d", rr.Code)
	}
	if len(fake.applied) != 0 {
		t.Fatal("a refused request reached the service")
	}
	rr := shellWrapPost(s, "/api/shell-wrap/apply", `{"tools":["claude-code"],"shells":["zsh"],"dry_run":true}`, tok, ck)
	if rr.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rr.Code, rr.Body.String())
	}
	if len(fake.applied) != 1 || !fake.applied[0].DryRun || fake.applied[0].Shells[0] != "zsh" {
		t.Fatalf("service saw %+v", fake.applied)
	}
	if rr := shellWrapPost(s, "/api/shell-wrap/disable", `{}`, tok, ck); rr.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
	}
	if len(fake.disabled) != 1 || fake.disabled[0] {
		t.Fatalf("disable calls %+v", fake.disabled)
	}
}

func TestShellWrapRoutesNotWired(t *testing.T) {
	s := shellWrapServer(t, nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/shell-wrap/status", nil))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("got %d", rr.Code)
	}
}
