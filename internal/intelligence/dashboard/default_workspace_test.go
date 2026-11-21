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

	"github.com/marmutapp/superbased-observer/internal/defaultworkspace"
)

// The "Default workspace" card: GET reports the resolved folder, PUT checks
// it, sets it up on a real save (folder, marker, repository) and writes
// [workspace].default_dir through the save pipeline with the confirm token;
// null resets to the built-in folder by clearing the key.

// withFakeGitInit gives the server a `git init` stand-in that makes the
// .git folder git.FindRoot looks for, and counts its calls.
func withFakeGitInit(s *Server) *int {
	calls := 0
	s.opts.WorkspaceGitInit = func(_ context.Context, dir string) error {
		calls++
		if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600)
	}
	return &calls
}

// pinWorkspaceHome points the home folder at a fresh temp folder.
func pinWorkspaceHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if defaultworkspace.InsideGitRepo(home) {
		t.Skip("the temp folder is inside a git repository on this host")
	}
	return home
}

func getDefaultWorkspace(t *testing.T, s *Server) (defaultWorkspaceView, *http.Cookie) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/workspace/default", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/workspace/default: %d %s", rr.Code, rr.Body.String())
	}
	var v defaultWorkspaceView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			cookie = c
		}
	}
	return v, cookie
}

func putDefaultWorkspace(t *testing.T, s *Server, query, body string, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	v, cookie := getDefaultWorkspace(t, s)
	req := httptest.NewRequest(http.MethodPut, "/api/workspace/default"+query, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if confirm {
		req.Header.Set(remoteConfirmHeader, v.ConfirmToken)
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func dirBody(dir string) string {
	m := map[string]any{"dir": nil}
	if dir != "" {
		m["dir"] = dir
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestDefaultWorkspace_GetBuiltin(t *testing.T) {
	home := pinWorkspaceHome(t)
	s, _ := newSecretTestServer(t, "[observer]\nlog_level = \"info\"\n")
	v, cookie := getDefaultWorkspace(t, s)
	want := filepath.Join(home, defaultworkspace.BuiltinName)
	if v.Dir != want || !v.Builtin || v.BuiltinDir != want || v.Configured != "" || v.Problem != "" {
		t.Fatalf("view = %+v, want the built-in %s", v, want)
	}
	if v.ConfirmToken == "" || cookie == nil || v.ConfigEtag == "" {
		t.Fatalf("GET must mint a confirm token and report the etag: %+v", v)
	}
}

func TestDefaultWorkspace_SaveCreatesAndWrites(t *testing.T) {
	pinWorkspaceHome(t)
	s, path := newSecretTestServer(t, "# mine\n[observer]\nlog_level = \"info\"\n")
	calls := withFakeGitInit(s)
	dir := filepath.Join(t.TempDir(), "scratch", "ws")

	// Without the confirm token a real save is refused.
	if rr := putDefaultWorkspace(t, s, "", dirBody(dir), false); rr.Code != http.StatusForbidden {
		t.Fatalf("no confirm token: %d %s", rr.Code, rr.Body.String())
	}
	// A dry run creates and writes nothing.
	before, _ := os.ReadFile(path)
	if rr := putDefaultWorkspace(t, s, "?dry_run=1", dirBody(dir), false); rr.Code != http.StatusOK {
		t.Fatalf("dry run: %d %s", rr.Code, rr.Body.String())
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a dry run wrote config.toml")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("a dry run created the folder: %v", err)
	}
	// The real save creates the folder and records it.
	rr := putDefaultWorkspace(t, s, "", dirBody(dir), true)
	if rr.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Fatalf("folder not created: %v", err)
	}
	cfg, err := loadConfigForDashboard(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Workspace.DefaultDir != dir {
		t.Fatalf("default_dir = %q, want %q", cfg.Workspace.DefaultDir, dir)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "# mine") {
		t.Fatalf("the save lost the file's other lines:\n%s", b)
	}
	v, _ := getDefaultWorkspace(t, s)
	if v.Dir != dir || v.Builtin || !v.Exists || !v.Ready || v.Problem != "" || *calls != 1 {
		t.Fatalf("after save: %+v (git init calls %d)", v, *calls)
	}

	// Reset clears the key and creates the built-in folder.
	if rr := putDefaultWorkspace(t, s, "", dirBody(""), true); rr.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rr.Code, rr.Body.String())
	}
	cfg, _ = loadConfigForDashboard(path)
	if cfg.Workspace.DefaultDir != "" {
		t.Fatalf("reset must clear the key, got %q", cfg.Workspace.DefaultDir)
	}
	v, _ = getDefaultWorkspace(t, s)
	if !v.Builtin || !v.Exists || !v.Ready || *calls != 2 {
		t.Fatalf("after reset: %+v", v)
	}
}

func TestDefaultWorkspace_SavingTheBuiltinStoresNothing(t *testing.T) {
	home := pinWorkspaceHome(t)
	s, path := newSecretTestServer(t, "[observer]\nlog_level = \"info\"\n")
	if rr := putDefaultWorkspace(t, s, "", dirBody(filepath.Join(home, defaultworkspace.BuiltinName)), true); rr.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	cfg, _ := loadConfigForDashboard(path)
	if cfg.Workspace.DefaultDir != "" {
		t.Fatalf("the built-in folder must not be recorded, got %q", cfg.Workspace.DefaultDir)
	}
}

func TestDefaultWorkspace_RefusesBadFolders(t *testing.T) {
	home := pinWorkspaceHome(t)
	repo := filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, path := newSecretTestServer(t, "[observer]\nlog_level = \"info\"\n")
	before, _ := os.ReadFile(path)
	for name, dir := range map[string]string{
		"home":          home,
		"relative":      filepath.Join("rel", "ws"),
		"data folder":   filepath.Join(home, ".observer", "ws"),
		"inside a repo": filepath.Join(repo, "ws"),
	} {
		rr := putDefaultWorkspace(t, s, "", dirBody(dir), true)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, rr.Code, rr.Body.String())
		}
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a refused save wrote config.toml")
	}
	if _, err := os.Stat(filepath.Join(repo, "ws")); !os.IsNotExist(err) {
		t.Fatalf("a refused folder was created: %v", err)
	}
	if rr := putDefaultWorkspace(t, s, "", `{"dir":"/x","extra":1}`, true); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rr.Code)
	}
}

// Without git the folder is still created and marked and the save goes
// through with a warning; GET reports it as not set up, so the consent step
// does not start on it.
func TestDefaultWorkspace_SaveWithoutGitWarns(t *testing.T) {
	pinWorkspaceHome(t)
	s, path := newSecretTestServer(t, "[observer]\nlog_level = \"info\"\n")
	s.opts.WorkspaceGitInit = func(context.Context, string) error { return os.ErrNotExist }
	dir := filepath.Join(t.TempDir(), "ws")
	rr := putDefaultWorkspace(t, s, "", dirBody(dir), true)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "not set up yet") {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	if !defaultworkspace.Marked(dir) {
		t.Fatal("the folder was not marked")
	}
	cfg, _ := loadConfigForDashboard(path)
	if cfg.Workspace.DefaultDir != dir {
		t.Fatalf("default_dir = %q", cfg.Workspace.DefaultDir)
	}
	if v, _ := getDefaultWorkspace(t, s); v.Ready || v.Problem == "" {
		t.Fatalf("a folder that is not a repository must not read ready: %+v", v)
	}
}

// TestDefaultWorkspace_RefusedSaveCreatesNothing (review finding 8,
// 2026-11-12): a save the pipeline refuses (a stale base_etag) or a path
// with a file in the way creates no folder and writes no config; the folder
// is set up only once the save went through.
func TestDefaultWorkspace_RefusedSaveCreatesNothing(t *testing.T) {
	pinWorkspaceHome(t)
	s, path := newSecretTestServer(t, "[observer]\nlog_level = \"info\"\n")
	calls := withFakeGitInit(s)
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	for _, tc := range []struct {
		name  string
		dir   string
		query string
		code  int
	}{
		{"stale base_etag", filepath.Join(t.TempDir(), "ws"), "?base_etag=stale", http.StatusConflict},
		{"a file is in the way", file, "", http.StatusBadRequest},
	} {
		rr := putDefaultWorkspace(t, s, tc.query, dirBody(tc.dir), true)
		if rr.Code != tc.code {
			t.Errorf("%s: %d %s, want %d", tc.name, rr.Code, rr.Body.String(), tc.code)
		}
		if tc.dir != file {
			if _, err := os.Stat(tc.dir); !os.IsNotExist(err) {
				t.Errorf("%s: the refused save created the folder: %v", tc.name, err)
			}
		}
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a refused save wrote config.toml")
	}
	if *calls != 0 {
		t.Fatalf("a refused save ran git init %d times", *calls)
	}
}

// A parent of projects and a folder already holding files are refused, and
// nothing is written into them.
func TestDefaultWorkspace_RefusesParentsAndBusyFolders(t *testing.T) {
	pinWorkspaceHome(t)
	s, _ := newSecretTestServer(t, "[observer]\nlog_level = \"info\"\n")
	calls := withFakeGitInit(s)
	code := t.TempDir()
	for _, name := range []string{"alpha", "beta"} {
		if err := os.MkdirAll(filepath.Join(code, name, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	busy := t.TempDir()
	if err := os.WriteFile(filepath.Join(busy, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	rr := putDefaultWorkspace(t, s, "", dirBody(code), true)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "holds git repositories") {
		t.Fatalf("parent of repositories: %d %s", rr.Code, rr.Body.String())
	}
	if rr := putDefaultWorkspace(t, s, "", dirBody(busy), true); rr.Code != http.StatusBadRequest {
		t.Fatalf("busy folder: %d %s", rr.Code, rr.Body.String())
	}
	if *calls != 0 || defaultworkspace.Marked(code) || defaultworkspace.Marked(busy) {
		t.Fatal("a refused folder was set up")
	}
}
