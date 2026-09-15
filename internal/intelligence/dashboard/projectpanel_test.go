package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// newProjectPanelServer builds a dashboard Server with the given token→root
// resolver and optional remote controller (for the allow_terminal_view gate).
func newProjectPanelServer(t *testing.T, resolver func(string) (TerminalRoot, bool), remote RemoteController) *Server {
	t.Helper()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	opts := Options{DB: database, ProjectRootResolver: resolver}
	if remote != nil {
		opts.Remote = remote
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// doGet issues a GET through the loopback handler, optionally stamping the
// remote-exposed listener-provenance marker.
func doGet(t *testing.T, s *Server, path string, remote bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if remote {
		req = req.WithContext(withRemoteExposed(req.Context()))
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// errorCode decodes an {"error":code} body.
func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body.String(), err)
	}
	return body.Error
}

// fixedResolver builds a token→TerminalRoot seam from a literal map. `root` is
// the browsable path ("" = nothing to browse → 409) and `authorized` is its
// provenance: true for an operator allow-listed launch root, false for the
// run's own working directory (the default-cwd shape the 2026-08-28 operator
// ruling made browsable).
func fixedResolver(m map[string]struct {
	root       string
	known      bool
	authorized bool
},
) func(string) (TerminalRoot, bool) {
	return func(token string) (TerminalRoot, bool) {
		if v, ok := m[token]; ok {
			return TerminalRoot{Path: v.root, Authorized: v.authorized}, v.known
		}
		return TerminalRoot{}, false
	}
}

func TestProjectPanelTokenGates(t *testing.T) {
	dir := t.TempDir()
	resolver := fixedResolver(map[string]struct {
		root       string
		known      bool
		authorized bool
	}{
		"LIVE":   {root: dir, known: true, authorized: true},
		"NOROOT": {root: "", known: true},
	})
	s := newProjectPanelServer(t, resolver, nil)

	t.Run("unknown token 404", func(t *testing.T) {
		rec := doGet(t, s, "/api/terminal/project/GHOST", false)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("code = %d, want 404", rec.Code)
		}
		if got := errorCode(t, rec); got != "unknown_token" {
			t.Fatalf("error = %q, want unknown_token", got)
		}
	})

	t.Run("no project root 409", func(t *testing.T) {
		rec := doGet(t, s, "/api/terminal/project/NOROOT", false)
		if rec.Code != http.StatusConflict {
			t.Fatalf("code = %d, want 409", rec.Code)
		}
		if got := errorCode(t, rec); got != "no_project_root" {
			t.Fatalf("error = %q, want no_project_root", got)
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/terminal/project/LIVE", nil)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("code = %d, want 405", rec.Code)
		}
	})
}

func TestProjectPanelNilResolverDisabled(t *testing.T) {
	s := newProjectPanelServer(t, nil, nil)
	rec := doGet(t, s, "/api/terminal/project/LIVE", false)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404 (panel disabled)", rec.Code)
	}
}

func TestProjectPanelRemoteGate(t *testing.T) {
	dir := t.TempDir()
	resolver := fixedResolver(map[string]struct {
		root       string
		known      bool
		authorized bool
	}{
		"LIVE":   {root: dir, known: true, authorized: true}, // rooted
		"NOROOT": {root: "", known: true},                    // rootless
		// "GHOST" is absent → unknown.
	})

	// view disabled: a remote-exposed caller is refused with an IDENTICAL 403 for
	// EVERY token state (finding 1) — the gate runs before ProjectRootResolver so
	// the response cannot be used as a token/root-state oracle (no 404-for-unknown
	// / 409-for-rootless / 403-for-rooted split).
	sOff := newProjectPanelServer(t, resolver, NewRemoteController(RemoteOptions{AllowTerminalView: false}))
	for _, token := range []string{"LIVE", "NOROOT", "GHOST"} {
		rec := doGet(t, sOff, "/api/terminal/project/"+token, true)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("remote view-off token=%s code = %d, want 403", token, rec.Code)
		}
		if got := errorCode(t, rec); got != "remote_view_disabled" {
			t.Fatalf("remote view-off token=%s error = %q, want remote_view_disabled", token, got)
		}
	}

	// Local (non-remote) caller is never gated.
	if rec := doGet(t, sOff, "/api/terminal/project/LIVE", false); rec.Code != http.StatusOK {
		t.Fatalf("local caller code = %d, want 200", rec.Code)
	}

	// view enabled: the remote caller passes the gate.
	sOn := newProjectPanelServer(t, resolver, NewRemoteController(RemoteOptions{AllowTerminalView: true}))
	if rec := doGet(t, sOn, "/api/terminal/project/LIVE", true); rec.Code != http.StatusOK {
		t.Fatalf("remote view-on code = %d, want 200", rec.Code)
	}
}

func TestProjectPanelFilesAndFile(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "hello.txt"), []byte("hi there\n"))
	mustWrite(t, filepath.Join(dir, "bin.dat"), []byte{'a', 0x00, 'b'})
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	resolver := fixedResolver(map[string]struct {
		root       string
		known      bool
		authorized bool
	}{"LIVE": {root: dir, known: true, authorized: true}})
	s := newProjectPanelServer(t, resolver, nil)

	t.Run("list happy path", func(t *testing.T) {
		rec := doGet(t, s, "/api/terminal/project/LIVE/files?path=", false)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d body=%s", rec.Code, rec.Body.String())
		}
		var resp projectFilesResp
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range resp.Entries {
			names = append(names, e.Name+":"+e.Type)
		}
		// "sub" is a dir and must sort before the files.
		if len(resp.Entries) == 0 || resp.Entries[0].Name != "sub" || resp.Entries[0].Type != "dir" {
			t.Fatalf("dirs-first ordering broken: %v", names)
		}
	})

	t.Run("read happy path", func(t *testing.T) {
		rec := doGet(t, s, "/api/terminal/project/LIVE/file?path=hello.txt", false)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d", rec.Code)
		}
		var resp projectFileResp
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Content != "hi there\n" || resp.Binary || resp.TooLarge {
			t.Fatalf("unexpected file resp: %+v", resp)
		}
	})

	t.Run("binary sniff", func(t *testing.T) {
		rec := doGet(t, s, "/api/terminal/project/LIVE/file?path=bin.dat", false)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d", rec.Code)
		}
		var resp projectFileResp
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.Binary || resp.Content != "" {
			t.Fatalf("want binary with empty content: %+v", resp)
		}
	})

	t.Run("path traversal rejected", func(t *testing.T) {
		rec := doGet(t, s, "/api/terminal/project/LIVE/file?path=../../etc/passwd", false)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400", rec.Code)
		}
		if got := errorCode(t, rec); got != "bad_path" {
			t.Fatalf("error = %q, want bad_path", got)
		}
	})

	t.Run("missing file 404", func(t *testing.T) {
		rec := doGet(t, s, "/api/terminal/project/LIVE/file?path=nope.txt", false)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("code = %d, want 404", rec.Code)
		}
		if got := errorCode(t, rec); got != "not_found" {
			t.Fatalf("error = %q, want not_found", got)
		}
	})
}

func TestProjectPanelMetaAndGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(cmd.Environ(),
			"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@e.co",
			"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@e.co")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	git("checkout", "-q", "-b", "main")
	git("commit", "-q", "--allow-empty", "-m", "first")

	resolver := fixedResolver(map[string]struct {
		root       string
		known      bool
		authorized bool
	}{"GIT": {root: dir, known: true, authorized: true}})
	s := newProjectPanelServer(t, resolver, nil)

	t.Run("meta", func(t *testing.T) {
		rec := doGet(t, s, "/api/terminal/project/GIT", false)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d", rec.Code)
		}
		var resp projectMetaResp
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.GitAvailable || !resp.IsGit {
			t.Fatalf("meta = %+v, want git available + is_git", resp)
		}
		if resp.Root != dir {
			t.Fatalf("root = %q, want %q (the one sanctioned path disclosure)", resp.Root, dir)
		}
		if resp.Branch != "main" {
			t.Fatalf("branch = %q, want main", resp.Branch)
		}
		// An allow-listed launch root is labelled as a project, unchanged by the
		// 2026-08-28 widening.
		if resp.RootKind != terminalRootKindProject {
			t.Fatalf("root_kind = %q, want %q for an authorized launch root", resp.RootKind, terminalRootKindProject)
		}
	})

	t.Run("git payload shape", func(t *testing.T) {
		rec := doGet(t, s, "/api/terminal/project/GIT/git", false)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d", rec.Code)
		}
		// Assert snake_case wire keys are present.
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"is_git", "branch", "log", "log_truncated", "status"} {
			if _, ok := raw[k]; !ok {
				t.Fatalf("git payload missing key %q: %s", k, rec.Body.String())
			}
		}
		var info struct {
			IsGit bool `json:"is_git"`
			Log   []struct {
				Hash    string `json:"hash"`
				Subject string `json:"subject"`
			} `json:"log"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
			t.Fatal(err)
		}
		if !info.IsGit || len(info.Log) != 1 || info.Log[0].Subject != "first" {
			t.Fatalf("unexpected git payload: %+v", info)
		}
	})
}

// TestProjectPanelServesWorkingDirRoot pins the OPERATOR RULING of 2026-08-28:
// a run whose browsable directory is its own working directory (a default-cwd
// launch, Authorized=false) is fully browsable, and the meta payload says so.
//
// The two halves are inseparable on purpose. If the handler ever goes back to
// requiring an authorized root the browse assertions fail; if it serves the
// working directory while still calling it a project, the root_kind assertion
// fails.
func TestProjectPanelServesWorkingDirRoot(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "notes.txt"), []byte("in the daemon cwd\n"))
	resolver := fixedResolver(map[string]struct {
		root       string
		known      bool
		authorized bool
	}{
		// The devbox shape: no allowed_project_roots configured, so the launch
		// carried no root and the child ran in the daemon's own cwd.
		"DEFAULTCWD": {root: dir, known: true, authorized: false},
	})
	s := newProjectPanelServer(t, resolver, nil)

	t.Run("meta labels the path as a working directory", func(t *testing.T) {
		rec := doGet(t, s, "/api/terminal/project/DEFAULTCWD", false)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200 (the ruling enables Files/Git for a default-cwd launch); body=%s",
				rec.Code, rec.Body.String())
		}
		var resp projectMetaResp
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Root != dir {
			t.Fatalf("root = %q, want the spawn dir %q", resp.Root, dir)
		}
		if resp.RootKind != terminalRootKindWorking {
			t.Fatalf("root_kind = %q, want %q — the panel must not call a default-cwd launch a project",
				resp.RootKind, terminalRootKindWorking)
		}
	})

	t.Run("files and file are served from the working directory", func(t *testing.T) {
		rec := doGet(t, s, "/api/terminal/project/DEFAULTCWD/files?path=", false)
		if rec.Code != http.StatusOK {
			t.Fatalf("files code = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		var list projectFilesResp
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		if len(list.Entries) != 1 || list.Entries[0].Name != "notes.txt" {
			t.Fatalf("listing = %+v, want notes.txt from the working directory", list.Entries)
		}
		rec = doGet(t, s, "/api/terminal/project/DEFAULTCWD/file?path=notes.txt", false)
		if rec.Code != http.StatusOK {
			t.Fatalf("file code = %d, want 200", rec.Code)
		}
		var file projectFileResp
		if err := json.Unmarshal(rec.Body.Bytes(), &file); err != nil {
			t.Fatal(err)
		}
		if file.Content != "in the daemon cwd\n" {
			t.Fatalf("content = %q", file.Content)
		}
	})

	t.Run("git is served from the working directory", func(t *testing.T) {
		rec := doGet(t, s, "/api/terminal/project/DEFAULTCWD/git", false)
		if rec.Code != http.StatusOK {
			t.Fatalf("git code = %d, want 200 (a non-repo dir still answers is_git:false)", rec.Code)
		}
	})

	// The dock's button-enablement seam must agree with the endpoint: one
	// decision, two consumers.
	if !s.hasProjectRoot("DEFAULTCWD") {
		t.Fatal("hasProjectRoot = false for a default-cwd launch; the Files/Git buttons would be disabled while the endpoint serves 200")
	}
	if s.hasProjectRoot("GHOST") {
		t.Fatal("hasProjectRoot = true for an unknown token")
	}
}

// TestProjectPanelWorkingDirRootKeepsContainmentGuards pins that the ruling
// widened WHICH root is browsable, not what may be reached from it: every
// per-request containment guard (traversal, absolute paths, symlinks escaping
// the root, non-regular files) still enforces on a working-directory root, and
// the remote allow_terminal_view gate still runs before the token resolves.
func TestProjectPanelWorkingDirRootKeepsContainmentGuards(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "inside.txt"), []byte("ok\n"))

	// A secret OUTSIDE the working directory, reachable only if containment
	// broke — via traversal, via an absolute path, or via an in-root symlink.
	outside := t.TempDir()
	secretPath := filepath.Join(outside, "secret.txt")
	mustWrite(t, secretPath, []byte("must never be served\n"))
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	resolver := fixedResolver(map[string]struct {
		root       string
		known      bool
		authorized bool
	}{"DEFAULTCWD": {root: dir, known: true, authorized: false}})
	s := newProjectPanelServer(t, resolver, nil)

	// Sanity: the root itself IS browsable, so a refusal below is the guard
	// firing and not the panel being disabled.
	if rec := doGet(t, s, "/api/terminal/project/DEFAULTCWD/file?path=inside.txt", false); rec.Code != http.StatusOK {
		t.Fatalf("in-root read code = %d, want 200", rec.Code)
	}

	for _, tc := range []struct {
		name string
		path string
	}{
		{"traversal out of the working dir", "/file?path=../" + filepath.Base(outside) + "/secret.txt"},
		{"absolute path", "/file?path=" + secretPath},
		{"symlinked dir is not listable", "/files?path=escape"},
		{"read through an escaping symlink", "/file?path=escape/secret.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := doGet(t, s, "/api/terminal/project/DEFAULTCWD"+tc.path, false)
			if rec.Code == http.StatusOK {
				t.Fatalf("guard did not fire on a working-dir root: code=200 body=%s", rec.Body.String())
			}
			if body := rec.Body.String(); strings.Contains(body, "must never be served") {
				t.Fatalf("served content from outside the root: %s", body)
			}
		})
	}

	// The remote read gate is unchanged by the widening.
	sOff := newProjectPanelServer(t, resolver, NewRemoteController(RemoteOptions{AllowTerminalView: false}))
	rec := doGet(t, sOff, "/api/terminal/project/DEFAULTCWD/files?path=", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("remote view-off on a working-dir root: code = %d, want 403", rec.Code)
	}
	if got := errorCode(t, rec); got != "remote_view_disabled" {
		t.Fatalf("remote view-off error = %q, want remote_view_disabled", got)
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
