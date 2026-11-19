//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// nonGitTestEnv isolates git from this machine's own global ignore file and
// points the temporary git directory at a folder the test can inspect.
func nonGitTestEnv(t *testing.T) (tmp string) {
	t.Helper()
	needGit(t)
	if runtime.GOOS == "windows" {
		t.Skip("the hosted host side is Linux and WSL2 only (POSIX roots)")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	tmp = t.TempDir()
	t.Setenv("TMPDIR", tmp)
	return tmp
}

// writeTree writes files (slash paths, relative to root) with their contents.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, body := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// treeDigest is every entry under root: path, mode, size, mtime and the
// content's hash, so a write anywhere in the folder changes it.
func treeDigest(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s %v %d %d", p, fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
		if fi.Mode().IsRegular() {
			body, err := os.ReadFile(p) //nolint:gosec // G304: a test's own temp tree
			if err != nil {
				return err
			}
			fmt.Fprintf(&b, " %x", sha256.Sum256(body))
		}
		b.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func manifestPaths(m sandboxremote.Manifest) []string {
	var out []string
	for _, f := range m.Files {
		out = append(out, f.Path)
	}
	return out
}

// TestHostedListWorkspaceNonGitPlainFolder (SBXD-8): a plain folder is listed
// with git's ignore machinery through a temporary git directory outside it:
// its .gitignore, the default ignore set and the extra patterns leave files
// out, the credential-shaped rule still applies, the temporary directory is
// removed and the folder is byte-identical afterwards (never git init'ed).
func TestHostedListWorkspaceNonGitPlainFolder(t *testing.T) {
	tmp := nonGitTestEnv(t)
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"src/main.go":               "package main\n",
		"README.md":                 "hi\n",
		".gitignore":                "secret.txt\n*.log\n",
		"secret.txt":                "do not send\n",
		"run.log":                   "log\n",
		"notes/keep.txt":            "keep\n",
		"node_modules/x/index.js":   "x\n",
		".venv/bin/python":          "py\n",
		"__pycache__/a.pyc":         "c\n",
		".env":                      "SECRET=1\n",
		"config/.env.local":         "SECRET=2\n",
		"deploy/key.pem":            "-----BEGIN-----\n",
		".DS_Store":                 "junk\n",
		"data/raw/big.csv":          "1,2\n",
		"sub/inner.txt":             "inner\n",
		"nested-not-a-repo/file.go": "package x\n",
	})
	before := treeDigest(t, root)
	m, err := hostedPlanUpload(context.Background(), root, "/nonexistent-home", hostedUploadListing{NonGit: true, Ignore: []string{"data/raw/"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".gitignore", "README.md", "nested-not-a-repo/file.go", "notes/keep.txt", "src/main.go", "sub/inner.txt"}
	if got := manifestPaths(m); !slices.Equal(got, want) {
		t.Fatalf("uploaded %q, want %q", got, want)
	}
	if !m.NonRepository || !strings.HasPrefix(m.ScopeKey, "nongit:") {
		t.Fatalf("manifest %+v", m)
	}
	// The key file is listed by git (no default row covers it) and left out
	// by the credential-shaped rule, so the consent screen names it.
	found := false
	for _, e := range m.Excluded {
		found = found || (e.Path == "deploy/key.pem" && e.Reason == sandboxremote.ExcludeCredentialShape)
	}
	if !found {
		t.Errorf("the key file is not listed as excluded: %+v", m.Excluded)
	}
	if after := treeDigest(t, root); after != before {
		t.Fatalf("the folder changed while it was listed:\nbefore\n%s\nafter\n%s", before, after)
	}
	if _, err := os.Lstat(filepath.Join(root, ".git")); !os.IsNotExist(err) {
		t.Fatal("the folder was git init'ed")
	}
	left, _ := os.ReadDir(tmp)
	for _, e := range left {
		if strings.HasPrefix(e.Name(), "observer-upload-list-") {
			t.Fatalf("the temporary git directory %s was left behind", e.Name())
		}
	}
}

// TestHostedListWorkspaceNonGitScopeKey: the scope key covers the listing,
// so a file added re-asks for consent and an edit does not.
func TestHostedListWorkspaceNonGitScopeKey(t *testing.T) {
	nonGitTestEnv(t)
	root := t.TempDir()
	writeTree(t, root, map[string]string{"a.go": "package a\n"})
	l := hostedUploadListing{NonGit: true}
	first, err := hostedPlanUpload(context.Background(), root, "/nonexistent-home", l)
	if err != nil {
		t.Fatal(err)
	}
	writeTree(t, root, map[string]string{"a.go": "package a // edited\n"})
	edited, _ := hostedPlanUpload(context.Background(), root, "/nonexistent-home", l)
	writeTree(t, root, map[string]string{"b.go": "package a\n"})
	added, _ := hostedPlanUpload(context.Background(), root, "/nonexistent-home", l)
	writeTree(t, root, map[string]string{"node_modules/z.js": "z\n"})
	ignored, _ := hostedPlanUpload(context.Background(), root, "/nonexistent-home", l)
	if edited.ScopeKey != first.ScopeKey {
		t.Error("an edit re-asks")
	}
	if added.ScopeKey == first.ScopeKey {
		t.Error("a file added does not re-ask")
	}
	if ignored.ScopeKey != added.ScopeKey {
		t.Error("an ignored file re-asks")
	}
}

// TestHostedListWorkspaceNonGitRefusals: a folder inside a repository, the
// home folder, a folder with a .git git cannot read, and a plain folder with
// upload_non_git off are refused, and the home folder is never walked.
func TestHostedListWorkspaceNonGitRefusals(t *testing.T) {
	nonGitTestEnv(t)
	l := hostedUploadListing{NonGit: true}
	ctx := context.Background()

	repo := t.TempDir()
	writeTree(t, repo, map[string]string{"sub/a.go": "package a\n"})
	if out, err := exec.Command("git", "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	if _, err := hostedPlanUpload(ctx, filepath.Join(repo, "sub"), "/nonexistent-home", l); err == nil || !strings.Contains(err.Error(), "inside the repository") {
		t.Errorf("a folder inside a repository: %v", err)
	}
	if m, err := hostedPlanUpload(ctx, repo, "/nonexistent-home", l); err != nil || m.NonRepository {
		t.Errorf("the repository root: %+v %v", m, err)
	}

	home := t.TempDir()
	writeTree(t, home, map[string]string{"a.txt": "a\n"})
	old := hostedListNonGit
	t.Cleanup(func() { hostedListNonGit = old })
	walked := false
	hostedListNonGit = func(ctx context.Context, root string, extra []string) ([]sandboxremote.Candidate, error) {
		walked = true
		return old(ctx, root, extra)
	}
	if _, err := hostedPlanUpload(ctx, home, filepath.ToSlash(home), l); !errors.Is(err, sandboxremote.ErrScopeHome) || walked {
		t.Errorf("the home folder: %v (walked %v)", err, walked)
	}
	hostedListNonGit = old

	plain := t.TempDir()
	writeTree(t, plain, map[string]string{"a.txt": "a\n"})
	if _, err := hostedPlanUpload(ctx, plain, "/nonexistent-home", hostedUploadListing{}); !errors.Is(err, sandboxremote.ErrScopeNotRepository) {
		t.Errorf("upload_non_git off: %v", err)
	}

	broken := t.TempDir()
	writeTree(t, broken, map[string]string{"a.txt": "a\n", ".git": "not a gitdir pointer\n"})
	if _, err := hostedPlanUpload(ctx, broken, "/nonexistent-home", l); !errors.Is(err, errHostedNonGitHoldsGit) {
		t.Errorf("a .git git cannot read: %v", err)
	}
}

// TestHostedWorkspaceRouteNonGit: the route answers a plain folder OK with a
// plain note under upload_non_git on, and the refusal under off; a folder
// inside a repository is refused either way.
func TestHostedWorkspaceRouteNonGit(t *testing.T) {
	nonGitTestEnv(t)
	plain := t.TempDir()
	ask := func(on bool, dir string) hostedWorkspaceView {
		t.Helper()
		w := httptest.NewRecorder()
		hostedWorkspaceServe(w, httptest.NewRequest(http.MethodGet, "/api/terminal/sandbox/hosted/workspace?dir="+url.QueryEscape(dir), nil), func(context.Context) (config.TerminalSandboxConfig, error) {
			c := config.Default().Terminal.Sandbox
			c.Hosted.UploadNonGit = on
			return c, nil
		})
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		var v hostedWorkspaceView
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := ask(true, plain); !v.OK || v.Code != sandboxremote.UploadNonRepositoryNote || !strings.Contains(v.Message, "diff file") || !strings.Contains(v.Message, "not a git repository") {
		t.Errorf("on: %+v", v)
	}
	if v := ask(false, plain); v.OK || v.Code != sandboxremote.ErrScopeNotRepository.Error() {
		t.Errorf("off: %+v", v)
	}
	w := httptest.NewRecorder()
	hostedWorkspaceServe(w, httptest.NewRequest(http.MethodGet, "/api/terminal/sandbox/hosted/workspace?dir="+url.QueryEscape(plain), nil), func(context.Context) (config.TerminalSandboxConfig, error) {
		return config.TerminalSandboxConfig{}, errors.New("no config")
	})
	if w.Code != http.StatusInternalServerError {
		t.Errorf("a config that does not load answers %d", w.Code)
	}
}

// TestHostedBaselineKeepsTheIgnoreSet (SBXD-8): the box's baseline step for
// a folder that is not a repository writes the listing's ignore set into the
// box repository's own exclude file (the lines as arguments, never shell
// text), so a dependency folder the agent creates in the box stays out of
// the diff; a repository's step is unchanged. Run here with this machine's
// sh and git standing in for the box's.
func TestHostedBaselineKeepsTheIgnoreSet(t *testing.T) {
	nonGitTestEnv(t)
	if got := hostedBaselineArgv(false, []string{"*.log"}); !slices.Equal(got, []string{"sh", "-c", hostedBaselineScript}) {
		t.Fatalf("a repository's baseline changed: %q", got)
	}
	ws := t.TempDir()
	writeTree(t, ws, map[string]string{"main.go": "package main\n"})
	argv := hostedBaselineArgv(true, []string{"*.log", "$(touch pwned)"})
	if argv[3] != "sh" || !slices.Contains(argv, "node_modules/") || !slices.Contains(argv, "$(touch pwned)") {
		t.Fatalf("argv %q", argv)
	}
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // G204: the test runs the box's own baseline argv
	cmd.Dir = ws
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("baseline: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(ws, "pwned")); !os.IsNotExist(err) {
		t.Fatal("an ignore line ran as shell text")
	}
	// The agent installs dependencies and writes a log and a source file.
	writeTree(t, ws, map[string]string{"node_modules/x/i.js": "x\n", ".venv/bin/py": "p\n", "run.log": "l\n", "new.go": "package main\n"})
	add := exec.Command("git", "-C", ws, "add", "-A")
	add.Env = cmd.Env
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("add: %v %s", err, out)
	}
	ls := exec.Command("git", "-C", ws, "diff", "--cached", "--name-only")
	ls.Env = cmd.Env
	out, err := ls.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(out)); !slices.Equal(got, []string{"new.go"}) {
		t.Fatalf("the box's diff holds %q, want only new.go", got)
	}
}

// TestHostedPlanCarriesTheUploadListing: the run's plan carries the
// listing the consent was given for, so the helper's re-list agrees.
func TestHostedPlanCarriesTheUploadListing(t *testing.T) {
	c := config.Default().Terminal.Sandbox.Hosted
	c.UploadIgnore = []string{"*.log"}
	l := hostedUploadListingFor(c)
	if !l.NonGit || !slices.Equal(l.Ignore, []string{"*.log"}) {
		t.Fatalf("listing %+v", l)
	}
	dir := t.TempDir()
	p, err := writeHostedPlan(dir, hostedPlanFile{Version: hostedPlanVersion, RunID: "r1", Provider: sandboxremote.VendorE2B, Root: "/w/p", UploadListing: l})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := readHostedPlan(p)
	if err != nil || !plan.UploadListing.NonGit || !slices.Equal(plan.UploadListing.Ignore, l.Ignore) {
		t.Fatalf("plan %+v %v", plan.UploadListing, err)
	}
}
