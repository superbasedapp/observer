//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

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
	"time"

	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// diffFixture is a person's repository with one commit, and the box the
// hosted driver makes of it: the same files, a fresh baseline repository
// (`git init && git add -A && commit`), then the agent's changes staged and
// `git diff --binary HEAD` saved, exactly as saveStagedDiff does.
type diffFixture struct {
	t    *testing.T
	repo string
	box  string
	diff string
	base string
}

func fixtureGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "maintenance.auto=false", "-c", "gc.auto=0", "-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newDiffFixture(t *testing.T) *diffFixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	f := &diffFixture{t: t, repo: filepath.Join(root, "app"), box: filepath.Join(root, "box"), diff: filepath.Join(root, "RUN1.diff")}
	for _, d := range []string{f.repo, f.box} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fixtureGit(t, f.repo, "init", "-q")
	f.write(f.repo, "a.txt", "one\ntwo\nthree\n")
	f.write(f.repo, "bin.dat", "\x00\x01\x02old")
	f.write(f.repo, "keep.txt", "kept\n")
	fixtureGit(t, f.repo, "add", "-A")
	fixtureGit(t, f.repo, "commit", "-qm", "base")
	f.base = fixtureGit(t, f.repo, "rev-parse", "HEAD")
	// The upload: the folder's files into the box, and its baseline.
	for _, n := range []string{"a.txt", "bin.dat", "keep.txt"} {
		b, _ := os.ReadFile(filepath.Join(f.repo, n))
		f.write(f.box, n, string(b))
	}
	fixtureGit(t, f.box, "init", "-q")
	fixtureGit(t, f.box, "add", "-A")
	fixtureGit(t, f.box, "commit", "-qm", "observer-baseline")
	return f
}

func (f *diffFixture) write(dir, name, body string) {
	f.t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// saveBoxDiff stages the box's changes and saves the diff the guest's
// one-shot prints.
func (f *diffFixture) saveBoxDiff() {
	f.t.Helper()
	fixtureGit(f.t, f.box, "add", "-A")
	out := fixtureGit(f.t, f.box, "--no-pager", "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--binary", "HEAD")
	if err := os.WriteFile(f.diff, []byte(out+"\n"), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// untouched checks the person's repository kept its HEAD, index and
// working tree.
func (f *diffFixture) untouched() {
	f.t.Helper()
	if h := fixtureGit(f.t, f.repo, "rev-parse", "HEAD"); h != f.base {
		f.t.Fatalf("HEAD moved to %s", h)
	}
	if s := fixtureGit(f.t, f.repo, "status", "--porcelain", "--untracked-files=all"); s != "" {
		f.t.Fatalf("the working tree or index changed: %q", s)
	}
}

func TestSandboxOpenDiffBranchCleanApply(t *testing.T) {
	f := newDiffFixture(t)
	f.write(f.box, "a.txt", "one\nTWO\nthree\n")
	f.write(f.box, "new/dir/b.txt", "new file\n")
	f.write(f.box, "bin.dat", "\x00\x01\x02new binary\xff")
	_ = os.Remove(filepath.Join(f.box, "keep.txt"))
	f.saveBoxDiff()

	res, err := sandboxOpenDiffBranch(context.Background(), f.repo, f.diff, "RUN1", f.base)
	if err != nil {
		t.Fatal(err)
	}
	if res.Branch != "observer-sandbox/RUN1/changes" || !workspace.ValidSHA(res.Commit) || res.Files != 4 {
		t.Fatalf("result %+v", res)
	}
	f.untouched()
	if p := fixtureGit(t, f.repo, "rev-parse", res.Branch+"^"); p != f.base {
		t.Fatalf("the branch's parent is %s, not the base", p)
	}
	// The branch holds exactly the box's files.
	boxTree := fixtureGit(t, f.box, "write-tree")
	if got := fixtureGit(t, f.repo, "rev-parse", res.Branch+"^{tree}"); got != boxTree {
		t.Fatalf("the branch's tree %s is not the box's %s", got, boxTree)
	}
	if author := fixtureGit(t, f.repo, "log", "-1", "--format=%an <%ae>", res.Branch); author != "Observer sandbox <observer@localhost>" {
		t.Fatalf("author %q", author)
	}
	// It checks out as a branch.
	fixtureGit(t, f.repo, "switch", "-q", res.Branch)
	if b, _ := os.ReadFile(filepath.Join(f.repo, "new", "dir", "b.txt")); string(b) != "new file\n" {
		t.Fatalf("checked-out file %q", b)
	}
}

func TestSandboxOpenDiffBranchRefuses(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *diffFixture)
		want  string
	}{
		{"a diff made against another version", func(f *diffFixture) {
			// The person committed a.txt differently after the files were
			// sent; the base recorded is the new commit, which the box did
			// not start from.
			f.write(f.box, "a.txt", "one\nTWO\nthree\n")
			f.saveBoxDiff()
			f.write(f.repo, "a.txt", "one\ntwo\nthree\nfour\n")
			fixtureGit(f.t, f.repo, "commit", "-qam", "later")
			f.base = fixtureGit(f.t, f.repo, "rev-parse", "HEAD")
		}, "not the one in commit"},
		{"a diff that does not apply", func(f *diffFixture) {
			// A hunk whose preimage blob name is right but whose context
			// was forged.
			f.write(f.box, "a.txt", "one\nTWO\nthree\n")
			f.saveBoxDiff()
			b, _ := os.ReadFile(f.diff)
			_ = os.WriteFile(f.diff, []byte(strings.Replace(string(b), " one\n", " uno\n", 1)), 0o600)
		}, "does not apply"},
		{"a path out of the repository", func(f *diffFixture) {
			_ = os.WriteFile(f.diff, []byte("diff --git a/../evil.txt b/../evil.txt\nnew file mode 100644\nindex 0000000000000000000000000000000000000000..e69de29bb2d1d6434b8b29ae775ad8c2e48c5391\n--- /dev/null\n+++ b/../evil.txt\n@@ -0,0 +1 @@\n+x\n"), 0o600)
		}, ""},
		{"a path into .git", func(f *diffFixture) {
			_ = os.WriteFile(f.diff, []byte("diff --git a/.git/hooks/pre-commit b/.git/hooks/pre-commit\nnew file mode 100755\nindex 0000000000000000000000000000000000000000..e69de29bb2d1d6434b8b29ae775ad8c2e48c5391\n--- /dev/null\n+++ b/.git/hooks/pre-commit\n@@ -0,0 +1 @@\n+x\n"), 0o600)
		}, ""},
		{"a symlink out of the tree", func(f *diffFixture) {
			if err := os.Symlink("../../../etc/passwd", filepath.Join(f.box, "evil")); err != nil {
				f.t.Skip(err)
			}
			f.saveBoxDiff()
		}, "outside the returned tree"},
		{"a branch that already exists", func(f *diffFixture) {
			f.write(f.box, "a.txt", "one\nTWO\nthree\n")
			f.saveBoxDiff()
			fixtureGit(f.t, f.repo, "branch", "observer-sandbox/RUN1/changes")
		}, "already exists"},
		{"a base the repository lacks", func(f *diffFixture) {
			f.write(f.box, "a.txt", "one\nTWO\nthree\n")
			f.saveBoxDiff()
			f.base = strings.Repeat("ab", 20)
		}, "is not in"},
		{"a diff that changes nothing", func(f *diffFixture) {
			_ = os.WriteFile(f.diff, []byte(""), 0o600)
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newDiffFixture(t)
			c.setup(f)
			headBefore := fixtureGit(t, f.repo, "rev-parse", "HEAD")
			refsBefore := fixtureGit(t, f.repo, "for-each-ref", "--format=%(refname) %(objectname)")
			_, err := sandboxOpenDiffBranch(context.Background(), f.repo, f.diff, "RUN1", f.base)
			t.Logf("refused: %v", err)
			if err == nil || (c.want != "" && !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			if h := fixtureGit(t, f.repo, "rev-parse", "HEAD"); h != headBefore {
				t.Fatal("HEAD moved")
			}
			if refs := fixtureGit(t, f.repo, "for-each-ref", "--format=%(refname) %(objectname)"); refs != refsBefore {
				t.Fatalf("refs changed: %q -> %q", refsBefore, refs)
			}
			if s := fixtureGit(t, f.repo, "status", "--porcelain", "--untracked-files=all"); s != "" {
				t.Fatalf("the working tree or index changed: %q", s)
			}
		})
	}
}

// TestHostedDiffRouteFlow drives the panel's routes over a saved diff: the
// list says it opens as a branch, the preview shows it, the branch action
// creates the branch, a second click is refused, and Remove takes the file.
func TestHostedDiffRouteFlow(t *testing.T) {
	f := newDiffFixture(t)
	f.write(f.box, "a.txt", "one\nTWO\nthree\n")
	f.saveBoxDiff()
	obs := t.TempDir()
	diffPath, _ := hostedDiffPaths(obs, "RUN1")
	if err := os.MkdirAll(filepath.Dir(diffPath), 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.diff)
	_ = os.WriteFile(diffPath, b, 0o600)
	if err := writeHostedDiffRecord(obs, hostedDiffRecord{
		V: hostedDiffRecordVersion, RunID: "RUN1", Root: f.repo, SavedAt: time.Now().UTC(),
		Base: hostedDiffBase{Commit: f.base, StatusKnown: true, StatusClean: true},
	}); err != nil {
		t.Fatal(err)
	}
	// A second diff with no record is offered as a file only.
	_ = os.WriteFile(filepath.Join(filepath.Dir(diffPath), "OLD1.diff"), b, 0o600)

	old := sandboxReturnsEnv
	sandboxReturnsEnv = func(string) (string, string, bool) { return obs, filepath.Join(obs, "workspaces"), true }
	t.Cleanup(func() { sandboxReturnsEnv = old })
	mux := http.NewServeMux()
	for _, r := range sandboxReturnsRoutes("") {
		mux.HandleFunc(r.Pattern, r.Handler)
	}
	do := func(method, path, body string) (int, map[string]any) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(hostedConfirmHeader, strings.Repeat("a", 64))
			req.AddCookie(&http.Cookie{Name: hostedConfirmCookie, Value: strings.Repeat("a", 64)})
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	code, list := do(http.MethodGet, sandboxReturnsPath, "")
	hosted, _ := list["hosted"].([]any)
	if code != 200 || len(hosted) != 2 {
		t.Fatalf("list %d %v", code, list)
	}
	byRun := map[string]map[string]any{}
	for _, h := range hosted {
		m := h.(map[string]any)
		byRun[m["run"].(string)] = m
	}
	if byRun["RUN1"]["exact"] != true || byRun["RUN1"]["branch"] != "observer-sandbox/RUN1/changes" || byRun["OLD1"]["exact"] == true {
		t.Fatalf("list %v", byRun)
	}
	code, prev := do(http.MethodGet, sandboxReturnsDiffPath+"?run=RUN1", "")
	if code != 200 || !strings.Contains(prev["text"].(string), "+TWO") || len(prev["files"].([]any)) != 1 {
		t.Fatalf("preview %d %v", code, prev)
	}
	// Without the confirm token the action is refused.
	req := httptest.NewRequest(http.MethodPost, sandboxReturnsBranchPath, strings.NewReader(`{"run":"RUN1"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("no token: %d", w.Code)
	}
	code, br := do(http.MethodPost, sandboxReturnsBranchPath, `{"run":"RUN1"}`)
	if code != 200 || br["branch"] != "observer-sandbox/RUN1/changes" {
		t.Fatalf("branch %d %v", code, br)
	}
	f.untouched()
	if code, again := do(http.MethodPost, sandboxReturnsBranchPath, `{"run":"RUN1"}`); code != http.StatusConflict || !strings.Contains(again["error"].(string), "already exists") {
		t.Fatalf("second click %d %v", code, again)
	}
	if code, file := do(http.MethodPost, sandboxReturnsBranchPath, `{"run":"OLD1"}`); code != http.StatusConflict || !strings.Contains(file["error"].(string), "as a file only") {
		t.Fatalf("old diff %d %v", code, file)
	}
	if code, _ := do(http.MethodPost, sandboxReturnsRemoveDiffPath, `{"run":"RUN1"}`); code != 200 {
		t.Fatalf("remove %d", code)
	}
	if _, err := os.Stat(diffPath); !os.IsNotExist(err) {
		t.Fatal("the diff is still there")
	}
	// The branch stays.
	fixtureGit(t, f.repo, "rev-parse", "--verify", "observer-sandbox/RUN1/changes")
	sandboxReturnsEnv = func(string) (string, string, bool) { return obs, "", false }
	if code, _ := do(http.MethodGet, sandboxReturnsPath, ""); code != http.StatusNotFound {
		t.Fatalf("module off: %d", code)
	}
}

// localCopyFixture is a bwrap clone-local run: a source repository, its
// managed copy (clone --no-hardlinks) with meta.json, and the run.
func localCopyFixture(t *testing.T, id string) (obs, managed, src string, run termsvc.SandboxRun) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	obs, managed, src = filepath.Join(root, "obs"), filepath.Join(root, "workspaces"), filepath.Join(root, "src")
	for _, d := range []string{obs, src, filepath.Join(managed, id)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fixtureGit(t, src, "init", "-q")
	_ = os.WriteFile(filepath.Join(src, ".gitignore"), []byte("node_modules/\n*.log\n"), 0o600)
	_ = os.WriteFile(filepath.Join(src, "a.txt"), []byte("one\n"), 0o600)
	fixtureGit(t, src, "add", "-A")
	fixtureGit(t, src, "commit", "-qm", "one")
	copyDir := filepath.Join(managed, id, "src")
	fixtureGit(t, root, "clone", "-q", "--no-hardlinks", "--", src, copyDir)
	meta, _ := workspace.MarshalMeta(workspace.Meta{Source: workspace.SourceCloneLocal, Origin: src, RunID: id, CreatedAt: time.Now().UTC()})
	_ = os.WriteFile(filepath.Join(managed, id, "meta.json"), meta, 0o600)
	return obs, managed, src, termsvc.SandboxRun{ID: id, Tool: "claude-code", Dir: copyDir, ProjectRoot: src, Copy: true}
}

// TestBwrapCopyRunReturnsAtItsEnd: a bwrap clone-local run's commit comes
// back as refs/observer/sandbox/<run> once the run is gone, by the same
// return the container drivers run; the record says so, and the copy is then
// removable only while its files are exactly its last commit's.
func TestBwrapCopyRunReturnsAtItsEnd(t *testing.T) {
	const id = "RUNbwrap000000001"
	obs, managed, src, run := localCopyFixture(t, id)
	rec, ok := planLocalReturn(managed, run, runReturnGit, time.Now().UTC())
	if !ok || rec.State != workspace.CopyReturnPending || rec.Request == nil || rec.Request.SourceRepo != src || !workspace.ValidSHA(rec.CopyBase) {
		t.Fatalf("plan %+v", rec)
	}
	if err := writeSandboxLocalReturn(obs, rec); err != nil {
		t.Fatal(err)
	}
	// The box commits in its copy.
	_ = os.WriteFile(filepath.Join(run.Dir, "b.txt"), []byte("two\n"), 0o600)
	fixtureGit(t, run.Dir, "add", "b.txt")
	fixtureGit(t, run.Dir, "commit", "-qm", "two")
	want := fixtureGit(t, run.Dir, "rev-parse", "HEAD")
	srcHead := fixtureGit(t, src, "rev-parse", "HEAD")

	// No relay record and no ledger: the run is gone, and the sweep returns.
	if !sandboxLocalRunGone(obs, id) {
		t.Fatal("the run is not gone")
	}
	sweepSandboxLocalReturns(context.Background(), obs, nil)
	got, err := readSandboxLocalReturn(sandboxLocalReturnPath(obs, id))
	if err != nil || got.State != workspace.CopyReturnReturned || got.Commit != want || got.Commits != 1 || got.Ref != workspace.ReturnRefPrefix+id {
		t.Fatalf("record %+v %v", got, err)
	}
	if r := fixtureGit(t, src, "rev-parse", workspace.ReturnRefPrefix+id); r != want {
		t.Fatalf("ref %s", r)
	}
	if h := fixtureGit(t, src, "rev-parse", "HEAD"); h != srcHead {
		t.Fatal("the source's HEAD moved")
	}
	// A second sweep does nothing more.
	sweepSandboxLocalReturns(context.Background(), obs, nil)

	views := listLocalReturns(context.Background(), obs, managed)
	if len(views) != 1 || views[0].State != workspace.CopyReturnReturned || views[0].Commits != 1 || !views[0].Removable || views[0].SizeBytes == 0 || !views[0].SafeToRemove {
		t.Fatalf("views %+v", views)
	}

	// An untracked, not ignored file is work that never came back: kept,
	// and the panel's "safe to remove" verdict says so before the click
	// (D4: the count used a rule of its own and counted it).
	_ = os.WriteFile(filepath.Join(run.Dir, "notes.md"), []byte("draft\n"), 0o600)
	views = listLocalReturns(context.Background(), obs, managed)
	if len(views) != 1 || !views[0].Removable || views[0].SafeToRemove || !strings.Contains(views[0].KeepReason, "not in its last commit") {
		t.Fatalf("the list's verdict after an untracked file: %+v", views)
	}
	if v, err := removeSandboxCopy(context.Background(), obs, managed, id); err != nil || v.Remove || !strings.Contains(v.Reason, "not in its last commit") {
		t.Fatalf("untracked: %+v %v", v, err)
	}
	_ = os.Remove(filepath.Join(run.Dir, "notes.md"))
	// A changed tracked file: kept.
	_ = os.WriteFile(filepath.Join(run.Dir, "a.txt"), []byte("changed\n"), 0o600)
	if v, err := removeSandboxCopy(context.Background(), obs, managed, id); err != nil || v.Remove || !strings.Contains(v.Reason, "changed or missing") {
		t.Fatalf("changed: %+v %v", v, err)
	}
	_ = os.WriteFile(filepath.Join(run.Dir, "a.txt"), []byte("one\n"), 0o600)
	// Ignored build output does not keep it.
	_ = os.MkdirAll(filepath.Join(run.Dir, "node_modules", "x"), 0o700)
	_ = os.WriteFile(filepath.Join(run.Dir, "node_modules", "x", "i.js"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(run.Dir, "build.log"), []byte("x"), 0o600)
	v, err := removeSandboxCopy(context.Background(), obs, managed, id)
	if err != nil || !v.Remove {
		t.Fatalf("clean: %+v %v", v, err)
	}
	if _, err := os.Stat(filepath.Join(managed, id)); !os.IsNotExist(err) {
		t.Fatal("the copy is still there")
	}
	// The returned ref stays in the source.
	fixtureGit(t, src, "rev-parse", "--verify", workspace.ReturnRefPrefix+id)
}

// TestBwrapCopyReturnRefusedKeepsTheCopy: a copy whose return was refused
// (here: the box planted a hook) is kept, and removing it is refused.
func TestBwrapCopyReturnRefusedKeepsTheCopy(t *testing.T) {
	const id = "RUNbwrap000000002"
	obs, managed, _, run := localCopyFixture(t, id)
	rec, ok := planLocalReturn(managed, run, runReturnGit, time.Now().UTC())
	if !ok {
		t.Fatal("no plan")
	}
	_ = writeSandboxLocalReturn(obs, rec)
	_ = os.WriteFile(filepath.Join(run.Dir, ".git", "hooks", "post-checkout"), []byte("#!/bin/sh\n"), 0o700)
	sweepSandboxLocalReturns(context.Background(), obs, nil)
	got, err := readSandboxLocalReturn(sandboxLocalReturnPath(obs, id))
	if err != nil || got.State != workspace.CopyReturnRefused || !strings.Contains(got.Reason, "not returned") {
		t.Fatalf("record %+v %v", got, err)
	}
	v, err := removeSandboxCopy(context.Background(), obs, managed, id)
	if err != nil || v.Remove {
		t.Fatalf("removal %+v %v", v, err)
	}
	if _, err := os.Stat(run.Dir); err != nil {
		t.Fatal("the copy went")
	}
}

// TestBwrapLiveRunReturnsNothing: a live or worktree run records no return
// (the table's rows), and a run whose relay record is there is not gone.
func TestBwrapLiveRunReturnsNothing(t *testing.T) {
	const id = "RUNbwrap000000003"
	_, managed, src, run := localCopyFixture(t, id)
	if _, ok := planLocalReturn(managed, termsvc.SandboxRun{ID: id, Dir: src, ProjectRoot: src}, runReturnGit, time.Now()); ok {
		t.Fatal("a live run planned a return")
	}
	meta, _ := workspace.MarshalMeta(workspace.Meta{Source: workspace.SourceWorktree, Origin: src, RunID: id})
	_ = os.WriteFile(filepath.Join(managed, id, "meta.json"), meta, 0o600)
	if _, ok := planLocalReturn(managed, run, runReturnGit, time.Now()); ok {
		t.Fatal("a worktree run planned a return")
	}
}

// TestSandboxLocalLedgerFileIsTheHelpers pins the ledger path the return
// waits on to the host helper's own.
func TestSandboxLocalLedgerFileIsTheHelpers(t *testing.T) {
	if got, want := sandboxLocalLedgerFile("/o", "RUN1"), sandboxLocalLedgerPathForTest("/o", "RUN1"); want != "" && got != want {
		t.Fatalf("%s != %s", got, want)
	}
}
