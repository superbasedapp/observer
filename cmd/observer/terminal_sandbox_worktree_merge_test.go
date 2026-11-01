//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// The merge fixes of lane SBX-WORKTREE-SOURCE (audit findings 1, 2, 5, 6
// and 7), through a real git.

// wtWriteFile writes body to path, creating its parent.
func wtWriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// plantNestedFilterRepo plants, as a box can (the worktree and its own git
// dir are writable in the box), a nested repository at <ws>/sub whose
// config names a clean filter that touches marker, with a committed file the
// filter applies to whose mtime then moves, so any git status inside sub
// re-reads it through the filter. It stages sub as a gitlink in the worktree's index, so a host git
// status in the worktree recurses into it. The marker the planting itself
// made is removed.
func plantNestedFilterRepo(t *testing.T, ws, marker string) {
	t.Helper()
	sub := filepath.Join(ws, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	wtGit(t, sub, "init", "-q")
	f, err := os.OpenFile(filepath.Join(sub, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(f, "[filter \"evil\"]\n\tclean = sh -c 'touch %s && cat'\n", marker)
	_ = f.Close()
	wtWriteFile(t, filepath.Join(sub, ".gitattributes"), "* filter=evil\n")
	wtWriteFile(t, filepath.Join(sub, "a.txt"), "a\n")
	wtGit(t, sub, "add", "-A")
	wtGit(t, sub, "commit", "-q", "-m", "sub")
	sha := gitOut(t, sub, "rev-parse", "HEAD")
	wtGit(t, ws, "update-index", "--add", "--cacheinfo", "160000,"+sha+",sub")
	// Same size, a later mtime: a status inside sub must re-read the file,
	// which runs the clean filter.
	later := time.Now().Add(10 * time.Second)
	if err := os.Chtimes(filepath.Join(sub, "a.txt"), later, later); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(marker)
}

// TestWorktreeRunEndKeepsANestedRepository (audit finding 1): a worktree
// whose tree holds a nested repository with a clean filter, staged as a
// gitlink, is kept at the end of the run and the filter never runs on the
// host (a control run of the old, unhardened status proves the plant is
// live on this git); a gitlink alone and a modules folder in the worktree's
// git dir are kept too; `observer workspaces ls` says why.
func TestWorktreeRunEndKeepsANestedRepository(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the planted filter is a POSIX shell command")
	}
	repo := worktreeRepo(t)
	r := newWorktreeRuntime(t)
	marker := filepath.Join(t.TempDir(), "FILTER-RAN")

	type planted struct {
		id, dir, want string
	}
	var runs []planted

	// The full plant: a nested repository with a clean filter and a gitlink.
	id, dir := prepareWorktreeRun(t, r, repo)
	plantNestedFilterRepo(t, dir, marker)
	control := exec.Command("git", "-C", dir, "status", "--porcelain=v1", "--untracked-files=normal")
	_ = control.Run()
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("control: the old cleanup's git status did not run the planted filter (%v); the test would prove nothing", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	runs = append(runs, planted{id, dir, "nested .git at sub"})

	// A gitlink alone (no nested directory).
	id, dir = prepareWorktreeRun(t, r, repo)
	wtGit(t, dir, "update-index", "--add", "--cacheinfo", "160000,"+gitOut(t, repo, "rev-parse", "HEAD")+",lib")
	runs = append(runs, planted{id, dir, "gitlink (submodule) in its index at lib"})

	// A modules folder in the worktree's own git dir.
	id, dir = prepareWorktreeRun(t, r, repo)
	admin, ok := readSandboxGitFile(filepath.Join(dir, ".git"))
	if !ok {
		t.Fatal("the worktree's .git file names no git dir")
	}
	if err := os.MkdirAll(filepath.Join(admin, "modules", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	runs = append(runs, planted{id, dir, "holds a modules folder"})

	for _, p := range runs {
		attachWorktreeRecord(t, r, p.id)
	}
	sweepSandboxWorktrees(context.Background(), r.observerDir, r.managedRoot, time.Now().UTC(), nil)

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the planted clean filter ran on the host at the end of the run")
	}
	var ls bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&ls)
	if err := listWorkspaces(cmd, r.managedRoot); err != nil {
		t.Fatal(err)
	}
	for _, p := range runs {
		rec, err := readSandboxWorktreeRecord(sandboxWorktreeRecordPath(r.observerDir, p.id))
		if err != nil || rec.State != sandboxWorktreeKept || !strings.Contains(rec.Reason, "another repository") || !strings.Contains(rec.Reason, p.want) {
			t.Errorf("run %s: record %+v %v, want kept naming %q", p.id, rec, err, p.want)
		}
		if _, err := os.Stat(p.dir); err != nil {
			t.Errorf("run %s: the worktree was not kept: %v", p.id, err)
		}
		if meta, ok := readWorkspaceMeta(filepath.Dir(p.dir)); !ok || !strings.Contains(meta.Kept, p.want) {
			t.Errorf("run %s: meta.json kept = %q, want the reason", p.id, meta.Kept)
		}
		if !strings.Contains(ls.String(), p.id+" was kept: ") {
			t.Errorf("observer workspaces ls does not say why %s was kept:\n%s", p.id, ls.String())
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the planted clean filter ran on the host")
	}
}

// TestWorktreeHostGitIsHardened (audit findings 1 and 6): `worktree add`
// does not run the main repository's post-checkout hook, and every end-of-
// run step carries the hardening flags and environment.
func TestWorktreeHostGitIsHardened(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the hook is a POSIX shell script")
	}
	repo := worktreeRepo(t)
	marker := filepath.Join(t.TempDir(), "HOOK-RAN")
	hook := filepath.Join(repo, ".git", "hooks", "post-checkout")
	wtWriteFile(t, hook, "#!/bin/sh\ntouch "+marker+"\n")
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}
	// Control: an ordinary checkout in the main repository runs the hook.
	wtGit(t, repo, "checkout", "-q", "-b", "control")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("control: git did not run the post-checkout hook (%v)", err)
	}
	_ = os.Remove(marker)
	r := newWorktreeRuntime(t)
	prepareWorktreeRun(t, r, repo)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("worktree add ran the main repository's post-checkout hook")
	}
	steps, err := workspace.PlanWorktreeEnd(workspace.WorktreeEndRequest{MainRoot: repo, WorkspaceDir: filepath.Join(repo, "x"), Branch: "observer-sandbox/a/work", Base: strings.Repeat("1", 40)}, workspace.WorktreeEndDecision{Action: workspace.WorktreeEndRemoveAll, DeleteBranch: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		joined := strings.Join(s.Argv, " ")
		if !s.Hardened || !strings.Contains(joined, "core.hooksPath=/dev/null") || !strings.Contains(joined, "protocol.file.allow=never") {
			t.Errorf("end step not hardened: %v", s.Argv)
		}
	}
	env := strings.Join(hardenedGitEnv([]string{"GIT_DIR=/evil", "PATH=/bin"}), "\n")
	if strings.Contains(env, "GIT_DIR=") || !strings.Contains(env, "GIT_CONFIG_NOSYSTEM=1") || !strings.Contains(env, "core.hooksPath") {
		t.Errorf("hardened env = %s", env)
	}
}

// TestWorktreeRunEndPrunesOnlyItsOwnRegistration (audit finding 6): the end
// of a run removes its own worktree registration only, never the user's
// other stale worktrees, whether git removed the worktree or its directory
// was already gone.
func TestWorktreeRunEndPrunesOnlyItsOwnRegistration(t *testing.T) {
	repo := worktreeRepo(t)
	userWT := filepath.Join(t.TempDir(), "mine")
	wtGit(t, repo, "worktree", "add", "-q", "-b", "mine", userWT)
	if err := os.RemoveAll(userWT); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(repo, ".git", "worktrees", "mine")
	if _, err := os.Stat(stale); err != nil {
		t.Fatal(err)
	}
	r := newWorktreeRuntime(t)
	clean, _ := prepareWorktreeRun(t, r, repo)
	gone, goneDir := prepareWorktreeRun(t, r, repo)
	goneAdmin, ok := readSandboxGitFile(filepath.Join(goneDir, ".git"))
	if !ok {
		t.Fatal("no git dir")
	}
	attachWorktreeRecord(t, r, clean)
	attachWorktreeRecord(t, r, gone)
	if err := os.RemoveAll(goneDir); err != nil {
		t.Fatal(err)
	}
	sweepSandboxWorktrees(context.Background(), r.observerDir, r.managedRoot, time.Now().UTC(), nil)
	list := gitOut(t, repo, "worktree", "list", "--porcelain")
	if strings.Contains(list, clean) || strings.Contains(list, gone) {
		t.Errorf("a run's registration is left:\n%s", list)
	}
	if _, err := os.Stat(goneAdmin); !os.IsNotExist(err) {
		t.Errorf("the gone run's registration %s is left (%v)", goneAdmin, err)
	}
	if _, err := os.Stat(stale); err != nil {
		t.Errorf("the user's own stale worktree registration was pruned: %v", err)
	}
}

// TestWorktreeRefusesAWriteBindOverTheGitDir (audit finding 2): a write
// bind of the repository's parent folder covers the git common dir, so the
// worktree source is refused naming the bind, at prepare and at attach; an
// org-set bind names the admin as the remedy.
func TestWorktreeRefusesAWriteBindOverTheGitDir(t *testing.T) {
	repo := worktreeRepo(t)
	parent := filepath.Dir(repo)
	r := newWorktreeRuntime(t)
	r.cfg.ExtraRWBinds = []string{parent}
	_, err := r.prepareWorkspace(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: repo, WorkspaceSource: "worktree"})
	if err == nil || !strings.Contains(err.Error(), parent) || !strings.Contains(err.Error(), "covers") {
		t.Fatalf("a parent-folder write bind at prepare: %v", err)
	}
	r.cfg.ExtraRWBinds = nil
	id, dir := prepareWorktreeRun(t, r, repo)
	if _, err := r.worktreeBox(id, dir, []string{dir, parent}); err == nil || !strings.Contains(err.Error(), parent) {
		t.Fatalf("a parent-folder write root at attach: %v", err)
	}
	inside := filepath.Join(repo, ".git", "refs")
	if _, err := r.worktreeBox(id, dir, []string{inside}); err == nil || !strings.Contains(err.Error(), inside) {
		t.Fatalf("a write root inside the git dir at attach: %v", err)
	}
	r.orgRWBinds = []string{parent}
	if err := r.worktreeWriteRootRefusal(filepath.Join(repo, ".git"), []string{parent}); err == nil || !strings.Contains(err.Error(), "organization's admin") {
		t.Fatalf("an org write bind over the git dir: %v", err)
	}
	if err := r.worktreeWriteRootRefusal(filepath.Join(repo, ".git"), []string{dir, t.TempDir()}); err != nil {
		t.Fatalf("unrelated write roots refused: %v", err)
	}
	// SHR-WORKTREE2 milestone 5 (lane SHR-FOLLOWUPS): a submodule's git dir
	// lives in the common dir's modules folder, so a write root covering it
	// (or the modules folder) is refused the same way.
	for _, sub := range []string{filepath.Join(repo, ".git", "modules"), filepath.Join(repo, ".git", "modules", "lib")} {
		if err := r.worktreeWriteRootRefusal(filepath.Join(repo, ".git"), []string{sub}); err == nil || !strings.Contains(err.Error(), sub) {
			t.Fatalf("a write root over a submodule git dir %s: %v", sub, err)
		}
	}
}

// TestWorktreeBoxRefusesASymlinkedWriteHole (audit finding 5): a symlink at
// the run's reflog dir, or above its ref dir, refuses the attach rather than
// moving a writable bind elsewhere.
func TestWorktreeBoxRefusesASymlinkedWriteHole(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	repo := worktreeRepo(t)
	r := newWorktreeRuntime(t)
	id, dir := prepareWorktreeRun(t, r, repo)
	common := filepath.Join(repo, ".git")
	swap := func(p string) func() {
		t.Helper()
		moved := filepath.Join(t.TempDir(), "moved")
		if err := os.Rename(p, moved); err != nil {
			t.Fatal(err)
		}
		if err := testSymlink(t, moved, p); err != nil {
			t.Fatal(err)
		}
		return func() {
			_ = os.Remove(p)
			if err := os.Rename(moved, p); err != nil {
				t.Fatal(err)
			}
		}
	}
	logDir := filepath.Join(common, "logs", "refs", "heads", "observer-sandbox", id)
	if _, err := os.Stat(logDir); err != nil {
		t.Skipf("no reflog dir on this git (%v)", err)
	}
	undo := swap(logDir)
	if _, err := r.worktreeBox(id, dir, []string{dir}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlinked reflog dir: %v", err)
	}
	undo()
	undo = swap(filepath.Join(common, "refs", "heads", "observer-sandbox"))
	if _, err := r.worktreeBox(id, dir, []string{dir}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlink above the run's ref dir: %v", err)
	}
	undo()
}

// TestWorktreeSourceOrgPinRealCheck (audit finding 7): the picker's org
// note comes from the real governance read, not a stub: no overlay shows
// the off reason, an applied pin on allow_worktree_source shows the org
// note.
func TestWorktreeSourceOrgPinRealCheck(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	wtWriteFile(t, cfgPath, "[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dbDir, "observer.db"))+"\"\n")
	old := daemonConfigPathSetting.Load()
	daemonConfigPathSetting.Store(&cfgPath)
	t.Cleanup(func() { daemonConfigPathSetting.Store(old) })
	avail := func() string {
		r := &sandboxRuntime{cfg: config.TerminalSandboxConfig{Enabled: true}}
		return r.worktreeSourceAvail().Reason
	}
	if got := avail(); got != worktreeReasonOff {
		t.Fatalf("no org pin: reason %q, want the off reason", got)
	}
	wtWriteFile(t, filepath.Join(dbDir, config.GovernanceSidecarFilename), `{"schema":1,"state":"applied","pinned":{"terminal.sandbox.allow_worktree_source":false}}`)
	if !sandboxWorktreeOrgPinCheck(cfgPath) {
		t.Fatal("the real pin check does not see the applied pin")
	}
	if got := avail(); got != worktreeReasonOrg {
		t.Fatalf("an applied org pin: reason %q, want the org note", got)
	}
}
