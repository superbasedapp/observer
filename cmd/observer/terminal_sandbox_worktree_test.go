//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// fakeWorktreeDriver stands for an active non-bwrap driver.
type fakeWorktreeDriver struct{ termsvc.SandboxLifecycle }

func (fakeWorktreeDriver) probe(context.Context) sandboxselect.Probe { return sandboxselect.Probe{} }
func (fakeWorktreeDriver) version() string                           { return "" }

// stubWorktreeOrgPin makes the org pin answer pinned for the test.
func stubWorktreeOrgPin(t *testing.T, pinned bool) {
	t.Helper()
	old := sandboxWorktreeOrgPinned
	sandboxWorktreeOrgPinned = func() bool { return pinned }
	t.Cleanup(func() { sandboxWorktreeOrgPinned = old })
}

// TestWorktreeSourceAvailability (milestone 4): the picker offers the
// worktree source only with the setting on; with it off it names the
// setting and what it does; an org pin keeping it off shows the org note;
// an enabled driver other than bwrap refuses it with a named reason.
func TestWorktreeSourceAvailability(t *testing.T) {
	cases := []struct {
		name    string
		on      bool
		pinned  bool
		drivers []string
		want    bool
		reason  string
	}{
		{"off by default", false, false, nil, false, worktreeReasonOff},
		{"org forbids", false, true, nil, false, worktreeReasonOrg},
		{"on", true, false, nil, true, ""},
		{"on with bwrap listed first", true, false, []string{"bwrap"}, true, ""},
		{"on with oci-runc enabled", true, false, []string{"oci-runc", "bwrap"}, false, worktreeDriverReason("oci-runc")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubWorktreeOrgPin(t, c.pinned)
			r := &sandboxRuntime{cfg: config.TerminalSandboxConfig{Enabled: true, AllowWorktreeSource: c.on, Backends: c.drivers}}
			for _, d := range c.drivers {
				if d != "bwrap" {
					if r.drivers == nil {
						r.drivers = map[string]sandboxDriver{}
					}
					r.drivers[d] = fakeWorktreeDriver{}
				}
			}
			var got *struct {
				ok     bool
				reason string
			}
			for _, s := range r.sources() {
				if s.ID == string(workspace.SourceWorktree) {
					got = &struct {
						ok     bool
						reason string
					}{s.Available, s.Reason}
				}
			}
			if got == nil || got.ok != c.want || got.reason != c.reason {
				t.Fatalf("worktree source = %+v, want available=%v reason %q", got, c.want, c.reason)
			}
		})
	}
	// A CLI launch that names bwrap is never substituted, so the source
	// stays offered there even while oci-runc is enabled.
	stubWorktreeOrgPin(t, false)
	forced := &sandboxRuntime{
		cfg:     config.TerminalSandboxConfig{Enabled: true, AllowWorktreeSource: true, Backends: []string{"oci-runc", "bwrap"}},
		drivers: map[string]sandboxDriver{"oci-runc": fakeWorktreeDriver{}}, forceBackend: "bwrap",
	}
	if a := forced.worktreeSourceAvail(); !a.Available {
		t.Fatalf("worktree source with the CLI naming bwrap: %+v, want available", a)
	}
	if !strings.Contains(worktreeReasonOff, ".git folder writable") {
		t.Fatalf("the off reason must say it mounts the .git folder writable: %q", worktreeReasonOff)
	}
}

// worktreeRepo makes a main repository with one commit and returns its
// top level (symlinks resolved).
func worktreeRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if r, err := filepath.EvalSymlinks(repo); err == nil {
		repo = r
	}
	wtGit(t, repo, "init", "-q")
	wtGit(t, repo, "checkout", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wtGit(t, repo, "add", "-A")
	wtGit(t, repo, "commit", "-q", "-m", "init")
	return repo
}

// wtGit runs git in dir with a fixed identity.
func wtGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

// gitOut runs git in dir and returns its trimmed output.
func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// newWorktreeRuntime is a bwrap runtime over temp dirs with the worktree
// source on.
func newWorktreeRuntime(t *testing.T) *sandboxRuntime {
	t.Helper()
	stubWorktreeOrgPin(t, false)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r, err := newSandboxRuntime(config.TerminalSandboxConfig{Enabled: true, HomeMode: "tmpfs", Egress: "host", AllowWorktreeSource: true}, nil, t.TempDir(), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestWorktreeMainLayoutRefusals (milestone 1): a symlinked .git, a
// symlinked object store, a reftable repository and a directory that is not
// a repository's top level refuse the launch; a plain repository passes.
func TestWorktreeMainLayoutRefusals(t *testing.T) {
	repo := worktreeRepo(t)
	if root, main, common, err := sandboxWorktreeMainLayout(repo); err != nil || root != repo || main != repo || common != filepath.Join(repo, ".git") {
		t.Fatalf("plain repository: %q %q %q %v", root, main, common, err)
	}
	sub := filepath.Join(repo, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := sandboxWorktreeMainLayout(sub); err == nil {
		t.Fatal("a subdirectory of a repository was accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	// A symlinked .git.
	linked := filepath.Join(t.TempDir(), "linked")
	if err := os.MkdirAll(linked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := testSymlink(t, filepath.Join(repo, ".git"), filepath.Join(linked, ".git")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := sandboxWorktreeMainLayout(linked); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlinked .git: %v", err)
	}
	// A symlinked object store.
	other := worktreeRepo(t)
	objects := filepath.Join(other, ".git", "objects")
	moved := filepath.Join(t.TempDir(), "objects")
	if err := os.Rename(objects, moved); err != nil {
		t.Fatal(err)
	}
	if err := testSymlink(t, moved, objects); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := sandboxWorktreeMainLayout(other); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlinked object store: %v", err)
	}
	// A reftable repository.
	rt := worktreeRepo(t)
	if err := os.MkdirAll(filepath.Join(rt, ".git", "reftable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := sandboxWorktreeMainLayout(rt); err == nil || !strings.Contains(err.Error(), "reftable") {
		t.Fatalf("a reftable repository: %v", err)
	}
}

// prepareWorktreeRun runs the real prepare path (worktreeBeforeAdd, the
// planned `git worktree add`, meta.json) and returns the run's workspace.
func prepareWorktreeRun(t *testing.T, r *sandboxRuntime, repo string) (string, string) {
	t.Helper()
	ws, err := r.prepareWorkspace(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: repo, WorkspaceSource: "worktree"})
	if err != nil {
		t.Fatalf("prepareWorkspace: %v", err)
	}
	return ws.id, ws.dir
}

// TestWorktreePrepareAddsADistinctBranch (milestone 2): the add creates the
// run's own branch at the main repository's HEAD, records it, and refuses
// on a node whose launches may take another driver.
func TestWorktreePrepareAddsADistinctBranch(t *testing.T) {
	repo := worktreeRepo(t)
	r := newWorktreeRuntime(t)
	id, dir := prepareWorktreeRun(t, r, repo)
	branch := "observer-sandbox/" + id + "/work"
	if got := gitOut(t, dir, "rev-parse", "--abbrev-ref", "HEAD"); got != branch {
		t.Fatalf("worktree branch = %q, want %q", got, branch)
	}
	if gitOut(t, repo, "rev-parse", "--abbrev-ref", "HEAD") != "main" {
		t.Fatal("the main checkout's branch moved")
	}
	rec, err := readSandboxWorktreeRecord(sandboxWorktreeRecordPath(r.observerDir, id))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Branch != branch || rec.Base != gitOut(t, repo, "rev-parse", "HEAD") || rec.WorkspaceDir != dir || rec.State != sandboxWorktreePreparing {
		t.Fatalf("record = %+v", rec)
	}
	// Two runs never share a branch.
	_, dir2 := prepareWorktreeRun(t, r, repo)
	if gitOut(t, dir2, "rev-parse", "--abbrev-ref", "HEAD") == branch {
		t.Fatal("a second run reused the first run's branch")
	}
	// Attribution (F0-14): the worktree resolves to the main repository.
	if root, ok := git.FindRoot(dir); !ok || root != repo {
		t.Fatalf("FindRoot(worktree) = %q %v, want the main repository %q", root, ok, repo)
	}
	if origin := relayCloneOrigin(r.managedRoot)(dir); origin != repo {
		t.Fatalf("relay clone origin = %q, want %q", origin, repo)
	}

	r.cfg.Backends = []string{"oci-runc", "bwrap"}
	r.drivers = map[string]sandboxDriver{"oci-runc": fakeWorktreeDriver{}}
	if _, err := r.prepareWorkspace(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: repo, WorkspaceSource: "worktree"}); err == nil || !strings.Contains(err.Error(), "oci-runc") {
		t.Fatalf("a worktree launch on a node enabling oci-runc: %v", err)
	}
}

// attachWorktreeRecord marks a prepared run attached, as worktreeBox does.
func attachWorktreeRecord(t *testing.T, r *sandboxRuntime, id string) {
	t.Helper()
	rec, err := readSandboxWorktreeRecord(sandboxWorktreeRecordPath(r.observerDir, id))
	if err != nil {
		t.Fatal(err)
	}
	rec.State = sandboxWorktreeAttached
	if err := writeSandboxWorktreeRecord(r.observerDir, rec); err != nil {
		t.Fatal(err)
	}
}

// TestWorktreeRunEnd (milestone 2): at the end of a run (no relay record
// any more) a clean worktree with no commits goes with its branch; a clean
// worktree with commits goes and its branch stays, listed; a dirty one is
// kept whole; a crashed launch still preparing is finished once past the
// grace; a kept run the user removes is pruned and forgotten with its
// branch left alone.
func TestWorktreeRunEnd(t *testing.T) {
	repo := worktreeRepo(t)
	r := newWorktreeRuntime(t)
	now := time.Now().UTC()
	sweep := func(at time.Time) { sweepSandboxWorktrees(context.Background(), r.observerDir, r.managedRoot, at, nil) }
	branchOf := func(id string) string { return "observer-sandbox/" + id + "/work" }
	hasBranch := func(b string) bool {
		return exec.Command("git", "-C", repo, "rev-parse", "--verify", "--quiet", "refs/heads/"+b).Run() == nil
	}
	recState := func(id string) string {
		rec, err := readSandboxWorktreeRecord(sandboxWorktreeRecordPath(r.observerDir, id))
		if err != nil {
			return ""
		}
		return rec.State
	}

	clean, cleanDir := prepareWorktreeRun(t, r, repo)
	committed, committedDir := prepareWorktreeRun(t, r, repo)
	dirty, dirtyDir := prepareWorktreeRun(t, r, repo)
	crashed, crashedDir := prepareWorktreeRun(t, r, repo)
	for _, id := range []string{clean, committed, dirty} {
		attachWorktreeRecord(t, r, id)
	}
	if err := os.WriteFile(filepath.Join(committedDir, "work.txt"), []byte("w\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wtGit(t, committedDir, "add", "work.txt")
	wtGit(t, committedDir, "commit", "-q", "-m", "work")
	if err := os.WriteFile(filepath.Join(dirtyDir, "wip.txt"), []byte("w\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sweep(now)
	if _, err := os.Lstat(cleanDir); !os.IsNotExist(err) || hasBranch(branchOf(clean)) || recState(clean) != "" {
		t.Errorf("clean run: dir %v branch %v record %q, want all gone", err, hasBranch(branchOf(clean)), recState(clean))
	}
	if _, err := os.Lstat(filepath.Join(r.managedRoot, clean)); !os.IsNotExist(err) {
		t.Errorf("clean run: the managed run dir is left (%v)", err)
	}
	if _, err := os.Lstat(committedDir); !os.IsNotExist(err) || !hasBranch(branchOf(committed)) || recState(committed) != sandboxWorktreeKept {
		t.Errorf("committed run: dir %v branch %v record %q, want the worktree gone and the branch kept", err, hasBranch(branchOf(committed)), recState(committed))
	}
	if meta, ok := readWorkspaceMeta(filepath.Join(r.managedRoot, committed)); !ok || meta.Source != workspace.SourceWorktree {
		t.Errorf("committed run: meta.json not left for `observer workspaces ls` (%+v %v)", meta, ok)
	}
	if _, err := os.Stat(filepath.Join(dirtyDir, "wip.txt")); err != nil || !hasBranch(branchOf(dirty)) || recState(dirty) != sandboxWorktreeKept {
		t.Errorf("dirty run: %v branch %v record %q, want everything kept", err, hasBranch(branchOf(dirty)), recState(dirty))
	}
	if _, err := os.Lstat(crashedDir); err != nil || recState(crashed) != sandboxWorktreePreparing {
		t.Errorf("a launch still within its preparing grace was ended: %v %q", err, recState(crashed))
	}

	// The crashed launch, past the grace.
	sweep(now.Add(sandboxWorktreePrepGrace + time.Minute))
	if _, err := os.Lstat(crashedDir); !os.IsNotExist(err) || hasBranch(branchOf(crashed)) || recState(crashed) != "" {
		t.Errorf("crashed run: dir %v branch %v record %q, want all gone", err, hasBranch(branchOf(crashed)), recState(crashed))
	}

	// The user removes the kept committed run: its registration is pruned,
	// its branch stays, the record goes.
	if err := os.RemoveAll(filepath.Join(r.managedRoot, committed)); err != nil {
		t.Fatal(err)
	}
	sweep(now)
	if !hasBranch(branchOf(committed)) || recState(committed) != "" {
		t.Errorf("forgotten committed run: branch %v record %q, want the branch kept and the record gone", hasBranch(branchOf(committed)), recState(committed))
	}
	if strings.Contains(gitOut(t, repo, "worktree", "list", "--porcelain"), committed) {
		t.Error("the removed worktree is still registered")
	}
	// A live run (its relay record present) is never ended: nothing here
	// writes one, so the attached dirty run stays kept and untouched.
	if recState(dirty) != sandboxWorktreeKept {
		t.Errorf("dirty run record = %q", recState(dirty))
	}
}

// TestWorktreeRunEndNeverDeletesAMovedBranch: a branch that moved after the
// facts were read is not deleted (compare-and-delete on the base).
func TestWorktreeRunEndNeverDeletesAMovedBranch(t *testing.T) {
	repo := worktreeRepo(t)
	r := newWorktreeRuntime(t)
	id, dir := prepareWorktreeRun(t, r, repo)
	branch := "observer-sandbox/" + id + "/work"
	if err := os.WriteFile(filepath.Join(dir, "x.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wtGit(t, dir, "add", "x.txt")
	wtGit(t, dir, "commit", "-q", "-m", "x")
	moved := gitOut(t, dir, "rev-parse", "HEAD")
	rec, err := readSandboxWorktreeRecord(sandboxWorktreeRecordPath(r.observerDir, id))
	if err != nil {
		t.Fatal(err)
	}
	// Even a decision that says "delete" cannot delete it: the base no
	// longer matches.
	steps, err := workspace.PlanWorktreeEnd(workspace.WorktreeEndRequest{MainRoot: rec.MainRoot, WorkspaceDir: dir, Branch: branch, Base: rec.Base}, workspace.WorktreeEndDecision{Action: workspace.WorktreeEndPruneOnly, DeleteBranch: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runReturnGit(context.Background(), steps[len(steps)-1]); err == nil {
		t.Fatal("update-ref deleted a branch that moved past the base")
	}
	if gitOut(t, repo, "rev-parse", "refs/heads/"+branch) != moved {
		t.Fatal("the moved branch changed")
	}
}

func TestFindSandboxWorktreeEntry(t *testing.T) {
	dir := filepath.FromSlash("/w/run/repo")
	out := []byte("worktree /home/u/repo\nHEAD 1111\nbranch refs/heads/main\n\nworktree " + filepath.ToSlash(dir) + "\nHEAD 2222\nbranch refs/heads/observer-sandbox/run/work\nlocked reason\n\n")
	e, ok := findSandboxWorktreeEntry(out, dir)
	if runtime.GOOS == "windows" {
		return
	}
	if !ok || e.branch != "refs/heads/observer-sandbox/run/work" || !e.locked {
		t.Fatalf("entry = %+v %v", e, ok)
	}
	if _, ok := findSandboxWorktreeEntry(out, "/w/other"); ok {
		t.Fatal("found an entry that is not listed")
	}
}
