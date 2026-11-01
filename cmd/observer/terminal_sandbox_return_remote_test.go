//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// remoteReturnFixture is a real git repository standing in for the remote
// and a clone-remote copy of it under the managed root (the host's clone,
// as planCloneRemote makes it). It returns the request the driver composes,
// a git runner and the remote's path.
func remoteReturnFixture(t *testing.T) (workspace.ReturnRequest, func(dir string, args ...string) string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	root := t.TempDir()
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e", "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	remote := filepath.Join(root, "remote")
	if err := os.MkdirAll(remote, 0o700); err != nil {
		t.Fatal(err)
	}
	git(remote, "init", "-q")
	_ = os.WriteFile(filepath.Join(remote, "a.txt"), []byte("one\n"), 0o600)
	git(remote, "add", "a.txt")
	git(remote, "commit", "-qm", "one")
	managed := filepath.Join(root, "workspaces")
	runID := "RUNREMOTE00000001"
	copyDir := filepath.Join(managed, runID, "remote")
	if err := os.MkdirAll(filepath.Dir(copyDir), 0o700); err != nil {
		t.Fatal(err)
	}
	git(root, "clone", "-q", "--", "file://"+remote, copyDir)
	rr, err := ociCloneRemoteReturn(managed, termsvc.SandboxRun{ID: runID, Dir: copyDir, Tool: "claude-code"})
	if err != nil || rr == nil {
		t.Fatalf("no return planned for a clone-remote copy: %v", err)
	}
	return *rr, git, remote
}

// TestCloneRemoteReturnLandsInAHostBareRepository is milestone 5: the box's
// commit comes back as refs/observer/sandbox/<run> in the host-created bare
// repository beside the copy, with the scan called before the ref (a
// recording scan); the remote is untouched (nothing pushed), the copy is
// kept, and the terminal's one fetch command brings the ref into a
// developer checkout.
func TestCloneRemoteReturnLandsInAHostBareRepository(t *testing.T) {
	req, git, remote := remoteReturnFixture(t)
	want, _ := workspace.ReturnRepoPath(req.ManagedRoot, req.RunID)
	if !req.Bare || req.SourceRepo != want || req.BaseCommit != git(remote, "rev-parse", "HEAD") {
		t.Fatalf("request %+v", req)
	}
	_ = os.WriteFile(filepath.Join(req.CopyDir, "b.txt"), []byte("two\n"), 0o600)
	git(req.CopyDir, "add", "b.txt")
	git(req.CopyDir, "commit", "-qm", "two")
	sha := git(req.CopyDir, "rev-parse", "HEAD")
	remoteRefsBefore := git(remote, "for-each-ref")
	var order []string
	run := func(ctx context.Context, st workspace.Step) ([]byte, error) {
		for _, a := range st.Argv {
			switch a {
			case "init", "fetch", "update-ref", "push":
				order = append(order, a)
			}
		}
		return runReturnGit(ctx, st)
	}
	scan := func(_ context.Context, in sandboxReturnScanInput) error {
		order = append(order, "scan")
		if in.Repo != req.SourceRepo || in.Commit != sha {
			t.Errorf("scan input %+v", in)
		}
		return nil
	}
	res, err := sandboxReturnBare(context.Background(), req, run, scan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "init,fetch,scan,update-ref" {
		t.Fatalf("order %v", order)
	}
	if got := git(req.SourceRepo, "rev-parse", res.Ref); got != sha || res.Ref != workspace.ReturnRefPrefix+req.RunID {
		t.Fatalf("ref %s = %s", res.Ref, got)
	}
	if git(req.SourceRepo, "rev-parse", "--is-bare-repository") != "true" {
		t.Fatal("the return repository is not bare")
	}
	if git(remote, "for-each-ref") != remoteRefsBefore {
		t.Fatal("the remote changed: something was pushed")
	}
	if _, err := os.Stat(filepath.Join(req.CopyDir, ".git")); err != nil {
		t.Fatal("the copy was not kept")
	}
	// The developer's own checkout fetches the ref with the one command.
	dev := filepath.Join(t.TempDir(), "dev")
	git(filepath.Dir(dev), "clone", "-q", "--", "file://"+remote, dev)
	cmd := workspace.ReturnFetchCommand(req.SourceRepo, res.Ref)
	git(dev, strings.Fields(cmd)[1:]...)
	if got := git(dev, "rev-parse", res.Ref); got != sha {
		t.Fatalf("the developer's checkout got %s", got)
	}
	// A second return of the run is refused and leaves the repository.
	if _, err := sandboxReturnBare(context.Background(), req, runReturnGit, nil); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second return: %v", err)
	}
}

// TestCloneRemoteReturnNothingNew: a copy still at the commit the host
// cloned returns nothing and creates no repository.
func TestCloneRemoteReturnNothingNew(t *testing.T) {
	req, _, _ := remoteReturnFixture(t)
	res, err := sandboxReturnBare(context.Background(), req, runReturnGit, nil)
	if err != nil || !res.NothingNew {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := os.Lstat(req.SourceRepo); err == nil {
		t.Fatal("a return repository was made for nothing")
	}
}

// TestCloneRemoteReturnRefusesAHostileCopy: a symlinked .git, a tree entry
// with "..", a symlink out of the tree and an over-cap .git are refused, no
// ref is written and no return repository is left.
func TestCloneRemoteReturnRefusesAHostileCopy(t *testing.T) {
	cases := map[string]func(t *testing.T, req workspace.ReturnRequest, git func(string, ...string) string){
		"symlinked .git": func(t *testing.T, req workspace.ReturnRequest, git func(string, ...string) string) {
			_ = os.WriteFile(filepath.Join(req.CopyDir, "b.txt"), []byte("x\n"), 0o600)
			git(req.CopyDir, "add", "b.txt")
			git(req.CopyDir, "commit", "-qm", "x")
			real := filepath.Join(t.TempDir(), "elsewhere.git")
			if err := os.Rename(filepath.Join(req.CopyDir, ".git"), real); err != nil {
				t.Fatal(err)
			}
			if err := testSymlink(t, real, filepath.Join(req.CopyDir, ".git")); err != nil {
				t.Fatal(err)
			}
		},
		"dot-dot path": func(t *testing.T, req workspace.ReturnRequest, git func(string, ...string) string) {
			// A tree object naming ".." written past git's own checks.
			raw := "100644 ..\x00" + strings.Repeat("\x01", 20)
			f := filepath.Join(t.TempDir(), "tree")
			_ = os.WriteFile(f, []byte(raw), 0o600)
			tree := git(req.CopyDir, "hash-object", "-t", "tree", "--literally", "-w", f)
			commit := git(req.CopyDir, "commit-tree", tree, "-p", "HEAD", "-m", "dot-dot")
			git(req.CopyDir, "update-ref", "HEAD", commit)
		},
		"symlink out of the tree": func(t *testing.T, req workspace.ReturnRequest, git func(string, ...string) string) {
			if err := testSymlink(t, "../../../../etc/passwd", filepath.Join(req.CopyDir, "leak")); err != nil {
				t.Fatal(err)
			}
			git(req.CopyDir, "add", "leak")
			git(req.CopyDir, "commit", "-qm", "leak")
		},
		"over-cap .git": func(t *testing.T, req workspace.ReturnRequest, git func(string, ...string) string) {
			_ = os.WriteFile(filepath.Join(req.CopyDir, "b.txt"), []byte("x\n"), 0o600)
			git(req.CopyDir, "add", "b.txt")
			git(req.CopyDir, "commit", "-qm", "x")
			big, err := os.Create(filepath.Join(req.CopyDir, ".git", "objects", "pad"))
			if err != nil {
				t.Fatal(err)
			}
			// Sparse: counts toward the cap, costs no disk.
			if err := big.Truncate(workspace.MaxReturnBytes + 1); err != nil {
				t.Skipf("no sparse file here: %v", err)
			}
			_ = big.Close()
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			req, git, _ := remoteReturnFixture(t)
			edit(t, req, git)
			res, err := sandboxReturnBare(context.Background(), req, runReturnGit, nil)
			if err == nil {
				t.Fatalf("a hostile copy returned %+v", res)
			}
			if _, serr := os.Lstat(req.SourceRepo); serr == nil {
				t.Fatalf("the return repository was left after a refusal (%v)", err)
			}
		})
	}
}

// TestCloneRemoteReturnRequestRules: a bare return lands only in the run's
// own return repository.
func TestCloneRemoteReturnRequestRules(t *testing.T) {
	skipDriverOffHost(t, "the clone-remote return (Linux daemon)")
	managed := "/home/dev/.observer/workspaces"
	repo, _ := workspace.ReturnRepoPath(managed, "RUN1abcdefgh")
	ok := workspace.ReturnRequest{SourceRepo: repo, CopyDir: managed + "/RUN1abcdefgh/x", ManagedRoot: managed, RunID: "RUN1abcdefgh", Bare: true}
	if _, err := workspace.PlanReturn(ok); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(r *workspace.ReturnRequest){
		"another repository": func(r *workspace.ReturnRequest) { r.SourceRepo = managed + "/other.return.git" },
		"the copy itself":    func(r *workspace.ReturnRequest) { r.SourceRepo = r.CopyDir },
		"bad base":           func(r *workspace.ReturnRequest) { r.BaseCommit = "HEAD~1" },
		"not bare":           func(r *workspace.ReturnRequest) { r.Bare = false },
	} {
		r := ok
		edit(&r)
		if _, err := workspace.PlanReturn(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestCloneRemoteReturnPlanErrorIsSaid is audit finding 8: a clone-remote
// copy whose return cannot be planned (here its HEAD cannot be read) gets
// an error, never a silent nil (the helper's terminal line is
// TestOCIAfterRunSaysAReturnRefusal).
func TestCloneRemoteReturnPlanErrorIsSaid(t *testing.T) {
	managed := t.TempDir()
	runID := "RUNREMOTE00000002"
	copyDir := filepath.Join(managed, runID, "remote")
	if err := os.MkdirAll(copyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rr, err := ociCloneRemoteReturn(managed, termsvc.SandboxRun{ID: runID, Dir: copyDir})
	if err == nil || rr != nil {
		t.Fatalf("a copy with no repository planned a return: %+v %v", rr, err)
	}
	if !strings.Contains(err.Error(), "HEAD") {
		t.Fatalf("the error does not say what failed: %v", err)
	}
}
