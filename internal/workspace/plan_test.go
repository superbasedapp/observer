package workspace

import (
	"path/filepath"
	"reflect"
	"testing"
)

func baseReq() Request {
	return Request{
		ProjectRoot: "/home/user/proj",
		ManagedRoot: "/home/user/.observer/workspaces",
		ID:          "abc123XYZ_-9Q",
	}
}

func TestPlanLive(t *testing.T) {
	req := baseReq()
	req.Source = SourceLive
	got, err := Plan(req)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if got.Dir != req.ProjectRoot {
		t.Fatalf("Dir = %q, want %q", got.Dir, req.ProjectRoot)
	}
	if len(got.Steps) != 0 {
		t.Fatalf("Steps = %v, want none (live is the degenerate case)", got.Steps)
	}
}

func TestPlanLiveRejectsRelativeProjectRoot(t *testing.T) {
	req := baseReq()
	req.Source = SourceLive
	req.ProjectRoot = "relative/proj"
	if _, err := Plan(req); err == nil {
		t.Fatalf("expected error for relative ProjectRoot")
	}
}

// TestCloneLocalUsesNoHardlinks is mutation proof #5 from
// docs/plans/b9-sandboxed-terminals-implementation-plan-2026-08-08.md §8:
// dropping --no-hardlinks from the composed clone argv must fail this
// test. Without it, git's default --local clone hardlinks object files,
// so the sandboxed agent's own git gc/repack could mutate objects shared
// with the REAL repository's object store.
func TestCloneLocalUsesNoHardlinks(t *testing.T) {
	req := baseReq()
	req.Source = SourceCloneLocal
	got, err := Plan(req)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(got.Steps) == 0 {
		t.Fatalf("no Steps returned")
	}
	argv := got.Steps[0].Argv
	wantDest := filepath.Join(req.ManagedRoot, req.ID, filepath.Base(req.ProjectRoot))
	want := []string{"git", "clone", "--no-hardlinks", "--", req.ProjectRoot, wantDest}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("clone-local argv = %v, want %v", argv, want)
	}
	found := false
	for _, a := range argv {
		if a == "--no-hardlinks" {
			found = true
		}
	}
	if !found {
		t.Fatalf("--no-hardlinks missing from clone-local argv %v", argv)
	}
}

func TestPlanCloneLocalDest(t *testing.T) {
	req := baseReq()
	req.Source = SourceCloneLocal
	got, err := Plan(req)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	want := filepath.Join(req.ManagedRoot, req.ID, "proj")
	if got.Dir != want {
		t.Fatalf("Dir = %q, want %q", got.Dir, want)
	}
}

func TestPlanCloneLocalWithBranch(t *testing.T) {
	req := baseReq()
	req.Source = SourceCloneLocal
	req.Branch = "feature-x"
	got, err := Plan(req)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(got.Steps) != 2 {
		t.Fatalf("Steps = %d, want 2 (clone + checkout -b)", len(got.Steps))
	}
	want := []string{"git", "-C", got.Dir, "checkout", "-b", "feature-x"}
	if !reflect.DeepEqual(got.Steps[1].Argv, want) {
		t.Fatalf("checkout argv = %v, want %v", got.Steps[1].Argv, want)
	}
}

func TestPlanCloneRemoteRequiresAllow(t *testing.T) {
	req := baseReq()
	req.Source = SourceCloneRemote
	req.RemoteURL = "https://github.com/example/repo.git"
	if _, err := Plan(req); err == nil {
		t.Fatalf("expected error: AllowRemoteClone is false")
	}
}

func TestPlanCloneRemote(t *testing.T) {
	req := baseReq()
	req.Source = SourceCloneRemote
	req.RemoteURL = "https://github.com/example/repo.git"
	req.AllowRemoteClone = true
	got, err := Plan(req)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	wantDest := filepath.Join(req.ManagedRoot, req.ID, "repo")
	if got.Dir != wantDest {
		t.Fatalf("Dir = %q, want %q", got.Dir, wantDest)
	}
	want := []string{"git", "clone", "--", req.RemoteURL, wantDest}
	if !reflect.DeepEqual(got.Steps[0].Argv, want) {
		t.Fatalf("clone-remote argv = %v, want %v", got.Steps[0].Argv, want)
	}
}

func TestPlanCloneRemoteWithBranch(t *testing.T) {
	req := baseReq()
	req.Source = SourceCloneRemote
	req.RemoteURL = "https://github.com/example/repo.git"
	req.AllowRemoteClone = true
	req.Branch = "feature-x"
	got, err := Plan(req)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(got.Steps) != 2 {
		t.Fatalf("Steps = %d, want 2 (clone + checkout -b)", len(got.Steps))
	}
	want := []string{"git", "-C", got.Dir, "checkout", "-b", "feature-x"}
	if !reflect.DeepEqual(got.Steps[1].Argv, want) {
		t.Fatalf("checkout argv = %v, want %v", got.Steps[1].Argv, want)
	}
}

func TestPlanCloneRemoteRejectsBadURL(t *testing.T) {
	req := baseReq()
	req.Source = SourceCloneRemote
	req.AllowRemoteClone = true
	req.RemoteURL = "ext::sh -c evil"
	if _, err := Plan(req); err == nil {
		t.Fatalf("expected error for ext:: URL")
	}
}

func TestPlanCloneRemoteEnforcesHostAllowlist(t *testing.T) {
	req := baseReq()
	req.Source = SourceCloneRemote
	req.AllowRemoteClone = true
	req.RemoteURL = "https://evil.example.com/x.git"
	req.RemoteAllowedHosts = []string{"github.com"}
	if _, err := Plan(req); err == nil {
		t.Fatalf("expected error: host not in RemoteAllowedHosts")
	}
}

func TestPlanCloneRemoteRejectsEmptyRepoLeaf(t *testing.T) {
	req := baseReq()
	req.Source = SourceCloneRemote
	req.AllowRemoteClone = true
	req.RemoteURL = "https://github.com/"
	if _, err := Plan(req); err == nil {
		t.Fatalf("expected error: URL has no repo path segment to derive a leaf from")
	}
}

func TestPlanWorktreeRequiresAllow(t *testing.T) {
	req := baseReq()
	req.Source = SourceWorktree
	req.Branch = "wt-branch"
	if _, err := Plan(req); err == nil {
		t.Fatalf("expected error: AllowWorktreeSource is false")
	}
}

func TestPlanWorktreeDefaultsTheBranchLabel(t *testing.T) {
	req := baseReq()
	req.Source = SourceWorktree
	req.AllowWorktreeSource = true
	got, err := Plan(req)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if want := "observer-sandbox/" + req.ID + "/work"; got.Branch != want {
		t.Fatalf("Branch = %q, want %q", got.Branch, want)
	}
}

func TestPlanWorktree(t *testing.T) {
	req := baseReq()
	req.Source = SourceWorktree
	req.AllowWorktreeSource = true
	req.Branch = "wt-branch"
	req.StartPoint = "0123456789abcdef0123456789abcdef01234567"
	got, err := Plan(req)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	branch := "observer-sandbox/" + req.ID + "/wt-branch"
	want := []string{"git", "-C", req.ProjectRoot, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "worktree", "add", "-b", branch, "--", got.Dir, req.StartPoint}
	if !reflect.DeepEqual(got.Steps[0].Argv, want) || !got.Steps[0].Hardened {
		t.Fatalf("worktree argv = %v (hardened %v), want %v hardened", got.Steps[0].Argv, got.Steps[0].Hardened, want)
	}
	if got.Branch != branch {
		t.Fatalf("Branch = %q, want %q", got.Branch, branch)
	}
}

func TestPlanWorktreeRefusesABadStartPoint(t *testing.T) {
	for _, sp := range []string{"HEAD", "-x", "0123", "0123456789ABCDEF0123456789ABCDEF01234567"} {
		req := baseReq()
		req.Source = SourceWorktree
		req.AllowWorktreeSource = true
		req.StartPoint = sp
		if _, err := Plan(req); err == nil {
			t.Errorf("start point %q accepted", sp)
		}
	}
}

func TestPlanUnknownSourceRejected(t *testing.T) {
	req := baseReq()
	req.Source = Source("bogus")
	if _, err := Plan(req); err == nil {
		t.Fatalf("expected error for unknown Source")
	}
}

// TestPlanDestMintingRejectsTraversal covers the injection-guard table
// for every argv-bound field Plan validates before it reaches a
// destination path: a ".."-bearing or otherwise unsafe ID/ProjectRoot
// must be rejected, never silently sanitized into something plausible.
func TestPlanDestMintingRejectsTraversal(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Request)
	}{
		{"id-dotdot", func(r *Request) { r.ID = ".." }},
		{"id-with-separator", func(r *Request) { r.ID = "a/../b" }},
		{"id-empty", func(r *Request) { r.ID = "" }},
		{"id-leading-dash", func(r *Request) { r.ID = "-rf" }},
		{"id-control-char", func(r *Request) { r.ID = "abc\ndef" }},
		{"projectroot-dotdot-segment", func(r *Request) { r.ProjectRoot = "/home/user/../etc" }},
		{"projectroot-relative", func(r *Request) { r.ProjectRoot = "relative/proj" }},
		{"managedroot-relative", func(r *Request) { r.ManagedRoot = "relative/workspaces" }},
		{"managedroot-empty", func(r *Request) { r.ManagedRoot = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := baseReq()
			req.Source = SourceCloneLocal
			tc.mut(&req)
			if _, err := Plan(req); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestPlanRejectsControlCharsInBranch(t *testing.T) {
	req := baseReq()
	req.Source = SourceCloneLocal
	req.Branch = "feat\nrm -rf /"
	if _, err := Plan(req); err == nil {
		t.Fatalf("expected error for branch containing a control character")
	}
}

func TestPlanRejectsLeadingDashInBranch(t *testing.T) {
	req := baseReq()
	req.Source = SourceCloneLocal
	req.Branch = "--upload-pack=evil"
	if _, err := Plan(req); err == nil {
		t.Fatalf("expected error for branch beginning with '-'")
	}
}
