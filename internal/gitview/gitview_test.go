package gitview

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseStatusPorcelainV2(t *testing.T) {
	// -z output: NUL-terminated records. Rename "2" records are followed by a
	// NUL-separated origin-path token.
	fields := []string{
		"# branch.oid abcdef",
		"# branch.head main",
		"# branch.upstream origin/main",
		"# branch.ab +2 -1",
		"1 M. N... 100644 100644 100644 1111111 2222222 staged.go",
		"1 .M N... 100644 100644 100644 3333333 4444444 dirty.go",
		"2 R. N... 100644 100644 100644 5555555 6666666 R100 new.go",
		"old.go", // origin path for the rename above
		"? untracked.txt",
		"! ignored.txt", // must be skipped
		"",              // trailing NUL
	}
	data := []byte(strings.Join(fields, "\x00"))

	branch, upstream, ahead, behind, files := parseStatusPorcelainV2(data)
	if branch != "main" {
		t.Errorf("branch = %q, want main", branch)
	}
	if upstream != "origin/main" {
		t.Errorf("upstream = %q, want origin/main", upstream)
	}
	if ahead != 2 || behind != 1 {
		t.Errorf("ahead/behind = %d/%d, want 2/1", ahead, behind)
	}
	want := []FileStatus{
		{Path: "staged.go", Staged: "M", Worktree: "."},
		{Path: "dirty.go", Staged: ".", Worktree: "M"},
		{Path: "new.go", Staged: "R", Worktree: ".", RenamedFrom: "old.go"},
		{Path: "untracked.txt", Staged: "?", Worktree: "?"},
	}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("files =\n%#v\nwant\n%#v", files, want)
	}
}

func TestParseStatusEmpty(t *testing.T) {
	// A clean repo on a detached head: only branch headers, no changes.
	data := []byte(strings.Join([]string{
		"# branch.head (detached)",
		"# branch.ab +0 -0",
		"",
	}, "\x00"))
	branch, upstream, ahead, behind, files := parseStatusPorcelainV2(data)
	if branch != "(detached)" {
		t.Errorf("branch = %q", branch)
	}
	if upstream != "" || ahead != 0 || behind != 0 {
		t.Errorf("unexpected upstream/ahead/behind: %q %d %d", upstream, ahead, behind)
	}
	if len(files) != 0 {
		t.Errorf("files = %v, want none", files)
	}
}

func TestParseLog(t *testing.T) {
	rec := func(parts ...string) string { return strings.Join(parts, "\x00") + "\x1e" }
	data := []byte(
		rec("h1", "p0", "Alice", "2026-07-23T10:00:00+00:00", "HEAD -> main, origin/main", "first") +
			"\n" + rec("h2", "p1 p2", "Bob", "2026-07-22T09:00:00+00:00", "tag: v1.0", "a merge") +
			"\n",
	)
	commits, truncated := parseLog(data)
	if truncated {
		t.Error("two commits must not be truncated")
	}
	if len(commits) != 2 {
		t.Fatalf("len(commits) = %d, want 2", len(commits))
	}
	if commits[0].Hash != "h1" || commits[0].Author != "Alice" || commits[0].Subject != "first" {
		t.Errorf("commit0 = %#v", commits[0])
	}
	if !reflect.DeepEqual(commits[0].Parents, []string{"p0"}) {
		t.Errorf("commit0 parents = %v", commits[0].Parents)
	}
	if !reflect.DeepEqual(commits[0].Refs, []string{"main", "origin/main"}) {
		t.Errorf("commit0 refs = %v, want [main origin/main]", commits[0].Refs)
	}
	if !reflect.DeepEqual(commits[1].Parents, []string{"p1", "p2"}) {
		t.Errorf("commit1 parents = %v, want [p1 p2]", commits[1].Parents)
	}
	if !reflect.DeepEqual(commits[1].Refs, []string{"v1.0"}) {
		t.Errorf("commit1 refs = %v, want [v1.0]", commits[1].Refs)
	}
}

func TestParseRefs(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"HEAD", nil},
		{"HEAD -> main", []string{"main"}},
		{"HEAD -> main, origin/main, tag: v1.0", []string{"main", "origin/main", "v1.0"}},
		{"tag: v2.3.4", []string{"v2.3.4"}},
	}
	for _, tt := range tests {
		if got := parseRefs(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseRefs(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseAheadBehind(t *testing.T) {
	tests := []struct {
		in           string
		wantA, wantB int
	}{
		{"+0 -0", 0, 0},
		{"+3 -5", 3, 5},
		{"", 0, 0},
	}
	for _, tt := range tests {
		a, b := parseAheadBehind(tt.in)
		if a != tt.wantA || b != tt.wantB {
			t.Errorf("parseAheadBehind(%q) = %d/%d, want %d/%d", tt.in, a, b, tt.wantA, tt.wantB)
		}
	}
}

// TestEmptyInfoWireShape asserts the array-contract invariant: a normalized
// snapshot marshals status/log as [] (never null), and each commit's
// parents/refs as [] (never null). Finding 7.
func TestEmptyInfoWireShape(t *testing.T) {
	b, err := json.Marshal(EmptyInfo())
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{`"status":[]`, `"log":[]`, `"status_truncated":false`} {
		if !strings.Contains(got, want) {
			t.Fatalf("EmptyInfo JSON = %s, want substring %q", got, want)
		}
	}

	// A root commit (no parents) + an undecorated commit (no refs), normalized,
	// must encode parents:[] and refs:[] rather than null.
	info := normalizeInfo(Info{
		IsGit: true,
		Log: []Commit{
			{Hash: "root", Parents: nil, Refs: nil, Subject: "init"},
		},
	})
	b, err = json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	got = string(b)
	for _, want := range []string{`"parents":[]`, `"refs":[]`} {
		if !strings.Contains(got, want) {
			t.Fatalf("normalized commit JSON = %s, want substring %q", got, want)
		}
	}
}

// TestSnapshotWireShapeClean builds a real one-commit repo and asserts the wire
// shape a clean repository produces: status:[] (no changes), the root commit's
// parents:[], and an undecorated commit's refs:[]. Finding 7 end-to-end.
func TestSnapshotWireShapeClean(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	ctx := context.Background()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(cmd.Environ(),
			"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@e.co",
			"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@e.co")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("checkout", "-q", "-b", "main")
	// Two commits: the newest carries the "main" ref decoration; the ROOT commit
	// (older, in a clean tree) is undecorated AND parentless, so it must encode
	// refs:[] and parents:[] rather than null.
	run("commit", "-q", "--allow-empty", "-m", "root")
	run("commit", "-q", "--allow-empty", "-m", "second")

	info, err := Snapshot(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	// Clean repo → status:[]; root commit → parents:[]; undecorated root → refs:[].
	for _, want := range []string{`"status":[]`, `"parents":[]`, `"refs":[]`} {
		if !strings.Contains(got, want) {
			t.Fatalf("Snapshot JSON = %s, want substring %q", got, want)
		}
	}
	if strings.Contains(got, `:null`) {
		t.Fatalf("Snapshot JSON contains a null (array-contract violation): %s", got)
	}
}

// TestSnapshotIntegration builds a throwaway repo and exercises the real git
// binary end-to-end. It is skipped when git is unavailable.
func TestSnapshotIntegration(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	ctx := context.Background()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(
			cmd.Environ(),
			"GIT_AUTHOR_NAME=Tester", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=Tester", "GIT_COMMITTER_EMAIL=t@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	// Non-git dir first.
	if info, err := Snapshot(ctx, dir); err != nil || info.IsGit {
		t.Fatalf("pre-init Snapshot: info.IsGit=%v err=%v, want false/nil", info.IsGit, err)
	}

	run("init", "-q")
	run("checkout", "-q", "-b", "main")
	run("commit", "-q", "--allow-empty", "-m", "initial commit")

	// A tracked change + an untracked file.
	if err := os.WriteFile(filepath.Join(dir, "tracked.txt"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "tracked.txt")
	run("commit", "-q", "-m", "add tracked")
	if err := os.WriteFile(filepath.Join(dir, "tracked.txt"), []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "untracked.txt"), []byte("u"), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := Snapshot(ctx, dir)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !info.IsGit {
		t.Fatal("IsGit = false, want true")
	}
	if info.Branch != "main" {
		t.Errorf("branch = %q, want main", info.Branch)
	}
	if len(info.Log) != 2 {
		t.Errorf("log has %d commits, want 2", len(info.Log))
	}
	if info.Log[0].Subject != "add tracked" {
		t.Errorf("newest subject = %q, want 'add tracked'", info.Log[0].Subject)
	}
	var haveTrackedMod, haveUntracked bool
	for _, f := range info.Status {
		if f.Path == "tracked.txt" {
			haveTrackedMod = true
		}
		if f.Path == "untracked.txt" && f.Staged == "?" {
			haveUntracked = true
		}
	}
	if !haveTrackedMod {
		t.Errorf("status missing modified tracked.txt: %+v", info.Status)
	}
	if !haveUntracked {
		t.Errorf("status missing untracked.txt: %+v", info.Status)
	}
}

// TestIsNoCommitsError_ExitCodeShape pins the structural predicate
// itself against synthetic *GitError values, independent of real git
// (2026-09-22 review finding 11): the ONLY accepted shape is exit code
// 1 with empty stderr. Exit 128 (git's own documented code for a
// "fatal" startup-level failure — a corrupt repository, a permission
// error, "not a git repository") must NEVER be read as a quiet-miss,
// even with empty stderr, because the pre-fix `ExitCode > 0` check let
// every positive code through.
func TestIsNoCommitsError_ExitCodeShape(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"exit1_emptyStderr_quietMiss", &GitError{ExitCode: 1, Stderr: ""}, true},
		{"exit128_emptyStderr_mustNotPassAsNoCommits", &GitError{ExitCode: 128, Stderr: ""}, false},
		{"exit1_withStderr_realDiagnostic", &GitError{ExitCode: 1, Stderr: "fatal: not a git repository"}, false},
		{"exit2_emptyStderr_otherPositiveCode", &GitError{ExitCode: 2, Stderr: ""}, false},
		{"exitNeg1_signalOrDeadline", &GitError{ExitCode: -1, Stderr: ""}, false},
		{"exit0_success_neverAnErrorButCheckAnyway", &GitError{ExitCode: 0, Stderr: ""}, false},
		{"notAGitError", errors.New("boom"), false},
		{"nilErr", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNoCommitsError(tt.err); got != tt.want {
				t.Errorf("IsNoCommitsError(%+v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestIsNoCommitsError_UnbornRepo pins IsNoCommitsError's real-git
// behaviour end-to-end across the 2026-09-22 review arc (finding #6,
// then S8's rework): a freshly initialized repository with zero commits
// fails `rev-parse --verify --quiet HEAD` SILENTLY — exit 1, empty
// stdout AND stderr, `--quiet`'s own documented contract — which
// IsNoCommitsError's structural (exit-code + empty-stderr) check must
// recognize; a repository WITH a commit must resolve cleanly; a
// genuinely unrelated failure ("not a repository at all") must NOT be
// misclassified, because it prints a non-empty diagnostic even under
// --quiet; and a repository whose `.git/HEAD` has been hand-corrupted
// into a BOGUS symref fails the rev-parse probe the exact SAME silent
// way an unborn repo does — proving IsNoCommitsError alone cannot tell
// the two apart, and pinning the independent symbolic-ref ref-state
// probe (internal/commitscan's resolveHeadSHA second probe) that DOES
// tell them apart: it succeeds for the healthy unborn branch pointer
// and fails for the bogus one.
func TestIsNoCommitsError_UnbornRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	ctx := context.Background()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(cmd.Environ(),
			"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@e.co",
			"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@e.co")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")

	// Case 1: unborn repo — the ONE healthy no-commit state.
	_, _, err := RunReadOnly(ctx, dir, 0, "rev-parse", "--verify", "--quiet", "HEAD")
	if err == nil {
		t.Fatal("rev-parse --verify --quiet HEAD on an unborn repo: want an error")
	}
	if !IsNoCommitsError(err) {
		t.Errorf("IsNoCommitsError(%v) = false, want true for an unborn repo", err)
	}
	var gitErr *GitError
	if !errors.As(err, &gitErr) || gitErr.Stderr != "" {
		t.Errorf("unborn-repo error = %+v (%v), want a *GitError with EMPTY Stderr", err, err)
	}
	// The independent ref-state probe: HEAD must be a symbolic ref
	// pointing at a branch that has no commit yet.
	branchOut, _, symErr := RunReadOnly(ctx, dir, 0, "symbolic-ref", "-q", "HEAD")
	if symErr != nil {
		t.Fatalf("symbolic-ref -q HEAD on an unborn repo: %v, want it to succeed (HEAD is a normal branch pointer)", symErr)
	}
	branch := strings.TrimSpace(string(branchOut))
	if branch == "" {
		t.Fatal("symbolic-ref -q HEAD returned an empty ref")
	}
	_, _, refErr := RunReadOnly(ctx, dir, 0, "show-ref", "--verify", "--quiet", branch)
	if refErr == nil {
		t.Errorf("show-ref --verify --quiet %q: want it to FAIL — the branch has no commit yet", branch)
	}
	// 2026-09-22 review finding 11: show-ref's own --quiet failure
	// contract is the exact same structural shape (exit 1, empty
	// stderr) rev-parse's is — internal/commitscan's second probe reuses
	// IsNoCommitsError for it rather than accepting ANY show-ref error as
	// "no ref yet", so real git must actually produce that shape here.
	if !IsNoCommitsError(refErr) {
		t.Errorf("IsNoCommitsError(%v) = false, want true for show-ref's quiet no-ref miss", refErr)
	}

	// Case 2: a genuinely unrelated failure class (not a repository at
	// all) must NOT be misclassified as "no commits yet" — its stderr is
	// non-empty even under --quiet, since --quiet only silences the
	// revision-resolution diagnostic, not "fatal: not a git repository".
	notARepo := t.TempDir()
	_, _, badErr := RunReadOnly(ctx, notARepo, 0, "rev-parse", "--verify", "--quiet", "HEAD")
	if badErr == nil {
		t.Fatal("rev-parse --verify --quiet HEAD outside any repository: want an error")
	}
	if IsNoCommitsError(badErr) {
		t.Errorf("IsNoCommitsError(%v) = true, want false for a not-a-repository error", badErr)
	}

	// Case 3: a repository whose .git/HEAD has been hand-corrupted into a
	// BOGUS symref (a "ref: " line git cannot resolve to any ref at
	// all — verified live: git reports "fatal: No such ref: HEAD" for
	// this exact shape, as opposed to a well-formed "ref: refs/heads/X"
	// pointing at a not-yet-existent branch, which IS the healthy case 1
	// shape). IsNoCommitsError ALONE cannot tell this apart from case 1
	// — the rev-parse probe fails the exact same silent way (exit 1,
	// empty output) either way — which is precisely why it is only the
	// FIRST of two probes a caller must chain (2026-09-22 review finding
	// S8). The second, independent probe (symbolic-ref) must fail here,
	// where it succeeded in case 1, so a caller chaining both never
	// reports "healthy empty" for a broken repository.
	dangling := t.TempDir()
	if out, err := exec.CommandContext(ctx, "git", "-C", dangling, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	bogusSymref := "ref: refs/heads/main garbage\n"
	if err := os.WriteFile(filepath.Join(dangling, ".git", "HEAD"), []byte(bogusSymref), 0o644); err != nil {
		t.Fatalf("corrupt .git/HEAD: %v", err)
	}
	_, _, danglingErr := RunReadOnly(ctx, dangling, 0, "rev-parse", "--verify", "--quiet", "HEAD")
	if danglingErr == nil {
		t.Fatal("rev-parse --verify --quiet HEAD on a bogus symref HEAD: want an error")
	}
	if !IsNoCommitsError(danglingErr) {
		t.Fatalf("IsNoCommitsError(%v) = false, want true — this is the ambiguous case the second probe must resolve, not the first", danglingErr)
	}
	if _, _, symErr := RunReadOnly(ctx, dangling, 0, "symbolic-ref", "-q", "HEAD"); symErr == nil {
		t.Error("symbolic-ref -q HEAD on a bogus symref HEAD: want an error — it must NOT be read as a healthy unborn branch pointer")
	}

	run("commit", "-q", "--allow-empty", "-m", "first")
	_, _, err = RunReadOnly(ctx, dir, 0, "rev-parse", "--verify", "--quiet", "HEAD")
	if err != nil {
		t.Fatalf("rev-parse --verify --quiet HEAD after a commit: %v", err)
	}
}

// TestGitEnvOverridesAreNetworkFreeAndNonInteractive pins the shared
// envelope's environment: no credential prompt, no askpass helper, stable
// C-locale output. GIT_NO_LAZY_FETCH=1 is NOT in the shared set - forcing
// it breaks the commit scanner's line counts on a blobless partial clone -
// it is added only by RunReadOnlyNoLazyFetch (the skills step, SKILL-2).
func TestGitEnvOverridesAreNetworkFreeAndNonInteractive(t *testing.T) {
	want := []string{"LC_ALL=C", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false"}
	for _, w := range want {
		found := false
		for _, e := range gitEnvOverrides {
			if e == w {
				found = true
			}
		}
		if !found {
			t.Errorf("gitEnvOverrides missing %q: %v", w, gitEnvOverrides)
		}
	}
	for _, e := range gitEnvOverrides {
		if e == noLazyFetchEnv {
			t.Errorf("gitEnvOverrides carries %q; it must stay scoped to RunReadOnlyNoLazyFetch", e)
		}
	}
	if noLazyFetchEnv != "GIT_NO_LAZY_FETCH=1" {
		t.Errorf("noLazyFetchEnv = %q", noLazyFetchEnv)
	}
}

func TestIsMissingObjectError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"not a tree object", &GitError{ExitCode: 128, Stderr: "fatal: not a tree object"}, true},
		{"bad object", &GitError{ExitCode: 128, Stderr: "fatal: bad object deadbeef"}, true},
		{"invalid name", &GitError{ExitCode: 128, Stderr: "fatal: Not a valid object name deadbeef"}, true},
		{"lazy fetch refused", &GitError{ExitCode: 128, Stderr: "fatal: lazy fetching disabled; some objects not available"}, true},
		{"other fatal", &GitError{ExitCode: 128, Stderr: "fatal: not a git repository"}, false},
		{"exit 1", &GitError{ExitCode: 1, Stderr: "bad object"}, false},
		{"timeout", &GitError{ExitCode: -1}, false},
		{"not a GitError", ErrGitUnavailable, false},
	}
	for _, c := range cases {
		if got := IsMissingObjectError(c.err); got != c.want {
			t.Errorf("%s: IsMissingObjectError = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsNotRepoError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"not a repo", &GitError{ExitCode: 128, Stderr: "fatal: not a git repository (or any of the parent directories): .git"}, true},
		{"GIT_DIR variant", &GitError{ExitCode: 128, Stderr: "fatal: not a git repository: '/x/.git'"}, true},
		{"wrapped", fmt.Errorf("commitscan: %w", &GitError{ExitCode: 128, Stderr: "fatal: not a git repository"}), true},
		{"dubious ownership", &GitError{ExitCode: 128, Stderr: "fatal: detected dubious ownership in repository at '/mnt/c/x'"}, false},
		{"missing object", &GitError{ExitCode: 128, Stderr: "fatal: bad object deadbeef"}, false},
		{"exit 1 with the phrase", &GitError{ExitCode: 1, Stderr: "not a git repository"}, false},
		{"quiet miss", &GitError{ExitCode: 1}, false},
		{"timeout", &GitError{ExitCode: -1}, false},
		{"git unavailable", ErrGitUnavailable, false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := IsNotRepoError(c.err); got != c.want {
			t.Errorf("%s: IsNotRepoError = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestIsNotRepoError_RealGit pins the classifier against real git output: a
// plain directory is not-a-repo; an unborn repo's quiet HEAD miss is not.
func TestIsNotRepoError_RealGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	plain := t.TempDir()
	_, _, err := RunReadOnly(ctx, plain, 0, "rev-parse", "--show-prefix")
	if err == nil {
		t.Skipf("%s resolved inside a repository (an enclosing .git?); cannot exercise the not-a-repo path", plain)
	}
	if !IsNotRepoError(err) {
		t.Errorf("IsNotRepoError(%v) = false, want true for a plain directory", err)
	}

	repo := t.TempDir()
	if out, err := exec.CommandContext(ctx, "git", "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	_, _, err = RunReadOnly(ctx, repo, 0, "rev-parse", "--verify", "--quiet", "HEAD")
	if err == nil {
		t.Fatal("rev-parse HEAD on an unborn repo: want an error")
	}
	if IsNotRepoError(err) {
		t.Errorf("IsNotRepoError(%v) = true, want false for an unborn repository", err)
	}
}
