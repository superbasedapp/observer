package git

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func makeRepo(t *testing.T, dir, branch, remote string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "HEAD"),
		[]byte("ref: refs/heads/"+branch+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := `[core]
	repositoryformatversion = 0
[remote "origin"]
	url = ` + remote + `
	fetch = +refs/heads/*:refs/remotes/origin/*
`
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolveGitRepo(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	makeRepo(t, dir, "main", "git@github.com:example/repo.git")

	sub := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	info, err := Resolve(sub)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !info.IsGit {
		t.Fatal("expected IsGit = true")
	}
	gotRoot, _ := filepath.EvalSymlinks(info.Root)
	wantRoot, _ := filepath.EvalSymlinks(dir)
	if gotRoot != wantRoot {
		t.Errorf("Root: got %q want %q", gotRoot, wantRoot)
	}
	if info.Branch != "main" {
		t.Errorf("Branch: got %q want main", info.Branch)
	}
	if info.Remote != "git@github.com:example/repo.git" {
		t.Errorf("Remote: got %q", info.Remote)
	}
}

func TestResolveNonGit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	info, err := Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.IsGit {
		t.Error("expected IsGit = false for non-git dir")
	}
	if info.Root == "" {
		t.Error("Root should fall back to input dir")
	}
}

func TestResolveDetachedHEAD(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "HEAD"),
		[]byte("abcdef1234567890\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !info.IsGit {
		t.Error("expected IsGit = true")
	}
	if info.Branch != "" {
		t.Errorf("detached HEAD should yield empty branch, got %q", info.Branch)
	}
}

func TestRelativePath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	makeRepo(t, dir, "main", "")

	if err := os.MkdirAll(filepath.Join(dir, "cmd"), 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(dir, "cmd", "main.go")
	if err := os.WriteFile(inside, []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := RelativePath(dir, inside); got != "cmd/main.go" {
		t.Errorf("inside: got %q want cmd/main.go", got)
	}

	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "foo.txt")
	if err := os.WriteFile(outsideFile, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	rel := RelativePath(dir, outsideFile)
	if !strings.HasPrefix(rel, "[external]/") {
		t.Errorf("outside: expected [external]/ prefix, got %q", rel)
	}
}

func TestFindRootWalksUp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	makeRepo(t, dir, "main", "")
	deep := filepath.Join(dir, "x", "y", "z")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	root, ok := FindRoot(deep)
	if !ok {
		t.Fatal("FindRoot returned false for deep subdir")
	}
	got, _ := filepath.EvalSymlinks(root)
	want, _ := filepath.EvalSymlinks(dir)
	if got != want {
		t.Errorf("FindRoot: got %q want %q", got, want)
	}
}

// TestReadGitFileDirHostFlavor pins the linked-worktree pointer read: a
// Git-for-Windows pointer (`gitdir: D:/repo/...`) read on a POSIX host is
// translated to the host flavor, so the main-repo root derived from it is
// a usable path rather than `D:/repo` (live 2026-10-22: every Windows
// worktree session's transcript actions landed on a `D:/...` project).
// Merged onto the F0-14 reader (readGitFileDir); the traversal and
// relative-pointer rules are resolveGitPointer's and are pinned there.
func TestReadGitFileDirHostFlavor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, body, want string
		ok               bool
	}{
		{"posix pointer", "gitdir: /home/u/repo/.git/worktrees/wt\n", "/home/u/repo/.git/worktrees/wt", true},
		{"relative pointer kept relative", "gitdir: ../repo/.git/worktrees/wt\n", "../repo/.git/worktrees/wt", true},
		{"empty rejected", "gitdir:\n", "", false},
		{"no gitdir line", "something else\n", "", false},
	}
	if runtime.GOOS != "windows" {
		tests = append(tests, struct {
			name, body, want string
			ok               bool
		}{"windows pointer", "gitdir: D:/repo/.git/worktrees/wt\n", "/mnt/d/repo/.git/worktrees/wt", true})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), ".git")
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, ok := readGitFileDir(p)
			if got != tc.want || ok != tc.ok {
				t.Errorf("readGitFileDir = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestHasLinkedWorktreesNeverResolvesAgainstTheWorkingDirectory (audit row 8,
// FU-193): a stored project root that is not rooted on this host is never
// joined against the daemon's working directory, even when the working
// directory holds a folder of that name with a linked-worktree admin dir.
func TestHasLinkedWorktreesNeverResolvesAgainstTheWorkingDirectory(t *testing.T) {
	const unknown = "Xcode (project unknown)"
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, unknown, ".git", "worktrees"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	if HasLinkedWorktrees(unknown) {
		t.Error("HasLinkedWorktrees resolved a relative root against the working directory")
	}
	if !HasLinkedWorktrees(filepath.Join(cwd, unknown)) {
		t.Error("an absolute root with linked worktrees is not reported")
	}
	for p, want := range map[string]bool{unknown: false, "rel/dir": false, "": false, filepath.Join(cwd, "x"): true} {
		if got := HostRooted(p); got != want {
			t.Errorf("HostRooted(%q) = %v, want %v", p, got, want)
		}
	}
}
