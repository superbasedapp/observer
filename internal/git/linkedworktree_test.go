package git

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// realPath resolves symlinks so a temp dir under a symlinked /tmp (macOS)
// compares equal to what the resolvers return.
func realPath(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// mainWithRemotes is initRepo plus an origin and an upstream remote.
func mainWithRemotes(t *testing.T) string {
	t.Helper()
	repo := initRepo(t)
	runOrFail(t, repo, "remote", "add", "origin", "git@github.com:Acme/Widget.git")
	runOrFail(t, repo, "remote", "add", "upstream", "https://github.com/UpstreamCo/Widget")
	return repo
}

// wantResolved asserts all three resolvers agree on root and checkout.
func wantResolved(t *testing.T, dir, wantRoot, wantCheckout string, wantWorktree bool) Identity {
	t.Helper()
	info, err := Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve(%s): %v", dir, err)
	}
	id, err := ResolveIdentity(dir, IdentityOptions{RootCommit: DefaultRootCommit})
	if err != nil {
		t.Fatalf("ResolveIdentity(%s): %v", dir, err)
	}
	root, ok := FindRoot(dir)
	checkout, cok := FindCheckoutRoot(dir)
	if !ok || !cok || !info.IsGit || !id.IsGit {
		t.Fatalf("%s: not resolved as git (FindRoot ok=%v FindCheckoutRoot ok=%v)", dir, ok, cok)
	}
	for name, got := range map[string]string{
		"Resolve.Root": info.Root, "ResolveIdentity.Root": id.Root, "FindRoot": root,
	} {
		if got != wantRoot {
			t.Errorf("%s: %s = %q, want %q", dir, name, got, wantRoot)
		}
	}
	for name, got := range map[string]string{
		"Resolve.CheckoutRoot": info.CheckoutRoot, "ResolveIdentity.CheckoutRoot": id.CheckoutRoot, "FindCheckoutRoot": checkout,
	} {
		if got != wantCheckout {
			t.Errorf("%s: %s = %q, want %q", dir, name, got, wantCheckout)
		}
	}
	if id.IsWorktree != wantWorktree {
		t.Errorf("%s: IsWorktree = %v, want %v", dir, id.IsWorktree, wantWorktree)
	}
	if info.Branch != id.Branch {
		t.Errorf("%s: Resolve.Branch %q != ResolveIdentity.Branch %q", dir, info.Branch, id.Branch)
	}
	return id
}

func TestLinkedWorktree_MatchesMainProject(t *testing.T) {
	ctx := context.Background()
	repo := mainWithRemotes(t)
	mainRoot := realPath(t, repo)
	mainID := wantResolved(t, repo, mainRoot, mainRoot, false)

	wt := filepath.Join(t.TempDir(), "wt")
	if err := WorktreeAdd(ctx, repo, wt, "feature/wt", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd: %v", err)
	}
	wtReal := realPath(t, wt)
	id := wantResolved(t, wt, mainRoot, wtReal, true)

	if id.Branch != "feature/wt" {
		t.Errorf("worktree Branch = %q, want its own branch feature/wt", id.Branch)
	}
	if mainID.Branch != "main" {
		t.Errorf("main Branch = %q, want main", mainID.Branch)
	}
	if id.Remote != "github.com/Acme/Widget" || id.Remote != mainID.Remote {
		t.Errorf("worktree Remote = %q, main %q, want github.com/Acme/Widget for both", id.Remote, mainID.Remote)
	}
	if id.UpstreamRemote != mainID.UpstreamRemote || id.UpstreamRemote == "" {
		t.Errorf("worktree UpstreamRemote = %q, main %q", id.UpstreamRemote, mainID.UpstreamRemote)
	}
	if id.RemoteOwner != mainID.RemoteOwner || id.UpstreamOwner != mainID.UpstreamOwner || id.RemoteOwner == "" {
		t.Errorf("owners differ: worktree %q/%q, main %q/%q", id.RemoteOwner, id.UpstreamOwner, mainID.RemoteOwner, mainID.UpstreamOwner)
	}
	if id.RootCommitSHA == "" || id.RootCommitSHA != mainID.RootCommitSHA {
		t.Errorf("worktree RootCommitSHA = %q, main %q, want equal and set", id.RootCommitSHA, mainID.RootCommitSHA)
	}
	if id.ContentFingerprint != mainID.ContentFingerprint {
		t.Errorf("worktree ContentFingerprint = %q, want the main project's %q", id.ContentFingerprint, mainID.ContentFingerprint)
	}
	// Resolve keeps its raw origin URL in a worktree too.
	info, _ := Resolve(wt)
	if info.Remote != "git@github.com:Acme/Widget.git" {
		t.Errorf("Resolve.Remote in worktree = %q, want the raw origin URL", info.Remote)
	}
}

func TestLinkedWorktree_NestedDirectory(t *testing.T) {
	ctx := context.Background()
	repo := mainWithRemotes(t)
	mainRoot := realPath(t, repo)

	wt := filepath.Join(t.TempDir(), "wt")
	if err := WorktreeAdd(ctx, repo, wt, "nested/wt", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd: %v", err)
	}
	svc := filepath.Join(wt, "services", "api")
	deep := filepath.Join(svc, "handlers")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(svc, "go.mod"), []byte("module example.com/api\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := wantResolved(t, deep, mainRoot, realPath(t, wt), true)
	if id.Workspace != "services/api" {
		t.Errorf("Workspace = %q, want services/api (relative to the worktree checkout)", id.Workspace)
	}

	// A worktree inside the main checkout is found before the main .git.
	inTree := filepath.Join(repo, ".worktrees", "x")
	if err := WorktreeAdd(ctx, repo, inTree, "nested/intree", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd in-tree: %v", err)
	}
	sub := filepath.Join(inTree, "pkg")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	wantResolved(t, sub, mainRoot, realPath(t, inTree), true)
}

func TestLinkedWorktree_BareCommonDir(t *testing.T) {
	ctx := context.Background()
	src := initRepo(t)
	base := t.TempDir()
	bare := filepath.Join(base, "widget.git")
	runOrFail(t, base, "clone", "--bare", src, bare)
	runOrFail(t, bare, "config", "remote.origin.url", "https://github.com/acme/widget.git")
	wt := filepath.Join(base, "wtb")
	if err := WorktreeAdd(ctx, bare, wt, "bare/wt", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd from bare: %v", err)
	}
	wtReal := realPath(t, wt)
	// A bare common dir has no main top level: the project is the checkout.
	id := wantResolved(t, wt, wtReal, wtReal, true)
	if id.Branch != "bare/wt" {
		t.Errorf("Branch = %q, want bare/wt", id.Branch)
	}
	if id.Remote != "github.com/acme/widget" {
		t.Errorf("Remote = %q, want the bare repository's origin", id.Remote)
	}
	if id.RootCommitSHA == "" {
		t.Error("RootCommitSHA should resolve in the checkout of a bare repository's worktree")
	}
}

func TestLinkedWorktree_SeparateGitDirMain(t *testing.T) {
	ctx := context.Background()
	gitAvailable(t)
	base := t.TempDir()
	checkout := filepath.Join(base, "main2")
	sep := filepath.Join(base, "sep.git")
	runOrFail(t, base, "init", "--separate-git-dir", sep, checkout)
	runOrFail(t, checkout, "checkout", "-b", "main")
	if err := os.WriteFile(filepath.Join(checkout, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	runOrFail(t, checkout, "add", "-A")
	runOrFail(t, checkout, "commit", "-m", "init")
	checkoutReal := realPath(t, checkout)

	// The main checkout itself: a `.git` file that is not a linked
	// worktree resolves to its own directory (before F0-14 it resolved to
	// the separate git dir's parent and claimed to be a worktree).
	sepID := wantResolved(t, checkout, checkoutReal, checkoutReal, false)
	if sepID.Branch != "" || sepID.Remote != "" {
		t.Errorf("separate-git-dir checkout reads no branch or remote (as before), got %q %q", sepID.Branch, sepID.Remote)
	}

	// Its linked worktree is one in git's layout, but the common dir names
	// no top level, so the project is the worktree's checkout.
	wt := filepath.Join(base, "wt")
	if err := WorktreeAdd(ctx, checkout, wt, "sep/wt", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd: %v", err)
	}
	wtReal := realPath(t, wt)
	id := wantResolved(t, wt, wtReal, wtReal, true)
	if id.Branch != "sep/wt" {
		t.Errorf("Branch = %q, want sep/wt", id.Branch)
	}
}

func TestLinkedWorktree_Submodule(t *testing.T) {
	gitAvailable(t)
	child := initRepo(t)
	parent := initRepo(t)
	runOrFail(t, parent, "-c", "protocol.file.allow=always", "submodule", "add", child, "sub")
	sub := filepath.Join(parent, "sub")
	if fi, err := os.Stat(filepath.Join(sub, ".git")); err != nil || fi.IsDir() {
		t.Fatalf("expected a submodule .git file: %v", err)
	}
	subReal := realPath(t, sub)
	wantResolved(t, sub, subReal, subReal, false)

	// The same submodule with an absolute gitdir (older git wrote these):
	// before F0-14 it resolved to `<parent>/.git/modules` as a worktree.
	modules := realPath(t, filepath.Join(parent, ".git", "modules", "sub"))
	if err := os.WriteFile(filepath.Join(sub, ".git"), []byte("gitdir: "+filepath.ToSlash(modules)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantResolved(t, sub, subReal, subReal, false)
}

func TestLinkedWorktree_PlantedGitFile(t *testing.T) {
	ctx := context.Background()
	repo := mainWithRemotes(t)
	wt := filepath.Join(t.TempDir(), "wt")
	if err := WorktreeAdd(ctx, repo, wt, "planted/real", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(wt, ".git"))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		// A copy of a real worktree's pointer: the worktree's own back
		// pointer names the real checkout, not this one.
		"copied_real_pointer": string(body),
		"missing_gitdir":      "gitdir: " + filepath.ToSlash(filepath.Join(t.TempDir(), "nope", "worktrees", "x")) + "\n",
		"plain_directory":     "gitdir: " + filepath.ToSlash(t.TempDir()) + "\n",
		// filepath.Join would clean the `..` away, so spell it out.
		"dotdot":         "gitdir: " + filepath.ToSlash(realPath(t, repo)) + "/.git/worktrees/../worktrees/wt\n",
		"relative":       "gitdir: .git/worktrees/wt\n",
		"no_gitdir_line": "not a pointer\n",
	}
	if runtime.GOOS != "windows" {
		// A Windows drive-letter gitdir read on another OS is not absolute.
		cases["drive_letter_on_unix"] = "gitdir: C:/Users/dev/widget/.git/worktrees/wt\n"
	} else {
		cases["drive_letter_missing"] = "gitdir: C:/no/such/dir/.git/worktrees/wt\n"
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".git"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			nested := filepath.Join(dir, "a")
			if err := os.MkdirAll(nested, 0o755); err != nil {
				t.Fatal(err)
			}
			dirReal := realPath(t, dir)
			id := wantResolved(t, nested, dirReal, dirReal, false)
			if id.Branch != "" || id.Remote != "" || id.UpstreamRemote != "" {
				t.Errorf("a planted .git file must not redirect branch or remote reads, got %q %q %q", id.Branch, id.Remote, id.UpstreamRemote)
			}
		})
	}
}

// TestLinkedWorktree_ForwardSlashGitdir: git writes gitdir with forward
// slashes on every OS (a `C:/...` string on Windows); the layout checks
// compare files, not spellings.
func TestLinkedWorktree_ForwardSlashGitdir(t *testing.T) {
	ctx := context.Background()
	repo := mainWithRemotes(t)
	wt := filepath.Join(t.TempDir(), "wt")
	if err := WorktreeAdd(ctx, repo, wt, "slash/wt", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd: %v", err)
	}
	adminDir := realPath(t, filepath.Join(repo, ".git", "worktrees", "wt"))
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+filepath.ToSlash(adminDir)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantResolved(t, wt, realPath(t, repo), realPath(t, wt), true)
}

func TestLegacyWorktreeRootTarget(t *testing.T) {
	repo := realPath(t, initRepo(t))
	plain := realPath(t, t.TempDir())
	cases := []struct {
		name, root, want string
		shape, ok        bool
	}{
		{"main repository", repo + "/.git/worktrees", repo, true, true},
		{"backslash spelling", repo + `\.git\worktrees`, repo, true, true},
		{"not a repository", plain + "/.git/worktrees", "", true, false},
		{"gone", "/no/such/repo/.git/worktrees", "", true, false},
		{"relative", "repo/.git/worktrees", "", true, false},
		{"bare suffix", repo + "/widget.git/worktrees", "", false, false},
		{"a normal root", repo, "", false, false},
		{"suffix only", "/.git/worktrees", "", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsLegacyWorktreeRoot(c.root); got != c.shape {
				t.Errorf("IsLegacyWorktreeRoot(%q) = %v, want %v", c.root, got, c.shape)
			}
			got, ok := LegacyWorktreeRootTarget(c.root)
			if ok != c.ok || (ok && got != c.want) {
				t.Errorf("LegacyWorktreeRootTarget(%q) = %q, %v; want %q, %v", c.root, got, ok, c.want, c.ok)
			}
		})
	}
}
