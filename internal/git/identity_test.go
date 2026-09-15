package git

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// appendRemote writes an additional `[remote "<name>"]` section to an
// already-created repo's .git/config (on top of makeRepo's origin
// section), so tests can exercise the all-remotes / upstream-pick logic.
func appendRemote(t *testing.T, dir, name, url string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("[remote \"" + name + "\"]\n\turl = " + url + "\n"); err != nil {
		t.Fatal(err)
	}
}

func TestResolveIdentity_NonGit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id, err := ResolveIdentity(dir, IdentityOptions{})
	if err != nil {
		t.Fatalf("ResolveIdentity: %v", err)
	}
	if id.IsGit {
		t.Error("expected IsGit = false")
	}
	if id.Root == "" {
		t.Error("Root should fall back to input dir")
	}
	if id.UpstreamRemote != "" || id.RemoteOwner != "" || id.UpstreamOwner != "" {
		t.Errorf("non-git dir should have empty remote signals, got %+v", id)
	}
	if id.Workspace != "" {
		t.Errorf("non-git dir should have empty workspace, got %q", id.Workspace)
	}
	if id.IsWorktree {
		t.Error("non-git dir must not be a worktree")
	}
	// An empty directory has nothing to fingerprint.
	if id.ContentFingerprint != "" {
		t.Errorf("empty dir should have empty fingerprint, got %q", id.ContentFingerprint)
	}
}

func TestResolveIdentity_RemoteNormalizedUnlikeResolve(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	raw := "git@github.com:Org/Repo.git"
	makeRepo(t, dir, "main", raw)

	info, err := Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.Remote != raw {
		t.Fatalf("Resolve should stay raw, got %q", info.Remote)
	}

	id, err := ResolveIdentity(dir, IdentityOptions{})
	if err != nil {
		t.Fatalf("ResolveIdentity: %v", err)
	}
	want := NormalizeRemote(raw)
	if id.Remote != want {
		t.Errorf("ResolveIdentity.Remote = %q, want normalized %q", id.Remote, want)
	}
}

func TestResolveIdentity_UpstreamPick(t *testing.T) {
	t.Parallel()

	t.Run("no_extra_remotes", func(t *testing.T) {
		dir := t.TempDir()
		makeRepo(t, dir, "main", "git@github.com:origin-org/repo.git")
		id, err := ResolveIdentity(dir, IdentityOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if id.UpstreamRemote != "" {
			t.Errorf("UpstreamRemote = %q, want empty", id.UpstreamRemote)
		}
	})

	t.Run("named_upstream_wins_over_file_order", func(t *testing.T) {
		dir := t.TempDir()
		makeRepo(t, dir, "main", "git@github.com:fork-org/repo.git")
		// File order: "somefork" appears before "upstream", but the
		// literal name "upstream" must still win.
		appendRemote(t, dir, "somefork", "git@github.com:other-org/repo.git")
		appendRemote(t, dir, "upstream", "git@github.com:acme/repo.git")
		id, err := ResolveIdentity(dir, IdentityOptions{})
		if err != nil {
			t.Fatal(err)
		}
		want := NormalizeRemote("git@github.com:acme/repo.git")
		if id.UpstreamRemote != want {
			t.Errorf("UpstreamRemote = %q, want %q", id.UpstreamRemote, want)
		}
	})

	t.Run("no_upstream_named_first_non_origin_wins", func(t *testing.T) {
		dir := t.TempDir()
		makeRepo(t, dir, "main", "git@github.com:fork-org/repo.git")
		appendRemote(t, dir, "acme-fork", "git@github.com:acme/repo.git")
		appendRemote(t, dir, "another", "git@github.com:someone-else/repo.git")
		id, err := ResolveIdentity(dir, IdentityOptions{})
		if err != nil {
			t.Fatal(err)
		}
		want := NormalizeRemote("git@github.com:acme/repo.git")
		if id.UpstreamRemote != want {
			t.Errorf("UpstreamRemote = %q, want %q (first non-origin in file order)", id.UpstreamRemote, want)
		}
	})
}

func TestOwnerOf(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"two_segments", "github.com/acme/repo", "github.com/acme"},
		{"exactly_two_segments", "github.com/acme", "github.com/acme"},
		{"non_default_port_stays_in_host", "gitlab.example.com:8443/acme/repo", "gitlab.example.com:8443/acme"},
		{"single_segment_underivable", "github.com", ""},
		{"empty_input", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := OwnerOf(c.in); got != c.want {
				t.Errorf("OwnerOf(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestWorkspaceManifestsAllowList(t *testing.T) {
	t.Parallel()
	want := []string{
		"package.json",
		"go.mod",
		"Cargo.toml",
		"pyproject.toml",
		"pom.xml",
		"build.gradle",
		"build.gradle.kts",
		"composer.json",
		"Gemfile",
		"pubspec.yaml",
		"BUILD.bazel",
		"project.json",
	}
	if len(WorkspaceManifests) != len(want) {
		t.Fatalf("WorkspaceManifests has %d entries, want %d: %v", len(WorkspaceManifests), len(want), WorkspaceManifests)
	}
	for i, w := range want {
		if WorkspaceManifests[i] != w {
			t.Errorf("WorkspaceManifests[%d] = %q, want %q", i, WorkspaceManifests[i], w)
		}
	}
}

func TestResolveIdentity_Workspace(t *testing.T) {
	t.Parallel()

	t.Run("cwd_at_root_is_empty", func(t *testing.T) {
		dir := t.TempDir()
		makeRepo(t, dir, "main", "")
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module root\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		id, err := ResolveIdentity(dir, IdentityOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if id.Workspace != "" {
			t.Errorf("Workspace at repo root = %q, want empty", id.Workspace)
		}
	})

	t.Run("nearest_manifest_wins", func(t *testing.T) {
		dir := t.TempDir()
		makeRepo(t, dir, "main", "")
		// Monorepo: root has no manifest; platform/services/payments has
		// one. cwd deep inside payments (no manifest there) should climb
		// up to the nearest ancestor manifest.
		payments := filepath.Join(dir, "platform", "services", "payments")
		if err := os.MkdirAll(payments, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(payments, "package.json"), []byte(`{"name":"payments"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		deep := filepath.Join(payments, "src", "handlers")
		if err := os.MkdirAll(deep, 0o755); err != nil {
			t.Fatal(err)
		}
		id, err := ResolveIdentity(deep, IdentityOptions{})
		if err != nil {
			t.Fatal(err)
		}
		want := "platform/services/payments"
		if id.Workspace != want {
			t.Errorf("Workspace = %q, want %q", id.Workspace, want)
		}
	})

	t.Run("outside_root_is_empty", func(t *testing.T) {
		dir := t.TempDir()
		makeRepo(t, dir, "main", "")
		outside := t.TempDir()
		id, err := ResolveIdentity(dir, IdentityOptions{})
		if err != nil {
			t.Fatal(err)
		}
		// Sanity: resolveWorkspace directly, since ResolveIdentity always
		// derives root from dir itself (dir is always "inside" its own
		// resolved root by construction). Exercise the helper with a
		// mismatched pair to pin the outside-root branch.
		if got := resolveWorkspace(id.Root, outside); got != "" {
			t.Errorf("resolveWorkspace(root, outside) = %q, want empty", got)
		}
	})
}

func TestResolveIdentity_Worktree(t *testing.T) {
	gitAvailable(t)
	ctx := context.Background()
	repo := initRepo(t)

	mainID, err := ResolveIdentity(repo, IdentityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if mainID.IsWorktree {
		t.Error("main repo checkout must not report IsWorktree")
	}

	wtPath := filepath.Join(t.TempDir(), "wt")
	if err := WorktreeAdd(ctx, repo, wtPath, "identity/wt1", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd: %v", err)
	}
	wtID, err := ResolveIdentity(wtPath, IdentityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !wtID.IsWorktree {
		t.Error("linked worktree must report IsWorktree = true")
	}
	// NOTE: findGitRoot's worktree root resolution has a known,
	// pre-existing defect (a linked worktree's ".git" file's "gitdir:"
	// value points at the main repo's PER-WORKTREE admin dir —
	// "<main>/.git/worktrees/<name>" — and filepath.Dir of that strips
	// only the "<name>" segment, landing on ".../worktrees" rather than
	// the main repo root). See internal/workspace's documented "blocked
	// on a pre-existing worktree-attribution bug" note. Resolve's public
	// behaviour must stay byte-identical (this task's hard rule), so
	// ResolveIdentity inherits the same Root value — only the new
	// IsWorktree bit is asserted precisely here; fixing Root resolution
	// is out of W1's scope.
	if wtID.Root == "" {
		t.Error("worktree Root must not be empty")
	}
}

func TestResolveIdentity_ContentFingerprint(t *testing.T) {
	t.Parallel()

	t.Run("empty_dir_is_empty", func(t *testing.T) {
		dir := t.TempDir()
		id, err := ResolveIdentity(dir, IdentityOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if id.ContentFingerprint != "" {
			t.Errorf("empty dir fingerprint = %q, want empty", id.ContentFingerprint)
		}
	})

	t.Run("deterministic_and_excludes_noise_dirs", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/foo\n\ngo 1.22\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, d := range []string{"cmd", "internal", "node_modules", ".git", "vendor"} {
			if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		id1, err := ResolveIdentity(dir, IdentityOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if id1.ContentFingerprint == "" {
			t.Fatal("expected a non-empty fingerprint")
		}
		id2, err := ResolveIdentity(dir, IdentityOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if id1.ContentFingerprint != id2.ContentFingerprint {
			t.Errorf("fingerprint not deterministic: %q vs %q", id1.ContentFingerprint, id2.ContentFingerprint)
		}

		// A directory whose only difference is an excluded noise dir
		// (node_modules/vendor/.git) must fingerprint identically.
		dir2 := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir2, "go.mod"), []byte("module example.com/foo\n\ngo 1.22\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, d := range []string{"cmd", "internal"} {
			if err := os.MkdirAll(filepath.Join(dir2, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		id3, err := ResolveIdentity(dir2, IdentityOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if id1.ContentFingerprint != id3.ContentFingerprint {
			t.Errorf("noise directories should not affect the fingerprint: %q vs %q", id1.ContentFingerprint, id3.ContentFingerprint)
		}

		// A genuinely different module name must fingerprint differently.
		dir4 := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir4, "go.mod"), []byte("module example.com/bar\n\ngo 1.22\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir4, "cmd"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir4, "internal"), 0o755); err != nil {
			t.Fatal(err)
		}
		id4, err := ResolveIdentity(dir4, IdentityOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if id1.ContentFingerprint == id4.ContentFingerprint {
			t.Error("different module names must not collide")
		}
	})

	t.Run("skip_option_leaves_it_empty", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/foo\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		id, err := ResolveIdentity(dir, IdentityOptions{SkipContentFingerprint: true})
		if err != nil {
			t.Fatal(err)
		}
		if id.ContentFingerprint != "" {
			t.Errorf("SkipContentFingerprint should leave it empty, got %q", id.ContentFingerprint)
		}
	})
}

func TestResolveIdentity_RootCommitOption(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	makeRepo(t, dir, "main", "")

	t.Run("nil_resolver_leaves_empty", func(t *testing.T) {
		id, err := ResolveIdentity(dir, IdentityOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if id.RootCommitSHA != "" {
			t.Errorf("nil RootCommit option should leave RootCommitSHA empty, got %q", id.RootCommitSHA)
		}
	})

	t.Run("resolver_result_is_used", func(t *testing.T) {
		id, err := ResolveIdentity(dir, IdentityOptions{
			RootCommit: func(ctx context.Context, repoRoot string) (string, error) {
				return "deadbeef", nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if id.RootCommitSHA != "deadbeef" {
			t.Errorf("RootCommitSHA = %q, want %q", id.RootCommitSHA, "deadbeef")
		}
	})

	t.Run("resolver_error_leaves_empty", func(t *testing.T) {
		id, err := ResolveIdentity(dir, IdentityOptions{
			RootCommit: func(ctx context.Context, repoRoot string) (string, error) {
				return "", errors.New("boom")
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if id.RootCommitSHA != "" {
			t.Errorf("errored resolver should leave RootCommitSHA empty, got %q", id.RootCommitSHA)
		}
	})

	t.Run("non_git_dir_never_calls_resolver", func(t *testing.T) {
		nonGit := t.TempDir()
		called := false
		_, err := ResolveIdentity(nonGit, IdentityOptions{
			RootCommit: func(ctx context.Context, repoRoot string) (string, error) {
				called = true
				return "x", nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if called {
			t.Error("RootCommit must not be invoked for a non-git directory")
		}
	})
}

func TestDefaultRootCommit_SingleRoot(t *testing.T) {
	repo := initRepo(t)
	ctx := context.Background()

	head, err := HeadSHA(ctx, repo)
	if err != nil {
		t.Fatalf("HeadSHA: %v", err)
	}
	got, err := DefaultRootCommit(ctx, repo)
	if err != nil {
		t.Fatalf("DefaultRootCommit: %v", err)
	}
	if got != head {
		t.Errorf("single-commit repo: root commit = %q, want HEAD %q", got, head)
	}
}

func TestDefaultRootCommit_MultipleRootsPicksSmallest(t *testing.T) {
	gitAvailable(t)
	repo := initRepo(t)
	ctx := context.Background()

	first, err := HeadSHA(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	// Create a second, unrelated root commit on an orphan branch, then
	// merge the two histories with --allow-unrelated-histories so the
	// repo ends up with two root commits.
	runOrFail(t, repo, "checkout", "--orphan", "second-root")
	runOrFail(t, repo, "rm", "-rf", "--cached", ".")
	if err := os.WriteFile(filepath.Join(repo, "second.txt"), []byte("second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runOrFail(t, repo, "add", "-A")
	runOrFail(t, repo, "commit", "-m", "second root")
	second, err := HeadSHA(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	runOrFail(t, repo, "checkout", "main")
	runOrFail(t, repo, "merge", "--allow-unrelated-histories", "-m", "merge", "second-root")

	got, err := DefaultRootCommit(ctx, repo)
	if err != nil {
		t.Fatalf("DefaultRootCommit: %v", err)
	}
	want := first
	if second < first {
		want = second
	}
	if got != want {
		t.Errorf("DefaultRootCommit = %q, want lexicographically smallest of {%q, %q} = %q", got, first, second, want)
	}
}

func TestDefaultRootCommit_NonGitDir(t *testing.T) {
	gitAvailable(t)
	dir := t.TempDir()
	got, err := DefaultRootCommit(context.Background(), dir)
	if err == nil {
		t.Fatalf("expected an error for a non-git dir, got sha %q", got)
	}
	if got != "" {
		t.Errorf("expected empty sha on error, got %q", got)
	}
}

func TestDefaultRootCommit_AlreadyCanceledContext(t *testing.T) {
	gitAvailable(t)
	repo := initRepo(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := DefaultRootCommit(ctx, repo)
	if err == nil {
		t.Fatalf("expected an error for an already-canceled context, got sha %q", got)
	}
	if got != "" {
		t.Errorf("expected empty sha on error, got %q", got)
	}
}

func runOrFail(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(
		os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

// DefaultRootCommit's 2s budget is not itself pinned by a timing-sensitive
// test: a real timeout would make the suite slow and flaky under load. The
// already-canceled-context case above exercises the same code path
// deterministically.
