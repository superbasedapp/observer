package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/git"
)

// TestSelectUnpushedSince_NormalRepoHashesUnchangedByF0_14 pins the org
// wire's project hashes (root_path_hash, git_remote_hash, the owner hashes
// and root_commit_hash, sessionPushSelect) for a repository that is not a
// linked worktree. The hex values were computed from the strings the code
// before F0-14 produced, so the linked-worktree fix cannot move any of them
// for an ordinary repository.
func TestSelectUnpushedSince_NormalRepoHashesUnchangedByF0_14(t *testing.T) {
	s, db := newTestStore(t)
	seedPushData(t, s, db)
	ctx := context.Background()

	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(base, "repo")
	for p, body := range map[string]string{
		filepath.Join(repo, ".git", "HEAD"): "ref: refs/heads/main\n",
		filepath.Join(repo, ".git", "config"): "[remote \"origin\"]\n\turl = git@github.com:Example/Repo.git\n" +
			"[remote \"upstream\"]\n\turl = https://github.com/UpstreamOrg/Repo\n",
		filepath.Join(repo, "pkg", "sub", "x.go"): "package sub\n",
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const rootSHA = "0123456789abcdef0123456789abcdef01234567"
	var ranIn string
	id, err := git.ResolveIdentity(filepath.Join(repo, "pkg", "sub"), git.IdentityOptions{
		RootCommit: func(_ context.Context, root string) (string, error) { ranIn = root; return rootSHA, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if id.Root != repo || id.CheckoutRoot != repo || ranIn != repo || id.IsWorktree {
		t.Fatalf("normal repository resolved Root=%q CheckoutRoot=%q rootCommitDir=%q IsWorktree=%v, want %q", id.Root, id.CheckoutRoot, ranIn, id.IsWorktree, repo)
	}
	pid, err := s.UpsertProjectWithIdentity(ctx, id.Root, id.Remote, ProjectIdentity{
		UpstreamRemote: id.UpstreamRemote, RemoteOwner: id.RemoteOwner, UpstreamOwner: id.UpstreamOwner,
		RootCommitSHA: id.RootCommitSHA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET project_id = ? WHERE id = 's1'`, pid); err != nil {
		t.Fatal(err)
	}

	batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@acme.example", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.Sessions) != 1 {
		t.Fatalf("expected 1 session row, got %d", len(batch.Sessions))
	}
	r := batch.Sessions[0]
	rootSum := sha256.Sum256([]byte(repo))
	for name, c := range map[string]struct{ got, want string }{
		"ProjectRootHash":       {r.ProjectRootHash, hex.EncodeToString(rootSum[:])},
		"GitRemoteHash":         {r.GitRemoteHash, "817da3ea1dff4992b238eb1f7263030e5ead9d981d93a8b4bf32c21043899b2b"},
		"GitUpstreamRemoteHash": {r.GitUpstreamRemoteHash, "82fa1a4885cca4765be36c2a2cdff1d33f8df48fbe9bb135574a0d81a448e8c3"},
		"GitRemoteOwnerHash":    {r.GitRemoteOwnerHash, "4d94a3fda99c493c12a91de030e17547136fed55d84011786517957b641e38c5"},
		"GitUpstreamOwnerHash":  {r.GitUpstreamOwnerHash, "ecb21f8819cff813a8cdb6d9f06b03e12fb9d10428ae3392cc4de435f9c69496"},
		"RootCommitHash":        {r.RootCommitHash, "deb87fabd17715bb31ad4cf4ffb9494eeb15f8d33d85b031a301c64ab3417eaa"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", name, c.got, c.want)
		}
	}
	if r.IsWorktree {
		t.Error("IsWorktree = true for a normal repository")
	}
}
