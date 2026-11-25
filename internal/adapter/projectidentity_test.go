package adapter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestApplyProjectIdentity(t *testing.T) {
	t.Parallel()
	res := &ParseResult{
		ToolEvents:  []models.ToolEvent{{ProjectRoot: "/repo"}, {ProjectRoot: "/repo"}},
		TokenEvents: []models.TokenEvent{{ProjectRoot: "/repo"}},
	}
	id := git.Identity{
		UpstreamRemote:     "github.com/acme/repo",
		RemoteOwner:        "github.com/fork-owner",
		UpstreamOwner:      "github.com/acme",
		RootCommitSHA:      "sha1",
		ContentFingerprint: "fp1",
		Workspace:          "services/api",
		IsWorktree:         true,
	}
	ApplyProjectIdentity(res, id)

	for i, ev := range res.ToolEvents {
		if ev.GitUpstreamRemote != id.UpstreamRemote || ev.GitRemoteOwner != id.RemoteOwner ||
			ev.GitUpstreamOwner != id.UpstreamOwner || ev.RootCommitSHA != id.RootCommitSHA ||
			ev.ContentFingerprint != id.ContentFingerprint || ev.Workspace != id.Workspace || !ev.IsWorktree {
			t.Errorf("ToolEvents[%d] not fully stamped: %+v", i, ev)
		}
	}
	tk := res.TokenEvents[0]
	if tk.GitUpstreamRemote != id.UpstreamRemote || tk.Workspace != id.Workspace || !tk.IsWorktree {
		t.Errorf("TokenEvents[0] not fully stamped: %+v", tk)
	}
}

func TestApplyProjectIdentity_ZeroIdentityLeavesEmpty(t *testing.T) {
	t.Parallel()
	res := &ParseResult{ToolEvents: []models.ToolEvent{{ProjectRoot: "/repo"}}}
	ApplyProjectIdentity(res, git.Identity{})
	ev := res.ToolEvents[0]
	if ev.GitUpstreamRemote != "" || ev.Workspace != "" || ev.IsWorktree {
		t.Errorf("zero identity should leave every field empty, got %+v", ev)
	}
}

func TestApplyProjectIdentityByRoot(t *testing.T) {
	t.Parallel()
	res := &ParseResult{
		ToolEvents: []models.ToolEvent{
			{ProjectRoot: "/repoA"},
			{ProjectRoot: "/repoB"},
			{ProjectRoot: "/unknown"},
		},
	}
	ids := map[string]git.Identity{
		"/repoA": {Workspace: "a-ws"},
		"/repoB": {Workspace: "b-ws"},
	}
	ApplyProjectIdentityByRoot(res, ids)

	if res.ToolEvents[0].Workspace != "a-ws" {
		t.Errorf("repoA workspace = %q, want a-ws", res.ToolEvents[0].Workspace)
	}
	if res.ToolEvents[1].Workspace != "b-ws" {
		t.Errorf("repoB workspace = %q, want b-ws", res.ToolEvents[1].Workspace)
	}
	if res.ToolEvents[2].Workspace != "" {
		t.Errorf("unknown root should be left untouched, got %q", res.ToolEvents[2].Workspace)
	}
}

func TestApplyProjectIdentityByRoot_EmptyMapNoOp(t *testing.T) {
	t.Parallel()
	res := &ParseResult{ToolEvents: []models.ToolEvent{{ProjectRoot: "/repo", Workspace: "keep-me"}}}
	ApplyProjectIdentityByRoot(res, nil)
	if res.ToolEvents[0].Workspace != "keep-me" {
		t.Errorf("empty ids map must be a no-op, got %q", res.ToolEvents[0].Workspace)
	}
}

// fakeRepo writes a minimal git layout (HEAD on branch feature, an origin
// remote) under a temp dir and returns its symlink-resolved root and a
// subdirectory inside it.
func fakeRepo(t *testing.T) (root, sub string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gitDir := filepath.Join(dir, ".git")
	sub = filepath.Join(dir, "pkg", "x")
	for _, d := range []string{gitDir, sub} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"HEAD":   "ref: refs/heads/feature\n",
		"config": "[remote \"origin\"]\n\turl = https://github.com/acme/repo.git\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(gitDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, sub
}

func TestResolveProjectRoot(t *testing.T) {
	if r, b, rem, id := ResolveProjectRoot("  \t "); r != "" || b != "" || rem != "" || id != (git.Identity{}) {
		t.Errorf("blank cwd = (%q, %q, %q, %+v), want all empty", r, b, rem, id)
	}
	root, sub := fakeRepo(t)
	r, b, rem, id := ResolveProjectRoot("  " + sub + "  ")
	if r != root || b != "feature" || rem != "github.com/acme/repo" {
		t.Errorf("repo cwd = (%q, %q, %q), want (%q, feature, github.com/acme/repo)", r, b, rem, root)
	}
	if id.Root != root || id.Branch != b || id.Remote != rem {
		t.Errorf("identity %+v does not match the returned root/branch/remote", id)
	}
}

func TestResolveProjectRootCached(t *testing.T) {
	cache := map[string]string{}
	if r, id, fresh := ResolveProjectRootCached(cache, ""); r != "" || fresh || id != (git.Identity{}) || len(cache) != 0 {
		t.Errorf("blank cwd = (%q, %+v, %v), cache %v; want empty and uncached", r, id, fresh, cache)
	}
	root, sub := fakeRepo(t)
	r, id, fresh := ResolveProjectRootCached(cache, sub)
	if r != root || !fresh || id.Root != root || id.Branch != "feature" || id.Remote != "github.com/acme/repo" {
		t.Errorf("first call = (%q, %+v, %v), want (%q, its identity, true)", r, id, fresh, root)
	}
	if len(cache) != 1 {
		t.Errorf("cache = %v, want one entry", cache)
	}
	for _, v := range cache {
		if v != root {
			t.Errorf("cached root = %q, want %q", v, root)
		}
	}
	// A cache hit returns the root but no identity, so callers copy the
	// branch / remote / identity out exactly once.
	r, id, fresh = ResolveProjectRootCached(cache, sub)
	if r != root || fresh || id != (git.Identity{}) {
		t.Errorf("cached call = (%q, %+v, %v), want (%q, zero, false)", r, id, fresh, root)
	}
}
