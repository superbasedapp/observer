package adapter

import (
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
