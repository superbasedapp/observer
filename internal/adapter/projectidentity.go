package adapter

import (
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// projectidentity.go gives every adapter a cheap, uniform way to land the
// Project Identity Resolver v2 signal bundle (docs/plans/project-identity
// -resolver-v2-plan-2026-09-06.md §3.1 / W1) onto a ParseResult, without
// threading six new fields through every per-line event-construction call
// site or handler function signature. Most adapters resolve exactly one
// project identity per ParseSessionFile call (one session file, one cwd);
// those call ApplyProjectIdentity once, right before returning. A handful
// of adapters cache git identity per distinct cwd within a single file
// (claudecode, codex, opencode); those call ApplyProjectIdentityByRoot
// with a root->identity map built from that same cache.

// ApplyProjectIdentity backfills GitUpstreamRemote, GitRemoteOwner,
// GitUpstreamOwner, RootCommitSHA, ContentFingerprint, Workspace and
// IsWorktree onto every event in res from one resolved git.Identity. Safe
// to call with a zero Identity (every field stays/becomes empty — never a
// fabricated value).
func ApplyProjectIdentity(res *ParseResult, id git.Identity) {
	for i := range res.ToolEvents {
		stampToolEventIdentity(&res.ToolEvents[i], id)
	}
	for i := range res.TokenEvents {
		stampTokenEventIdentity(&res.TokenEvents[i], id)
	}
}

// ApplyProjectIdentityByRoot is ApplyProjectIdentity for adapters whose
// events may carry more than one distinct ProjectRoot within a single
// ParseSessionFile call. ids maps a resolved project ROOT to the
// git.Identity computed for the cwd that produced it (last-write-wins
// when two distinct cwds share a root within one file — an accepted
// approximation for the rare monorepo-multi-cwd-same-file case; every
// OTHER identity field is root-scoped and unaffected). An event whose
// ProjectRoot has no entry in ids is left untouched.
func ApplyProjectIdentityByRoot(res *ParseResult, ids map[string]git.Identity) {
	if len(ids) == 0 {
		return
	}
	for i := range res.ToolEvents {
		if id, ok := ids[res.ToolEvents[i].ProjectRoot]; ok {
			stampToolEventIdentity(&res.ToolEvents[i], id)
		}
	}
	for i := range res.TokenEvents {
		if id, ok := ids[res.TokenEvents[i].ProjectRoot]; ok {
			stampTokenEventIdentity(&res.TokenEvents[i], id)
		}
	}
}

func stampToolEventIdentity(ev *models.ToolEvent, id git.Identity) {
	ev.GitUpstreamRemote = id.UpstreamRemote
	ev.GitRemoteOwner = id.RemoteOwner
	ev.GitUpstreamOwner = id.UpstreamOwner
	ev.RootCommitSHA = id.RootCommitSHA
	ev.ContentFingerprint = id.ContentFingerprint
	ev.Workspace = id.Workspace
	ev.IsWorktree = id.IsWorktree
}

func stampTokenEventIdentity(ev *models.TokenEvent, id git.Identity) {
	ev.GitUpstreamRemote = id.UpstreamRemote
	ev.GitRemoteOwner = id.RemoteOwner
	ev.GitUpstreamOwner = id.UpstreamOwner
	ev.RootCommitSHA = id.RootCommitSHA
	ev.ContentFingerprint = id.ContentFingerprint
	ev.Workspace = id.Workspace
	ev.IsWorktree = id.IsWorktree
}
