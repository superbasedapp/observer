package adapter

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
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

// ResolveProjectRoot resolves a session's raw cwd to its project root,
// git branch, normalized git remote and full git identity, for adapters
// that resolve one cwd per session without a cache (droid, kirocli). The
// cwd is trimmed; a blank one yields ("", "", "", zero identity). A cwd
// outside any git repository (or one git cannot read) yields the
// translated cwd itself as the root and an empty branch, remote and
// identity.
//
// The foreign-path translation is UNCONDITIONAL: a foreign-OS cwd (a
// Windows `C:\...` path read by a WSL2 observer over /mnt/c, or a
// \\wsl.localhost path read by a Windows observer) is mapped to its
// locally visible equivalent by crossmount.TranslateForeignPath BEFORE
// git sees it. A drive-letter string reaching git would be treated as
// relative by filepath.Abs, get the observer's OWN cwd prefixed onto it,
// and misfile the session under the observer's own repository
// ([[feedback-foreign-path-git-resolve]]).
func ResolveProjectRoot(rawCWD string) (root, branch, remote string, id git.Identity) {
	cwd := strings.TrimSpace(rawCWD)
	if cwd == "" {
		return "", "", "", git.Identity{}
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	identity, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		return cwd, "", "", git.Identity{}
	}
	// identity.Remote is already NormalizeRemote'd by ResolveIdentity.
	return identity.Root, identity.Branch, identity.Remote, identity
}

// ResolveProjectRootCached resolves cwd to its project root with the same
// unconditional foreign-path translation as ResolveProjectRoot (but no
// trimming), memoized in cache keyed by the translated cwd, for adapters
// that resolve per parse (commandcode, codebuddy, muse, junie). A cwd git
// cannot resolve is cached as its own root.
//
// fresh is true only on the call that first resolves a translated cwd
// successfully; only that call returns a non-zero id, so the caller
// copies branch, remote and identity out of it exactly once. A blank cwd
// returns ("", zero, false), and a cache hit or an unresolvable cwd
// returns the root with a zero id and false.
func ResolveProjectRootCached(cache map[string]string, cwd string) (root string, id git.Identity, fresh bool) {
	if cwd == "" {
		return "", git.Identity{}, false
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	if root, ok := cache[cwd]; ok {
		return root, git.Identity{}, false
	}
	id, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		cache[cwd] = cwd
		return cwd, git.Identity{}, false
	}
	cache[cwd] = id.Root
	// id.Remote is already NormalizeRemote'd by ResolveIdentity.
	return id.Root, id, true
}

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
