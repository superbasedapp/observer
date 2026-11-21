package store

import (
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// ingestroot.go: the project-root resolution seam for capture paths that
// hand Ingest a raw working directory (live 2026-11-07). Every Claude Code,
// Codex, Cursor, Hermes and lifecycle hook builder sets ProjectRoot to the
// payload's cwd, while the watcher records the same session under the git
// root of that cwd (git.ResolveIdentity: the main repository for a linked
// worktree, the top level for a subdirectory). sessions.project_id is
// last-writer-wins (UpsertSession), so a worktree session flipped between
// the main project and a project of its own on every hook, and a
// subdirectory cwd minted a project row of its own. A hook process wires a
// resolver here so its rows land where the watcher's do.

// ProjectRootResolver maps the project root an event arrived with to the
// git identity it is recorded under. ok=false keeps the event as it came
// (not a git working tree, not a path on this host, a placeholder root).
// The production resolver is the hook processes' (cmd/observer); the New()
// default is nil, which resolves nothing, so the watcher (whose adapters
// already resolve) and internal/store's own tests are unchanged.
type ProjectRootResolver func(root string) (git.Identity, bool)

// SetProjectRootResolver wires the resolver Ingest applies to every tool
// and token event before it reads the event's project root. Pass nil to
// disable it again.
func (s *Store) SetProjectRootResolver(fn ProjectRootResolver) { s.projectRootResolver = fn }

// resolveIngestRoots returns copies of events and tokens whose project roots
// went through resolve (each distinct root once). The caller's slices are
// never changed. A resolved event takes the identity's root; its remote and
// identity fields fill only where the builder left them empty, and
// IsWorktree only turns on, so a value a builder knew is never replaced.
func resolveIngestRoots(resolve ProjectRootResolver, events []models.ToolEvent, tokens []models.TokenEvent) ([]models.ToolEvent, []models.TokenEvent) {
	type answer struct {
		id git.Identity
		ok bool
	}
	seen := map[string]answer{}
	lookup := func(root string) (git.Identity, bool) {
		if root == "" {
			return git.Identity{}, false
		}
		a, cached := seen[root]
		if !cached {
			a.id, a.ok = resolve(root)
			a.ok = a.ok && a.id.Root != ""
			seen[root] = a
		}
		return a.id, a.ok
	}
	outEvents := append([]models.ToolEvent(nil), events...)
	for i := range outEvents {
		e := &outEvents[i]
		id, ok := lookup(e.ProjectRoot)
		if !ok {
			continue
		}
		e.ProjectRoot = id.Root
		fillEmpty(&e.GitRemote, id.Remote)
		fillEmpty(&e.GitUpstreamRemote, id.UpstreamRemote)
		fillEmpty(&e.GitRemoteOwner, id.RemoteOwner)
		fillEmpty(&e.GitUpstreamOwner, id.UpstreamOwner)
		fillEmpty(&e.RootCommitSHA, id.RootCommitSHA)
		fillEmpty(&e.ContentFingerprint, id.ContentFingerprint)
		fillEmpty(&e.Workspace, id.Workspace)
		e.IsWorktree = e.IsWorktree || id.IsWorktree
	}
	outTokens := append([]models.TokenEvent(nil), tokens...)
	for i := range outTokens {
		t := &outTokens[i]
		id, ok := lookup(t.ProjectRoot)
		if !ok {
			continue
		}
		t.ProjectRoot = id.Root
		fillEmpty(&t.GitRemote, id.Remote)
		fillEmpty(&t.GitUpstreamRemote, id.UpstreamRemote)
		fillEmpty(&t.GitRemoteOwner, id.RemoteOwner)
		fillEmpty(&t.GitUpstreamOwner, id.UpstreamOwner)
		fillEmpty(&t.RootCommitSHA, id.RootCommitSHA)
		fillEmpty(&t.ContentFingerprint, id.ContentFingerprint)
		fillEmpty(&t.Workspace, id.Workspace)
		t.IsWorktree = t.IsWorktree || id.IsWorktree
	}
	return outEvents, outTokens
}

// fillEmpty sets *dst to v when *dst is empty.
func fillEmpty(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}
