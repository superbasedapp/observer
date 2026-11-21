package main

import (
	"database/sql"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// hook_ingestroot.go: where a hook process files its rows (live 2026-11-07).
// Hook builders set ProjectRoot to the payload's working directory. The
// watcher records the same session under that directory's git root (the
// claudecode adapter's resolveProjectRoot: crossmount.TranslateForeignPath,
// then git.ResolveIdentity), so a linked worktree's session flipped between
// the main repository's project and a project of its own on every hook
// (sessions.project_id is last-writer-wins), and a subdirectory cwd minted a
// project row of its own. Every store a hook process ingests through is built
// by hookIngestStore, which resolves each root the watcher's way first.

// hookIngestIdentity is the git identity a hook event's root is recorded
// under: the root of the git working tree containing it (the main
// repository's top level inside a linked worktree, F0-14), resolved exactly
// as the watcher resolves a transcript cwd. ok is false outside a git
// working tree and for a root that is not a path on this host (a "[tool]"
// placeholder, a foreign path this host cannot reach); the event then keeps
// the root it came with. File reads only: no git process runs (the lazy
// root-commit exec stays in the store).
func hookIngestIdentity(root string) (git.Identity, bool) {
	dir := crossmount.TranslateForeignPath(root)
	if dir == "" || !git.HostRooted(dir) {
		return git.Identity{}, false
	}
	id, err := git.ResolveIdentity(dir, git.IdentityOptions{})
	if err != nil || !id.IsGit || id.Root == "" {
		return git.Identity{}, false
	}
	return id, true
}

// hookIngestRootOf is the project root a hook record that names its project
// by root (a compaction capture) is filed under: hookIngestIdentity's root,
// else dir as it came.
func hookIngestRootOf(dir string) string {
	if id, ok := hookIngestIdentity(dir); ok {
		return id.Root
	}
	return dir
}

// hookIngestStore is the Store a hook process ingests through: the plain
// store with the hook root resolver wired (store.SetProjectRootResolver).
// hookCaptureStore adds the excerpt indexer on top of it.
func hookIngestStore(database *sql.DB) *store.Store {
	st := store.New(database)
	st.SetProjectRootResolver(hookIngestIdentity)
	return st
}

// Cache lifetimes of the daemon's root resolver. A git answer is kept a
// minute; a "not a git tree" answer only a few seconds, so a worktree a tool
// creates and opens at once is not filed under its own folder for long.
const (
	ingestRootCacheTTL     = time.Minute
	ingestRootMissCacheTTL = 5 * time.Second
)

// daemonIngestRootResolver is hookIngestIdentity for the daemon's long-lived
// stores (the watcher's and the OTLP receiver's), which ingest the same
// roots many times a minute: each root's answer is cached briefly. Safe for
// concurrent use. With it wired, every live writer (watcher, OTLP, hooks,
// the lifecycle drainer) files a session under the same root.
func daemonIngestRootResolver() store.ProjectRootResolver {
	type entry struct {
		id      git.Identity
		ok      bool
		expires time.Time
	}
	var (
		mu    sync.Mutex
		cache = map[string]entry{}
	)
	return func(root string) (git.Identity, bool) {
		now := time.Now()
		mu.Lock()
		e, hit := cache[root]
		mu.Unlock()
		if hit && now.Before(e.expires) {
			return e.id, e.ok
		}
		id, ok := hookIngestIdentity(root)
		ttl := ingestRootMissCacheTTL
		if ok {
			ttl = ingestRootCacheTTL
		}
		mu.Lock()
		if len(cache) > 4096 {
			cache = map[string]entry{}
		}
		cache[root] = entry{id: id, ok: ok, expires: now.Add(ttl)}
		mu.Unlock()
		return id, ok
	}
}
