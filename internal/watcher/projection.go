package watcher

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// projection.go is the watcher's one seam for a sandboxed run's projected
// tool state (sandbox plan v2 section 5.4, gap G27, lane SBX-P3C): a box
// whose tool state is a per-run projection (a row that crosses a kernel, or
// an image's own copy of the tool) writes its transcripts into a host
// directory outside every adapter's own roots, so the host watcher would
// never see them. AddProjectionRoot registers that directory as an extra
// watch root for the run's life, bound to the tool's own adapter: a file
// under the host directory is offered to the adapter as if it lay at the
// box path the tool wrote it at (its own tree in the box, the same path as
// on the host because the box mounts the home at its own path), so the
// adapter's shape rules apply unchanged and no tool name is branched on.
// The returned func removes the root again (at the run's end).
//
// SQLite stores are never read live through this seam (SBX-BE-10): only
// the transcript subtrees a per-tool seed row names are registered, and
// the db-copy one-shot still covers a store.

// projectionAdapter is the tool's adapter seen through one projection
// root: WatchPaths is the host directory, a file there is judged as the
// adapter would judge it at its box path, and what it parses is bound to
// the run (ParseSessionFile, bindToRun).
type projectionAdapter struct {
	adapter.Adapter
	hostRoot string
	boxRoot  string
	bind     ProjectionBinding
	owner    projectionSessionOwner
	logger   Logger

	mu  sync.Mutex
	ids map[string]string
}

// WatchPaths is the projection root only, so the walk, the symlink-escape
// check and the dispatch stay inside it.
func (p *projectionAdapter) WatchPaths() []string { return []string{p.hostRoot} }

// IsSessionFile maps path from the host directory onto the box path and
// asks the tool's own adapter.
func (p *projectionAdapter) IsSessionFile(path string) bool {
	rel, err := filepath.Rel(p.hostRoot, path)
	if err != nil || rel == "." || !filepath.IsLocal(rel) {
		return false
	}
	return p.Adapter.IsSessionFile(filepath.Join(p.boxRoot, rel))
}

// ProjectionBinding binds a projection root's transcripts to the sandbox
// run that wrote them (lane SBX-P3C audit finding 3): the box writes the
// transcripts, so the session id and the cwd in them are the box's word.
// RunID names the run and Workspace is the run's workspace directory on
// the host. A zero binding (no workspace) leaves events as parsed.
type ProjectionBinding struct {
	RunID     string
	Workspace string
}

// projectionSessionOwner answers what the store already holds for a
// session id (exists, its project root, and whether any of its rows came
// from a source file outside this projection root).
type projectionSessionOwner func(ctx context.Context, sessionID string) (store.SessionOwnerFacts, error)

// ParseSessionFile parses with the tool's own adapter, then binds every
// event to the run (bindToRun).
func (p *projectionAdapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	res, err := p.Adapter.ParseSessionFile(ctx, path, fromOffset)
	if err != nil || p.bind.Workspace == "" {
		return res, err
	}
	p.bindToRun(ctx, &res)
	return res, nil
}

// projectionClaimedRule is why bindToRun rebinds or renames, walked as one
// decision per event field (a table of two rows, kept here with their
// reasons for the log):
//
//   - project: an event whose project root is not the run's workspace or
//     inside it lands on the workspace; the box's claim is kept only in the
//     action's metadata (sandbox_claimed_cwd) and its git fields, which the
//     adapter resolved from the claimed directory on the host, are cleared;
//   - session: an id the store already holds under another project, or
//     with rows from a source outside this projection, is never merged
//     into: it is namespaced to the run ("sandbox-<run>-<id>"), so the
//     other session is untouched. The decision is made once per id and
//     kept for the root's life, so every window of a file agrees.
func (p *projectionAdapter) bindToRun(ctx context.Context, res *adapter.ParseResult) {
	ws := filepath.Clean(p.bind.Workspace)
	inRun := func(root string) bool { return root != "" && adapter.HasPathPrefix(filepath.Clean(root), ws) }
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		ev.SessionID = p.sessionFor(ctx, ev.SessionID)
		if ev.Metadata != nil && ev.Metadata.ParentSessionID != "" {
			ev.Metadata.ParentSessionID = p.sessionFor(ctx, ev.Metadata.ParentSessionID)
		}
		if inRun(ev.ProjectRoot) {
			continue
		}
		if ev.Metadata == nil {
			ev.Metadata = &models.ActionMetadata{}
		}
		ev.Metadata.SandboxClaimedCwd = ev.ProjectRoot
		ev.ProjectRoot = ws
		ev.GitBranch, ev.GitRemote, ev.GitUpstreamRemote, ev.GitRemoteOwner, ev.GitUpstreamOwner = "", "", "", "", ""
		ev.RootCommitSHA, ev.ContentFingerprint, ev.Workspace, ev.IsWorktree = "", "", "", false
	}
	for i := range res.TokenEvents {
		ev := &res.TokenEvents[i]
		ev.SessionID = p.sessionFor(ctx, ev.SessionID)
		if inRun(ev.ProjectRoot) {
			continue
		}
		ev.ProjectRoot = ws
		ev.GitBranch, ev.GitRemote, ev.GitUpstreamRemote, ev.GitRemoteOwner, ev.GitUpstreamOwner = "", "", "", "", ""
		ev.RootCommitSHA, ev.ContentFingerprint, ev.Workspace, ev.IsWorktree = "", "", "", false
	}
	for i := range res.CacheObservations {
		res.CacheObservations[i].SessionID = p.sessionFor(ctx, res.CacheObservations[i].SessionID)
	}
	for i := range res.SessionLineages {
		l := &res.SessionLineages[i]
		l.SessionID = p.sessionFor(ctx, l.SessionID)
		if l.ForkedFromID != "" {
			l.ForkedFromID = p.sessionFor(ctx, l.ForkedFromID)
		}
		if l.ParentThreadID != "" {
			l.ParentThreadID = p.sessionFor(ctx, l.ParentThreadID)
		}
	}
	for i := range res.SessionSurfaces {
		res.SessionSurfaces[i].SessionID = p.sessionFor(ctx, res.SessionSurfaces[i].SessionID)
	}
	for i := range res.SessionToolVersions {
		res.SessionToolVersions[i].SessionID = p.sessionFor(ctx, res.SessionToolVersions[i].SessionID)
	}
	// A process id the box reports names a process in the box, never one
	// on this host: no pid bridge is seeded from a projection.
	res.SessionProcessSeeds = nil
}

// sessionFor is the run's id for a box-claimed session id (see
// bindToRun): the id itself, or the run-namespaced one when the store
// already holds it under another project or from another source. A store
// error namespaces too (never merge on doubt).
func (p *projectionAdapter) sessionFor(ctx context.Context, id string) string {
	if id == "" {
		return id
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if got, ok := p.ids[id]; ok {
		return got
	}
	if p.ids == nil {
		p.ids = map[string]string{}
	}
	out, reason := id, ""
	if p.owner != nil {
		facts, err := p.owner(ctx, id)
		switch {
		case err != nil:
			reason = "the store could not say who owns it: " + err.Error()
		case facts.Exists && !adapter.HasPathPrefix(filepath.Clean(facts.ProjectRoot), filepath.Clean(p.bind.Workspace)):
			reason = "it already belongs to another project"
		case facts.Exists && facts.ForeignSource:
			reason = "it already holds rows from a source outside this run"
		}
	}
	if reason != "" {
		out = "sandbox-" + p.bind.RunID + "-" + id
		if p.logger != nil {
			p.logger.Warn("watcher: a sandbox run's transcript names an existing session; it is namespaced to the run, not merged",
				"run", p.bind.RunID, "session", id, "as", out, "reason", reason)
		}
	}
	p.ids[id] = out
	return out
}

// runIDOK reports whether id is a clean run token for a namespaced id.
func runIDOK(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// AddProjectionRoot registers hostRoot (an existing directory) as a watch
// root of the adapter named tool, whose files are judged at boxRoot and
// whose events are bound to the run bind names (bindToRun), walks what is
// already there, and returns the func that removes it. It refuses an
// unknown or disabled adapter, a watcher that is not running, a root
// already watched, and a path that is not clean and absolute.
func (w *Watcher) AddProjectionRoot(ctx context.Context, tool, hostRoot, boxRoot string, bind ProjectionBinding) (func(), error) {
	if !filepath.IsAbs(hostRoot) || filepath.Clean(hostRoot) != hostRoot || !filepath.IsAbs(boxRoot) || filepath.Clean(boxRoot) != boxRoot {
		return nil, fmt.Errorf("watcher.AddProjectionRoot: %q and %q must be clean absolute paths", hostRoot, boxRoot)
	}
	base := w.registry.Get(tool)
	if base == nil {
		return nil, fmt.Errorf("watcher.AddProjectionRoot: no adapter %q", tool)
	}
	if w.allow != nil && !slices.Contains(w.allow, tool) {
		return nil, fmt.Errorf("watcher.AddProjectionRoot: the %s adapter is not enabled", tool)
	}
	if bind.Workspace != "" && (!filepath.IsAbs(bind.Workspace) || !runIDOK(bind.RunID)) {
		return nil, fmt.Errorf("watcher.AddProjectionRoot: the run binding %+v needs an absolute workspace and a clean run id", bind)
	}
	pa := &projectionAdapter{Adapter: base, hostRoot: hostRoot, boxRoot: boxRoot, bind: bind, logger: w.logger}
	if w.store != nil {
		pa.owner = func(ctx context.Context, sessionID string) (store.SessionOwnerFacts, error) {
			return w.store.SessionOwnerFacts(ctx, sessionID, hostRoot)
		}
	}
	w.liveMu.Lock()
	fsw := w.fsw
	if fsw == nil || w.byRoot == nil {
		w.liveMu.Unlock()
		return nil, fmt.Errorf("watcher.AddProjectionRoot: the watcher is not running")
	}
	if _, ok := w.byRoot[hostRoot]; ok {
		w.liveMu.Unlock()
		return nil, fmt.Errorf("watcher.AddProjectionRoot: %s is already watched", hostRoot)
	}
	w.byRoot[hostRoot] = pa
	w.liveMu.Unlock()
	addRoot := w.addRoot
	if addRoot == nil {
		addRoot = addRecursive
	}
	if res := addRoot(cancelAwareAdder{ctx: ctx, next: fsw}, hostRoot); res.RootErr != nil {
		w.removeProjectionRoot(hostRoot, pa)
		return nil, fmt.Errorf("watcher.AddProjectionRoot: watch %s: %w", hostRoot, res.RootErr)
	}
	w.logger.Info("watcher: added a sandbox projection root", "adapter", tool, "root", hostRoot)
	// A sandbox projection root is not part of the first-run history
	// capture progress (captureprogress), so its walk records nothing there.
	_ = w.walkRoot(ctx, pa, hostRoot, false, nil)
	return func() { w.removeProjectionRoot(hostRoot, pa) }, nil
}

// removeProjectionRoot drops the root when it is still pa's (the inotify
// watches under it go away with the directory, which the run's end
// removes).
func (w *Watcher) removeProjectionRoot(hostRoot string, pa *projectionAdapter) {
	w.liveMu.Lock()
	defer w.liveMu.Unlock()
	if cur, ok := w.byRoot[hostRoot]; ok && cur == pa {
		delete(w.byRoot, hostRoot)
		if w.fsw != nil {
			_ = w.fsw.Remove(hostRoot)
		}
	}
}

// IngestProjectionOnce reads every transcript already under hostRoot once,
// through the same projection adapter AddProjectionRoot builds (judged at
// boxRoot, bound to the run), with no live watch (lane LEFT-SBX): a
// sandboxed run no running watcher watched (a CLI launch, `observer <tool>
// --observer-sandbox oci-runsc`) is ingested this way before its projection
// is removed, so its transcripts are kept. The rules are AddProjectionRoot's.
func (w *Watcher) IngestProjectionOnce(ctx context.Context, tool, hostRoot, boxRoot string, bind ProjectionBinding) (ScanResult, error) {
	if !filepath.IsAbs(hostRoot) || filepath.Clean(hostRoot) != hostRoot || !filepath.IsAbs(boxRoot) || filepath.Clean(boxRoot) != boxRoot {
		return ScanResult{}, fmt.Errorf("watcher.IngestProjectionOnce: %q and %q must be clean absolute paths", hostRoot, boxRoot)
	}
	base := w.registry.Get(tool)
	if base == nil {
		return ScanResult{}, fmt.Errorf("watcher.IngestProjectionOnce: no adapter %q", tool)
	}
	if w.allow != nil && !slices.Contains(w.allow, tool) {
		return ScanResult{}, fmt.Errorf("watcher.IngestProjectionOnce: the %s adapter is not enabled", tool)
	}
	if bind.Workspace != "" && (!filepath.IsAbs(bind.Workspace) || !runIDOK(bind.RunID)) {
		return ScanResult{}, fmt.Errorf("watcher.IngestProjectionOnce: the run binding %+v needs an absolute workspace and a clean run id", bind)
	}
	pa := &projectionAdapter{Adapter: base, hostRoot: hostRoot, boxRoot: boxRoot, bind: bind, logger: w.logger}
	if w.store != nil {
		pa.owner = func(ctx context.Context, sessionID string) (store.SessionOwnerFacts, error) {
			return w.store.SessionOwnerFacts(ctx, sessionID, hostRoot)
		}
	}
	return w.walkRoot(ctx, pa, hostRoot, false, nil), nil
}
