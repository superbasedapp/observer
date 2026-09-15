package main

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	adapterdefaults "github.com/marmutapp/superbased-observer/internal/adapter/defaults"
)

// genericDiscoverConfig tunes the poll loop. Injectable so tests can use
// tiny durations. Mirrors codexDiscoverConfig exactly.
type genericDiscoverConfig struct {
	// window bounds the total watch time after the child starts.
	window time.Duration
	// poll is the interval between watch-root scans.
	poll time.Duration
}

// defaultGenericDiscoverConfig matches codex's production timing: most
// adapters write their first session-identifying record within the first
// second or two, so the window mostly covers a slow first flush.
func defaultGenericDiscoverConfig() genericDiscoverConfig {
	return genericDiscoverConfig{window: 30 * time.Second, poll: 750 * time.Millisecond}
}

// genericDiscoverModTimeSkew is how far before the child-start stamp a
// candidate file's ModTime may fall and still be considered "new". Absorbs
// coarse filesystem timestamp granularity; the pre-start name/path snapshot
// is the primary "new file" signal, this guard only rejects clearly-stale
// (path-recycled) files. Mirrors codexRolloutModTimeSkew.
const genericDiscoverModTimeSkew = 5 * time.Second

// genericAdapterRegistry is the process-wide, memoized set of production
// adapters (the same list cmd/observer/main.go's buildWatcher registers),
// built once via adapterdefaults.Adapters(). A launcher process is not the
// daemon and has no live watcher.Registry to reuse, but the adapter set
// itself is pure/stateless, so building a local one here is cheap and safe.
var genericAdapterRegistry = sync.OnceValue(func() *adapter.Registry {
	reg := adapter.NewRegistry()
	for _, a := range adapterdefaults.Adapters() {
		reg.Register(a)
	}
	return reg
})

// resolveDiscoverableAdapter returns the adapter registered under tool, or
// nil when tool is empty, unknown, or declares no session-file watch roots
// at all (e.g. the browser-capture rail's *-web adapters, which receive
// data over a native-messaging bridge rather than a session file — there is
// nothing on disk to poll for).
func resolveDiscoverableAdapter(tool string) adapter.Adapter {
	if tool == "" {
		return nil
	}
	a := genericAdapterRegistry().Get(tool)
	if a == nil || len(a.WatchPaths()) == 0 {
		return nil
	}
	return a
}

// genericDiscoverCandidate is a newly discovered session file plus the
// identity read from parsing it.
type genericDiscoverCandidate struct {
	path        string
	sessionID   string
	info        os.FileInfo
	projectRoot string // "" when the adapter's ParseResult didn't carry one
}

// snapshotGenericSessionFiles records the set of paths a.IsSessionFile
// currently accepts under a's watch roots. Taken BEFORE the child starts so
// the child's own new session file — necessarily absent from this set — is
// detectable without relying on wall clocks. A watch root may be a
// directory or a single file (e.g. aider's per-repo transcript path);
// filepath.WalkDir handles both. Best-effort: unreadable roots are skipped.
func snapshotGenericSessionFiles(a adapter.Adapter) map[string]struct{} {
	existing := make(map[string]struct{})
	for _, root := range a.WatchPaths() {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil //nolint:nilerr // skip unreadable entries, keep walking
			}
			if a.IsSessionFile(path) {
				existing[path] = struct{}{}
			}
			return nil
		})
	}
	return existing
}

// scanNewGenericSessionFiles returns session-file paths that appeared AFTER
// the pre-start snapshot: a path not in preexisting, whose ModTime is at or
// after startedAt (within genericDiscoverModTimeSkew). Mirrors
// scanNewCodexRollouts, generalized to any adapter's IsSessionFile.
func scanNewGenericSessionFiles(a adapter.Adapter, preexisting map[string]struct{}, startedAt time.Time) []string {
	var out []string
	for _, root := range a.WatchPaths() {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil //nolint:nilerr // skip unreadable entries, keep walking
			}
			if !a.IsSessionFile(path) {
				return nil
			}
			if _, seen := preexisting[path]; seen {
				return nil // pre-existing file (appended-to), not this run's
			}
			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			if info.ModTime().Before(startedAt.Add(-genericDiscoverModTimeSkew)) {
				return nil
			}
			out = append(out, path)
			return nil
		})
	}
	return out
}

// resolveGenericCandidate turns a newly discovered path into a candidate, or
// reports ok=false when it isn't (yet, or ever) usable.
//
// This is the ONE per-adapter-shape branch in the engine, and it dispatches
// on the adapter.CursorSemantics capability (a declared FileCursorSemantics
// kind), never on tool name. Two kinds are excluded:
//
//   - CursorWatermark: an opaque high-water mark over a monolithic store
//     (SQLite row id, `MAX(time_updated)`) shared by EVERY session that
//     tool has ever run. A "new file" appearing under such a root proves
//     nothing about a new session — the file usually already existed
//     (excluded by the pre-start snapshot already) and even a genuinely
//     fresh one holds every session that tool will ever record, not just
//     this run's.
//   - CursorEncrypted: a file the adapter tracks but cannot decode on this
//     host (e.g. Antigravity desktop's OSCrypt-gated `.pb` store) — no
//     session id can be read from it without adapter-internal key
//     material this engine does not have.
//
// An adapter that doesn't implement CursorSemantics, or reports any other
// kind for path, is byte-offset shaped by default (the historical
// assumption every pre-CursorSemantics adapter still gets) — eligible.
func resolveGenericCandidate(ctx context.Context, a adapter.Adapter, path string) (genericDiscoverCandidate, bool) {
	if cs, ok := a.(adapter.CursorSemantics); ok {
		switch cs.CursorSemanticsFor(path).Kind {
		case adapter.CursorWatermark, adapter.CursorEncrypted, adapter.CursorNoActions:
			return genericDiscoverCandidate{}, false
		}
	}
	before, err := os.Stat(path)
	if err != nil || !before.Mode().IsRegular() {
		return genericDiscoverCandidate{}, false
	}
	res, err := a.ParseSessionFile(ctx, path, 0)
	if err != nil {
		return genericDiscoverCandidate{}, false
	}
	sessionID, projectRoot := uniqueSessionIdentity(res)
	if sessionID == "" {
		return genericDiscoverCandidate{}, false
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		return genericDiscoverCandidate{}, false
	}
	return genericDiscoverCandidate{path: path, sessionID: sessionID, projectRoot: projectRoot, info: after}, true
}

// uniqueSessionIdentity accepts only a consistent primary session across the
// entire parsed file. A first event cannot identify a shared history file,
// and a subagent-only transcript cannot identify the terminal's primary run.
func uniqueSessionIdentity(res adapter.ParseResult) (sessionID, projectRoot string) {
	primary := false
	observe := func(id, root string, sidechain bool) bool {
		if id == "" {
			return true
		}
		if sessionID != "" && sessionID != id {
			return false
		}
		if root != "" {
			root = filepath.Clean(root)
			if projectRoot != "" && projectRoot != root {
				return false
			}
			projectRoot = root
		}
		sessionID = id
		primary = primary || !sidechain
		return true
	}
	for _, e := range res.ToolEvents {
		if !observe(e.SessionID, e.ProjectRoot, e.IsSidechain) {
			return "", ""
		}
	}
	for _, e := range res.TokenEvents {
		if !observe(e.SessionID, e.ProjectRoot, e.IsSidechain) {
			return "", ""
		}
	}
	for _, lineage := range res.SessionLineages {
		if lineage.SessionID == sessionID && (lineage.ParentThreadID != "" || lineage.ThreadSource == "subagent") {
			return "", ""
		}
	}
	if !primary {
		return "", ""
	}
	return sessionID, projectRoot
}

// cwdUnderProjectRoot reports whether cwd denotes projectRoot itself, or a
// directory under it. Unknown information (either side empty) never
// excludes — the candidate still counts toward the ambiguity check, the
// same "can't exclude, so it still counts" rule codex's cwd corroboration
// uses for a candidate with no cwd at all.
//
// Unlike codex's exact-match cwd comparison (codex's own session_meta
// always carries the raw process cwd), a generic adapter's ParseResult
// ProjectRoot is frequently git-root-resolved (internal/git) — for a launch
// from a project subdirectory that would never equal the raw cwd exactly,
// so exact match here would wrongly exclude the right candidate. Symlink
// resolution is attempted on both sides; a resolution failure falls back to
// the cleaned-path comparison.
func cwdUnderProjectRoot(cwd, projectRoot string) bool {
	if cwd == "" || projectRoot == "" {
		return true
	}
	cc, rc := filepath.Clean(cwd), filepath.Clean(projectRoot)
	if resolved, err := filepath.EvalSymlinks(cc); err == nil {
		cc = filepath.Clean(resolved)
	}
	if resolved, err := filepath.EvalSymlinks(rc); err == nil {
		rc = filepath.Clean(resolved)
	}
	if cc == rc {
		return true
	}
	return strings.HasPrefix(cc, rc+string(filepath.Separator))
}

// selectDiscoveredGenericSession applies the same never-guess abstention
// policy as selectDiscoveredCodexSession: exactly one surviving candidate
// after cwd corroboration → its id; zero → nothing yet; two or more → the
// caller abstains rather than picking.
func selectDiscoveredGenericSession(cands []genericDiscoverCandidate, targetCwd string) (string, int) {
	kept := make(map[string]struct{})
	for _, c := range cands {
		if c.sessionID == "" {
			continue
		}
		if !cwdUnderProjectRoot(targetCwd, c.projectRoot) {
			continue
		}
		kept[c.sessionID] = struct{}{}
	}
	if len(kept) == 1 {
		for id := range kept {
			return id, 1
		}
	}
	return "", len(kept)
}

// runGenericDiscovery watches a's watch roots for this run's new session
// file across the FULL window and announces its session id via announce
// (wired to announceDiscoveredOOBSession in production) ONLY at window
// close, and ONLY when exactly one candidate survived cwd corroboration
// over the whole window. Structurally identical to runCodexDiscovery — see
// that function's doc comment for the full R2-1 / F1 reasoning (an
// unrelated concurrent same-cwd session racing ahead, and why the decision
// is deferred to window close rather than made mid-window).
//
// Candidates already resolved (a path whose ParseSessionFile succeeded) are
// cached by path so a slow-growing file is parsed at most once per run;
// paths that aren't yet resolvable, or are shape-excluded, are retried
// (cheaply — a CursorSemantics check plus a WalkDir pass) on every poll,
// since a shape-excluded file could in principle transition (an adapter
// implementing CursorSemantics per-path, not per-adapter) and a not-yet-
// written file may become parseable moments later.
func runGenericDiscovery(ctx context.Context, a adapter.Adapter, preexisting map[string]struct{}, startedAt time.Time, targetCwd string, cfg genericDiscoverConfig, announce func(string)) {
	deadline := time.Now().Add(cfg.window)
	resolved := make(map[string]genericDiscoverCandidate)
	for {
		if ctx.Err() != nil {
			return // child exited: forgo discovery rather than risk a cut-short guess
		}
		for _, path := range scanNewGenericSessionFiles(a, preexisting, startedAt) {
			if _, ok := resolved[path]; ok {
				continue
			}
			if cand, ok := resolveGenericCandidate(ctx, a, path); ok {
				resolved[path] = cand
			}
		}
		if time.Now().After(deadline) {
			break
		}
		timer := time.NewTimer(cfg.poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	// F1: cancel wins over a completed final scan — see runCodexDiscovery's
	// identical re-check for the full reasoning.
	if ctx.Err() != nil {
		return
	}
	cands := make([]genericDiscoverCandidate, 0, len(resolved))
	for _, c := range resolved {
		fresh, ok := resolveGenericCandidate(ctx, a, c.path)
		if !ok || fresh.sessionID != c.sessionID || fresh.projectRoot != c.projectRoot || !os.SameFile(c.info, fresh.info) {
			return
		}
		cands = append(cands, fresh)
	}
	if ctx.Err() != nil {
		return
	}
	if id, count := selectDiscoveredGenericSession(cands, targetCwd); count == 1 {
		announce(id)
	}
}

// genericDiscoveryPlan takes its snapshot before spawn, then starts its bounded
// poll only after spawn succeeds. A nil plan is an intentional no-op.
type genericDiscoveryPlan struct {
	ctx         context.Context
	a           adapter.Adapter
	preexisting map[string]struct{}
	startedAt   time.Time
	cwd         string
}

func prepareGenericDiscovery(ctx context.Context, tool, dir string) *genericDiscoveryPlan {
	if !oobChannelActive() || tool == "" {
		return nil
	}
	a := resolveDiscoverableAdapter(tool)
	if a == nil || terminalNativeDiscoveryAvailable(a) {
		return nil
	}
	return prepareAdapterDiscovery(ctx, a, dir)
}

func prepareAdapterDiscovery(ctx context.Context, a adapter.Adapter, dir string) *genericDiscoveryPlan {
	preexisting := snapshotGenericSessionFiles(a)
	if dir == "" {
		dir, _ = os.Getwd()
	}
	return &genericDiscoveryPlan{ctx: ctx, a: a, preexisting: preexisting, startedAt: time.Now(), cwd: dir}
}

func (p *genericDiscoveryPlan) start() context.CancelFunc {
	if p == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(p.ctx)
	go runGenericDiscovery(ctx, p.a, p.preexisting, p.startedAt, p.cwd, defaultGenericDiscoverConfig(), announceDiscoveredOOBSession)
	return cancel
}
