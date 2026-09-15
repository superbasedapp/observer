package kirocli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter is the file-watcher implementation of the Kiro CLI adapter.
// It parses BOTH on-disk layouts of the mode-dependent dual store (see
// the package doc): the interactive flat-file bundle under
// `~/.kiro/sessions/cli/` and the non-interactive SQLite
// `conversations_v2` table under the kiro-cli data dir. Layout is
// resolved from the file shape at IsSessionFile / ParseSessionFile
// time — one package, layout-sniffing dispatch, mirroring antigravity.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an Adapter with platform-default cross-mount roots and a
// default scrubber.
func New() *Adapter {
	return &Adapter{
		scrubber: scrub.New(),
		roots:    defaultRoots(),
	}
}

// NewWithOptions customises scrubber and roots for tests. Pass nil
// scrubber for the default; pass no roots for default platform
// discovery.
func NewWithOptions(s *scrub.Scrubber, roots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolKiroCLI }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// layout identifies which Kiro CLI store shape a path belongs to.
type layout int

const (
	layoutUnknown layout = iota
	// layoutFlat is a flat-bundle `<uuid>.json` or `<uuid>.jsonl` under
	// `.../.kiro/sessions/cli/`. Both extensions route to the same
	// bundle parse and emit events under the canonical `.jsonl`
	// SourceFile so the store's (source_file, source_event_id) dedup
	// drops the cross-trigger duplicates.
	layoutFlat
	// layoutSQLite is the `data.sqlite3` (or its -wal/-shm sidecar)
	// under a kiro-cli data dir. The sidecars route here purely as
	// fsnotify triggers; the open always targets data.sqlite3.
	layoutSQLite
	// layoutIDE is a Kiro IDE session's `messages.jsonl` under
	// `.../.kiro/sessions/<workspaceBucket>/<sessionId>/`, the SIBLING
	// subtree of the CLI's `cli/` bundles. The bucket is
	// sha256(normalized workspaceFolders)[:16] or the literal `global`
	// (a window with no folder open); the literal `cli` is the flat
	// CLI bundle dir and is NEVER an IDE bucket. The sibling
	// `session.json` and the `snapshots/` + `sub-executions/` subtrees
	// are not triggers — see classifyLayout.
	layoutIDE
)

// sessionsPathMarker is the path segment every Kiro session store hangs
// off, on every OS.
const sessionsPathMarker = "/.kiro/sessions/"

// classifyLayout returns the store layout for a path, gated on the
// path living under a recognisable Kiro subtree. Root-gating in
// IsSessionFile is still required — this only recognises the shape.
func classifyLayout(path string) layout {
	// Normalise separators first so a Windows path read on Linux (where
	// filepath.Base won't split on backslashes) still yields the right
	// basename.
	norm := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	base := norm
	if i := strings.LastIndex(norm, "/"); i >= 0 {
		base = norm[i+1:]
	}

	switch base {
	case "data.sqlite3", "data.sqlite3-wal", "data.sqlite3-shm":
		// Belt-and-braces: parent dir must look like a kiro-cli data
		// dir on either OS layout.
		if strings.Contains(norm, "/kiro-cli/") {
			return layoutSQLite
		}
		return layoutUnknown
	}

	// LastIndex, not Index: the store dir itself is the watch root, so a
	// path can legitimately carry the marker twice (a workspace whose
	// own tree contains a `.kiro/sessions/` dir, or the defaults
	// invariant test joining a full-shape fixture under the root). The
	// INNERMOST marker is the one whose subpath encodes the layout.
	i := strings.LastIndex(norm, sessionsPathMarker)
	if i < 0 {
		return layoutUnknown
	}
	return classifySessionsSubpath(strings.Split(norm[i+len(sessionsPathMarker):], "/"), base)
}

// classifySessionsSubpath resolves the layout of a path already known
// to live under `.kiro/sessions/`, from its remaining path segments.
// The two sibling subtrees are told apart by the FIRST segment (the
// bucket): the literal `cli` is the CLI's flat-bundle dir, anything
// else is an IDE workspace bucket.
//
//	cli/<uuid>.json | cli/<uuid>.jsonl         → layoutFlat
//	<bucket>/<sessionId>/messages.jsonl        → layoutIDE
//
// Everything else under either subtree is NOT a trigger: the `.history`
// / `.lock` flat siblings, the IDE's `session.json` (read as a sibling
// of messages.jsonl, never on its own), and the whole `snapshots/**` +
// `sub-executions/**` subtrees.
func classifySessionsSubpath(parts []string, base string) layout {
	if len(parts) == 0 || parts[0] == "" {
		return layoutUnknown
	}
	if parts[0] == "cli" {
		if len(parts) != 2 {
			return layoutUnknown
		}
		if strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".jsonl") {
			return layoutFlat
		}
		return layoutUnknown
	}
	// IDE: exactly <bucket>/<sessionId>/messages.jsonl. The length gate
	// is what excludes snapshots/<id>/<relPath> and
	// sub-executions/<execId>.jsonl without a second pattern list.
	if len(parts) == 3 && parts[2] == "messages.jsonl" {
		return layoutIDE
	}
	return layoutUnknown
}

// layoutSurfaces is the ONE table mapping a store layout onto its
// capture surface (plan §3.1: resolved at the boundary, one row per
// layout, never a tool-name branch downstream). Both CLI layouts are
// the same surface — the flat bundle and the SQLite store are just the
// interactive vs `--no-interactive` modes of the same terminal binary.
// The IDE layout is Kiro's own VS Code fork driving the agent.
var layoutSurfaces = map[layout]models.SessionSurface{
	layoutFlat:   {Surface: models.SurfaceCLI, SurfaceHost: "kiro-cli"},
	layoutSQLite: {Surface: models.SurfaceCLI, SurfaceHost: "kiro-cli"},
	layoutIDE:    {Surface: models.SurfaceIDE, SurfaceHost: "kiro"},
}

// agentSurfaces OVERRIDES layoutSurfaces when the flat bundle's
// `session_state.agent_name` names an orchestrator that merely USES
// kiro-cli as its execution engine. The layout says "a flat bundle was
// written"; the agent name says WHO drove it, and that is the finer
// truth about the capture surface.
//
// Grounded 2026-09-03 across five live sessions on the step-in host:
// "kiro_default" (a plain terminal run — no override, layoutSurfaces
// wins), null (no override), and "kirocrew" ×3 — AWS's Kiro Crew desktop
// app orchestrating kiro-cli agents. A Crew-driven run is not a terminal
// session at all: the user is typing in a desktop chat tab.
//
// Exact-match only, never a prefix test: `~/.kiro/crew/
// agent_model_state.json` also names `kirocrew-heartbeat` and
// `kirocrew-lite`, and none of those were observed on a session, so
// claiming them would be a guess. An unlisted agent name falls through to
// the layout answer — the honest default.
//
// This is the kiro-cli HALF of the kiro-crew double-count rule; see
// internal/adapter/kirocrew/doc.go "Ownership". kiro-cli owns the rows;
// the surface stamp is resolved here, from kiro-cli's OWN file, so it is
// race-free and needs no cross-store lookup.
var agentSurfaces = map[string]models.SessionSurface{
	"kirocrew": {Surface: models.SurfaceDesktop, SurfaceHost: "kiro-crew"},
}

// surfaceFor returns the SessionSurface stamp for a layout + session.
// An unmapped layout yields the zero value, which the caller must not
// emit (honesty rule: no grounded discriminator ⇒ no stamp).
func surfaceFor(l layout, sessionID string) models.SessionSurface {
	s, ok := layoutSurfaces[l]
	if !ok || sessionID == "" {
		return models.SessionSurface{}
	}
	s.SessionID = sessionID
	return s
}

// surfaceForAgent returns the surface stamp for a flat bundle, consulting
// agentSurfaces first and falling back to the layout answer. A zero
// return must not be emitted.
func surfaceForAgent(l layout, sessionID, agentName string) models.SessionSurface {
	if s, ok := agentSurfaces[strings.TrimSpace(agentName)]; ok && sessionID != "" {
		s.SessionID = sessionID
		return s
	}
	return surfaceFor(l, sessionID)
}

// IsSessionFile implements adapter.Adapter. Three families, each ANDed
// with adapter.UnderAnyWatchRoot so a stray data.sqlite3 / <uuid>.json
// elsewhere on disk cannot claim the dispatch:
//
//  1. Flat bundle: `<uuid>.json` / `<uuid>.jsonl` under
//     `.../.kiro/sessions/cli/`. The `.history` / `.lock` siblings are
//     rejected (read only as bundle siblings, never as triggers).
//  2. SQLite: `data.sqlite3` (+ -wal / -shm poll triggers) under the
//     kiro-cli data dir.
//  3. Kiro IDE: `messages.jsonl` under
//     `.../.kiro/sessions/<workspaceBucket>/<sessionId>/`. Its sibling
//     `session.json` and the `snapshots/` / `sub-executions/` subtrees
//     are rejected.
func (a *Adapter) IsSessionFile(path string) bool {
	if classifyLayout(path) == layoutUnknown {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// ParseSessionFile implements adapter.Adapter, dispatching on layout.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	switch classifyLayout(path) {
	case layoutFlat:
		return a.parseFlatBundle(ctx, path, fromOffset)
	case layoutSQLite:
		return a.parseStateDB(ctx, path, fromOffset)
	case layoutIDE:
		return a.parseIDESession(ctx, path, fromOffset)
	default:
		return adapter.ParseResult{NewOffset: fromOffset}, nil
	}
}

// bundlePaths derives the canonical `.jsonl` + `.json` sibling paths
// for a flat-bundle trigger (either extension).
func bundlePaths(trigger string) (jsonlPath, jsonPath, sessionID string) {
	dir := filepath.Dir(trigger)
	base := filepath.Base(trigger)
	sessionID = strings.TrimSuffix(strings.TrimSuffix(base, ".jsonl"), ".json")
	jsonlPath = filepath.Join(dir, sessionID+".jsonl")
	jsonPath = filepath.Join(dir, sessionID+".json")
	return jsonlPath, jsonPath, sessionID
}

// warnf appends a formatted warning to res.Warnings.
func warnf(res *adapter.ParseResult, format string, args ...any) {
	res.Warnings = append(res.Warnings, fmt.Sprintf(format, args...))
}
