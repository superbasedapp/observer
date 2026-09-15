package clinecli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter is the file-watcher implementation of the Cline CLI adapter.
// Capture strategy is SQLite-backfill primary against
// `<root>/data/db/sessions.db` + per-session JSON
// (`<root>/data/sessions/<id>/<id>.messages.json`), with an optional
// hooks-JSONL tail (Phase 3 of the plan) for sessions where the
// operator has registered hook commands or run a subagent. See the
// package doc for the full strategy.
//
// Hook + SQLite running in tandem may produce two rows per turn
// (one from each path) sharing SessionID but with distinct SourceFile
// values: hook rows would carry "clinecli:hook"; SQLite rows carry
// the absolute path to sessions.db; messages.json rows carry the
// absolute path to <id>.messages.json. The (SourceFile, SourceEventID)
// UNIQUE index makes re-scans within each path idempotent;
// cross-path dedup is a Phase 3 follow-up (mirrors the Hermes H1
// finding) via a SessionHookChecker analogous to the cursor adapter's
// at internal/adapter/cursor/scan.go:51-87.
type Adapter struct {
	scrubber  *scrub.Scrubber
	roots     []string
	hookCheck SessionHookChecker
}

// New returns an Adapter with platform-default cross-mount roots
// (every `<home>/.cline` plus `$CLINE_DIR` when set) and a default
// scrubber.
func New() *Adapter {
	return &Adapter{
		scrubber: scrub.New(),
		roots:    defaultRoots(),
	}
}

// NewWithOptions customises scrubber and roots for tests. Pass nil
// scrubber for the default; pass nil/empty roots for default platform
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

// WithSessionHookChecker injects the predicate the SQLite path
// consults to detect "this session already has live-hook rows;
// skip the SQLite re-emit." A nil checker (the default) means
// always emit — appropriate for cold-start ingestion or installs
// where the operator has not enabled hooks. Returns the adapter
// for chaining.
//
// Mirrors cursor.Adapter.WithSessionHookChecker — same dedup
// problem (two paths, both authoritative for different sessions,
// no per-session orchestration above the watcher). Resolution:
// the consumer holds a per-session "this is covered by hooks"
// truth and projects it down into the adapter at parse time.
//
// See the H1 finding from docs/audits/hermes-audit-2026-06-05.md:
// hook + SQLite cross-path double-count was the architectural
// follow-up the hermes adapter ships WITHOUT. This adapter ships
// the gate by default so cline-cli avoids the same trap.
func (a *Adapter) WithSessionHookChecker(check SessionHookChecker) *Adapter {
	a.hookCheck = check
	return a
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolClineCLI }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Matches two families of
// files under a `<root>/data/` subtree:
//
//  1. The SQLite trio: `db/sessions.db`, `db/sessions.db-wal`,
//     `db/sessions.db-shm`. The WAL/SHM sidecars fire fsnotify when
//     Cline writes; the parser uses them as poll triggers and only
//     opens the main .db file. The per-session
//     `<id>.messages.json` files are walked INSIDE scanStateDB —
//     they don't trigger ParseSessionFile separately (matches the
//     hermes precedent; Cline CLI commits sessions.db in the same
//     transaction as each messages.json write, so the sessions.db
//     trigger is always the canonical signal).
//  2. The optional hook log: `logs/hooks.jsonl`. Phase 3 of the plan
//     — the cursor's natural shape there is a byte offset into the
//     JSONL file. Gated through IsSessionFile today so the watcher
//     creates a parse_cursors row + tracks the file; ParseSessionFile
//     stubs to no-op until the tailer ships.
//
// Both are gated through adapter.UnderAnyWatchRoot so a generic
// `sessions.db` or `hooks.jsonl` elsewhere on disk can't accidentally
// claim the dispatch. The under-root check is the v1.4.51 invariant
// every adapter must enforce.
func (a *Adapter) IsSessionFile(path string) bool {
	var relative string
	switch filepath.Base(path) {
	case "sessions.db", "sessions.db-wal", "sessions.db-shm":
		relative = filepath.Join("data", "db", filepath.Base(path))
	case "hooks.jsonl":
		relative = filepath.Join("data", "logs", "hooks.jsonl")
	default:
		return false
	}
	// Preserve the historical .cline subtree layout beneath an explicitly
	// watched parent, while accepting CLINE_DIR itself without that basename.
	normalized := filepath.ToSlash(filepath.Clean(path))
	legacySuffix := "/.cline/" + filepath.ToSlash(relative)
	if strings.HasSuffix(normalized, legacySuffix) && adapter.UnderAnyWatchRoot(path, a.WatchPaths()) {
		return true
	}
	for _, root := range a.WatchPaths() {
		if filepath.Clean(path) == filepath.Join(root, relative) {
			return true
		}
	}
	return false
}

// buildProcessSeeds emits a candidate (OS pid → session) attribution
// link for every still-open session whose sessions.pid names a live
// local process. Cline CLI records the owning CLI process's real OS pid
// in sessions.pid, and the watcher (the daemon) reads it directly, so
// no ancestor-walk is needed — the write is a direct seed.
//
// Foreign-mount sources (a Windows cline process's DB read from a WSL2
// observer) are skipped: that pid is a Windows pid, meaningless on the
// Linux daemon's /proc. The store re-validates liveness + identity
// ("cline" in the process comm/cmdline) before writing, so a dead or
// recycled pid on this host is rejected there too (a miss beats a wrong
// link).
func buildProcessSeeds(sessions []sessionRow, dbPath string) []models.SessionProcessSeed {
	if isForeignMountPath(dbPath) {
		return nil
	}
	var seeds []models.SessionProcessSeed
	for _, s := range sessions {
		// Only a still-open session (ended_at NULL) has a live
		// process; skip closed ones to avoid a doomed /proc probe.
		if s.EndedAt.Valid || s.PID <= 1 || s.ID == "" {
			continue
		}
		seeds = append(seeds, models.SessionProcessSeed{
			PID:       int(s.PID),
			SessionID: s.ID,
			Tool:      models.ToolClineCLI,
			CWD:       s.CWD,
			ExecHint:  "cline",
		})
	}
	return seeds
}

// ParseSessionFile implements adapter.Adapter.
//
// Dispatches by the file's basename:
//
//   - `sessions.db` / `sessions.db-wal` / `sessions.db-shm`: open the
//     main DB file and scan rows past the parse cursor's UnixMilli
//     watermark. The WAL/SHM sidecars route here purely as fsnotify
//     triggers; the SQLite open always targets `sessions.db`. Returns
//     events for every new/updated session + per-message rows from
//     each session's paired messages.json.
//   - `hooks.jsonl`: Phase 3 of the plan — for now a no-op (returns
//     the input offset unchanged so the cursor stays put).
//
// The fromOffset int64 is a UnixMilli watermark on sessions.updated_at.
// Conversion happens inside scanStateDB; the watcher persists the
// returned NewOffset back into parse_cursors.offset for the next
// scan. fromOffset == 0 disables the filter (a full backfill).
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	base := filepath.Base(path)
	switch base {
	case "sessions.db", "sessions.db-wal", "sessions.db-shm":
		dbPath := path
		if strings.HasSuffix(base, "-wal") {
			dbPath = strings.TrimSuffix(path, "-wal")
		} else if strings.HasSuffix(base, "-shm") {
			dbPath = strings.TrimSuffix(path, "-shm")
		}
		sessions, newOffset, err := scanStateDB(ctx, dbPath, fromOffset)
		if err != nil {
			return adapter.ParseResult{NewOffset: fromOffset}, fmt.Errorf("clinecli.ParseSessionFile: %w", err)
		}
		if len(sessions) == 0 {
			return adapter.ParseResult{NewOffset: newOffset}, nil
		}
		toolEvents, tokenEvents, warnings := buildEvents(ctx, sessions, dbPath, a.scrubber, a.hookCheck)
		// §14.3 Tier-2 cache observation. cline-cli's content blocks
		// carry NO volatile fields (clean Anthropic shape), so the
		// canonical marshaller is a straight struct-encode per
		// type. See docs/audits/cachetrack-cline-cli-tier2-audit-
		// 2026-06-09.md for the audit.
		cacheObservations := buildCacheObservations(sessions, dbPath)
		return adapter.ParseResult{
			ToolEvents:          toolEvents,
			TokenEvents:         tokenEvents,
			CacheObservations:   cacheObservations,
			SessionProcessSeeds: buildProcessSeeds(sessions, dbPath),
			// Capture-surface attribution resolved from Cline's own
			// sessions.source column through surfaceBySource
			// (surface.go). Cline `next` routes VS Code / JetBrains /
			// Neovim sessions through this same sessions.db, so the
			// tool id stays cline-cli and these columns are the split.
			SessionSurfaces: buildSessionSurfaces(sessions),
			NewOffset:       newOffset,
			Warnings:        warnings,
		}, nil
	case "hooks.jsonl":
		// hooks.jsonl tailer. The cursor (fromOffset) is a byte
		// offset into the file — parseHooksJSONL seeks past it and
		// emits one ToolEvent (and sometimes a TokenEvent) per
		// complete JSON line. Partial trailing lines stay
		// unconsumed so the next tail call picks them up.
		tools, tokens, newOffset, warnings, err := parseHooksJSONL(ctx, path, fromOffset, a.scrubber)
		if err != nil {
			return adapter.ParseResult{NewOffset: fromOffset}, fmt.Errorf("clinecli.ParseSessionFile: %w", err)
		}
		return adapter.ParseResult{
			ToolEvents:  tools,
			TokenEvents: tokens,
			NewOffset:   newOffset,
			Warnings:    warnings,
		}, nil
	default:
		return adapter.ParseResult{NewOffset: fromOffset}, nil
	}
}
