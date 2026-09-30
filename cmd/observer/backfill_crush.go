package main

// backfill_crush.go — the correcting half of `observer backfill
// --crush-rescan`.
//
// WHY A RESCAN IS NOT ENOUGH. The Crush adapter reports session-level
// usage (one `tokens:<session id>` row per session). Before 2026-09-27
// it reported the session's prompt/completion counters for every
// session, but Crush OVERWRITES those counters with the LAST step's
// context size, so a multi-step session stored a snapshot (live:
// session 30bc155f kept 8975/5 where the truth is 0/0 + Crush's own
// $0.0863). The fixed parser emits the corrected values under the SAME
// event id, but the store's token upsert is MAX-monotone by design, so a
// plain rescan can never lower the stored row.
//
// WHAT THIS PASS DOES. After the ordinary crush rescan (the table row in
// buildRescanPasses, which inserts anything new), it re-parses every
// crush.db that already holds token rows from watermark 0 and hands the
// fresh parse to store.CorrectTokenEvents, which makes the stored rows
// of the sessions the parse observed equal to it: changed rows are
// updated in place (re-sent to the org by agent migration 140's
// trigger) - including the reliability column, which the upsert never
// rewrites - and rows the parse no longer emits are deleted as a
// correction (tombstoned on the org by migration 141; no retention
// marker). Since 2026-09-28 the parser emits a row for EVERY non-vacant
// session: a session whose counts are not reportable (multi-step, or no
// counters) carries its model + Crush's own cost (zero included) with
// 0/0 counts and reliability "unknown". So a zero-cost MULTI-step
// session's stale snapshot is now corrected IN PLACE (model kept) rather
// than deleted, and one the 2026-09-27 parser never stored is inserted
// by the ordinary rescan that runs first. A zero-cost one-step session
// keeps its row and its real counts. No schema change, idempotent,
// crush rows only.

import (
	"context"
	"fmt"
	"os"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// CrushTokenCorrectionReport summarises the correcting pass of
// --crush-rescan.
type CrushTokenCorrectionReport struct {
	// FilesChecked is the number of crush.db files re-parsed.
	FilesChecked int `json:"files_checked"`
	// FilesMissing were referenced by stored rows but are gone from disk;
	// their rows are left alone (nothing authoritative to correct from).
	FilesMissing int `json:"files_missing"`
	// Errors counts files whose re-parse or correction failed; the pass
	// continues with the next file.
	Errors int `json:"errors"`
	store.TokenCorrection
}

// crushParseFunc re-parses one crush.db from watermark 0. Injected so the
// pass is testable without the adapter's filesystem discovery.
type crushParseFunc func(ctx context.Context, path string) (adapter.ParseResult, error)

// runCrushTokenCorrection runs the correcting pass over every crush.db
// that already has token_usage rows.
func runCrushTokenCorrection(ctx context.Context, st *store.Store, parse crushParseFunc) (CrushTokenCorrectionReport, error) {
	var rep CrushTokenCorrectionReport
	files, err := st.TokenSourceFiles(ctx, models.ToolCrush)
	if err != nil {
		return rep, fmt.Errorf("crush token correction: %w", err)
	}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			rep.FilesMissing++
			continue
		}
		res, err := parse(ctx, f)
		if err != nil {
			rep.Errors++
			continue
		}
		rep.FilesChecked++
		c, err := st.CorrectTokenEvents(ctx, models.ToolCrush, f, observedSessions(res), res.TokenEvents)
		if err != nil {
			rep.Errors++
			continue
		}
		rep.Examined += c.Examined
		rep.Updated += c.Updated
		rep.Deleted += c.Deleted
		rep.Missing += c.Missing
	}
	return rep, nil
}

// observedSessions is every session id a parse emitted any row for. Only
// these sessions' stored token rows are in scope for correction: a
// session the tool itself deleted keeps its history.
func observedSessions(res adapter.ParseResult) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, e := range res.ToolEvents {
		add(e.SessionID)
	}
	for _, e := range res.TokenEvents {
		add(e.SessionID)
	}
	return out
}
