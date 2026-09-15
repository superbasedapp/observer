package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/verbosity"
)

// verbosityorgrows.go is the W3.1 org-wire seam for the Output Composition
// (Verbosity) feature. It OWNS the actions.content_bytes reference for the
// org-push path — verbosity.go (the node read-side) already reads
// content_bytes for the dashboard/MCP surfaces, but this file is the one that
// turns it into a wire row, so orgpush.go never touches the actions table
// directly (module-boundary discipline: one owner per table/read seam).
//
// Unlike the Arc-4 day-bucketed summaries (cachesummary.go et al.), this
// aggregate is SESSION-scoped: one row per session, recomputed and upserted
// on every push over a trailing window (verbositySummaryWindowDays), mirroring
// cacheSummaryWindowDays's idempotent-recompute model. Output is BYTE COUNTS +
// a small canonical language→bytes/category array — no assistant text, no
// authored code, no path ever leaves this function.

// verbositySummaryWindowDays bounds the recompute to recently-active
// sessions; the server upserts by (org_id, session_id), so re-pushing a
// session already on the server is idempotent and simply refreshes its row.
const verbositySummaryWindowDays = 7

// SelectSessionVerbositySummaries recomputes the W3.1 output-composition wire
// row for every session started within the trailing window. It reuses the
// existing node read-side (LoadSessionVerbosity + AuthoredCaptureStats) rather
// than re-deriving the byte math, so the org panel's numbers are guaranteed
// to match the node's own VerbosityCard / MCP get_output_composition for the
// same session.
func (s *Store) SelectSessionVerbositySummaries(ctx context.Context) ([]orgcontract.SessionVerbosityRow, error) {
	since := isoSinceDays(verbositySummaryWindowDays)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM sessions WHERE started_at >= ? ORDER BY id`, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionVerbositySummaries: sessions: %w", err)
	}
	var sessionIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store.SelectSessionVerbositySummaries: scan: %w", err)
		}
		sessionIDs = append(sessionIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("store.SelectSessionVerbositySummaries: %w", err)
	}
	rows.Close()

	out := make([]orgcontract.SessionVerbosityRow, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		b, err := s.LoadSessionVerbosity(ctx, sessionID)
		if err != nil {
			return nil, fmt.Errorf("store.SelectSessionVerbositySummaries: %s: %w", sessionID, err)
		}
		captured, totalAuthored, err := s.AuthoredCaptureStats(ctx, sessionID)
		if err != nil {
			return nil, fmt.Errorf("store.SelectSessionVerbositySummaries: %s: %w", sessionID, err)
		}
		row, err := buildSessionVerbosityRow(sessionID, b, captured, totalAuthored)
		if err != nil {
			return nil, fmt.Errorf("store.SelectSessionVerbositySummaries: %s: %w", sessionID, err)
		}
		// Genuine no-activity: a session with no measured output composition
		// at all (no visible/written/command bytes, no authored actions)
		// ships nothing — the org rollup renders the absent row as a zeroed
		// panel, and every push would otherwise re-carry an all-zero row for
		// each windowed session.
		if row.TotalBytes == 0 && row.WrittenBytes == 0 && row.CommandBytes == 0 && totalAuthored == 0 {
			continue
		}
		out = append(out, row)
	}
	return out, nil
}

// buildSessionVerbosityRow shapes a Breakdown into the wire row — the org
// analog of internal/mcp/tools_output_composition.go::buildOutputComposition,
// splitting ByCategory() into six discrete fields (Prose/Code/Docs/Config/
// Data/Unknown) instead of a map, and JSON-encoding the per-language code
// split as orgcontract.VerbosityLanguageBytes entries.
func buildSessionVerbosityRow(sessionID string, b *verbosity.Breakdown, captured, totalAuthored int64) (orgcontract.SessionVerbosityRow, error) {
	cats := b.ByCategory()
	var total int64
	for _, v := range cats {
		total += v
	}

	langBytes := b.CodeByLang()
	langs := make([]orgcontract.VerbosityLanguageBytes, 0, len(langBytes))
	for lang, by := range langBytes {
		langs = append(langs, orgcontract.VerbosityLanguageBytes{
			Language: lang,
			Bytes:    by,
			Category: string(verbosity.CategoryOf(lang)),
		})
	}
	sort.Slice(langs, func(i, j int) bool {
		if langs[i].Bytes != langs[j].Bytes {
			return langs[i].Bytes > langs[j].Bytes
		}
		return langs[i].Language < langs[j].Language
	})
	langJSON, err := json.Marshal(langs)
	if err != nil {
		return orgcontract.SessionVerbosityRow{}, fmt.Errorf("marshal code_by_language: %w", err)
	}

	return orgcontract.SessionVerbosityRow{
		SessionID:    sessionID,
		TotalBytes:   total,
		CodeBytes:    b.CodeBytes(),
		ExplainBytes: b.ExplainBytes(),

		ProseBytes:   cats[verbosity.Prose],
		DocsBytes:    cats[verbosity.Docs],
		ConfigBytes:  cats[verbosity.Config],
		DataBytes:    cats[verbosity.Data],
		UnknownBytes: cats[verbosity.Unknown],

		NarrativeBytes:        b.Visible.NarrativeBytes,
		ArtifactBytes:         b.Visible.ArtifactBytes,
		ArtifactUntaggedBytes: b.Visible.ArtifactUntaggedBytes,
		WrittenBytes:          sumInt64Map(b.Written) + sumInt64Map(b.WrittenUnknownExt),
		CommandBytes:          sumInt64Map(b.Command),

		CodeByLanguageJSON: string(langJSON),
		AuthoredCaptured:   totalAuthored == 0 || captured > 0,
	}, nil
}

// sumInt64Map sums a language/dialect→bytes map. Duplicated (deliberately —
// not exported) from internal/mcp/tools_output_composition.go's helper of the
// same name: that one lives in package mcp, this one in package store, and
// neither package should import the other for a four-line helper.
func sumInt64Map(m map[string]int64) int64 {
	var total int64
	for _, v := range m {
		total += v
	}
	return total
}

// probeSessionVerbositySubstrate is the Track R2 change-detection probe for the
// session_verbosity wire. It lives here — with the wire's own SQL — so
// orgsnapgate.go and orgpush.go stay free of the table names.
//
// PROBE: the pair (MAX(sessions.rowid), MAX(actions.id)) — two index-endpoint
// seeks, O(1).
//
// WHY THAT REFLECTS MUTATION: this wire has TWO substrates, and both must be in
// the probe. The windowed `sessions` scan chooses WHICH sessions ship, while the
// per-session byte math (LoadSessionVerbosity + AuthoredCaptureStats) is derived
// entirely from `actions` rows. A session whose transcript keeps growing gains
// new action ids even though no new session row appears, so an actions-blind
// probe would freeze a live session's composition panel.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: an in-place UPDATE of an existing
// action's body columns (the ingest MAX-upgrade path) does not move either
// maximum; snapGate's maxSkipAge recomputes within the hour. The window slide
// itself is not a correctness concern — the server upserts by (org_id,
// session_id) and never deletes, so a session ageing out of the node's window
// simply stops being refreshed.
func (s *Store) probeSessionVerbositySubstrate(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `
		SELECT 's' || (SELECT COALESCE(MAX(rowid), 0) FROM sessions) ||
		       ':a' || (SELECT COALESCE(MAX(id), 0) FROM actions)`)
}
