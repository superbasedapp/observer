package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TokenCorrection reports what one CorrectTokenEvents call changed.
type TokenCorrection struct {
	// Examined is the number of stored rows in scope (the tool's rows
	// from the source file, for the sessions the re-parse observed).
	Examined int `json:"examined"`
	// Updated rows had token dims that differed from the fresh parse and
	// were rewritten in place to its values.
	Updated int `json:"updated"`
	// Deleted rows had no counterpart in the fresh parse and were removed
	// as a correction (never as retention ageing).
	Deleted int `json:"deleted"`
	// Missing counts fresh events with no stored row; they are left to
	// the normal Ingest path (a rescan inserts them), never inserted here.
	Missing int `json:"missing"`
}

// storedTokenRow is the token-dimension projection CorrectTokenEvents
// compares. Nullable columns are read through COALESCE so NULL and 0 are
// the same value, exactly as the org push reads them.
type storedTokenRow struct {
	id                  int64
	sessionID           string
	sourceEventID       string
	model               string
	input, output       int64
	cacheRead           int64
	cacheCreation       int64
	cacheCreation1h     int64
	reasoning           int64
	cost                float64
	source, reliability string
}

// CorrectTokenEvents makes the stored token_usage rows of one tool and
// one source file agree with an AUTHORITATIVE re-parse of that file, for
// the sessions the re-parse observed.
//
// It exists because InsertTokenEvents' ON CONFLICT is MAX-monotone on
// purpose - a partial re-parse of an in-flight request must never lower
// a stored count - which also means a FIXED adapter can never lower a
// count its older parser over-reported. This is the one path allowed to
// (driven by an explicit backfill, never by live ingest):
//
//   - a stored row whose token dims (model, input, output, cache read /
//     creation / 1h creation, reasoning, cost, source, reliability) differ
//     from the fresh event with the same source_event_id is UPDATED in
//     place. The row keeps its id, so the org re-send trigger (agent
//     migration 140, org_push_change_token_usage) queues it and the org
//     applies the newer node revision. An empty fresh model never clears
//     a stored one.
//   - a stored row with NO fresh counterpart, for a session the re-parse
//     observed, is DELETED as a correction: the retention marker is NOT
//     set, so migration 141's delete trigger records an org tombstone.
//     A session the re-parse did not observe is never touched (a session
//     the tool itself deleted keeps its history).
//   - a fresh event with no stored row is only counted (Missing); the
//     caller's normal Ingest inserts it, so this seam never duplicates the
//     insert path.
//
// Everything runs in one transaction. Idempotent: a second call with the
// same parse finds nothing to change, and an unchanged row is never
// rewritten, so no re-send is queued. Events whose Tool or SourceFile do
// not match the arguments are ignored.
func (s *Store) CorrectTokenEvents(ctx context.Context, tool, sourceFile string, sessions []string, events []models.TokenEvent) (TokenCorrection, error) {
	var out TokenCorrection
	if tool == "" || sourceFile == "" || len(sessions) == 0 {
		return out, nil
	}
	inScope := make(map[string]bool, len(sessions))
	for _, id := range sessions {
		if id != "" {
			inScope[id] = true
		}
	}
	fresh := make(map[string]models.TokenEvent, len(events))
	for _, e := range events {
		if e.Tool != tool || e.SourceFile != sourceFile || e.SourceEventID == "" {
			continue
		}
		fresh[e.SourceEventID] = e
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, fmt.Errorf("store.CorrectTokenEvents: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stored, err := loadStoredTokenRows(ctx, tx, tool, sourceFile)
	if err != nil {
		return out, err
	}
	seen := make(map[string]bool, len(stored))
	for _, r := range stored {
		if !inScope[r.sessionID] {
			continue
		}
		out.Examined++
		seen[r.sourceEventID] = true
		e, ok := fresh[r.sourceEventID]
		if !ok {
			if _, err := tx.ExecContext(ctx, `DELETE FROM token_usage WHERE id = ?`, r.id); err != nil {
				return out, fmt.Errorf("store.CorrectTokenEvents: delete: %w", err)
			}
			out.Deleted++
			continue
		}
		if tokenRowMatches(r, e) {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE token_usage SET
			model = COALESCE(NULLIF(?, ''), model),
			input_tokens = ?, output_tokens = ?,
			cache_read_tokens = ?, cache_creation_tokens = ?,
			cache_creation_1h_tokens = ?, reasoning_tokens = ?,
			estimated_cost_usd = ?, source = ?, reliability = ?
			WHERE id = ?`,
			e.Model, e.InputTokens, e.OutputTokens,
			e.CacheReadTokens, e.CacheCreationTokens,
			nullableInt64(e.CacheCreation1hTokens), e.ReasoningTokens,
			e.EstimatedCostUSD, e.Source, e.Reliability, r.id); err != nil {
			return out, fmt.Errorf("store.CorrectTokenEvents: update: %w", err)
		}
		out.Updated++
	}
	for id, e := range fresh {
		if !seen[id] && inScope[e.SessionID] {
			out.Missing++
		}
	}
	if err := tx.Commit(); err != nil {
		return out, fmt.Errorf("store.CorrectTokenEvents: commit: %w", err)
	}
	return out, nil
}

// TokenSourceFiles returns the distinct source files that hold token_usage
// rows for tool, sorted. It is how a correcting backfill finds the files
// whose stored rows it must re-check.
func (s *Store) TokenSourceFiles(ctx context.Context, tool string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT source_file FROM token_usage
		WHERE tool = ? AND COALESCE(source_file, '') != '' ORDER BY source_file`, tool)
	if err != nil {
		return nil, fmt.Errorf("store.TokenSourceFiles: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			return nil, fmt.Errorf("store.TokenSourceFiles: scan: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func loadStoredTokenRows(ctx context.Context, tx *sql.Tx, tool, sourceFile string) ([]storedTokenRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, session_id, COALESCE(source_event_id, ''),
		COALESCE(model, ''), COALESCE(input_tokens, 0), COALESCE(output_tokens, 0),
		COALESCE(cache_read_tokens, 0), COALESCE(cache_creation_tokens, 0),
		COALESCE(cache_creation_1h_tokens, 0), COALESCE(reasoning_tokens, 0),
		COALESCE(estimated_cost_usd, 0), COALESCE(source, ''), COALESCE(reliability, '')
		FROM token_usage WHERE tool = ? AND source_file = ? ORDER BY id`, tool, sourceFile)
	if err != nil {
		return nil, fmt.Errorf("store.CorrectTokenEvents: load: %w", err)
	}
	defer rows.Close()
	var out []storedTokenRow
	for rows.Next() {
		var r storedTokenRow
		if err := rows.Scan(&r.id, &r.sessionID, &r.sourceEventID, &r.model,
			&r.input, &r.output, &r.cacheRead, &r.cacheCreation, &r.cacheCreation1h,
			&r.reasoning, &r.cost, &r.source, &r.reliability); err != nil {
			return nil, fmt.Errorf("store.CorrectTokenEvents: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// tokenRowMatches reports whether a stored row already carries the fresh
// event's token dims. An empty fresh model matches any stored model (the
// update would keep it anyway); cost compares within a float tolerance.
func tokenRowMatches(r storedTokenRow, e models.TokenEvent) bool {
	return (e.Model == "" || e.Model == r.model) &&
		r.input == e.InputTokens && r.output == e.OutputTokens &&
		r.cacheRead == e.CacheReadTokens && r.cacheCreation == e.CacheCreationTokens &&
		r.cacheCreation1h == e.CacheCreation1hTokens && r.reasoning == e.ReasoningTokens &&
		math.Abs(r.cost-e.EstimatedCostUSD) < 1e-12 &&
		r.source == e.Source && r.reliability == e.Reliability
}
