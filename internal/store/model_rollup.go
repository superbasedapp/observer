package store

import (
	"context"
	"fmt"
)

// rollupSessionModels fills sessions.model from token_usage.model for the
// given session ids (IDE-13 / plan C8).
//
// THE GAP. sessions.model is populated by UpsertSession from
// models.ToolEvent.Model at ingest time (see Ingest, above), but several
// adapters (codex, cursor, cline, cowork, ...) emit ToolEvents that never
// carry a Model — their per-call model only ever lands on the
// corresponding models.TokenEvent, via token_usage.model. A session whose
// only model-bearing signal is its token rows therefore keeps
// sessions.model == ” forever, even though the model is perfectly known
// one table over. UpsertSession's
// `model = COALESCE(NULLIF(excluded.model, ”), sessions.model)` merge
// rule only ever WIDENS from a non-empty incoming ToolEvent.Model — it
// has no path back to token_usage, so the two tables silently diverge for
// these adapters. This function is the store-seam repair: it runs the
// token_usage → sessions rollup directly, after the token batch has
// landed in a call to InsertTokenEvents.
//
// WHY THE NEWEST TOKEN ROW WINS. A session can span more than one model
// (a mid-session model switch), and token_usage already carries the full
// per-call history — that per-model detail is not lost by this rollup.
// sessions.model is a single summary column, and the most useful single
// value for "what model is/was this session on" is its most recent one,
// so the subquery orders by (timestamp DESC, id DESC) — id as the
// tiebreak for rows sharing a timestamp, since it reflects insert order.
//
// SAFETY. The UPDATE only ever touches a row whose model is currently
// NULL or ” (never overwrites a model a ToolEvent already supplied —
// UpsertSession's merge rule already protects that direction, this is
// belt-and-suspenders for the same invariant) and only when at least one
// of the session's token_usage rows actually carries a non-empty model —
// a session with zero model-bearing token rows is left untouched (stays
// ”, never set to NULL) rather than being touched with a no-op write.
func (s *Store) rollupSessionModels(ctx context.Context, sessionIDs []string) error {
	seen := make(map[string]struct{}, len(sessionIDs))
	ids := make([]string, 0, len(sessionIDs))
	for _, id := range sessionIDs {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil
	}

	stmt, err := s.db.PrepareContext(ctx, `
		UPDATE sessions
		SET model = (
			SELECT model FROM token_usage
			WHERE session_id = ? AND model IS NOT NULL AND model <> ''
			ORDER BY timestamp DESC, id DESC LIMIT 1
		)
		WHERE id = ?
		  AND (model IS NULL OR model = '')
		  AND EXISTS (
			SELECT 1 FROM token_usage WHERE session_id = ? AND model <> ''
		  )`)
	if err != nil {
		return fmt.Errorf("store.rollupSessionModels: prepare: %w", err)
	}
	defer stmt.Close()

	for _, id := range ids {
		if _, err := stmt.ExecContext(ctx, id, id, id); err != nil {
			return fmt.Errorf("store.rollupSessionModels: %w", err)
		}
	}
	return nil
}

// BackfillSessionModels applies the C8 sessions.model rollup (see
// rollupSessionModels above) set-based across every session in the DB,
// not just a just-ingested batch. It's the intended engine for a future
// `observer backfill --session-models` mode that repairs pre-existing
// rows written before this rollup existed (e.g. the codex/cursor/
// cline/cowork sessions IDE-13 found with sessions.model == ” despite a
// resolvable token_usage.model) — no such CLI mode is wired yet, this is
// just the store-side primitive it would call.
//
// Returns the number of session rows updated. Same safety rules as
// rollupSessionModels: only empty-model sessions with at least one
// model-bearing token_usage row are touched, and the newest token row
// (by timestamp, then id) wins.
func (s *Store) BackfillSessionModels(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE sessions
		SET model = (
			SELECT model FROM token_usage
			WHERE token_usage.session_id = sessions.id
			  AND token_usage.model IS NOT NULL AND token_usage.model <> ''
			ORDER BY token_usage.timestamp DESC, token_usage.id DESC LIMIT 1
		)
		WHERE (model IS NULL OR model = '')
		  AND EXISTS (
			SELECT 1 FROM token_usage
			WHERE token_usage.session_id = sessions.id AND token_usage.model <> ''
		  )`)
	if err != nil {
		return 0, fmt.Errorf("store.BackfillSessionModels: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store.BackfillSessionModels: rows affected: %w", err)
	}
	return n, nil
}
