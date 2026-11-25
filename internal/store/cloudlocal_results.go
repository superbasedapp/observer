package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// cloudlocal_results.go holds the cloud_results / cloud_result_overrides half
// of the cloud-intelligence store seam (cloudlocal.go describes the whole seam).

// -- Results + overrides -----------------------------------------------------

// UpsertCloudResult stores a validated enrichment result for a session. If a
// prior newest result exists for the session it is marked superseded_by the new
// row (a regeneration). If r.ID is empty a random id is minted; the id is
// returned.
func (s *Store) UpsertCloudResult(ctx context.Context, r CloudResult) (string, error) {
	if r.SessionID == "" {
		return "", errors.New("store.UpsertCloudResult: session id is required")
	}
	if r.ResultJSON == "" {
		return "", errors.New("store.UpsertCloudResult: result json is required")
	}
	if r.ID == "" {
		id, err := cloudRandomID("res_")
		if err != nil {
			return "", fmt.Errorf("store.UpsertCloudResult: %w", err)
		}
		r.ID = id
	}
	if r.ReceivedAt.IsZero() {
		r.ReceivedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store.UpsertCloudResult: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// A row with this id already stored is a RE-PULL of the same result (the
	// results cursor was reset at sign-in, or a retry): update it in place and
	// leave the supersede chain alone. Chaining here would mark the session's
	// newer result superseded by this older one and leave no current result.
	var existing int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM cloud_results WHERE id = ?`, r.ID).Scan(&existing); err != nil {
		return "", fmt.Errorf("store.UpsertCloudResult: %w", err)
	}

	// Find the current newest (non-superseded) result for this session so we
	// can chain it. Excludes the row we're about to insert.
	var priorID string
	if existing == 0 {
		err = tx.QueryRowContext(ctx, `
			SELECT id FROM cloud_results
			 WHERE session_id = ? AND superseded_by IS NULL AND id <> ?`,
			r.SessionID, r.ID).Scan(&priorID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			priorID = ""
		case err != nil:
			return "", fmt.Errorf("store.UpsertCloudResult: %w", err)
		}
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO cloud_results
		  (id, session_id, schema_version, result_json, model_route, prompt_hash,
		   tokens, cost_usd, received_at, superseded_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
		ON CONFLICT(id) DO UPDATE SET
		  session_id     = excluded.session_id,
		  schema_version = excluded.schema_version,
		  result_json    = excluded.result_json,
		  model_route    = excluded.model_route,
		  prompt_hash    = excluded.prompt_hash,
		  tokens         = excluded.tokens,
		  cost_usd       = excluded.cost_usd,
		  received_at    = excluded.received_at`,
		r.ID, r.SessionID, r.SchemaVersion, r.ResultJSON, r.Provenance.ModelRoute,
		r.Provenance.PromptHash, r.Provenance.Tokens, r.Provenance.CostUSD,
		cloudFormatTime(r.ReceivedAt))
	if err != nil {
		return "", fmt.Errorf("store.UpsertCloudResult: %w", err)
	}
	if priorID != "" {
		if _, err := tx.ExecContext(ctx,
			`UPDATE cloud_results SET superseded_by = ? WHERE id = ?`, r.ID, priorID); err != nil {
			return "", fmt.Errorf("store.UpsertCloudResult: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store.UpsertCloudResult: %w", err)
	}
	return r.ID, nil
}

// HasCloudResult reports whether a result with this id is already stored, so a
// re-pull (a reset results cursor) can skip one-time side effects such as the
// taxonomy tag merge the user may since have undone.
func (s *Store) HasCloudResult(ctx context.Context, id string) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM cloud_results WHERE id = ?`, id).Scan(&n); err != nil {
		return false, fmt.Errorf("store.HasCloudResult: %w", err)
	}
	return n > 0, nil
}

// SetCloudResultOverride records (or replaces) a user edit over a result field.
// User edits are keyed by (result_id, field); the value always wins on read.
func (s *Store) SetCloudResultOverride(ctx context.Context, resultID, field, userValue string) error {
	if resultID == "" || field == "" {
		return errors.New("store.SetCloudResultOverride: result id and field are required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cloud_result_overrides (result_id, field, user_value, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(result_id, field) DO UPDATE SET
		  user_value = excluded.user_value,
		  updated_at = excluded.updated_at`,
		resultID, field, userValue, cloudFormatTime(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("store.SetCloudResultOverride: %w", err)
	}
	return nil
}

// GetCloudSessionResult returns the newest (non-superseded) result for a
// session together with the effective per-field overrides. Override handling
// honors two rules (plan §6 CI-P5): the user edit always wins, and a
// regenerated result never clobbers an override — overrides are aggregated
// across ALL of the session's results (latest updated_at per field wins), so an
// override bound to a now-superseded result still applies to its replacement.
// ok=false means the session has no result.
func (s *Store) GetCloudSessionResult(ctx context.Context, sessionID string) (CloudResult, map[string]CloudResultOverride, bool, error) {
	var (
		r            CloudResult
		receivedAt   string
		supersededBy sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, session_id, schema_version, result_json, model_route, prompt_hash,
		       tokens, cost_usd, received_at, superseded_by
		  FROM cloud_results
		 WHERE session_id = ? AND superseded_by IS NULL
		 ORDER BY received_at DESC, id DESC
		 LIMIT 1`, sessionID).
		Scan(&r.ID, &r.SessionID, &r.SchemaVersion, &r.ResultJSON, &r.Provenance.ModelRoute,
			&r.Provenance.PromptHash, &r.Provenance.Tokens, &r.Provenance.CostUSD,
			&receivedAt, &supersededBy)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudResult{}, nil, false, nil
	}
	if err != nil {
		return CloudResult{}, nil, false, fmt.Errorf("store.GetCloudSessionResult: %w", err)
	}
	r.ReceivedAt = cloudParseTime(receivedAt)
	if supersededBy.Valid && supersededBy.String != "" {
		v := supersededBy.String
		r.SupersededBy = &v
	}

	// Aggregate overrides across every result of this session, keeping the
	// latest per field. A regeneration cannot clobber a user edit this way.
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.field, o.user_value, o.updated_at
		  FROM cloud_result_overrides o
		  JOIN cloud_results cr ON cr.id = o.result_id
		 WHERE cr.session_id = ?`, sessionID)
	if err != nil {
		return CloudResult{}, nil, false, fmt.Errorf("store.GetCloudSessionResult: %w", err)
	}
	defer func() { _ = rows.Close() }()
	overrides := map[string]CloudResultOverride{}
	for rows.Next() {
		var field, val, updated string
		if err := rows.Scan(&field, &val, &updated); err != nil {
			return CloudResult{}, nil, false, fmt.Errorf("store.GetCloudSessionResult: %w", err)
		}
		o := CloudResultOverride{Field: field, UserValue: val, UpdatedAt: cloudParseTime(updated)}
		if prev, ok := overrides[field]; !ok || o.UpdatedAt.After(prev.UpdatedAt) {
			overrides[field] = o
		}
	}
	if err := rows.Err(); err != nil {
		return CloudResult{}, nil, false, fmt.Errorf("store.GetCloudSessionResult: %w", err)
	}
	if len(overrides) == 0 {
		overrides = nil
	}
	return r, overrides, true, nil
}

// nullableCloudTime renders an optional time as a nullable stored stamp.
func nullableCloudTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return cloudFormatTime(*t)
}

// CloudResultsSummary returns the total stored results and the newest
// received_at (RFC3339Nano UTC string, "" when none — chronological via MAX).
func (s *Store) CloudResultsSummary(ctx context.Context) (total int, lastReceivedAt string, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MAX(received_at), '') FROM cloud_results`).
		Scan(&total, &lastReceivedAt)
	if err != nil {
		return 0, "", fmt.Errorf("store.CloudResultsSummary: %w", err)
	}
	return total, lastReceivedAt, nil
}
