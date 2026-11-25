//go:build !sbo_omit_egress_aggregate_share

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/aggregate"
)

// aggregate.go is the SINGLE store seam for the opt-in aggregate rail's
// node-local state (design §6.5): the per-month submission ledger
// (aggregate_submissions) and the single-row consent receipt
// (aggregate_consent), both created by migration 062. These tables are
// NODE-LOCAL — pinned in tests/invariant/privacy_test.go and never named in
// internal/store/orgpush.go, so they can never enter the Teams wire. The rail
// is org-independent; nothing here round-trips through org-push.

// Aggregate submission states (design §6.5). A month is marked Submitted only
// after a confirmed collector success; on response loss the persisted
// submission_id is reused so a retry cannot double-count.
const (
	AggregateStatePending   = "pending"
	AggregateStateSubmitted = "submitted"
	AggregateStateFailed    = "failed"
)

// aggregateConsentRowID is the fixed primary key of the single-row
// aggregate_consent table.
const aggregateConsentRowID = 1

// AggregateSubmissionRow is one row of the per-month submission ledger. It
// holds only month/hash/state/attempt bookkeeping plus a bounded snapshot of
// the content-free allow-listed payload (design §6.5) — no project paths,
// prompts, or model ids can appear (the wire allow-list guarantees it).
type AggregateSubmissionRow struct {
	Month         string
	PayloadHash   string
	SubmissionID  string
	SchemaVersion int
	Attempts      int
	State         string
	PayloadJSON   string
	LastError     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// LoadAggregateState returns the ledger row for month, or (nil, nil) when no
// attempt has been recorded for it yet.
func (s *Store) LoadAggregateState(ctx context.Context, month string) (*AggregateSubmissionRow, error) {
	var (
		row                  AggregateSubmissionRow
		createdAt, updatedAt string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT month, payload_hash, submission_id, schema_version, attempts, state,
		       payload_json, last_error, created_at, updated_at
		  FROM aggregate_submissions WHERE month = ?`, month).
		Scan(&row.Month, &row.PayloadHash, &row.SubmissionID, &row.SchemaVersion,
			&row.Attempts, &row.State, &row.PayloadJSON, &row.LastError, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store.LoadAggregateState: %w", err)
	}
	row.CreatedAt = parseStoredTime(createdAt)
	row.UpdatedAt = parseStoredTime(updatedAt)
	return &row, nil
}

// ListAggregateStates returns every ledger row, newest month first, for
// `observer aggregate status`.
func (s *Store) ListAggregateStates(ctx context.Context) ([]AggregateSubmissionRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT month, payload_hash, submission_id, schema_version, attempts, state,
		       payload_json, last_error, created_at, updated_at
		  FROM aggregate_submissions ORDER BY month DESC`)
	if err != nil {
		return nil, fmt.Errorf("store.ListAggregateStates: %w", err)
	}
	defer rows.Close()
	var out []AggregateSubmissionRow
	for rows.Next() {
		var (
			row                  AggregateSubmissionRow
			createdAt, updatedAt string
		)
		if err := rows.Scan(&row.Month, &row.PayloadHash, &row.SubmissionID, &row.SchemaVersion,
			&row.Attempts, &row.State, &row.PayloadJSON, &row.LastError, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("store.ListAggregateStates: scan: %w", err)
		}
		row.CreatedAt = parseStoredTime(createdAt)
		row.UpdatedAt = parseStoredTime(updatedAt)
		out = append(out, row)
	}
	return out, rows.Err()
}

// StartAggregateAttempt records (or refreshes) a pending attempt for month
// BEFORE any network send, minting a submission_id on first attempt and
// REUSING it on retry so a lost collector response cannot cause a double count
// (design §3.1/§6.5, finding #14). It increments the attempt counter, stamps
// the payload hash + bounded JSON snapshot, and returns the submission_id to
// stamp into the outbound payload. Idempotent per month.
func (s *Store) StartAggregateAttempt(ctx context.Context, month, submissionID, payloadHash, payloadJSON string, schemaVersion int, now time.Time) (string, error) {
	existing, err := s.LoadAggregateState(ctx, month)
	if err != nil {
		return "", err
	}
	ts := formatAggTime(now)
	if existing != nil {
		// Reuse the persisted submission_id (retry safety); refresh the
		// payload snapshot in case the corpus changed between attempts.
		if existing.State == AggregateStateSubmitted {
			return existing.SubmissionID, nil
		}
		id := existing.SubmissionID
		if id == "" {
			id = submissionID
		}
		if _, err := s.db.ExecContext(ctx, `
			UPDATE aggregate_submissions
			   SET payload_hash = ?, submission_id = ?, schema_version = ?,
			       attempts = attempts + 1, state = ?, payload_json = ?, updated_at = ?
			 WHERE month = ?`,
			payloadHash, id, schemaVersion, AggregateStatePending, payloadJSON, ts, month); err != nil {
			return "", fmt.Errorf("store.StartAggregateAttempt: update: %w", err)
		}
		return id, nil
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO aggregate_submissions
			(month, payload_hash, submission_id, schema_version, attempts, state, payload_json, last_error, created_at, updated_at)
		VALUES (?, ?, ?, ?, 1, ?, ?, '', ?, ?)`,
		month, payloadHash, submissionID, schemaVersion, AggregateStatePending, payloadJSON, ts, ts); err != nil {
		return "", fmt.Errorf("store.StartAggregateAttempt: insert: %w", err)
	}
	return submissionID, nil
}

// MarkAggregateSubmitted flips month to the submitted terminal state after a
// confirmed collector success (design §6.5). Clears any prior error.
func (s *Store) MarkAggregateSubmitted(ctx context.Context, month string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE aggregate_submissions SET state = ?, last_error = '', updated_at = ?
		 WHERE month = ?`, AggregateStateSubmitted, formatAggTime(now), month)
	if err != nil {
		return fmt.Errorf("store.MarkAggregateSubmitted: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.MarkAggregateSubmitted: no ledger row for month %q", month)
	}
	return nil
}

// MarkAggregateFailed records a failed attempt for month with a bounded error
// string, leaving the row retryable (design §6.5).
func (s *Store) MarkAggregateFailed(ctx context.Context, month, errMsg string, now time.Time) error {
	const maxErr = 500
	if len(errMsg) > maxErr {
		errMsg = errMsg[:maxErr]
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE aggregate_submissions SET state = ?, last_error = ?, updated_at = ?
		 WHERE month = ?`, AggregateStateFailed, errMsg, formatAggTime(now), month); err != nil {
		return fmt.Errorf("store.MarkAggregateFailed: %w", err)
	}
	return nil
}

// SaveConsentReceipt writes (replacing any prior) the single-row consent
// receipt (design §9.1). It records exactly what the operator consented to so
// a later material change is detectable by CheckConsent.
func (s *Store) SaveConsentReceipt(ctx context.Context, r aggregate.Receipt) error {
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO aggregate_consent
			(id, schema_version, endpoint, pricing_version, cost_method_version,
			 tool_registry_version, actor, disclosure_hash, scope_db_path, consented_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')
		ON CONFLICT(id) DO UPDATE SET
			schema_version = excluded.schema_version,
			endpoint = excluded.endpoint,
			pricing_version = excluded.pricing_version,
			cost_method_version = excluded.cost_method_version,
			tool_registry_version = excluded.tool_registry_version,
			actor = excluded.actor,
			disclosure_hash = excluded.disclosure_hash,
			scope_db_path = excluded.scope_db_path,
			consented_at = excluded.consented_at,
			revoked_at = ''`,
		aggregateConsentRowID, r.SchemaVersion, aggregate.NormalizeEndpoint(r.Endpoint),
		r.PricingVersion, r.CostMethodVersion, r.ToolRegistryVersion, r.Actor,
		r.DisclosureHash, r.ScopeDBPath, formatAggTime(r.ConsentedAt)); err != nil {
		return fmt.Errorf("store.SaveConsentReceipt: %w", err)
	}
	return nil
}

// LoadConsentReceipt returns the current (non-revoked) consent receipt, or
// (nil, nil) when none exists or it has been revoked. A revoked receipt is
// treated as absent so CheckConsent returns ConsentMissing/ConsentRevoked
// rather than a stale ConsentValid.
func (s *Store) LoadConsentReceipt(ctx context.Context) (*aggregate.Receipt, error) {
	var (
		r           aggregate.Receipt
		consentedAt string
		revokedAt   string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT schema_version, endpoint, pricing_version, cost_method_version,
		       tool_registry_version, actor, disclosure_hash, scope_db_path, consented_at, revoked_at
		  FROM aggregate_consent WHERE id = ?`, aggregateConsentRowID).
		Scan(&r.SchemaVersion, &r.Endpoint, &r.PricingVersion, &r.CostMethodVersion,
			&r.ToolRegistryVersion, &r.Actor, &r.DisclosureHash, &r.ScopeDBPath, &consentedAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store.LoadConsentReceipt: %w", err)
	}
	if revokedAt != "" {
		return nil, nil
	}
	r.ConsentedAt = parseStoredTime(consentedAt)
	return &r, nil
}

// RevokeConsent marks the receipt revoked (design §9.5): future submissions
// stop. It does NOT delete the row (so `status` can show when consent was
// revoked) and is idempotent — a no-op when no receipt exists.
func (s *Store) RevokeConsent(ctx context.Context, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `
		UPDATE aggregate_consent SET revoked_at = ? WHERE id = ? AND revoked_at = ''`,
		formatAggTime(now), aggregateConsentRowID); err != nil {
		return fmt.Errorf("store.RevokeConsent: %w", err)
	}
	return nil
}

func formatAggTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
