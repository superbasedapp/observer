package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Prompt-submit "reconsider-once" persistence (migration 110,
// docs/plans/prompt-submit-intervention-exploration-2026-09-07.md §5.4).
//
// OWNERSHIP INVARIANT (CLAUDE.md module-boundary rule 4) — this file is
// the ONE owner of guard_prompt_reconsider. No other code may
// INSERT/UPDATE/DELETE it. Every write is a single statement (no
// multi-step transaction is needed for this table's shape), and every
// helper is failure-isolated by the same contract as internal/store/
// guard.go: callers on hot paths (the prompt-submit hook, the pure
// reconsider-once engine in internal/guard) treat a returned error as
// log-and-continue, never as a reason to fail the hook reply.
//
// FAIL-CLOSED CONTRACT — ConfirmPromptReconsider treats BOTH "no such
// fingerprint" and "fingerprint expired" as found=false, never as an
// error. A caller must never read found=false as "confirmed" — it means
// "there was nothing to confirm", so the caller's state machine should
// treat this send as a FRESH interrupt (§5.3 "expired, re-interrupted"),
// not silently let it through.
//
// MODULE-BOUNDARY NOTE — PromptReconsiderRow is the store's own
// SQL-shaped type, not a policy/guard domain type (the cachetrack /
// GuardEventRow precedent: domain types do not leak past the store
// seam). The pure reconsider-once engine (internal/guard) translates its
// own domain types into/out of this row shape at the boundary.

// PromptReconsiderRow is one guard_prompt_reconsider row.
type PromptReconsiderRow struct {
	Fingerprint string
	SessionID   string
	Tool        string
	Detectors   string // comma-joined detector ids
	WarnedAt    time.Time
	ConfirmedAt time.Time // zero value means NULL / not yet confirmed
	ExpiresAt   time.Time
}

// promptStamp/parsePromptStamp convert between time.Time and this
// table's INTEGER unix-nanoseconds columns (F8, round-2 review):
// warned_at/confirmed_at/expires_at deliberately do NOT use the
// package's usual timestamp()/parseStamp() RFC3339Nano TEXT
// convention. RFC3339Nano trims trailing zero fractional digits, so
// two stamps can compare LEXICOGRAPHICALLY out of chronological order
// across a sub-second boundary ("…10:00:00Z" sorts AFTER
// "…10:00:00.5Z" as TEXT despite being chronologically later) — and
// this table's Confirm/Prune queries compare these columns directly in
// SQL (`WHERE expires_at > ?` / `< ?`), so a TEXT column would
// intermittently mis-order a live grant as expired or vice versa.
// INTEGER unix nanoseconds compare correctly with ordinary numeric
// `<`/`>` regardless of fractional width — the same representation
// internal/store/remotesession.go already uses for created_at/
// last_seen for the identical reason.
func promptStamp(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().UnixNano()
}

func parsePromptStamp(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}

// LookupPromptReconsider looks up an active (non-expired, per `now`)
// reconsider-once row by fingerprint. ok is false when no row exists OR
// the row has expired (expired rows are treated as a miss by this
// lookup — callers that need to distinguish "never warned" from "warned
// but expired" should compare expires_at themselves if ever needed; v1
// callers only need the miss/hit distinction).
func (s *Store) LookupPromptReconsider(ctx context.Context, fingerprint string, now time.Time) (PromptReconsiderRow, bool, error) {
	if fingerprint == "" {
		return PromptReconsiderRow{}, false, nil
	}
	var row PromptReconsiderRow
	var warnedAt, expiresAt int64
	var confirmedAt sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT fingerprint, session_id, COALESCE(tool,''), detectors,
		       warned_at, confirmed_at, expires_at
		  FROM guard_prompt_reconsider
		 WHERE fingerprint = ?`, fingerprint).Scan(
		&row.Fingerprint, &row.SessionID, &row.Tool, &row.Detectors,
		&warnedAt, &confirmedAt, &expiresAt,
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return PromptReconsiderRow{}, false, nil
	case err != nil:
		return PromptReconsiderRow{}, false, fmt.Errorf("store.LookupPromptReconsider: %w", err)
	}
	row.WarnedAt = parsePromptStamp(warnedAt)
	row.ExpiresAt = parsePromptStamp(expiresAt)
	if confirmedAt.Valid {
		row.ConfirmedAt = parsePromptStamp(confirmedAt.Int64)
	}
	if !row.ExpiresAt.IsZero() && !now.Before(row.ExpiresAt) {
		// Expired: treated as a miss (fresh-interrupt territory), not an
		// error — the row still exists and PrunePromptReconsider will
		// eventually sweep it.
		return PromptReconsiderRow{}, false, nil
	}
	return row, true, nil
}

// RecordPromptWarned inserts a fresh reconsider-once row (the first
// interrupt for this fingerprint) — or REPLACES an existing row for the
// same fingerprint (INSERT OR REPLACE, since a fingerprint that already
// expired and is being re-warned should reset warned_at/expires_at and
// clear confirmed_at, matching the §5.3 "expired, re-interrupted" state-
// machine outcome).
func (s *Store) RecordPromptWarned(ctx context.Context, row PromptReconsiderRow) error {
	if row.Fingerprint == "" {
		return errors.New("store.RecordPromptWarned: fingerprint required")
	}
	if row.SessionID == "" {
		return errors.New("store.RecordPromptWarned: session_id required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO guard_prompt_reconsider
		    (fingerprint, session_id, tool, detectors, warned_at, confirmed_at, expires_at)
		VALUES (?, ?, ?, ?, ?, NULL, ?)`,
		row.Fingerprint, row.SessionID, nullableString(row.Tool), row.Detectors,
		promptStamp(row.WarnedAt), promptStamp(row.ExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("store.RecordPromptWarned: %w", err)
	}
	return nil
}

// ConfirmPromptReconsider stamps confirmed_at = now on the row matching
// fingerprint, IF it exists and has not already expired as of now (per
// expires_at). Returns (found bool, err error); found is false when the
// fingerprint has no row or the row already expired — callers must NOT
// treat "not found" as an error, just as "there was nothing to confirm"
// (fail-closed: an expired/missing row means the caller should treat
// this as a FRESH interrupt, not a confirmation).
func (s *Store) ConfirmPromptReconsider(ctx context.Context, fingerprint string, now time.Time) (bool, error) {
	if fingerprint == "" {
		return false, nil
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE guard_prompt_reconsider
		   SET confirmed_at = ?
		 WHERE fingerprint = ? AND expires_at > ?`,
		promptStamp(now), fingerprint, promptStamp(now),
	)
	if err != nil {
		return false, fmt.Errorf("store.ConfirmPromptReconsider: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store.ConfirmPromptReconsider: rows affected: %w", err)
	}
	return n > 0, nil
}

// CountPromptReconsider reports (total, expiredButNotYetPruned) rows in
// guard_prompt_reconsider as of now — the `observer guard prompt status`
// summary (Part B item 4). expired counts rows PrunePromptReconsider
// would remove on its next sweep; it is a subset of total, never
// double-counted against it.
func (s *Store) CountPromptReconsider(ctx context.Context, now time.Time) (total, expired int, err error) {
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM guard_prompt_reconsider`).Scan(&total); err != nil {
		return 0, 0, fmt.Errorf("store.CountPromptReconsider: total: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM guard_prompt_reconsider WHERE expires_at < ?`, promptStamp(now),
	).Scan(&expired); err != nil {
		return 0, 0, fmt.Errorf("store.CountPromptReconsider: expired: %w", err)
	}
	return total, expired, nil
}

// ListPromptReconsider returns up to limit guard_prompt_reconsider rows,
// most-recently-warned first — the dashboard Security page's "pending
// reconsider grants" list (PHASE-3b-DASHBOARD,
// docs/plans/prompt-submit-intervention-exploration-2026-09-07.md §8.2).
// Unlike LookupPromptReconsider this does NOT filter out expired rows —
// the dashboard wants to show an expiring-soon or just-expired grant too
// (Confirmed distinguishes a resolved grant from one still pending an
// answer); callers that only want the live count should keep using
// CountPromptReconsider. limit<=0 defaults to 200. Detectors is the
// comma-joined detector TYPE list already stored on the row — never a
// matched value or prompt span (see the package doc comment).
func (s *Store) ListPromptReconsider(ctx context.Context, limit int) ([]PromptReconsiderRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT fingerprint, session_id, COALESCE(tool,''), detectors,
		       warned_at, confirmed_at, expires_at
		  FROM guard_prompt_reconsider
		 ORDER BY warned_at DESC
		 LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListPromptReconsider: %w", err)
	}
	defer rows.Close()
	var out []PromptReconsiderRow
	for rows.Next() {
		var row PromptReconsiderRow
		var warnedAt, expiresAt int64
		var confirmedAt sql.NullInt64
		if err := rows.Scan(&row.Fingerprint, &row.SessionID, &row.Tool, &row.Detectors,
			&warnedAt, &confirmedAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("store.ListPromptReconsider: scan: %w", err)
		}
		row.WarnedAt = parsePromptStamp(warnedAt)
		row.ExpiresAt = parsePromptStamp(expiresAt)
		if confirmedAt.Valid {
			row.ConfirmedAt = parsePromptStamp(confirmedAt.Int64)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListPromptReconsider: rows: %w", err)
	}
	return out, nil
}

// DeletePromptReconsider removes ONE guard_prompt_reconsider row by
// fingerprint, regardless of expiry — the `observer guard prompt clear
// <fingerprint>` seam (Part B item 4). Returns whether a row existed.
// Distinct from PrunePromptReconsider (age-based sweep of every
// expired row): this is a single, explicit, operator-requested
// removal — e.g. to force a fresh ask-once interrupt on the next
// identical resend without waiting out the TTL.
func (s *Store) DeletePromptReconsider(ctx context.Context, fingerprint string) (bool, error) {
	if fingerprint == "" {
		return false, errors.New("store.DeletePromptReconsider: fingerprint required")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM guard_prompt_reconsider WHERE fingerprint = ?`, fingerprint)
	if err != nil {
		return false, fmt.Errorf("store.DeletePromptReconsider: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store.DeletePromptReconsider: rows affected: %w", err)
	}
	return n > 0, nil
}

// DeleteAllPromptReconsider empties guard_prompt_reconsider —
// `observer guard prompt clear --all`. Returns the count removed.
func (s *Store) DeleteAllPromptReconsider(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM guard_prompt_reconsider`)
	if err != nil {
		return 0, fmt.Errorf("store.DeleteAllPromptReconsider: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store.DeleteAllPromptReconsider: rows affected: %w", err)
	}
	return int(n), nil
}

// PrunePromptReconsider deletes every row whose expires_at is before
// now, regardless of confirmed state (an old grant, confirmed or not,
// has no further value once its TTL is long past — this is a
// straightforward age-based sweep, unlike PruneGuardRows' retention-days
// chain-checkpoint machinery, because this table carries no tamper-
// evident hash chain). Returns the count removed.
func (s *Store) PrunePromptReconsider(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM guard_prompt_reconsider WHERE expires_at < ?`, promptStamp(now))
	if err != nil {
		return 0, fmt.Errorf("store.PrunePromptReconsider: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store.PrunePromptReconsider: rows affected: %w", err)
	}
	return int(n), nil
}
