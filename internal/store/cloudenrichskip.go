package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// cloudenrichskip.go is the durable node-local backoff seam behind the
// background enrichment sweep's permanently-failing-candidate skip
// (cmd/observer/cloudautoenrich.go). Before migration 120 the skip lived
// only in an in-memory map inside cloudAutoEnrichLoop, so a daemon restart
// forgot every skip and immediately retried a session whose consent spawn
// can never succeed (a malformed transcript, say), and
// ListCloudAutoEnrichCandidates's join kept re-surfacing it every tick.
// cloud_enrich_skips (migration 120) makes the skip survive a restart and
// puts the exclusion in SQL instead of in the scheduler's memory.
//
// Content-free by construction, same posture as every other cloud_* table:
// last_error_class is a short fixed CLASS token (e.g. "spawn_timeout" /
// "consent_spawn_failed"), never subprocess output. NODE-LOCAL: no org
// share key, no paired orgserver migration, joins the forbidden-table
// sentinel walked by tests/invariant/privacy_test.go.

// cloudEnrichSkipBaseBackoff / cloudEnrichSkipMaxBackoff bound the
// exponential backoff RecordCloudEnrichSkip applies: 1h * 2^(attempts-1),
// capped at 7 days, so a session that will never succeed is retried at a
// slowing cadence instead of hot-looping the sweep forever.
const (
	cloudEnrichSkipBaseBackoff = time.Hour
	cloudEnrichSkipMaxBackoff  = 7 * 24 * time.Hour
)

// cloudEnrichSkipBackoff returns the backoff duration for the given
// (1-based) attempt count, capped at cloudEnrichSkipMaxBackoff. Split out as
// its own function (rather than inlined) so a test can pin the exact table
// without duplicating the shift arithmetic, and so the shift itself is
// capped — a very large attempts count can never overflow into a negative
// or huge duration.
func cloudEnrichSkipBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	const maxShift = 8 // 1h*2^8 = 256h, already past the 168h (7d) cap.
	shift := attempts - 1
	if shift > maxShift {
		shift = maxShift
	}
	d := cloudEnrichSkipBaseBackoff * time.Duration(int64(1)<<uint(shift))
	if d > cloudEnrichSkipMaxBackoff {
		d = cloudEnrichSkipMaxBackoff
	}
	return d
}

// RecordCloudEnrichSkip upserts the durable backoff row for a session whose
// `observer cloud consent` spawn just failed: attempts increments (1 for a
// fresh row), next_at moves to now+cloudEnrichSkipBackoff(attempts), and
// last_error_class is overwritten with the content-free class string
// errClass (never subprocess output). Called once per failed spawn attempt
// from cmd/observer/cloudautoenrich.go's loop.
func (s *Store) RecordCloudEnrichSkip(ctx context.Context, sessionID, errClass string, now time.Time) error {
	const pfx = "store.RecordCloudEnrichSkip"
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// The backoff computation happens here in Go (over the current attempts
	// count), not in SQL, so cloudEnrichSkipBackoff stays independently
	// testable.
	var attempts int
	err := s.db.QueryRowContext(ctx, `SELECT attempts FROM cloud_enrich_skips WHERE session_id = ?`, sessionID).Scan(&attempts)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%s: %w", pfx, err)
	}
	attempts++
	nextAt := now.Add(cloudEnrichSkipBackoff(attempts))
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO cloud_enrich_skips (session_id, attempts, next_at, last_error_class, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(session_id) DO UPDATE SET
			attempts         = excluded.attempts,
			next_at          = excluded.next_at,
			last_error_class = excluded.last_error_class,
			updated_at       = excluded.updated_at`,
		sessionID, attempts, cloudFormatTime(nextAt), errClass, cloudFormatTime(now))
	if err != nil {
		return fmt.Errorf("%s: %w", pfx, err)
	}
	return nil
}

// ClearCloudEnrichSkip deletes a session's durable backoff row. Called after
// a successful consent spawn so a session that eventually succeeds carries
// no stale skip if it somehow becomes a candidate again later. Deleting a
// row that does not exist is not an error.
func (s *Store) ClearCloudEnrichSkip(ctx context.Context, sessionID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM cloud_enrich_skips WHERE session_id = ?`, sessionID); err != nil {
		return fmt.Errorf("store.ClearCloudEnrichSkip: %w", err)
	}
	return nil
}

// CloudEnrichSkip is one durable backoff row, exposed for tests and any
// future diagnostics surface (e.g. `observer doctor`).
type CloudEnrichSkip struct {
	SessionID      string
	Attempts       int
	NextAt         time.Time
	LastErrorClass string
	UpdatedAt      time.Time
}

// GetCloudEnrichSkip reads one session's durable backoff row. ok=false means
// the session has never failed a spawn, or its skip was cleared after a
// later success.
func (s *Store) GetCloudEnrichSkip(ctx context.Context, sessionID string) (CloudEnrichSkip, bool, error) {
	var nextAt, updatedAt string
	r := CloudEnrichSkip{SessionID: sessionID}
	err := s.db.QueryRowContext(ctx, `
		SELECT attempts, next_at, last_error_class, updated_at
		  FROM cloud_enrich_skips WHERE session_id = ?`, sessionID).
		Scan(&r.Attempts, &nextAt, &r.LastErrorClass, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudEnrichSkip{}, false, nil
	}
	if err != nil {
		return CloudEnrichSkip{}, false, fmt.Errorf("store.GetCloudEnrichSkip: %w", err)
	}
	r.NextAt = cloudParseTime(nextAt)
	r.UpdatedAt = cloudParseTime(updatedAt)
	return r, true, nil
}
