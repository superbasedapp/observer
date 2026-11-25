package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Test-only API: none of these has a caller outside this package's tests.
// Production code reaches the same logic through reserveAllowanceTx,
// finalizeReservationTx and resolveActivateStatus. Test builds only.

// ReserveAllowance runs reserveAllowanceTx in its own tenant transaction.
func (s *Store) ReserveAllowance(ctx context.Context, accountID, feature string, now time.Time) (string, error) {
	var reservationID string
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		reservationID, e = reserveAllowanceTx(ctx, tx, accountID, feature, now, s.spendCeilings)
		return e
	})
	if err != nil {
		return "", err
	}
	return reservationID, nil
}

// SettleReservation marks a reservation settled: the user unit is CONSUMED
// (daily/monthly/global stay), only the concurrency slot is released. Idempotent.
func (s *Store) SettleReservation(ctx context.Context, accountID, reservationID string) error {
	return s.finalizeReservation(ctx, accountID, reservationID, "settled", false)
}

// ReleaseReservation marks a reservation released (or expired) and REFUNDS the
// user unit (daily/monthly/global decremented) plus the concurrency slot — for
// jobs that never produced a result (parked, evidence_expired, canceled).
// Idempotent.
func (s *Store) ReleaseReservation(ctx context.Context, accountID, reservationID string, expired bool) error {
	state := "released"
	if expired {
		state = "expired"
	}
	return s.finalizeReservation(ctx, accountID, reservationID, state, true)
}

// finalizeReservation runs finalizeReservationTx in its own tenant transaction.
func (s *Store) finalizeReservation(ctx context.Context, accountID, reservationID, newState string, refundUnit bool) error {
	return s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return finalizeReservationTx(ctx, tx, accountID, reservationID, newState, refundUnit)
	})
}

// ResolveActivateStatus is a thin, read-only export of resolveActivateStatus
// (same precedent as ClassifyPaddleEvent in paddle.go): the live-defect fix's
// (2026-09-12) status + trial-end decision for an "activate" action, WITHOUT
// touching the database. Used by table-driven tests.
func ResolveActivateStatus(ev PaddleEvent, existingStatus string, existingTrialEnd *time.Time) (status string, trialEnd *time.Time) {
	return resolveActivateStatus(ev, existingStatus, existingTrialEnd)
}

// NextMonthlyCycleStart returns the first instant of the next UTC calendar
// month — the cycle boundary a deferred downgrade starts at. It is anchored to
// exactly the window MonthlyWindowKey names, so an assignment that begins here
// begins with a fresh monthly counter.
func NextMonthlyCycleStart(now time.Time) time.Time {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
}

// IssuedByStaff returns the issued_by value of a document a staff action
// caused.
func IssuedByStaff(staffID string) string { return "staff:" + staffID }
