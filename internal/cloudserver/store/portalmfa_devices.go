package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/portalmfa"
)

// portalmfa_devices.go is the store seam of two second-factor guards: the
// passkey approval of a new device (FR-6, cloud 0145 device_approvals) and the
// recovery-code failure counter (FR-24, cloud 0145 portal_recovery_failures).
// The decisions are internal/cloudserver/portalmfa's; this file stores and
// reads.

// ErrDeviceApprovalRequired: the account holds a passkey and no unexpired,
// unconsumed approval exists for this device thumbprint.
var ErrDeviceApprovalRequired = errors.New("cloudserver/store: a new device of this account needs a passkey approval")

// ApproveDevice records that a passkey-verified portal session approves the
// device with this thumbprint until now+ttl. A repeat approval renews it.
func (s *Store) ApproveDevice(ctx context.Context, accountID, sessionID, thumbprint string, ttl time.Duration, now time.Time) (time.Time, error) {
	now = nowOr(now)
	exp := now.Add(ttl)
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return approveDeviceTx(ctx, tx, accountID, sessionID, thumbprint, now, exp)
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("cloudserver/store.ApproveDevice: %w", err)
	}
	return exp, nil
}

// approveDeviceTx writes (or renews) one device approval in the caller's
// transaction, already in accountID's tenant context. It is the one writer of
// device_approvals, shared by ApproveDevice and the connect flow's approval
// (ResolveConnectRequest), where approving a machine is that device's
// approval.
func approveDeviceTx(ctx context.Context, tx pgx.Tx, accountID, sessionID, thumbprint string, now, exp time.Time) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO device_approvals (account_id, thumbprint, session_id, approved_at, expires_at)
		 VALUES ($1::uuid, $2, $3::uuid, $4, $5)
		 ON CONFLICT (account_id, thumbprint) DO UPDATE
		    SET session_id = EXCLUDED.session_id, approved_at = EXCLUDED.approved_at,
		        expires_at = EXCLUDED.expires_at, consumed_at = NULL`,
		accountID, thumbprint, sessionID, now, exp)
	return err
}

// accountHoldsPasskeyTx reports whether the account in the caller's tenant
// context holds an active passkey.
func accountHoldsPasskeyTx(ctx context.Context, tx pgx.Tx, accountID string) (bool, error) {
	var active int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM portal_passkeys WHERE account_id = $1::uuid AND revoked_at IS NULL`, accountID).Scan(&active); err != nil {
		return false, fmt.Errorf("count passkeys: %w", err)
	}
	return active > 0, nil
}

// consumeDeviceApprovalTx is Exchange's gate for a device not yet registered:
// an account with no active passkey passes untouched; one with a passkey needs
// a live approval, which this spends (single use). The caller's transaction is
// already in the account's context.
func consumeDeviceApprovalTx(ctx context.Context, tx pgx.Tx, accountID, thumbprint string, now time.Time) error {
	var active int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM portal_passkeys WHERE account_id = $1::uuid AND revoked_at IS NULL`, accountID).Scan(&active); err != nil {
		return fmt.Errorf("count passkeys: %w", err)
	}
	if active == 0 {
		return nil
	}
	tag, err := tx.Exec(ctx,
		`UPDATE device_approvals SET consumed_at = $3
		  WHERE account_id = $1::uuid AND thumbprint = $2 AND consumed_at IS NULL AND expires_at > $3`,
		accountID, thumbprint, now)
	if err != nil {
		return fmt.Errorf("consume approval: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrDeviceApprovalRequired
	}
	return nil
}

// RecoveryFailureState reads the account's recovery-code failure counter
// (zero value when none).
func (s *Store) RecoveryFailureState(ctx context.Context, accountID string) (portalmfa.RecoveryFailureState, error) {
	var out portalmfa.RecoveryFailureState
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var lock *time.Time
		err := tx.QueryRow(ctx,
			`SELECT failures, window_start, locked_until FROM portal_recovery_failures WHERE account_id = $1::uuid`,
			accountID).Scan(&out.Failures, &out.WindowStart, &lock)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if lock != nil {
			out.LockedUntil = lock.UTC()
		}
		out.WindowStart = out.WindowStart.UTC()
		return nil
	})
	if err != nil {
		return portalmfa.RecoveryFailureState{}, fmt.Errorf("cloudserver/store.RecoveryFailureState: %w", err)
	}
	return out, nil
}

// NoteRecoveryFailure counts one wrong recovery code (portalmfa.
// NextRecoveryFailure under a row lock) and reports whether it tripped the
// lockout and until when.
func (s *Store) NoteRecoveryFailure(ctx context.Context, accountID string, now time.Time) (tripped bool, lockedUntil time.Time, err error) {
	now = nowOr(now)
	err = s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if err := portalPasskeyLockTx(ctx, tx, accountID); err != nil {
			return err
		}
		var cur portalmfa.RecoveryFailureState
		var lock *time.Time
		qerr := tx.QueryRow(ctx,
			`SELECT failures, window_start, locked_until FROM portal_recovery_failures WHERE account_id = $1::uuid FOR UPDATE`,
			accountID).Scan(&cur.Failures, &cur.WindowStart, &lock)
		if qerr != nil && !errors.Is(qerr, pgx.ErrNoRows) {
			return qerr
		}
		if lock != nil {
			cur.LockedUntil = lock.UTC()
		}
		next, trip := portalmfa.NextRecoveryFailure(cur, now)
		var nl *time.Time
		if !next.LockedUntil.IsZero() {
			nl = &next.LockedUntil
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO portal_recovery_failures (account_id, failures, window_start, locked_until)
			 VALUES ($1::uuid, $2, $3, $4)
			 ON CONFLICT (account_id) DO UPDATE
			    SET failures = EXCLUDED.failures, window_start = EXCLUDED.window_start, locked_until = EXCLUDED.locked_until`,
			accountID, next.Failures, next.WindowStart, nl); err != nil {
			return err
		}
		tripped, lockedUntil = trip, next.LockedUntil
		return nil
	})
	if err != nil {
		return false, time.Time{}, fmt.Errorf("cloudserver/store.NoteRecoveryFailure: %w", err)
	}
	return tripped, lockedUntil, nil
}

// ClearRecoveryFailures resets the counter after a good code.
func (s *Store) ClearRecoveryFailures(ctx context.Context, accountID string) error {
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM portal_recovery_failures WHERE account_id = $1::uuid`, accountID)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.ClearRecoveryFailures: %w", err)
	}
	return nil
}
