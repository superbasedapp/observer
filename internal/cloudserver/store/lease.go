package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// LeaseNextJob invokes the SECURITY DEFINER dequeue primitive — the ONE
// cross-tenant data read (plan §6 CI-P3). It atomically leases one due job (or
// reclaims one whose lease expired) and returns its account scope, after which
// the worker opens an ordinary tenant transaction. Returns (nil, nil) when
// nothing is due.
func (s *Store) LeaseNextJob(ctx context.Context, worker string, classes []string, leaseFor time.Duration, now time.Time) (*LeasedJob, error) {
	if now.IsZero() {
		now = time.Now()
	}
	secs := int(leaseFor.Seconds())
	if secs <= 0 {
		secs = 60
	}
	var lj LeasedJob
	found := false
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var receiptID, reservationID *string
		e := tx.QueryRow(ctx,
			`SELECT job_id::text, account_id::text, evidence_pk::text, feature, route_id,
			        route_version, prompt_version, consent_generation,
			        consent_receipt_id::text, reservation_id::text, attempts, lease_generation
			   FROM sbci_lease_next_job($1, $2, $3, $4)`,
			worker, now, classes, secs).Scan(
			&lj.JobID, &lj.AccountID, &lj.EvidencePK, &lj.Feature, &lj.RouteID,
			&lj.RouteVersion, &lj.PromptVersion, &lj.ConsentGeneration,
			&receiptID, &reservationID, &lj.Attempts, &lj.LeaseGeneration,
		)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return fmt.Errorf("lease: %w", e)
		}
		if receiptID != nil {
			lj.ConsentReceiptID = *receiptID
		}
		if reservationID != nil {
			lj.ReservationID = *reservationID
		}
		found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &lj, nil
}

// MarkJobRunning flips a leased job to running just before the (no-op this
// phase) executor runs. Tenant-scoped.
func (s *Store) MarkJobRunning(ctx context.Context, accountID, jobID string, now time.Time) error {
	return s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE analysis_jobs SET state = 'running', updated_at = $3
			  WHERE account_id = $1::uuid AND id = $2::uuid AND state = 'leased'`,
			accountID, jobID, now)
		if e != nil {
			return fmt.Errorf("mark running: %w", e)
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// AccountConsentGeneration returns the account's current consent generation
// (the lease revalidation compares it to the job's admission generation).
func (s *Store) AccountConsentGeneration(ctx context.Context, accountID string) (int64, error) {
	var gen int64
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT consent_generation FROM accounts WHERE account_id = $1::uuid`,
			accountID).Scan(&gen)
	})
	return gen, err
}
