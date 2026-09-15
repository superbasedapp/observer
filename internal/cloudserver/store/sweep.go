package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// SweepExpiredEvidence deletes evidence BYTES and marks the objects deleted for
// every evidence object past its immutable expires_at, ACROSS all tenants and
// REGARDLESS of the owning job's state (plan §2.8: queue poison, dead-letter,
// crash, cancellation, and kill-switch pause can never extend the raw-object
// lifetime — the sweeper deletes purely by expires_at, never consulting the
// queue). It runs through the SECURITY DEFINER sweep primitive (the only other
// cross-tenant write besides the lease). Returns how many blobs were deleted.
func (s *Store) SweepExpiredEvidence(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var deleted int
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sbci_sweep_expired_evidence($1)`, now).Scan(&deleted)
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.SweepExpiredEvidence: %w", err)
	}
	return deleted, nil
}

// RetentionSweepResult is the content-free tally of one retention pass (counts
// only, never any account id or content).
type RetentionSweepResult struct {
	ConsentPurged  int `json:"consent_purged"`
	AuditPurged    int `json:"audit_purged"`
	AccountsPurged int `json:"accounts_purged"`
}

// SweepRetention ages out the rows a completed account deletion RETAINED once
// their TTL passes (W6d): the consent-proof + billing rows at 12 months, then
// the audit + lifecycle rows and the pseudonymized account row itself at 24
// months (children before the account row — FK-safe). It runs the cross-tenant
// SECURITY DEFINER sbci_sweep_retention and never touches a live account.
func (s *Store) SweepRetention(ctx context.Context, now time.Time) (RetentionSweepResult, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var res RetentionSweepResult
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT consent_purged, audit_purged, accounts_purged FROM sbci_sweep_retention($1)`, now).
			Scan(&res.ConsentPurged, &res.AuditPurged, &res.AccountsPurged)
	})
	if err != nil {
		return RetentionSweepResult{}, fmt.Errorf("cloudserver/store.SweepRetention: %w", err)
	}
	return res, nil
}

// SweepResultsRetention ages out results of LIVE (status='active') accounts
// once they outlive their CURRENT plan's results_retention_days (migration
// 0037, W5) — distinct from SweepRetention, which ages out rows a COMPLETED
// ACCOUNT DELETION already retained. It deletes a result's revision history
// before the result itself (FK-safe) and runs the cross-tenant SECURITY
// DEFINER sbci_sweep_results_retention. Returns how many results were deleted.
func (s *Store) SweepResultsRetention(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var deleted int64
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sbci_sweep_results_retention($1)`, now).Scan(&deleted)
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.SweepResultsRetention: %w", err)
	}
	return deleted, nil
}
