package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrCloudBackgroundPolicyChanged refuses work scheduled under retired consent.
var ErrCloudBackgroundPolicyChanged = errors.New("store: background enrichment policy changed; nothing authorized")

// CheckCloudBackgroundPolicy refuses stale background work before reading text.
// InsertCloudConsentReceipt repeats this check atomically at the write boundary.
func (s *Store) CheckCloudBackgroundPolicy(ctx context.Context, generation int64, purpose string) error {
	p, ok, err := s.GetCloudEnrichPolicy(ctx)
	if err != nil {
		return err
	}
	want, eligible := p.PurposeName()
	if !ok || !eligible || !p.Background || generation < 1 || p.Generation != generation || want != purpose {
		return ErrCloudBackgroundPolicyChanged
	}
	return nil
}

// retireCloudBackgroundReceiptsTx invalidates all prior unattended receipts in
// the same transaction as a policy edit. An insert either precedes this edit
// and is retired here, or follows it and fails its generation predicate.
func retireCloudBackgroundReceiptsTx(ctx context.Context, tx *sql.Tx, now time.Time) ([]string, error) {
	const retired = `SELECT id FROM cloud_consent_receipts WHERE background_generation > 0
		AND background_generation <> (SELECT generation FROM cloud_enrich_policy WHERE id = 1)`
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT receipt_id FROM cloud_dispatch_leases
		WHERE receipt_id IN (`+retired+`) AND released_at IS NULL AND expires_at > ?`, cloudFormatTime(now))
	if err != nil {
		return nil, err
	}
	var active []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		active = append(active, id)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	for _, query := range []string{
		`UPDATE cloud_consent_receipts SET invalidated_at = ? WHERE invalidated_at IS NULL AND id IN (` + retired + `)`,
		`UPDATE cloud_outbox SET state = 'cancelled', last_error = 'background_policy_changed', updated_at = ?
		 WHERE state IN ('pending', 'sending', 'failed_retryable', 'reconfirmation_required') AND receipt_id IN (` + retired + `)`,
		`UPDATE cloud_dispatch_leases SET cancelled_at = ? WHERE cancelled_at IS NULL AND released_at IS NULL AND receipt_id IN (` + retired + `)`,
	} {
		if _, err := tx.ExecContext(ctx, query, cloudFormatTime(now)); err != nil {
			return nil, fmt.Errorf("retire background authorization: %w", err)
		}
	}
	return active, nil
}
