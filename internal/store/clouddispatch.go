package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// clouddispatch.go is the DISPATCH-LEASE seam for the two standing cloud rails
// (Sol re-review of the W5-upload remediation, N2; migration 100). It is the
// ONE owner of cloud_dispatch_leases.
//
// The lease closes the revoke/dispatch race the per-attempt receipt re-check
// (PreAttempt) leaves open: that check reads and returns, and a sender paused
// between it and the socket write can still dispatch under a receipt a
// `consent revoke` retired — and revoke, being a separate process, has already
// printed "nothing further will be sent". The lease is DB-backed precisely
// because grant, revoke and sync are separate processes sharing only the
// database.
//
// Protocol:
//
//   - AcquireCloudDispatchLease runs immediately before EVERY physical attempt.
//     In one immediate transaction it re-verifies the EXACT receipt (id AND
//     consent generation) is still live, standing, unexpired and for the stated
//     purpose, then records the lease. A receipt that is not live refuses the
//     lease (ErrCloudDispatchRefused) — no attempt begins under it.
//   - ReleaseCloudDispatchLease runs immediately after the attempt returns.
//   - CancelCloudDispatchLeasesForReceipt marks every unreleased lease under a
//     receipt cancelled (revoke; ReplaceStandingConsentGrant does the same
//     inside its own transaction for the receipts it supersedes).
//   - AwaitCloudDispatchQuiescence blocks until no lease under the given
//     receipts is ACTIVE (unreleased and unexpired). It is what lets revoke and
//     supersede promise, truthfully, that nothing further can begin dispatch
//     under the retired receipt once they return.
//
// The wait is bounded by construction: a lease expires after the caller's
// per-attempt HTTP timeout, and the caller applies that same instant as the
// attempt's request-context deadline, so a sender descheduled past its lease
// finds its request already dead before any byte is written.

// ErrCloudDispatchRefused is returned when a dispatch lease is requested under
// a receipt that is no longer live at the exact terms the caller named. The
// caller must not dispatch; the receipt was revoked, superseded, expired, or
// its generation moved between prepare and attempt.
var ErrCloudDispatchRefused = errors.New("store: dispatch refused — the consent receipt no longer authorizes this send at these terms")

// CloudDispatchLeaseRequest names the exact terms a lease is requested at.
type CloudDispatchLeaseRequest struct {
	// ReceiptID is the EXACT receipt the bytes about to be sent were built
	// under — never "the newest grant for the purpose".
	ReceiptID string
	// GrantMode defaults to standing; per-upload callers name it explicitly.
	GrantMode CloudGrantMode
	// Purpose the receipt must carry.
	Purpose string
	// ConsentGeneration the receipt must still be at.
	ConsentGeneration int
	// TTL bounds the lease. It must equal (or exceed) the per-attempt HTTP
	// timeout the caller applies to the attempt, and the caller must apply
	// ExpiresAt as the attempt's request deadline (see CloudDispatchLease).
	TTL time.Duration
}

// CloudDispatchLease is one acquired lease.
type CloudDispatchLease struct {
	ID        string
	ReceiptID string
	// ExpiresAt is the instant after which the lease no longer counts as
	// active. The holder MUST bound its physical attempt by it.
	ExpiresAt time.Time
}

// cloudDispatchDefaultTTL is used when a request names no TTL. It matches the
// network client's per-attempt HTTP timeout.
const cloudDispatchDefaultTTL = 30 * time.Second

// cloudDispatchPollInterval is how often AwaitCloudDispatchQuiescence re-reads.
const cloudDispatchPollInterval = 20 * time.Millisecond

// AcquireCloudDispatchLease records a dispatch lease under req.ReceiptID, or
// refuses with ErrCloudDispatchRefused when the receipt is not live at exactly
// req's terms. The verification and the insert are ONE immediate transaction
// (the DSN's `_txlock=immediate` takes the write lock at BEGIN), so a revoke
// committed before this call is always seen and a revoke started after it
// serializes behind the inserted row and will wait for it.
func (s *Store) AcquireCloudDispatchLease(ctx context.Context, req CloudDispatchLeaseRequest) (CloudDispatchLease, error) {
	const pfx = "store.AcquireCloudDispatchLease"
	if req.ReceiptID == "" {
		return CloudDispatchLease{}, fmt.Errorf("%s: receipt id is required", pfx)
	}
	if req.Purpose == "" {
		return CloudDispatchLease{}, fmt.Errorf("%s: purpose is required", pfx)
	}
	if req.ConsentGeneration < 0 || (req.GrantMode != CloudGrantPerUpload && req.ConsentGeneration < 1) {
		return CloudDispatchLease{}, fmt.Errorf("%s: consent generation %d is not positive", pfx, req.ConsentGeneration)
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = cloudDispatchDefaultTTL
	}
	id, err := cloudRandomID("lease_")
	if err != nil {
		return CloudDispatchLease{}, fmt.Errorf("%s: %w", pfx, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CloudDispatchLease{}, fmt.Errorf("%s: %w", pfx, err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	if reason, rerr := cloudDispatchReceiptLiveTx(ctx, tx, req, now); rerr != nil {
		return CloudDispatchLease{}, fmt.Errorf("%s: %w", pfx, rerr)
	} else if reason != "" {
		return CloudDispatchLease{}, fmt.Errorf("%s: %w: %s", pfx, ErrCloudDispatchRefused, reason)
	}

	expires := now.Add(ttl)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cloud_dispatch_leases
		  (id, receipt_id, purpose, consent_generation, acquired_at, expires_at, released_at, cancelled_at)
		VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)`,
		id, req.ReceiptID, req.Purpose, req.ConsentGeneration,
		cloudFormatTime(now), cloudFormatTime(expires)); err != nil {
		return CloudDispatchLease{}, fmt.Errorf("%s: insert lease: %w", pfx, err)
	}
	if err := tx.Commit(); err != nil {
		return CloudDispatchLease{}, fmt.Errorf("%s: %w", pfx, err)
	}
	return CloudDispatchLease{ID: id, ReceiptID: req.ReceiptID, ExpiresAt: expires}, nil
}

// cloudDispatchReceiptLiveTx is the exact-terms liveness read. It returns a
// content-free reason when the receipt does not authorize a dispatch at req's
// terms, "" when it does, and an error only for a read failure.
func cloudDispatchReceiptLiveTx(ctx context.Context, tx *sql.Tx, req CloudDispatchLeaseRequest, now time.Time) (string, error) {
	var (
		invalidatedAt sql.NullString
		reviewAt      sql.NullString
		purpose       string
		grantMode     string
		generation    int
	)
	err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(invalidated_at, ''), purpose, grant_mode, consent_generation, review_at
		  FROM cloud_consent_receipts WHERE id = ?`, req.ReceiptID).
		Scan(&invalidatedAt, &purpose, &grantMode, &generation, &reviewAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "the consent receipt does not exist", nil
	}
	if err != nil {
		return "", err
	}
	wantMode := req.GrantMode
	if wantMode == "" {
		wantMode = CloudGrantStanding
	}
	switch {
	case invalidatedAt.Valid && invalidatedAt.String != "":
		return "the consent receipt was revoked or superseded", nil
	case CloudGrantMode(grantMode) != wantMode:
		return "the consent receipt has a different grant mode", nil
	case purpose != req.Purpose:
		return fmt.Sprintf("the consent receipt is for purpose %q, not %q", purpose, req.Purpose), nil
	case generation != req.ConsentGeneration:
		return fmt.Sprintf("the consent generation moved (receipt at %d, send built at %d)", generation, req.ConsentGeneration), nil
	}
	if reviewAt.Valid && reviewAt.String != "" {
		if t := cloudParseTime(reviewAt.String); !t.IsZero() && !t.After(now) {
			return "the standing grant's review date has passed", nil
		}
	}
	return "", nil
}

// ReleaseCloudDispatchLease marks a lease released (idempotent). It is called
// immediately after the physical attempt returns, success or failure.
func (s *Store) ReleaseCloudDispatchLease(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("store.ReleaseCloudDispatchLease: lease id is required")
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE cloud_dispatch_leases SET released_at = ?
		 WHERE id = ? AND released_at IS NULL`,
		cloudFormatTime(time.Now().UTC()), id); err != nil {
		return fmt.Errorf("store.ReleaseCloudDispatchLease: %w", err)
	}
	return nil
}

// CancelCloudDispatchLeasesForReceipt marks every unreleased lease under a
// receipt cancelled. It does not wait — pair it with AwaitCloudDispatchQuiescence.
// Returns how many leases were marked.
func (s *Store) CancelCloudDispatchLeasesForReceipt(ctx context.Context, receiptID string) (int, error) {
	if receiptID == "" {
		return 0, errors.New("store.CancelCloudDispatchLeasesForReceipt: receipt id is required")
	}
	n, err := cancelCloudDispatchLeasesTx(ctx, s.db, receiptID, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("store.CancelCloudDispatchLeasesForReceipt: %w", err)
	}
	return n, nil
}

// cloudExecer is the subset of *sql.DB / *sql.Tx the lease cancel needs, so
// ReplaceStandingConsentGrant can run it inside its own transaction.
type cloudExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func cancelCloudDispatchLeasesTx(ctx context.Context, ex cloudExecer, receiptID string, now time.Time) (int, error) {
	res, err := ex.ExecContext(ctx, `
		UPDATE cloud_dispatch_leases SET cancelled_at = ?
		 WHERE receipt_id = ? AND released_at IS NULL AND cancelled_at IS NULL`,
		cloudFormatTime(now), receiptID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// CountActiveCloudDispatchLeases returns how many leases under the given
// receipts are ACTIVE: unreleased and not yet expired. Cancellation does not
// end a lease — only release or expiry does — because a cancelled lease's
// holder may already be mid-attempt.
func (s *Store) CountActiveCloudDispatchLeases(ctx context.Context, receiptIDs []string) (int, error) {
	if len(receiptIDs) == 0 {
		return 0, nil
	}
	args := make([]any, 0, len(receiptIDs)+1)
	for _, id := range receiptIDs {
		args = append(args, id)
	}
	args = append(args, cloudFormatTime(time.Now().UTC()))
	var n int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM cloud_dispatch_leases
		 WHERE receipt_id IN (`+strings.TrimSuffix(strings.Repeat("?,", len(receiptIDs)), ",")+`)
		   AND released_at IS NULL AND expires_at > ?`, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("store.CountActiveCloudDispatchLeases: %w", err)
	}
	return n, nil
}

// AwaitCloudDispatchQuiescence blocks until no lease under receiptIDs is active
// (released or expired), or ctx ends. It returns the number of active leases it
// found on its FIRST read — how many in-flight attempts the caller actually
// waited for — so a revoke can say so. The wait is bounded by the leases' own
// expiry, which the holders apply as their attempt deadline; it never blocks
// past the per-attempt HTTP timeout.
func (s *Store) AwaitCloudDispatchQuiescence(ctx context.Context, receiptIDs []string) (int, error) {
	const pfx = "store.AwaitCloudDispatchQuiescence"
	first, err := s.CountActiveCloudDispatchLeases(ctx, receiptIDs)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", pfx, err)
	}
	if first == 0 {
		return 0, nil
	}
	t := time.NewTicker(cloudDispatchPollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return first, fmt.Errorf("%s: %w", pfx, ctx.Err())
		case <-t.C:
		}
		n, err := s.CountActiveCloudDispatchLeases(ctx, receiptIDs)
		if err != nil {
			return first, fmt.Errorf("%s: %w", pfx, err)
		}
		if n == 0 {
			return first, nil
		}
	}
}
