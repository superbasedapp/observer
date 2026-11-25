package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// cloudlocal_outbox.go holds the cloud_outbox send state machine of the
// cloud-intelligence store seam (cloudlocal.go describes the whole seam and
// the CloudOutboxState vocabulary).

// -- Outbox ------------------------------------------------------------------

// EnqueueCloudOutbox enqueues one send job in the pending state. It REFUSES
// (ErrCloudSessionIneligible) any session not eligible for personal-cloud
// enrichment — the check delegates to EligibleForPersonalCloud so the
// data-authority contract stays the one source of truth. It also refuses a
// missing/invalidated receipt and a digest incoherent with that receipt.
// item.ID/State/RetryCount/timestamps are set by the store; the returned id is
// the minted outbox id.
func (s *Store) EnqueueCloudOutbox(ctx context.Context, item CloudOutboxItem) (string, error) {
	if item.SessionID == "" {
		return "", errors.New("store.EnqueueCloudOutbox: session id is required")
	}
	if item.ReceiptID == "" {
		return "", errors.New("store.EnqueueCloudOutbox: receipt id is required")
	}
	if item.EvidenceContentDigest == "" || item.UploadDigest == "" {
		return "", errors.New("store.EnqueueCloudOutbox: both digests are required")
	}
	// Eligibility gate (plan §7 invariant 3): org / unknown / missing sessions
	// never reach personal cloud paths.
	eligible, err := s.EligibleForPersonalCloud(ctx, item.SessionID)
	if err != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
	}
	if !eligible {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", ErrCloudSessionIneligible)
	}
	// Receipt must exist, be live, and bind the same upload digest (coherence
	// at enqueue).
	rcpt, ok, err := s.GetCloudConsentReceipt(ctx, item.ReceiptID)
	if err != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
	}
	if !ok {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", ErrCloudReceiptNotFound)
	}
	if rcpt.InvalidatedAt != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w: receipt is invalidated", ErrCloudReconfirmationRequired)
	}
	if item.UploadDigest != rcpt.UploadDigest {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", ErrCloudReceiptDigestMismatch)
	}
	if item.ID == "" {
		id, err := cloudRandomID("job_")
		if err != nil {
			return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
		}
		item.ID = id
	}
	featureSet := item.FeatureSetJSON
	if featureSet == "" {
		featureSet = "[]"
	}
	now := time.Now().UTC()
	// Duplicate guard and insert in ONE transaction: two processes (the
	// daemon's auto-enrich sweep and the dashboard's "Enrich now" both spawn
	// `observer cloud consent`) racing on the same session serialize on the
	// SQLite write lock, so the loser sees the winner's row and refuses.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var dup int
	if err := tx.QueryRowContext(
		ctx, `
		SELECT COUNT(1) FROM cloud_outbox
		 WHERE session_id = ? AND upload_digest = ? AND state IN (?, ?, ?)`,
		item.SessionID, item.UploadDigest,
		string(CloudOutboxPending), string(CloudOutboxSending), string(CloudOutboxFailedRetryable),
	).Scan(&dup); err != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
	}
	if dup > 0 {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", ErrCloudOutboxDuplicate)
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO cloud_outbox
		  (id, session_id, feature_set_json, evidence_content_digest, upload_digest,
		   receipt_id, state, retry_count, last_error, created_at, updated_at)
		SELECT ?, ?, ?, ?, ?, ?, ?, 0, '', ?, ?
        WHERE EXISTS (SELECT 1 FROM cloud_consent_receipts WHERE id = ? AND invalidated_at IS NULL)`,
		item.ID, item.SessionID, featureSet, item.EvidenceContentDigest, item.UploadDigest,
		item.ReceiptID, string(CloudOutboxPending), cloudFormatTime(now), cloudFormatTime(now), item.ReceiptID)
	if err != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", ErrCloudReconfirmationRequired)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
	}
	return item.ID, nil
}

// FindLiveCloudOutboxForUpload returns the newest in-flight (pending / sending
// / failed_retryable) outbox item for a session whose upload bytes are exactly
// uploadDigest; ok=false when none. It is the read half of EnqueueCloudOutbox's
// duplicate guard, so a caller can report the job that already carries the
// bytes instead of minting a second receipt.
func (s *Store) FindLiveCloudOutboxForUpload(ctx context.Context, sessionID, uploadDigest string) (CloudOutboxItem, bool, error) {
	if sessionID == "" || uploadDigest == "" {
		return CloudOutboxItem{}, false, errors.New("store.FindLiveCloudOutboxForUpload: session id and upload digest are required")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, session_id, feature_set_json, evidence_content_digest, upload_digest,
		       receipt_id, state, retry_count, last_error, created_at, updated_at
		  FROM cloud_outbox
		 WHERE session_id = ? AND upload_digest = ? AND state IN (?, ?, ?)
		 ORDER BY created_at DESC, id DESC
		 LIMIT 1`,
		sessionID, uploadDigest,
		string(CloudOutboxPending), string(CloudOutboxSending), string(CloudOutboxFailedRetryable))
	if err != nil {
		return CloudOutboxItem{}, false, fmt.Errorf("store.FindLiveCloudOutboxForUpload: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items, err := scanCloudOutboxRows(rows, "store.FindLiveCloudOutboxForUpload")
	if err != nil {
		return CloudOutboxItem{}, false, err
	}
	if len(items) == 0 {
		return CloudOutboxItem{}, false, nil
	}
	return items[0], true, nil
}

// GetCloudOutbox loads an outbox item by id. ok=false means it does not exist.
func (s *Store) GetCloudOutbox(ctx context.Context, id string) (CloudOutboxItem, bool, error) {
	var (
		it                 CloudOutboxItem
		kind               string
		state              string
		createdAt, updated string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, kind, session_id, feature_set_json, evidence_content_digest, upload_digest,
		       receipt_id, state, retry_count, last_error, created_at, updated_at
		  FROM cloud_outbox WHERE id = ?`, id).
		Scan(&it.ID, &kind, &it.SessionID, &it.FeatureSetJSON, &it.EvidenceContentDigest, &it.UploadDigest,
			&it.ReceiptID, &state, &it.RetryCount, &it.LastError, &createdAt, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudOutboxItem{}, false, nil
	}
	if err != nil {
		return CloudOutboxItem{}, false, fmt.Errorf("store.GetCloudOutbox: %w", err)
	}
	it.Kind = CloudOutboxKind(kind)
	it.State = CloudOutboxState(state)
	it.CreatedAt = cloudParseTime(createdAt)
	it.UpdatedAt = cloudParseTime(updated)
	return it, true, nil
}

// PrepareCloudOutboxSend is THE reconfirmation rule (plan §6 CI-P1 /
// §7 invariant 4), hardened for FD1 (endpoint binding) and FD3 (atomic
// re-verify). sendEndpoint is the immutable absolute URL the client will POST
// to (client.UploadEndpoint()); it MUST equal the endpoint the consent receipt
// bound, or the send is refused (ErrCloudEndpointMismatch, reconfirmation
// required) — confirmed evidence can only ever reach the approved origin+path.
//
// It rebuilds the envelope ONCE, compares BOTH digests against the stored
// outbox value AND the bound receipt's confirmed upload digest, then — in ONE
// transaction (the DSN's _txlock=immediate holds the write lock from BEGIN) —
// RE-READS eligibility, receipt validity, endpoint and digests and CASes to
// `sending`. The re-read closes the race where the receipt is invalidated or
// the session is upgraded to org DURING the rebuild: such a change makes the
// atomic re-verify fail and the item moves to reconfirmation_required instead
// of sending. The returned CloudSendLease lets the caller re-verify once more
// immediately before HTTP dispatch (VerifyCloudSendAuthorization).
//
// Outcomes:
//   - authorized  -> `sending`, rebuilt bytes + lease returned;
//   - digest/endpoint mismatch, invalidated receipt, or org/ineligible session
//     -> `reconfirmation_required` and a typed error.
//
// It NEVER auto-updates the stored digests and NEVER auto-sends a mismatch.
// Only `pending` and `failed_retryable` items are preparable.
func (s *Store) PrepareCloudOutboxSend(ctx context.Context, id, sendEndpoint string, rebuild EnvelopeRebuild) ([]byte, CloudSendLease, error) {
	if rebuild == nil {
		return nil, CloudSendLease{}, errors.New("store.PrepareCloudOutboxSend: rebuild func is required")
	}
	item, ok, err := s.GetCloudOutbox(ctx, id)
	if err != nil {
		return nil, CloudSendLease{}, err
	}
	if !ok {
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w", ErrCloudOutboxNotFound)
	}
	// This path is session-evidence ONLY: it rebuilds an envelope from a live
	// session and compares digests. A structural snapshot has no session to
	// rebuild from — its stored bytes ARE the artifact — so routing one here
	// would either fail obscurely or, worse, re-aggregate. Refuse explicitly.
	if item.Kind != CloudOutboxKindSessionEvidence {
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w: kind %q - use PrepareStructuralSend", ErrCloudOutboxKindMismatch, item.Kind)
	}
	if item.State != CloudOutboxPending && item.State != CloudOutboxFailedRetryable {
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w: state %q is not preparable", ErrIllegalCloudOutboxTransition, item.State)
	}
	rcpt, ok, err := s.GetCloudConsentReceipt(ctx, item.ReceiptID)
	if err != nil {
		return nil, CloudSendLease{}, err
	}
	if !ok {
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w", ErrCloudReceiptNotFound)
	}
	// An invalidated receipt is a material change: reconfirmation required.
	if rcpt.InvalidatedAt != nil {
		if err := s.moveCloudOutbox(ctx, id, preparableStates(), CloudOutboxReconfirmationRequired, false, "receipt_invalidated"); err != nil {
			return nil, CloudSendLease{}, err
		}
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w", ErrCloudReconfirmationRequired)
	}
	// FD1: the send target must equal the endpoint the receipt bound.
	normSend := normalizeCloudEndpoint(sendEndpoint)
	if normSend == "" || normSend != normalizeCloudEndpoint(rcpt.Endpoint) {
		if err := s.moveCloudOutbox(ctx, id, preparableStates(), CloudOutboxReconfirmationRequired, false, "endpoint_mismatch"); err != nil {
			return nil, CloudSendLease{}, err
		}
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w: bound %q, send %q", ErrCloudEndpointMismatch, rcpt.Endpoint, sendEndpoint)
	}
	// Rebuild ONCE.
	uploadBytes, evDigest, upDigest, err := rebuild(ctx)
	if err != nil {
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: rebuild: %w", err)
	}
	// Compare BOTH digests against the stored outbox values AND the receipt's
	// confirmed upload digest. Any mismatch => reconfirmation required.
	if evDigest != item.EvidenceContentDigest || upDigest != item.UploadDigest || upDigest != rcpt.UploadDigest {
		if err := s.moveCloudOutbox(ctx, id, preparableStates(), CloudOutboxReconfirmationRequired, false, "digest_mismatch"); err != nil {
			return nil, CloudSendLease{}, err
		}
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w", ErrCloudReconfirmationRequired)
	}
	// FD3: atomically RE-READ authorization and CAS to `sending` in one
	// transaction. Authorization can have changed during the rebuild (a
	// concurrent InvalidateCloudConsentReceipt or a personal->org upgrade); the
	// re-read catches it and refuses the transition.
	if err := s.prepareSendCAS(ctx, item, normSend); err != nil {
		if errors.Is(err, ErrCloudReconfirmationRequired) {
			if merr := s.moveCloudOutbox(ctx, id, preparableStates(), CloudOutboxReconfirmationRequired, false, "authorization_changed"); merr != nil {
				return nil, CloudSendLease{}, merr
			}
		}
		return nil, CloudSendLease{}, err
	}
	return uploadBytes, CloudSendLease{
		OutboxID:     item.ID,
		ReceiptID:    item.ReceiptID,
		SessionID:    item.SessionID,
		UploadDigest: item.UploadDigest,
		Endpoint:     normSend,
	}, nil
}

// prepareSendCAS re-reads eligibility + receipt validity/endpoint/digest inside
// one immediate transaction and CASes the item pending/failed_retryable ->
// sending. A changed authorization returns ErrCloudReconfirmationRequired (the
// caller moves the row to reconfirmation_required); a lost preparable state
// returns ErrIllegalCloudOutboxTransition.
func (s *Store) prepareSendCAS(ctx context.Context, item CloudOutboxItem, normSend string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// State still preparable?
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM cloud_outbox WHERE id = ?`, item.ID).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store.prepareSendCAS: %w", ErrCloudOutboxNotFound)
		}
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	}
	if CloudOutboxState(state) != CloudOutboxPending && CloudOutboxState(state) != CloudOutboxFailedRetryable {
		return fmt.Errorf("store.prepareSendCAS: %w: state %q is not preparable", ErrIllegalCloudOutboxTransition, state)
	}

	// Receipt still live, same endpoint, same upload digest?
	var (
		invalidatedAt sql.NullString
		upDigest      string
		endpoint      string
	)
	if err := tx.QueryRowContext(ctx,
		`SELECT invalidated_at, upload_digest, endpoint FROM cloud_consent_receipts WHERE id = ?`, item.ReceiptID).
		Scan(&invalidatedAt, &upDigest, &endpoint); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store.prepareSendCAS: %w: receipt gone", ErrCloudReconfirmationRequired)
		}
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	}
	if invalidatedAt.Valid && invalidatedAt.String != "" {
		return fmt.Errorf("store.prepareSendCAS: %w: receipt invalidated", ErrCloudReconfirmationRequired)
	}
	if upDigest != item.UploadDigest || normalizeCloudEndpoint(endpoint) != normSend {
		return fmt.Errorf("store.prepareSendCAS: %w: receipt drift", ErrCloudReconfirmationRequired)
	}

	// Session still eligible for personal enrichment (not upgraded to org)?
	if elig, err := sessionEligibleTx(ctx, tx, item.SessionID); err != nil {
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	} else if !elig {
		return fmt.Errorf("store.prepareSendCAS: %w: session no longer personal-eligible", ErrCloudReconfirmationRequired)
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE cloud_outbox SET state = ?, last_error = '', updated_at = ?
		  WHERE id = ? AND state IN (?, ?)`,
		string(CloudOutboxSending), cloudFormatTime(time.Now().UTC()), item.ID,
		string(CloudOutboxPending), string(CloudOutboxFailedRetryable))
	if err != nil {
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store.prepareSendCAS: %w: state changed under the CAS", ErrIllegalCloudOutboxTransition)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	}
	return nil
}

// sessionEligibleTx reads a session's stored authority through tx and delegates
// the eligibility decision to the pure dataauthority contract (the single
// source of truth). A NULL/missing authority is ineligible (fail closed).
func sessionEligibleTx(ctx context.Context, tx *sql.Tx, sessionID string) (bool, error) {
	var auth sql.NullString
	var ver sql.NullInt64
	err := tx.QueryRowContext(ctx,
		`SELECT authority, authority_classifier_version FROM sessions WHERE id = ?`, sessionID).Scan(&auth, &ver)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !auth.Valid || auth.String == "" {
		return false, nil
	}
	c := dataauthority.Classification{Authority: dataauthority.Authority(auth.String), Version: int(ver.Int64)}
	return c.EligibleForPersonalEnrichment(), nil
}

// VerifyCloudSendAuthorization is the final pre-dispatch check (FD3): called
// immediately before the HTTP upload, it re-reads the receipt validity/endpoint/
// digest and the session eligibility captured in the lease. If anything changed
// (receipt invalidated, session upgraded to org, endpoint/digest drift) it moves
// the item OUT of `sending` back to reconfirmation_required and returns
// ErrCloudSendUnauthorized so the transport aborts without sending. nil means
// still authorized.
func (s *Store) VerifyCloudSendAuthorization(ctx context.Context, lease CloudSendLease) error {
	unauthorized := func(reason string) error {
		if err := s.moveCloudOutbox(ctx, lease.OutboxID, []CloudOutboxState{CloudOutboxSending}, CloudOutboxReconfirmationRequired, false, "send_unauthorized"); err != nil {
			return err
		}
		return fmt.Errorf("store.VerifyCloudSendAuthorization: %w: %s", ErrCloudSendUnauthorized, reason)
	}
	rcpt, ok, err := s.GetCloudConsentReceipt(ctx, lease.ReceiptID)
	if err != nil {
		return err
	}
	if !ok {
		return unauthorized("receipt gone")
	}
	if rcpt.InvalidatedAt != nil {
		return unauthorized("receipt invalidated")
	}
	if rcpt.UploadDigest != lease.UploadDigest || normalizeCloudEndpoint(rcpt.Endpoint) != lease.Endpoint {
		return unauthorized("receipt drift")
	}
	elig, err := s.EligibleForPersonalCloud(ctx, lease.SessionID)
	if err != nil {
		return err
	}
	if !elig {
		return unauthorized("session no longer personal-eligible")
	}
	return nil
}

// normalizeCloudEndpoint reduces an endpoint URL to a comparable origin+path:
// lowercased scheme+host, default ports dropped, cleaned path, query/fragment
// ignored. A URL that does not parse, or lacks scheme/host, normalizes to "" so
// it can never match a real endpoint (fail closed for FD1).
func normalizeCloudEndpoint(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme == "" || host == "" {
		return ""
	}
	if port := u.Port(); port != "" {
		if !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
			host = host + ":" + port
		}
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	} else {
		p = path.Clean(p)
	}
	return scheme + "://" + host + p
}

// MarkCloudOutboxSent transitions a sending item to sent (terminal success).
func (s *Store) MarkCloudOutboxSent(ctx context.Context, id string) error {
	return s.moveCloudOutbox(ctx, id, []CloudOutboxState{CloudOutboxSending}, CloudOutboxSent, false, "")
}

// MarkCloudOutboxRetryable transitions a sending item to failed_retryable,
// increments retry_count, and records the content-free error CLASS string.
func (s *Store) MarkCloudOutboxRetryable(ctx context.Context, id, errClass string) error {
	return s.moveCloudOutbox(ctx, id, []CloudOutboxState{CloudOutboxSending}, CloudOutboxFailedRetryable, true, errClass)
}

// MarkCloudOutboxTerminal transitions a sending or failed_retryable item to
// failed_terminal and records the content-free error CLASS string.
func (s *Store) MarkCloudOutboxTerminal(ctx context.Context, id, errClass string) error {
	return s.moveCloudOutbox(ctx, id, []CloudOutboxState{CloudOutboxSending, CloudOutboxFailedRetryable}, CloudOutboxFailedTerminal, false, errClass)
}

// MarkCloudOutboxReconfirmation transitions a sending item back to
// reconfirmation_required and records the content-free error CLASS string. It is
// the correct landing for a SERVER refusal of the exact bytes
// (reconfirmation_required): the developer re-previews and re-consents (via
// ReconfirmCloudOutbox), rather than the item burning as a terminal failure.
func (s *Store) MarkCloudOutboxReconfirmation(ctx context.Context, id, errClass string) error {
	return s.moveCloudOutbox(ctx, id, []CloudOutboxState{CloudOutboxSending}, CloudOutboxReconfirmationRequired, false, errClass)
}

// ReconfirmCloudOutbox is the ONLY digest-updating transition, and it is
// explicit and developer-driven (never automatic): a reconfirmation_required
// item, once the developer has re-previewed and confirmed a new receipt, moves
// back to pending with its bound receipt and both digests updated. The new
// receipt must exist, be live, and bind newUploadDigest (coherence).
func (s *Store) ReconfirmCloudOutbox(ctx context.Context, id, newReceiptID, newEvidenceDigest, newUploadDigest string) error {
	if newReceiptID == "" || newEvidenceDigest == "" || newUploadDigest == "" {
		return errors.New("store.ReconfirmCloudOutbox: new receipt id and both digests are required")
	}
	rcpt, ok, err := s.GetCloudConsentReceipt(ctx, newReceiptID)
	if err != nil {
		return fmt.Errorf("store.ReconfirmCloudOutbox: %w", err)
	}
	if !ok {
		return fmt.Errorf("store.ReconfirmCloudOutbox: %w", ErrCloudReceiptNotFound)
	}
	if rcpt.InvalidatedAt != nil {
		return fmt.Errorf("store.ReconfirmCloudOutbox: %w: new receipt is invalidated", ErrCloudReconfirmationRequired)
	}
	if newUploadDigest != rcpt.UploadDigest {
		return fmt.Errorf("store.ReconfirmCloudOutbox: %w", ErrCloudReceiptDigestMismatch)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE cloud_outbox
		   SET state = ?, receipt_id = ?, evidence_content_digest = ?, upload_digest = ?,
		       last_error = '', updated_at = ?
		 WHERE id = ? AND state = ?`,
		string(CloudOutboxPending), newReceiptID, newEvidenceDigest, newUploadDigest,
		cloudFormatTime(time.Now().UTC()), id, string(CloudOutboxReconfirmationRequired))
	if err != nil {
		return fmt.Errorf("store.ReconfirmCloudOutbox: %w", err)
	}
	return s.checkTransitionApplied(ctx, id, res, CloudOutboxReconfirmationRequired, CloudOutboxPending)
}

// CancelForReceipt cancels every non-terminal outbox item bound to receiptID
// (consent revocation / material receipt change). pending,
// reconfirmation_required, failed_retryable AND in-flight `sending` items move
// to cancelled (FD3: a revoked receipt must also cancel a row that a sync loop
// already moved to sending — the idempotency key makes an ambiguous prior
// delivery safe, and VerifyCloudSendAuthorization aborts the dispatch before it
// leaves the machine). Already-terminal (sent/failed_terminal/cancelled) items
// are left untouched. Returns the number cancelled.
func (s *Store) CancelCloudOutboxForReceipt(ctx context.Context, receiptID string) (int, error) {
	if receiptID == "" {
		return 0, errors.New("store.CancelCloudOutboxForReceipt: receipt id is required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE cloud_outbox
		   SET state = ?, updated_at = ?
		 WHERE receipt_id = ? AND state IN (?, ?, ?, ?)`,
		string(CloudOutboxCancelled), cloudFormatTime(time.Now().UTC()), receiptID,
		string(CloudOutboxPending), string(CloudOutboxReconfirmationRequired),
		string(CloudOutboxFailedRetryable), string(CloudOutboxSending))
	if err != nil {
		return 0, fmt.Errorf("store.CancelCloudOutboxForReceipt: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store.CancelCloudOutboxForReceipt: %w", err)
	}
	return int(n), nil
}

// ReclaimStaleCloudSending resets outbox items stuck in `sending` since before
// olderThan back to failed_retryable so a later sync retries them (FD4). A
// crash/kill/restart after the transition to sending but before a mark
// operation would otherwise strand the item forever — ListSendableCloudOutbox
// excludes `sending`. The idempotency key (client.Upload) makes a retry of an
// ambiguously-delivered upload safe. `observer cloud sync` calls this at
// startup with a conservative lease age. Returns the number reclaimed.
func (s *Store) ReclaimStaleCloudSending(ctx context.Context, olderThan time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE cloud_outbox
		   SET state = ?, last_error = 'reclaimed_stale_sending', updated_at = ?
		 WHERE state = ? AND updated_at <= ?`,
		string(CloudOutboxFailedRetryable), cloudFormatTime(time.Now().UTC()),
		string(CloudOutboxSending), cloudFormatTime(olderThan.UTC()))
	if err != nil {
		return 0, fmt.Errorf("store.ReclaimStaleCloudSending: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store.ReclaimStaleCloudSending: %w", err)
	}
	return int(n), nil
}

// preparableStates is the from-set for PrepareCloudOutboxSend transitions.
func preparableStates() []CloudOutboxState {
	return []CloudOutboxState{CloudOutboxPending, CloudOutboxFailedRetryable}
}

// moveCloudOutbox is the single guarded state-transition primitive: it moves
// item id from any of `from` to `to` in one UPDATE, optionally incrementing
// retry_count and recording a content-free error class. A zero-row result is
// disambiguated into ErrCloudOutboxNotFound vs ErrIllegalCloudOutboxTransition.
func (s *Store) moveCloudOutbox(ctx context.Context, id string, from []CloudOutboxState, to CloudOutboxState, incRetry bool, errClass string) error {
	if len(from) == 0 {
		return errors.New("store.moveCloudOutbox: empty from-set")
	}
	placeholders := make([]string, len(from))
	args := make([]any, 0, len(from)+4)
	args = append(args, string(to), errClass, cloudFormatTime(time.Now().UTC()))
	for i, st := range from {
		placeholders[i] = "?"
		_ = st // appended below in a second pass to keep arg order clear
	}
	retryClause := ""
	if incRetry {
		retryClause = ", retry_count = retry_count + 1"
	}
	// WHERE args: id then the from-states.
	args = append(args, id)
	for _, st := range from {
		args = append(args, string(st))
	}
	//nolint:gosec // G201: retryClause is a fixed in-function literal and placeholders is a "?, ?" list; every value binds via ?.
	query := fmt.Sprintf(`
		UPDATE cloud_outbox
		   SET state = ?, last_error = ?, updated_at = ?%s
		 WHERE id = ? AND state IN (%s)`,
		retryClause, strings.Join(placeholders, ", "))
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("store.moveCloudOutbox: %w", err)
	}
	return s.checkTransitionApplied(ctx, id, res, from[0], to)
}

// checkTransitionApplied turns a zero-row UPDATE into a typed error: if the row
// does not exist it is ErrCloudOutboxNotFound, otherwise the current state did
// not permit the transition (ErrIllegalCloudOutboxTransition).
func (s *Store) checkTransitionApplied(ctx context.Context, id string, res sql.Result, _ CloudOutboxState, to CloudOutboxState) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store.checkTransitionApplied: %w", err)
	}
	if n > 0 {
		return nil
	}
	cur, ok, err := s.GetCloudOutbox(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("store.checkTransitionApplied: %w", ErrCloudOutboxNotFound)
	}
	return fmt.Errorf("store.checkTransitionApplied: %w: cannot move %q -> %q", ErrIllegalCloudOutboxTransition, cur.State, to)
}

// ListSendableCloudOutbox returns SESSION-EVIDENCE outbox items in a preparable
// state (pending / failed_retryable), oldest first — the manual drain set for
// `observer cloud sync`. Items awaiting reconfirmation or already terminal are
// deliberately excluded.
//
// The kind filter is load-bearing (migration 098): structural-insights items
// live in the same table but are prepared through an entirely different path
// (PrepareStructuralSend replays stored bytes; PrepareCloudOutboxSend rebuilds
// an envelope from a session). Their drain set is
// ListSendableStructuralOutbox, which orders by revision rather than by
// creation time.
func (s *Store) ListSendableCloudOutbox(ctx context.Context) ([]CloudOutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, session_id, feature_set_json, evidence_content_digest, upload_digest,
		       receipt_id, state, retry_count, last_error, created_at, updated_at
		  FROM cloud_outbox
		 WHERE kind = ? AND state IN (?, ?)
		 ORDER BY created_at ASC, id ASC`,
		string(CloudOutboxKindSessionEvidence),
		string(CloudOutboxPending), string(CloudOutboxFailedRetryable))
	if err != nil {
		return nil, fmt.Errorf("store.ListSendableCloudOutbox: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanCloudOutboxRows(rows, "store.ListSendableCloudOutbox")
}

// CloudOutboxCountsByState returns per-state outbox counts and the total across
// every state (including the terminal states ListSendableCloudOutbox omits).
func (s *Store) CloudOutboxCountsByState(ctx context.Context) (map[string]int, int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT state, COUNT(*) FROM cloud_outbox GROUP BY state`)
	if err != nil {
		return nil, 0, fmt.Errorf("store.CloudOutboxCountsByState: %w", err)
	}
	defer func() { _ = rows.Close() }()
	byState := map[string]int{}
	total := 0
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, 0, fmt.Errorf("store.CloudOutboxCountsByState: scan: %w", err)
		}
		byState[st] = n
		total += n
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store.CloudOutboxCountsByState: %w", err)
	}
	return byState, total, nil
}

// ListCloudOutboxForSession returns every outbox item bound to sessionID (any
// state), oldest first — the session-detail surface. NODE-LOCAL.
func (s *Store) ListCloudOutboxForSession(ctx context.Context, sessionID string) ([]CloudOutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, session_id, feature_set_json, evidence_content_digest, upload_digest,
		       receipt_id, state, retry_count, last_error, created_at, updated_at
		  FROM cloud_outbox WHERE session_id = ?
		 ORDER BY created_at ASC, id ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.ListCloudOutboxForSession: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanCloudOutboxRows(rows, "store.ListCloudOutboxForSession")
}
