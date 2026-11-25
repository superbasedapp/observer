package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// cloudlocal_consent.go holds the cloud_consent_receipts half of the
// cloud-intelligence store seam (cloudlocal.go describes the whole seam and
// its shared types).

// -- Consent receipts --------------------------------------------------------

// InsertCloudConsentReceipt stores a receipt. If r.ID is empty a random id is
// minted; the stored (or minted) id is returned.
func (s *Store) InsertCloudConsentReceipt(ctx context.Context, r CloudConsentReceipt) (string, error) {
	if r.AccountPseudonym == "" {
		return "", errors.New("store.InsertCloudConsentReceipt: account pseudonym is required")
	}
	if r.UploadDigest == "" {
		return "", errors.New("store.InsertCloudConsentReceipt: upload digest is required")
	}
	if r.ID == "" {
		id, err := cloudRandomID("rcpt_")
		if err != nil {
			return "", fmt.Errorf("store.InsertCloudConsentReceipt: %w", err)
		}
		r.ID = id
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	fieldClasses := r.FieldClassesJSON
	if fieldClasses == "" {
		fieldClasses = "[]"
	}
	// An unset grant mode is per-upload: the 097 semantics, so a caller written
	// before standing grants existed keeps exactly its old meaning.
	grantMode := r.GrantMode
	if grantMode == "" {
		grantMode = CloudGrantPerUpload
	}
	if grantMode != CloudGrantPerUpload && grantMode != CloudGrantStanding {
		return "", fmt.Errorf("store.InsertCloudConsentReceipt: unknown grant mode %q", grantMode)
	}
	if _, err := ParseCloudEvidenceSettings(r.EvidenceSettingsJSON); err != nil {
		return "", fmt.Errorf("store.InsertCloudConsentReceipt: %w", err)
	}
	if r.BackgroundGeneration < 0 {
		return "", ErrCloudBackgroundPolicyChanged
	}
	if r.ConsentGeneration < 0 {
		return "", errors.New("store.InsertCloudConsentReceipt: consent generation is negative")
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO cloud_consent_receipts
		  (id, account_pseudonym, device_label_ref, purpose, field_classes_json,
		   envelope_schema_version, scrubber_version, endpoint,
		   retention_policy_version, upload_digest, created_at, invalidated_at,
		   grant_mode, data_dictionary_digest, declared_timezone,
		   source_window_rule, review_at, consent_generation, background_generation, evidence_settings_json)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE ? = 0 OR EXISTS (
            SELECT 1 FROM cloud_enrich_policy WHERE id = 1 AND background = 1 AND generation = ?
              AND ((level = 'titles' AND ? = 'structural_activity_insights')
                OR (level = 'excerpts' AND ? = 'bounded_context_enrichment'))
        )`,
		r.ID, r.AccountPseudonym, r.DeviceLabelRef, r.Purpose, fieldClasses,
		r.EnvelopeSchemaVersion, r.ScrubberVersion, r.Endpoint,
		r.RetentionPolicyVersion, r.UploadDigest, cloudFormatTime(r.CreatedAt),
		nullableCloudTime(r.InvalidatedAt),
		string(grantMode), r.DataDictionaryDigest, r.DeclaredTimezone,
		r.SourceWindowRule, nullableCloudTime(r.ReviewAt), r.ConsentGeneration, r.BackgroundGeneration, r.EvidenceSettingsJSON,
		r.BackgroundGeneration, r.BackgroundGeneration, r.Purpose, r.Purpose)
	if err != nil {
		return "", fmt.Errorf("store.InsertCloudConsentReceipt: %w", err)
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return "", fmt.Errorf("store.InsertCloudConsentReceipt: %w", ErrCloudBackgroundPolicyChanged)
	}
	return r.ID, nil
}

// GetCloudConsentReceipt loads a receipt by id. ok=false means it does not
// exist.
func (s *Store) GetCloudConsentReceipt(ctx context.Context, id string) (CloudConsentReceipt, bool, error) {
	var (
		r             CloudConsentReceipt
		createdAt     string
		invalidatedAt sql.NullString
		grantMode     string
		reviewAt      sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, account_pseudonym, device_label_ref, purpose, field_classes_json,
		       envelope_schema_version, scrubber_version, endpoint,
		       retention_policy_version, upload_digest, created_at, invalidated_at,
		       grant_mode, data_dictionary_digest, declared_timezone,
		       source_window_rule, review_at, consent_generation, background_generation, evidence_settings_json
		  FROM cloud_consent_receipts WHERE id = ?`, id).
		Scan(&r.ID, &r.AccountPseudonym, &r.DeviceLabelRef, &r.Purpose, &r.FieldClassesJSON,
			&r.EnvelopeSchemaVersion, &r.ScrubberVersion, &r.Endpoint,
			&r.RetentionPolicyVersion, &r.UploadDigest, &createdAt, &invalidatedAt,
			&grantMode, &r.DataDictionaryDigest, &r.DeclaredTimezone,
			&r.SourceWindowRule, &reviewAt, &r.ConsentGeneration, &r.BackgroundGeneration, &r.EvidenceSettingsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudConsentReceipt{}, false, nil
	}
	if err != nil {
		return CloudConsentReceipt{}, false, fmt.Errorf("store.GetCloudConsentReceipt: %w", err)
	}
	r.CreatedAt = cloudParseTime(createdAt)
	if invalidatedAt.Valid && invalidatedAt.String != "" {
		t := cloudParseTime(invalidatedAt.String)
		r.InvalidatedAt = &t
	}
	r.GrantMode = CloudGrantMode(grantMode)
	if reviewAt.Valid && reviewAt.String != "" {
		t := cloudParseTime(reviewAt.String)
		r.ReviewAt = &t
	}
	return r, true, nil
}

// cloudReceiptColumns is the receipt column list every receipt read shares, so
// GetCloudConsentReceipt and the list reads below can never drift apart.
const cloudReceiptColumns = `id, account_pseudonym, device_label_ref, purpose, field_classes_json,
	       envelope_schema_version, scrubber_version, endpoint,
	       retention_policy_version, upload_digest, created_at, invalidated_at,
	       grant_mode, data_dictionary_digest, declared_timezone,
	       source_window_rule, review_at, consent_generation, background_generation, evidence_settings_json`

// scanCloudReceiptRows scans a cloudReceiptColumns result set.
func scanCloudReceiptRows(rows *sql.Rows, pfx string) ([]CloudConsentReceipt, error) {
	var out []CloudConsentReceipt
	for rows.Next() {
		var (
			r             CloudConsentReceipt
			createdAt     string
			invalidatedAt sql.NullString
			grantMode     string
			reviewAt      sql.NullString
		)
		if err := rows.Scan(&r.ID, &r.AccountPseudonym, &r.DeviceLabelRef, &r.Purpose, &r.FieldClassesJSON,
			&r.EnvelopeSchemaVersion, &r.ScrubberVersion, &r.Endpoint,
			&r.RetentionPolicyVersion, &r.UploadDigest, &createdAt, &invalidatedAt,
			&grantMode, &r.DataDictionaryDigest, &r.DeclaredTimezone,
			&r.SourceWindowRule, &reviewAt, &r.ConsentGeneration, &r.BackgroundGeneration, &r.EvidenceSettingsJSON); err != nil {
			return nil, fmt.Errorf("%s: scan: %w", pfx, err)
		}
		r.CreatedAt = cloudParseTime(createdAt)
		if invalidatedAt.Valid && invalidatedAt.String != "" {
			t := cloudParseTime(invalidatedAt.String)
			r.InvalidatedAt = &t
		}
		r.GrantMode = CloudGrantMode(grantMode)
		if reviewAt.Valid && reviewAt.String != "" {
			t := cloudParseTime(reviewAt.String)
			r.ReviewAt = &t
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", pfx, err)
	}
	return out, nil
}

// ListCloudConsentReceipts returns EVERY stored receipt, newest first —
// including invalidated ones, because "what did I ever grant, and when was it
// revoked?" is exactly the question the consent-management surface
// (`observer cloud consent list`) answers. It is content-free: a receipt
// carries purposes, versions, digests and timestamps, never session data.
func (s *Store) ListCloudConsentReceipts(ctx context.Context) ([]CloudConsentReceipt, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+cloudReceiptColumns+`
		  FROM cloud_consent_receipts
		 ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("store.ListCloudConsentReceipts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanCloudReceiptRows(rows, "store.ListCloudConsentReceipts")
}

// ListLiveCloudConsentReceipts returns the receipts that have NOT been
// invalidated, newest first, optionally narrowed to one purpose ("" = every
// purpose). It is the read the consent-gated egress gateway
// (internal/cloudgateway) resolves live grant state from before any feature
// egress.
//
// "Live" here means exactly one thing — not invalidated. Expiry/review_at is
// deliberately NOT applied in SQL: that is a CLOCK policy, and the gateway owns
// the clock (it can be injected in tests, and a single place decides what
// "expired" means). A row this returns is a candidate; the gateway decides.
func (s *Store) ListLiveCloudConsentReceipts(ctx context.Context, purpose string) ([]CloudConsentReceipt, error) {
	query := `SELECT ` + cloudReceiptColumns + `
		  FROM cloud_consent_receipts
		 WHERE COALESCE(invalidated_at, '') = ''`
	args := []any{}
	if purpose != "" {
		query += ` AND purpose = ?`
		args = append(args, purpose)
	}
	query += ` ORDER BY created_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListLiveCloudConsentReceipts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanCloudReceiptRows(rows, "store.ListLiveCloudConsentReceipts")
}

// MaxCloudConsentGeneration returns the highest consent_generation recorded for
// a purpose across ALL its receipts, live or invalidated (0 when the purpose has
// none). Counting invalidated receipts too is the point: the generation is a
// monotonic "these terms changed" counter, so revoking and re-granting must
// produce a HIGHER generation, never reuse a retired one — a queued snapshot
// recording generation N must not be silently accepted under a later grant that
// happens to be numbered N again.
func (s *Store) MaxCloudConsentGeneration(ctx context.Context, purpose string) (int, error) {
	if purpose == "" {
		return 0, errors.New("store.MaxCloudConsentGeneration: purpose is required")
	}
	var maxGen int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(consent_generation), 0) FROM cloud_consent_receipts WHERE purpose = ?`,
		purpose).Scan(&maxGen); err != nil {
		return 0, fmt.Errorf("store.MaxCloudConsentGeneration: %w", err)
	}
	return maxGen, nil
}

// StandingGrantReplacement reports what recording a standing grant did to the
// state that preceded it. It is content-free (ids and counts) and exists so the
// CLI can state the consequences rather than performing them silently.
type StandingGrantReplacement struct {
	// ReceiptID is the newly recorded standing receipt.
	ReceiptID string
	// ConsentGeneration is the generation actually allocated inside the
	// transaction — which may differ from any value a caller previewed.
	ConsentGeneration int
	// SupersededReceiptIDs are the previously-live standing receipts for the
	// purpose, now invalidated.
	SupersededReceiptIDs []string
	// RequeuedForReconfirmation is how many non-terminal outbox rows bound to
	// those receipts were moved to reconfirmation_required.
	RequeuedForReconfirmation int
}

// ReplaceStandingConsentGrant records a STANDING grant as the ONE live standing
// grant for its purpose, in a single transaction that:
//
//  1. allocates the consent generation (current max for the purpose, + 1);
//  2. invalidates every other live standing receipt for that purpose;
//  3. moves their non-terminal outbox rows to reconfirmation_required;
//  4. inserts the new receipt.
//
// WHY ONE LIVE RECEIPT PER PURPOSE. With two live standing receipts, a queued
// snapshot stays validly bound to the OLDER one while any path that resolves
// "the newest grant" reads the newer — so bytes built under retired terms could
// ship declaring current terms. Making the re-grant supersede removes the
// ambiguity at the root rather than asking every reader to disambiguate.
//
// WHY RECONFIRMATION, NOT CANCELLATION. The developer re-granting has not
// withdrawn consent; they have changed its terms. Cancelling would silently
// destroy captured windows. reconfirmation_required is the honest state: the
// item is not sendable, and it is visible, so it can be re-bound or re-captured
// under the new grant. (Revoking, which IS a withdrawal, still cancels — see
// CancelCloudOutboxForReceipt.)
//
// GENERATION ALLOCATION happens INSIDE this transaction. The DSN's
// `_txlock=immediate` takes SQLite's write lock at BEGIN, so two concurrent
// grants serialize and cannot both read the same max; migration 099's partial
// UNIQUE index on (purpose, consent_generation) for live-shaped standing rows is
// the backstop that turns any future racy path into a loud failure rather than a
// silent duplicate.
func (s *Store) ReplaceStandingConsentGrant(ctx context.Context, r CloudConsentReceipt) (StandingGrantReplacement, error) {
	const pfx = "store.ReplaceStandingConsentGrant"
	if r.Purpose == "" {
		return StandingGrantReplacement{}, fmt.Errorf("%s: purpose is required", pfx)
	}
	if r.AccountPseudonym == "" {
		return StandingGrantReplacement{}, fmt.Errorf("%s: account pseudonym is required", pfx)
	}
	if r.UploadDigest == "" {
		return StandingGrantReplacement{}, fmt.Errorf("%s: upload digest is required", pfx)
	}
	if r.GrantMode != "" && r.GrantMode != CloudGrantStanding {
		return StandingGrantReplacement{}, fmt.Errorf("%s: grant mode %q is not standing", pfx, r.GrantMode)
	}
	r.GrantMode = CloudGrantStanding
	if r.ID == "" {
		id, err := cloudRandomID("rcpt_")
		if err != nil {
			return StandingGrantReplacement{}, fmt.Errorf("%s: %w", pfx, err)
		}
		r.ID = id
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	if r.FieldClassesJSON == "" {
		r.FieldClassesJSON = "[]"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return StandingGrantReplacement{}, fmt.Errorf("%s: %w", pfx, err)
	}
	defer func() { _ = tx.Rollback() }()

	// 1. Allocate the generation under the write lock this transaction holds.
	var maxGen int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(consent_generation), 0) FROM cloud_consent_receipts WHERE purpose = ?`,
		r.Purpose).Scan(&maxGen); err != nil {
		return StandingGrantReplacement{}, fmt.Errorf("%s: allocate generation: %w", pfx, err)
	}
	out := StandingGrantReplacement{ReceiptID: r.ID, ConsentGeneration: maxGen + 1}

	// 2. Find the live standing receipts this grant supersedes.
	rows, err := tx.QueryContext(ctx, `
		SELECT id FROM cloud_consent_receipts
		 WHERE purpose = ? AND grant_mode = ? AND COALESCE(invalidated_at, '') = ''`,
		r.Purpose, string(CloudGrantStanding))
	if err != nil {
		return StandingGrantReplacement{}, fmt.Errorf("%s: read live standing grants: %w", pfx, err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return StandingGrantReplacement{}, fmt.Errorf("%s: scan: %w", pfx, err)
		}
		out.SupersededReceiptIDs = append(out.SupersededReceiptIDs, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return StandingGrantReplacement{}, fmt.Errorf("%s: %w", pfx, err)
	}
	_ = rows.Close()

	now := cloudFormatTime(time.Now().UTC())
	for _, id := range out.SupersededReceiptIDs {
		if _, err := tx.ExecContext(ctx,
			`UPDATE cloud_consent_receipts SET invalidated_at = ? WHERE id = ? AND invalidated_at IS NULL`,
			now, id); err != nil {
			return StandingGrantReplacement{}, fmt.Errorf("%s: supersede %s: %w", pfx, id, err)
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE cloud_outbox
			   SET state = ?, last_error = 'superseded_by_new_grant', updated_at = ?
			 WHERE receipt_id = ? AND state IN (?, ?, ?)`,
			string(CloudOutboxReconfirmationRequired), now, id,
			string(CloudOutboxPending), string(CloudOutboxFailedRetryable), string(CloudOutboxSending))
		if err != nil {
			return StandingGrantReplacement{}, fmt.Errorf("%s: requeue items of %s: %w", pfx, id, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return StandingGrantReplacement{}, fmt.Errorf("%s: %w", pfx, err)
		}
		out.RequeuedForReconfirmation += int(n)
		// 3b. Cancel the dispatch leases held under the superseded receipt
		// (migration 100, Sol re-review N2). The CLI then waits for those
		// leases to drain — AwaitCloudDispatchQuiescence — OUTSIDE this
		// transaction, so a sender releasing its lease is never blocked behind
		// the write lock this transaction holds.
		if _, err := cancelCloudDispatchLeasesTx(ctx, tx, id, time.Now().UTC()); err != nil {
			return StandingGrantReplacement{}, fmt.Errorf("%s: cancel dispatch leases of %s: %w", pfx, id, err)
		}
	}

	// 4. Insert the new receipt with the generation this transaction allocated.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cloud_consent_receipts
		  (id, account_pseudonym, device_label_ref, purpose, field_classes_json,
		   envelope_schema_version, scrubber_version, endpoint,
		   retention_policy_version, upload_digest, created_at, invalidated_at,
		   grant_mode, data_dictionary_digest, declared_timezone,
		   source_window_rule, review_at, consent_generation)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.AccountPseudonym, r.DeviceLabelRef, r.Purpose, r.FieldClassesJSON,
		r.EnvelopeSchemaVersion, r.ScrubberVersion, r.Endpoint,
		r.RetentionPolicyVersion, r.UploadDigest, cloudFormatTime(r.CreatedAt),
		string(CloudGrantStanding), r.DataDictionaryDigest, r.DeclaredTimezone,
		r.SourceWindowRule, nullableCloudTime(r.ReviewAt), out.ConsentGeneration); err != nil {
		if isUniqueConstraintErr(err) {
			// Migration 099's index fired: another grant for this purpose took the
			// same generation. Say so plainly rather than retrying into a loop —
			// this is an interactive command and a re-run allocates the next one.
			return StandingGrantReplacement{}, fmt.Errorf(
				"%s: consent generation %d for purpose %q was allocated concurrently - nothing was recorded; re-run the grant",
				pfx, out.ConsentGeneration, r.Purpose,
			)
		}
		return StandingGrantReplacement{}, fmt.Errorf("%s: insert receipt: %w", pfx, err)
	}
	if err := tx.Commit(); err != nil {
		return StandingGrantReplacement{}, fmt.Errorf("%s: %w", pfx, err)
	}
	return out, nil
}

// InvalidateCloudConsentReceipt stamps a receipt invalidated (idempotent — a
// re-invalidation keeps the first timestamp). A material change to schema,
// field class, retention, or subprocessors pauses the lane by invalidating the
// receipt (amendment §4.2); CancelCloudOutboxForReceipt then cancels the
// dependent jobs. Missing id is a no-op.
func (s *Store) InvalidateCloudConsentReceipt(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE cloud_consent_receipts
		   SET invalidated_at = ?
		 WHERE id = ? AND invalidated_at IS NULL`,
		cloudFormatTime(time.Now().UTC()), id)
	if err != nil {
		return fmt.Errorf("store.InvalidateCloudConsentReceipt: %w", err)
	}
	return nil
}

// -- CI-P5 dashboard read seam (FF1) -----------------------------------------
//
// These aggregate reads back the NODE dashboard's Cloud Intelligence surfaces.
// They live in this store seam — not as ad-hoc SQL in the handler — so the
// §7.7 "one store seam per database" invariant holds: a cloud-schema or
// eligibility change is made here once and both the CLI and the dashboard track
// it. The handler decides how to degrade (empty state) on error; the seam
// returns errors rather than swallowing them.

// CloudReceiptCounts returns the total consent receipts and the live (not
// invalidated) subset. invalidated_at is stored NULL or "" while live.
func (s *Store) CloudReceiptCounts(ctx context.Context) (total, live int, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*),
		       COALESCE(SUM(CASE WHEN COALESCE(invalidated_at, '') = '' THEN 1 ELSE 0 END), 0)
		  FROM cloud_consent_receipts`).Scan(&total, &live)
	if err != nil {
		return 0, 0, fmt.Errorf("store.CloudReceiptCounts: %w", err)
	}
	return total, live, nil
}
