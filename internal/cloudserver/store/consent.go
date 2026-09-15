package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ConsentState is the current granted-purpose set for an account plus the
// monotonic generation (Sol SC4). Generation is bumped by every consent event
// (grant/update/revoke/preview_confirmation) and recorded on a job at admission;
// the execution lease revalidates it.
type ConsentState struct {
	Purposes   []string
	Generation int64
}

// CurrentConsent returns the account's current granted purposes (from the most
// recent grant/update/revoke event) and its consent generation.
func (s *Store) CurrentConsent(ctx context.Context, accountID string) (ConsentState, error) {
	var st ConsentState
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if e := tx.QueryRow(ctx,
			`SELECT consent_generation FROM accounts WHERE account_id = $1::uuid`,
			accountID).Scan(&st.Generation); e != nil {
			return fmt.Errorf("read generation: %w", e)
		}
		e := tx.QueryRow(ctx,
			`SELECT purposes FROM consent_events
			  WHERE account_id = $1::uuid AND event_type IN ('grant','update','revoke')
			  ORDER BY generation DESC, created_at DESC LIMIT 1`,
			accountID).Scan(&st.Purposes)
		if errors.Is(e, pgx.ErrNoRows) {
			st.Purposes = nil
			return nil
		}
		return e
	})
	return st, err
}

// SetConsent replaces the granted-purpose set, bumping the generation and
// recording an 'update' event. Returns the new generation.
func (s *Store) SetConsent(ctx context.Context, accountID string, purposes []string, now time.Time) (int64, error) {
	var gen int64
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		gen, e = bumpGenerationTx(ctx, tx, accountID)
		if e != nil {
			return e
		}
		if _, e := tx.Exec(ctx,
			`INSERT INTO consent_events (account_id, event_type, purposes, generation)
			 VALUES ($1::uuid, 'update', $2, $3)`,
			accountID, purposes, gen); e != nil {
			return fmt.Errorf("record consent event: %w", e)
		}
		return nil
	})
	return gen, err
}

// PreviewConfirmationInput binds the confirmed literal-preview digest to a
// receipt (Sol SC1). purposes/field_classes are what the user confirmed.
type PreviewConfirmationInput struct {
	DeviceID        string // "" ⇒ NULL
	Purposes        []string
	FieldClasses    []string
	EvidenceSchema  string
	ScrubberVersion string
	RetentionPolicy string
	Endpoint        string
	Subprocessors   []string
	UploadDigest    string
	ContentDigest   string
	ExpiresAt       *time.Time
	Now             time.Time
}

// RecordPreviewConfirmation creates a consent receipt binding the upload digest
// of the literal preview and bumps the generation. Returns the receipt id and
// the new generation.
func (s *Store) RecordPreviewConfirmation(ctx context.Context, accountID string, in PreviewConfirmationInput) (receiptID string, gen int64, err error) {
	err = s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		gen, e = bumpGenerationTx(ctx, tx, accountID)
		if e != nil {
			return e
		}
		var deviceID any
		if in.DeviceID != "" {
			deviceID = in.DeviceID
		}
		sub := in.Subprocessors
		if sub == nil {
			sub = []string{}
		}
		if e := tx.QueryRow(ctx,
			`INSERT INTO consent_receipts
			   (account_id, device_id, purposes, field_classes, evidence_schema,
			    scrubber_version, retention_policy, endpoint, subprocessors,
			    upload_digest, evidence_content_digest, generation, expires_at)
			 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			 RETURNING id::text`,
			accountID, deviceID, in.Purposes, in.FieldClasses, in.EvidenceSchema,
			in.ScrubberVersion, in.RetentionPolicy, in.Endpoint, sub,
			in.UploadDigest, nullString(in.ContentDigest), gen, in.ExpiresAt).Scan(&receiptID); e != nil {
			return fmt.Errorf("insert receipt: %w", e)
		}
		if _, e := tx.Exec(ctx,
			`INSERT INTO consent_events (account_id, receipt_id, event_type, purposes, generation)
			 VALUES ($1::uuid, $2::uuid, 'preview_confirmation', $3, $4)`,
			accountID, receiptID, in.Purposes, gen); e != nil {
			return fmt.Errorf("record preview event: %w", e)
		}
		return nil
	})
	return receiptID, gen, err
}

// ReceiptForDigest returns the most recent consent receipt whose upload digest
// matches (the receipt the job's evidence must correspond to), or ErrNotFound.
func (s *Store) ReceiptForDigest(ctx context.Context, accountID, uploadDigest string) (receiptID string, purposes []string, generation int64, err error) {
	err = s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT id::text, purposes, generation FROM consent_receipts
			  WHERE account_id = $1::uuid AND upload_digest = $2
			  ORDER BY created_at DESC LIMIT 1`,
			accountID, uploadDigest).Scan(&receiptID, &purposes, &generation)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	return receiptID, purposes, generation, err
}

// bumpGenerationTx increments and returns the account's consent generation.
func bumpGenerationTx(ctx context.Context, tx pgx.Tx, accountID string) (int64, error) {
	var gen int64
	if err := tx.QueryRow(ctx,
		`UPDATE accounts SET consent_generation = consent_generation + 1, updated_at = now()
		  WHERE account_id = $1::uuid RETURNING consent_generation`,
		accountID).Scan(&gen); err != nil {
		return 0, fmt.Errorf("cloudserver/store.bumpGeneration: %w", err)
	}
	return gen, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
