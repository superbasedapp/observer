package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// EvidenceTTL is the immutable free-tier evidence lifetime (plan §2.8):
// expires_at = created_at + 1h, stamped at creation and never extended.
const EvidenceTTL = 1 * time.Hour

// ensureProjectTx resolves-or-creates a cloud_projects row and returns its pk.
func ensureProjectTx(ctx context.Context, tx pgx.Tx, accountID, cloudProjectID string) (string, error) {
	var pk string
	err := tx.QueryRow(ctx,
		`INSERT INTO cloud_projects (account_id, cloud_project_id) VALUES ($1::uuid, $2)
		 ON CONFLICT (account_id, cloud_project_id)
		 DO UPDATE SET cloud_project_id = cloud_projects.cloud_project_id
		 RETURNING id::text`,
		accountID, cloudProjectID).Scan(&pk)
	if err != nil {
		return "", fmt.Errorf("cloudserver/store.ensureProject: %w", err)
	}
	return pk, nil
}

// ensureSessionTx resolves-or-creates a cloud_sessions row and returns its pk.
// metrics is the content-free structural snapshot captured at submit time
// (migration 0037, W5) — the envelope's MetricsBlock/Outcomes/ActivityMix
// field names verbatim, no excerpts/paths/action targets. A nil/empty metrics
// leaves the stored value UNCHANGED on conflict (coalesce), so a caller that
// has none to report never clobbers a snapshot an earlier submit stored.
func ensureSessionTx(ctx context.Context, tx pgx.Tx, accountID, projectPK, cloudSessionID, tool, model string, metrics []byte) (string, error) {
	var pk string
	var m any
	if len(metrics) > 0 {
		m = metrics
	}
	err := tx.QueryRow(ctx,
		`INSERT INTO cloud_sessions (account_id, project_pk, cloud_session_id, tool, model_family, metrics)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb)
		 ON CONFLICT (account_id, cloud_session_id)
		 DO UPDATE SET tool = EXCLUDED.tool, model_family = EXCLUDED.model_family,
		               metrics = coalesce(EXCLUDED.metrics, cloud_sessions.metrics)
		 RETURNING id::text`,
		accountID, projectPK, cloudSessionID, tool, model, m).Scan(&pk)
	if err != nil {
		return "", fmt.Errorf("cloudserver/store.ensureSession: %w", err)
	}
	return pk, nil
}

// createEvidenceTx writes an evidence object with an immutable
// expires_at = now + EvidenceTTL.
func createEvidenceTx(ctx context.Context, tx pgx.Tx, accountID, sessionPK, blobRef, uploadDigest, contentDigest string, sizeBytes int64, now time.Time) (string, error) {
	var pk string
	var sess any
	if sessionPK != "" {
		sess = sessionPK
	}
	err := tx.QueryRow(ctx,
		`INSERT INTO evidence_objects
		   (account_id, session_pk, blob_ref, upload_digest, evidence_content_digest, size_bytes, created_at, expires_at)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)
		 RETURNING id::text`,
		accountID, sess, blobRef, uploadDigest, contentDigest, sizeBytes, now, now.Add(EvidenceTTL)).Scan(&pk)
	if err != nil {
		return "", fmt.Errorf("cloudserver/store.createEvidence: %w", err)
	}
	return pk, nil
}

// EvidenceObject is the row a lease reads to gate on TTL headroom / deletion.
type EvidenceObject struct {
	ID        string
	BlobRef   string
	ExpiresAt time.Time
	DeletedAt *time.Time
}

// GetEvidence loads one evidence object by pk (tenant-scoped).
func (s *Store) GetEvidence(ctx context.Context, accountID, evidencePK string) (EvidenceObject, error) {
	var eo EvidenceObject
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT id::text, blob_ref, expires_at, deleted_at FROM evidence_objects
			  WHERE account_id = $1::uuid AND id = $2::uuid`,
			accountID, evidencePK).Scan(&eo.ID, &eo.BlobRef, &eo.ExpiresAt, &eo.DeletedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	return eo, err
}

// MarkEvidenceDeleted sets deleted_at (early deletion; the expires_at trigger
// still forbids extending the TTL). Idempotent.
func (s *Store) MarkEvidenceDeleted(ctx context.Context, accountID, evidencePK string, now time.Time) error {
	return s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return markEvidenceDeletedTx(ctx, tx, accountID, evidencePK, now)
	})
}

func markEvidenceDeletedTx(ctx context.Context, tx pgx.Tx, accountID, evidencePK string, now time.Time) error {
	_, e := tx.Exec(ctx,
		`UPDATE evidence_objects SET deleted_at = $3
		  WHERE account_id = $1::uuid AND id = $2::uuid AND deleted_at IS NULL`,
		accountID, evidencePK, now)
	return e
}
