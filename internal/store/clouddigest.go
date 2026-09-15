package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// clouddigest.go is the store seam over migration 118's cloud_digests table
// (value-upgrade plan of record §W5,
// docs/plans/cloud-intelligence-value-upgrade-plan-2026-09-14.md): the
// weekly project digest — a server-side rollup over a project's own
// already-uploaded session_enrichment results — that `observer cloud sync`
// pulls back alongside session enrichment results.
//
// Same discipline as cloudpolicy.go / cloudautoenrich.go: this file does not
// import internal/cloudcontract or internal/cloudclient/cloudgateway/
// cloudpop/cloudcred (the zero-egress invariant). cloud_digests is
// NODE-LOCAL like every other cloud_* table and never enters the org-push
// wire.

// CloudDigest is one weekly project digest received from the hosted
// service. ResultJSON is the validated cloudcontract.DigestResult body,
// stored opaque here the same way CloudResult stores a session-enrichment
// body — this package stays agnostic of the enrichment/digest schema.
type CloudDigest struct {
	// ID is the server result id (the wire's ResultRecord.ResultID) — a
	// re-pull of the same digest updates this row in place rather than
	// opening a new supersede chain.
	ID string
	// CloudProjectID is the project pseudonym the digest covers.
	CloudProjectID string
	// LocalProjectID is the local projects.id (as a string, matching
	// GetOrCreateCloudProjectPseudonym's convention) this device resolved
	// the pseudonym to, or "" when the pseudonym is not recognized on this
	// device (a project enrolled elsewhere, or a stale mapping).
	LocalProjectID string
	// PeriodStart / PeriodEnd bound the digest's ISO week ("YYYY-MM-DD").
	PeriodStart string
	PeriodEnd   string
	// SchemaVersion is the digest result schema (cloudcontract.DigestSchemaVersion).
	SchemaVersion string
	// ResultJSON is the validated DigestResult body, opaque JSON.
	ResultJSON string
	// ReceivedAt is the server result creation time (local time for legacy callers).
	ReceivedAt time.Time
	// ServerSequence orders replacements within the server result stream.
	ServerSequence int64
	// ServerStream identifies the estate and cursor family; empty uses timestamps.
	ServerStream string
	// SupersededBy is the id of a later digest for the same project+period,
	// or nil when this is the current (head) digest for that period.
	SupersededBy *string
}

// UpsertCloudDigest stores or updates one digest. A newer digest for the
// same (cloud_project_id, period_start, period_end) — a different ID —
// marks every other current digest for that project+period superseded by
// this one, mirroring how a regenerated session-enrichment result
// supersedes the prior one. Re-upserting the SAME id (a re-pull under an
// unchanged cursor) updates the row in place and leaves any existing
// superseded_by value untouched.
func (s *Store) UpsertCloudDigest(ctx context.Context, d CloudDigest) error {
	const pfx = "store.UpsertCloudDigest"
	if d.ID == "" {
		return fmt.Errorf("%s: id is required", pfx)
	}
	receivedAt := d.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = time.Now().UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s: begin: %w", pfx, err)
	}
	defer func() { _ = tx.Rollback() }()

	// Replayed IDs are historical updates, never a new replacement. For an
	// unseen ID compare server ordering before changing the current head, so
	// overlapping pulls cannot let an older result retire a newer one.
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM cloud_digests WHERE id = ?)`, d.ID).Scan(&exists); err != nil {
		return fmt.Errorf("%s: read existing: %w", pfx, err)
	}
	var supersededBy any
	if !exists {
		var headID, headTime, headStream string
		var headSequence int64
		err := tx.QueryRowContext(ctx, `SELECT id, received_at, server_sequence, server_stream FROM cloud_digests
			WHERE cloud_project_id = ? AND period_start = ? AND period_end = ? AND superseded_by IS NULL
			ORDER BY received_at DESC, id DESC LIMIT 1`,
			d.CloudProjectID, d.PeriodStart, d.PeriodEnd).Scan(&headID, &headTime, &headSequence, &headStream)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%s: read current: %w", pfx, err)
		}
		older := headID != "" && cloudParseTime(headTime).After(receivedAt)
		if d.ServerStream != "" && headStream == d.ServerStream && headSequence > 0 && d.ServerSequence > 0 {
			older = headSequence > d.ServerSequence
		}
		if older {
			supersededBy = headID
		} else if _, err := tx.ExecContext(ctx, `UPDATE cloud_digests SET superseded_by = ?
			WHERE cloud_project_id = ? AND period_start = ? AND period_end = ? AND superseded_by IS NULL`,
			d.ID, d.CloudProjectID, d.PeriodStart, d.PeriodEnd); err != nil {
			return fmt.Errorf("%s: supersede prior: %w", pfx, err)
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cloud_digests
		  (id, cloud_project_id, local_project_id, period_start, period_end,
		   schema_version, result_json, received_at, superseded_by, server_sequence, server_stream)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			cloud_project_id = excluded.cloud_project_id,
			local_project_id = excluded.local_project_id,
			period_start     = excluded.period_start,
			period_end       = excluded.period_end,
			schema_version   = excluded.schema_version,
			result_json      = excluded.result_json,
			received_at      = excluded.received_at,
			server_sequence = CASE WHEN cloud_digests.server_stream = excluded.server_stream
                THEN MAX(cloud_digests.server_sequence, excluded.server_sequence) ELSE excluded.server_sequence END,
            server_stream = excluded.server_stream`,
		d.ID, d.CloudProjectID, d.LocalProjectID, d.PeriodStart, d.PeriodEnd,
		d.SchemaVersion, d.ResultJSON, cloudFormatTime(receivedAt), supersededBy, d.ServerSequence, d.ServerStream); err != nil {
		return fmt.Errorf("%s: %w", pfx, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%s: commit: %w", pfx, err)
	}
	return nil
}

// ListCloudDigests returns current (non-superseded) digests, newest period
// first, capped at limit. localProjectID "" lists every project's digests
// on this device (incl. ones with an unresolved local_project_id); a
// nonempty value scopes to one local project.
func (s *Store) ListCloudDigests(ctx context.Context, localProjectID string, limit int) ([]CloudDigest, error) {
	const pfx = "store.ListCloudDigests"
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, cloud_project_id, local_project_id, period_start, period_end,
		       schema_version, result_json, received_at, superseded_by, server_sequence, server_stream
		  FROM cloud_digests
		 WHERE superseded_by IS NULL`
	args := []any{}
	if localProjectID != "" {
		query += ` AND local_project_id = ?`
		args = append(args, localProjectID)
	}
	query += ` ORDER BY period_end DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pfx, err)
	}
	defer func() { _ = rows.Close() }()

	var out []CloudDigest
	for rows.Next() {
		var (
			d            CloudDigest
			receivedAt   string
			supersededBy sql.NullString
		)
		if err := rows.Scan(&d.ID, &d.CloudProjectID, &d.LocalProjectID, &d.PeriodStart, &d.PeriodEnd,
			&d.SchemaVersion, &d.ResultJSON, &receivedAt, &supersededBy, &d.ServerSequence, &d.ServerStream); err != nil {
			return nil, fmt.Errorf("%s: %w", pfx, err)
		}
		d.ReceivedAt = cloudParseTime(receivedAt)
		if supersededBy.Valid && supersededBy.String != "" {
			v := supersededBy.String
			d.SupersededBy = &v
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", pfx, err)
	}
	return out, nil
}

// LookupLocalProjectByCloudPseudonym is the reverse of
// GetOrCreateCloudProjectPseudonym: given a cloud project pseudonym (as
// received on a pulled digest's cloud_project_id), it returns the local
// project id (the projects.id row, formatted as a string) this device
// minted that pseudonym for. It is read-only — unlike
// GetOrCreateCloudProjectPseudonym it never mints, since a pseudonym this
// device doesn't recognize is legitimately unassociable here (e.g. a
// digest for a project enrolled from a different device). ok=false on no
// match is expected, routine behavior, never an error.
func (s *Store) LookupLocalProjectByCloudPseudonym(ctx context.Context, cloudProjectID string) (string, bool, error) {
	if cloudProjectID == "" {
		return "", false, nil
	}
	var localProjectID string
	err := s.db.QueryRowContext(ctx,
		`SELECT local_project_id FROM cloud_project_map WHERE cloud_pseudonym = ?`,
		cloudProjectID).Scan(&localProjectID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store.LookupLocalProjectByCloudPseudonym: %w", err)
	}
	return localProjectID, true, nil
}
