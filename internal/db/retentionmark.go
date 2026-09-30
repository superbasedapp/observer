package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// RetentionDeleteMarkerKey is the schema_meta key agent migration 141's delete
// triggers check (org_push_delete_*): while it is present, a DELETE on a
// pushed table (sessions, actions, api_turns, token_usage) is node-local
// AGEING, not a correction, and records no org tombstone. The migration SQL
// spells this literal; TestRetentionDeleteMarkerKeyMatchesMigration pins the
// two together.
const RetentionDeleteMarkerKey = "org_push_retention_delete"

// AgeingCutoffKey is the schema_meta key holding the LATEST cutoff any
// retention age / size-cap pass ever applied to actions (RFC3339): every
// action older than it may have been aged out of this node. The resync heal
// never asks the org to delete a row older than it (a row the node forgot by
// ageing is not a correction). Written by RecordAgeingCutoff only.
const AgeingCutoffKey = "retention_ageing_cutoff"

// RecordAgeingCutoff raises AgeingCutoffKey to cutoff (never lowers it),
// inside the retention pass's own transaction.
func RecordAgeingCutoff(ctx context.Context, tx *sql.Tx, cutoff string) error {
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_meta (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = CASE
		   WHEN julianday(excluded.value) > COALESCE(julianday(schema_meta.value), 0) THEN excluded.value
		   ELSE schema_meta.value END`, AgeingCutoffKey, cutoff); err != nil {
		return fmt.Errorf("db.RecordAgeingCutoff: %w", err)
	}
	return nil
}

// WithRetentionDeletes runs fn inside tx with the retention marker set, and
// clears the marker before returning, so every DELETE fn issues on a pushed
// table is recorded as node-local ageing (class b): the org keeps those rows
// under its own retention policy.
//
// The marker lives only inside tx. SQLite admits one writer at a time, so no
// other connection can observe it or delete under it, and a rollback (or a
// crash) removes it together with the deletes. Callers must pass the SAME
// transaction to fn's statements. fn's error is returned as-is and the marker
// is still cleared (the caller rolls tx back anyway).
func WithRetentionDeletes(ctx context.Context, tx *sql.Tx, fn func() error) error {
	if tx == nil {
		return errors.New("db.WithRetentionDeletes: nil transaction")
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_meta (key, value) VALUES (?, '1')
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, RetentionDeleteMarkerKey); err != nil {
		return fmt.Errorf("db.WithRetentionDeletes: set marker: %w", err)
	}
	ferr := fn()
	if _, err := tx.ExecContext(ctx, `DELETE FROM schema_meta WHERE key = ?`, RetentionDeleteMarkerKey); err != nil {
		if ferr != nil {
			return ferr
		}
		return fmt.Errorf("db.WithRetentionDeletes: clear marker: %w", err)
	}
	return ferr
}
