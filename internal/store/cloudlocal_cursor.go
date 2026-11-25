package store

import (
	"context"
	"fmt"
	"strings"
)

// cloudlocal_cursor.go holds the per-host results-pull cursor of the
// cloud-intelligence store seam (cloudlocal.go describes the whole seam).

// -- CI-P2 Lane E CLI reads --------------------------------------------------
//
// These are node-local reads the `observer cloud` CLI composes; SQL stays in
// this store seam (module boundary — cmd/observer holds no SQL). None of them
// import the pure cloud contract/builder packages or the network lane, and
// none touch the org-push wire.

// cloudResultCursorKey is the schema_meta key PREFIX holding the opaque
// results-pull cursor `observer cloud sync` advances (a tiny node-local
// singleton per cloud host; the results themselves are rows in cloud_results).
//
// Since 2026-09-15 the cursor is keyed by the cloud HOST it was minted
// against ("cloud_results_cursor:<host>"): the hosted per-account results
// sequence is per estate, so a node that once synced against staging and
// then pointed at production would otherwise carry staging's cursor (say 6)
// into production, where the first result is seq 1, and never pull a
// production result. The bare legacy key is deliberately NOT read as a
// fallback - its value is ambiguous - so a node starts a fresh pull per host
// (idempotent: cloud_results upserts by result id).
const cloudResultCursorKey = "cloud_results_cursor" //nolint:gosec // G101: schema_meta cursor key name, not a credential.

// cloudResultCursorKeyFor returns the per-host schema_meta key; an empty host
// selects the bare legacy key (tests / callers with no resolved base URL).
func cloudResultCursorKeyFor(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return cloudResultCursorKey
	}
	return cloudResultCursorKey + ":" + host
}

// SaveCloudResultCursor persists the opaque results-pull cursor for one cloud
// host (schema_meta singleton per host). An empty cursor is a no-op (never
// clobber a real cursor with "").
func (s *Store) SaveCloudResultCursor(ctx context.Context, host, cursor string) error {
	if cursor == "" {
		return nil
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		cloudResultCursorKeyFor(host), cursor); err != nil {
		return fmt.Errorf("store.SaveCloudResultCursor: %w", err)
	}
	return nil
}

// LoadCloudResultCursor reads the opaque results-pull cursor for one cloud
// host; "" when never saved against that host (a first sync pulls from the
// beginning).
func (s *Store) LoadCloudResultCursor(ctx context.Context, host string) (string, error) {
	v, err := s.readMeta(ctx, cloudResultCursorKeyFor(host))
	if err != nil {
		return "", fmt.Errorf("store.LoadCloudResultCursor: %w", err)
	}
	return v, nil
}

// ClearCloudResultCursor deletes the results-pull cursor for one cloud host
// (an empty host selects the bare legacy key). The hosted cursor is a
// per-ACCOUNT sequence ("v2:<n>"), so a cursor minted under one account (or
// against a since-rebuilt server) skips that many results of the next one;
// sign-in, sign-out and account deletion therefore start the host's pull from
// the beginning again. Clearing an absent cursor is not an error, and a re-pull
// is idempotent (UpsertCloudResult updates an already-stored result in place).
func (s *Store) ClearCloudResultCursor(ctx context.Context, host string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM schema_meta WHERE key = ?`, cloudResultCursorKeyFor(host)); err != nil {
		return fmt.Errorf("store.ClearCloudResultCursor: %w", err)
	}
	return nil
}

// ClearAllCloudResultCursors deletes every cloud host's results-pull cursor
// (the bare legacy key included): the full local wipe `observer cloud logout
// --all-hosts` and `delete-account --local-only` perform.
func (s *Store) ClearAllCloudResultCursors(ctx context.Context) error {
	prefix := cloudResultCursorKey + ":"
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM schema_meta WHERE key = ? OR substr(key, 1, ?) = ?`,
		cloudResultCursorKey, len(prefix), prefix); err != nil {
		return fmt.Errorf("store.ClearAllCloudResultCursors: %w", err)
	}
	return nil
}

// HasCloudResultCursor reports whether a results-pull cursor exists for ANY
// cloud host (legacy bare key included) - the dashboard's "has ever synced"
// signal, which does not know the resolved base URL.
func (s *Store) HasCloudResultCursor(ctx context.Context) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM schema_meta WHERE (key = ? OR key LIKE ?) AND COALESCE(value, '') <> ''`,
		cloudResultCursorKey, cloudResultCursorKey+":%").Scan(&n); err != nil {
		return false, fmt.Errorf("store.HasCloudResultCursor: %w", err)
	}
	return n > 0, nil
}
