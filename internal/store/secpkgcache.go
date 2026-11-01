//go:build !sbo_omit_security && !sbo_omit_security_deps

package store

import (
	"context"
	"fmt"
	"time"
)

// The install gate's online-answer cache (security pillar plan section 8.3;
// agent migration 182, component security.deps).
//
// ONE OWNER: sec_pkg_cache is written exclusively here. NODE-LOCAL: never
// pushed (privacy sentinel). Only public package names reach it, and the
// answer is the caller's opaque JSON: the store does not interpret it, so
// the cache rules stay in internal/secfeed.

// SecPkgCacheRow is one cached answer.
type SecPkgCacheRow struct {
	Ecosystem  string
	Name       string
	Version    string
	Status     string
	AnswerJSON string
	FetchedAt  time.Time
	ExpiresAt  time.Time
}

// UpsertSecPkgCache writes rows, replacing an older answer for the same
// package.
func (s *Store) UpsertSecPkgCache(ctx context.Context, rows []SecPkgCacheRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.UpsertSecPkgCache: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, r := range rows {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sec_pkg_cache (ecosystem, name, version, status, answer_json, fetched_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (ecosystem, name, version) DO UPDATE SET
				status = excluded.status, answer_json = excluded.answer_json,
				fetched_at = excluded.fetched_at, expires_at = excluded.expires_at`,
			r.Ecosystem, r.Name, r.Version, r.Status, r.AnswerJSON,
			r.FetchedAt.UTC().Format(secTime), r.ExpiresAt.UTC().Format(secTime)); err != nil {
			return fmt.Errorf("store.UpsertSecPkgCache: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.UpsertSecPkgCache: %w", err)
	}
	return nil
}

// LiveSecPkgCache returns the answers not yet expired at now, newest first,
// at most limit.
func (s *Store) LiveSecPkgCache(ctx context.Context, now time.Time, limit int) ([]SecPkgCacheRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ecosystem, name, version, status, answer_json, fetched_at, expires_at
		FROM sec_pkg_cache WHERE expires_at > ? ORDER BY fetched_at DESC LIMIT ?`, now.UTC().Format(secTime), limit)
	if err != nil {
		return nil, fmt.Errorf("store.LiveSecPkgCache: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []SecPkgCacheRow
	for rows.Next() {
		var r SecPkgCacheRow
		var fetched, expires string
		if err := rows.Scan(&r.Ecosystem, &r.Name, &r.Version, &r.Status, &r.AnswerJSON, &fetched, &expires); err != nil {
			return nil, fmt.Errorf("store.LiveSecPkgCache: %w", err)
		}
		r.FetchedAt, _ = time.Parse(secTime, fetched)
		r.ExpiresAt, _ = time.Parse(secTime, expires)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LiveSecPkgCache: %w", err)
	}
	return out, nil
}

// SecPkgCacheStats reports the cache's size and its newest fetch (the
// Scanners tab's "last online refresh" age).
func (s *Store) SecPkgCacheStats(ctx context.Context) (rows int, newest time.Time, err error) {
	var last string
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MAX(fetched_at), '') FROM sec_pkg_cache`).Scan(&rows, &last); err != nil {
		return 0, time.Time{}, fmt.Errorf("store.SecPkgCacheStats: %w", err)
	}
	newest, _ = time.Parse(secTime, last)
	return rows, newest, nil
}

// PruneSecPkgCache deletes answers that expired before cutoff (the
// last-known-good window is over).
func (s *Store) PruneSecPkgCache(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sec_pkg_cache WHERE expires_at < ?`, cutoff.UTC().Format(secTime))
	if err != nil {
		return 0, fmt.Errorf("store.PruneSecPkgCache: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
