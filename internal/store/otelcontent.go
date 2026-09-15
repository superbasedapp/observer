package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// InsertOTelContent persists scrubbed native-OTel content bodies (migration
// 045). Callers MUST have already scrubbed Content for secrets; this method
// computes ContentHash (sha256-hex, via [HashOTelContent]) when empty and
// inserts idempotently — re-delivered OTLP exports collide on the UNIQUE key
// and are ignored. Returns the number of rows newly inserted.
//
// ContentHash semantics: it is the dedup/idempotency anchor
// (UNIQUE(content_hash, kind, request_id, tool_use_id) — see migration
// 048_otel_content.sql), and the org-push wire shape ships it UNCONDITIONALLY
// (content-free identity) while Content ships only under the node's
// content-sharing opt-in. A caller that bounds Content to a storage cap
// (cmd/observer/otlp_ingest.go::ingestOTelContent, 32 KiB default) MUST hash
// the FULL pre-truncation text and pass it explicitly via r.ContentHash —
// never leave it empty for this method to derive from r.Content once Content
// has been truncated. Two distinct large bodies that share an identical
// prefix up to the truncation cutoff would otherwise hash identically post-
// truncation, collide on the UNIQUE key, and the second row would be
// silently dropped by ON CONFLICT DO NOTHING — real data loss, not just a
// cosmetic dedup quirk. The empty-hash fallback below exists for callers
// (tests, any future untruncated caller) that pass full, unbounded Content.
func (s *Store) InsertOTelContent(ctx context.Context, rows []models.OTelContent) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.InsertOTelContent: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var inserted int
	for _, r := range rows {
		if r.Kind == "" {
			return inserted, fmt.Errorf("store.InsertOTelContent: kind is required")
		}
		hash := r.ContentHash
		if hash == "" {
			hash = HashOTelContent(r.Content)
		}
		res, err := tx.ExecContext(ctx,
			`INSERT INTO otel_content
			    (request_id, session_id, tool_use_id, kind, content, content_hash, timestamp, source)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(content_hash, kind, request_id, tool_use_id) DO NOTHING`,
			// request_id + tool_use_id are part of the UNIQUE key, so they must
			// be stored as '' (not NULL) — SQLite treats NULLs as distinct and
			// idempotency would break for prompt rows (no tool_use_id).
			r.RequestID, nullableString(r.SessionID),
			r.ToolUseID, r.Kind,
			nullableString(r.Content), hash,
			timestamp(r.Timestamp), nullableString(r.Source))
		if err != nil {
			return inserted, fmt.Errorf("store.InsertOTelContent: insert: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			inserted++
		}
	}
	if err := tx.Commit(); err != nil {
		return inserted, fmt.Errorf("store.InsertOTelContent: commit: %w", err)
	}
	return inserted, nil
}

// HashOTelContent returns the sha256-hex content_hash for an otel_content
// row's body. Callers that truncate Content for storage must hash the FULL
// pre-truncation text and pass the result via models.OTelContent.ContentHash
// — see the ContentHash semantics note on [Store.InsertOTelContent].
func HashOTelContent(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}
