package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// cloudlocal_lookup.go adds a single READ-ONLY forward lookup over the
// cloud_session_map table that cloudlocal.go (the table's owning seam) does
// not provide: given a LOCAL session id, return the cloud pseudonym this
// device already minted for it, if any — WITHOUT minting one.
//
// This is deliberately a separate file rather than an addition to
// cloudlocal.go: it exists so the dashboard's read-only session surface
// (internal/intelligence/dashboard/cloud.go, issue "show the local uuid <->
// cloud pseudonym mapping to the user") can resolve a session's pseudonym for
// DISPLAY without ever causing a pseudonym to be minted as a side effect of
// merely opening a session's detail panel. GetOrCreateCloudSessionPseudonym
// (cloudlocal.go) is the write path used when a session is actually enrolled
// for cloud enrichment (EnqueueCloudOutbox etc.); this is its read-only
// sibling, mirroring the existing reverse lookup
// LookupLocalSessionByCloudPseudonym in shape and contract: ok=false on no
// match is expected, routine behavior, never an error.
//
// cloud_session_map is NODE-LOCAL (migration 097) and never enters the
// org-push wire; this lookup performs no write and touches no other table.

// LookupCloudSessionPseudonym returns the cloud pseudonym (e.g. "cs_...")
// already minted for a local session id, if one exists. It never mints — a
// session that has never been enrolled for cloud enrichment legitimately has
// no pseudonym yet, and that is not an error.
func (s *Store) LookupCloudSessionPseudonym(ctx context.Context, localSessionID string) (string, bool, error) {
	if localSessionID == "" {
		return "", false, nil
	}
	var pseudonym string
	err := s.db.QueryRowContext(ctx,
		`SELECT cloud_pseudonym FROM cloud_session_map WHERE local_session_id = ?`,
		localSessionID).Scan(&pseudonym)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store.LookupCloudSessionPseudonym: %w", err)
	}
	return pseudonym, true, nil
}
