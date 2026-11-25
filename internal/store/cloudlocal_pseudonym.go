package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// cloudlocal_pseudonym.go holds the cloud_session_map / cloud_project_map half
// of the cloud-intelligence store seam (cloudlocal.go describes the whole seam).

// -- Pseudonym mappings ------------------------------------------------------

// GetOrCreateCloudSessionPseudonym returns the random cloud pseudonym for a
// local session id, minting one on first use. The pseudonym is crypto/rand,
// never derived from the local id.
func (s *Store) GetOrCreateCloudSessionPseudonym(ctx context.Context, localSessionID string) (string, error) {
	return s.getOrCreatePseudonym(ctx, "cloud_session_map", "local_session_id", localSessionID, "cs_")
}

// GetOrCreateCloudProjectPseudonym returns the random cloud pseudonym for a
// local project id, minting one on first use.
func (s *Store) GetOrCreateCloudProjectPseudonym(ctx context.Context, localProjectID string) (string, error) {
	return s.getOrCreatePseudonym(ctx, "cloud_project_map", "local_project_id", localProjectID, "cp_")
}

// LookupLocalSessionByCloudPseudonym is the reverse of
// GetOrCreateCloudSessionPseudonym: given a cloud session pseudonym (as
// received on a pulled result's cloud_session_id), it returns the local
// session id this device minted that pseudonym for. It is a read-only lookup
// — unlike getOrCreatePseudonym it never mints, since a pseudonym this device
// doesn't recognize is legitimately unassociable here (e.g. a result for a
// session enrolled from a different device, or a stale pseudonym). ok=false
// on no match is expected, routine behavior, never an error.
func (s *Store) LookupLocalSessionByCloudPseudonym(ctx context.Context, cloudSessionID string) (string, bool, error) {
	if cloudSessionID == "" {
		return "", false, nil
	}
	var localSessionID string
	err := s.db.QueryRowContext(ctx,
		`SELECT local_session_id FROM cloud_session_map WHERE cloud_pseudonym = ?`,
		cloudSessionID).Scan(&localSessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store.LookupLocalSessionByCloudPseudonym: %w", err)
	}
	return localSessionID, true, nil
}

// getOrCreatePseudonym is the shared get-or-create for the two mapping tables.
// The table/column names are internal constants (never caller input), so the
// fmt.Sprintf into the query is not an injection surface.
func (s *Store) getOrCreatePseudonym(ctx context.Context, table, keyCol, localID, prefix string) (string, error) {
	if localID == "" {
		return "", fmt.Errorf("store.getOrCreatePseudonym: local id is required")
	}
	var pseudonym string
	err := s.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT cloud_pseudonym FROM %s WHERE %s = ?`, table, keyCol), localID).
		Scan(&pseudonym)
	switch {
	case err == nil:
		return pseudonym, nil
	case !errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("store.getOrCreatePseudonym: %w", err)
	}
	// Mint a random pseudonym. INSERT OR IGNORE + re-select closes the race
	// where two callers mint for the same local id concurrently: the loser's
	// insert is ignored and it reads the winner's pseudonym.
	minted, err := cloudRandomID(prefix)
	if err != nil {
		return "", fmt.Errorf("store.getOrCreatePseudonym: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		fmt.Sprintf(`INSERT OR IGNORE INTO %s (%s, cloud_pseudonym, created_at) VALUES (?, ?, ?)`, table, keyCol),
		localID, minted, cloudFormatTime(time.Now().UTC()))
	if err != nil {
		return "", fmt.Errorf("store.getOrCreatePseudonym: %w", err)
	}
	err = s.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT cloud_pseudonym FROM %s WHERE %s = ?`, table, keyCol), localID).
		Scan(&pseudonym)
	if err != nil {
		return "", fmt.Errorf("store.getOrCreatePseudonym: %w", err)
	}
	return pseudonym, nil
}
