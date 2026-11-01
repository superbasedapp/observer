package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// securitypurpose.go keeps the org's stated purpose for its Code security
// views (security plan 7.12, lane SEC-E3) and what those views show under
// the org's settings (operator ruling P-089), as the last push response
// carried them, in the schema_meta rows below. One writer
// (internal/orgclient, from the push response) and one reader (the node
// dashboard's affected-worker notice). Node-local; never on the push wire.

// securityOrgPurposeKey is the schema_meta key.
const securityOrgPurposeKey = "security_org_purpose"

// securityOrgVisibilityKey is the schema_meta key of the org's visibility
// settings (a JSON orgcontract.SecurityVisibility).
const securityOrgVisibilityKey = "security_org_visibility"

// SetSecurityOrgVisibility stores what the org's Code security views show.
func (s *Store) SetSecurityOrgVisibility(ctx context.Context, v orgcontract.SecurityVisibility) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("store.SetSecurityOrgVisibility: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO schema_meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, securityOrgVisibilityKey, string(raw)); err != nil {
		return fmt.Errorf("store.SetSecurityOrgVisibility: %w", err)
	}
	return nil
}

// SecurityOrgVisibility reads what the org's views show; ok is false when no
// push response carried it yet (or the stored value is unreadable).
func (s *Store) SecurityOrgVisibility(ctx context.Context) (v orgcontract.SecurityVisibility, ok bool, err error) {
	var raw sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = ?`, securityOrgVisibilityKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return v, false, nil
	}
	if err != nil {
		return v, false, fmt.Errorf("store.SecurityOrgVisibility: %w", err)
	}
	if json.Unmarshal([]byte(raw.String), &v) != nil || v.MinGroup < 1 {
		return orgcontract.SecurityVisibility{}, false, nil
	}
	return v, true, nil
}

// SetSecurityOrgPurpose stores the org's stated purpose id.
func (s *Store) SetSecurityOrgPurpose(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `INSERT INTO schema_meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, securityOrgPurposeKey, id); err != nil {
		return fmt.Errorf("store.SetSecurityOrgPurpose: %w", err)
	}
	return nil
}

// SecurityOrgPurpose reads the stored purpose id, "" when none was received.
func (s *Store) SecurityOrgPurpose(ctx context.Context) (string, error) {
	var v sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = ?`, securityOrgPurposeKey).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store.SecurityOrgPurpose: %w", err)
	}
	return v.String, nil
}
