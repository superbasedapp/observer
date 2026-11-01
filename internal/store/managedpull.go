package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// The node's persisted copy of each module managed pull's last verified
// signed document (agent migration 187, roadmap F0-7). NODE-LOCAL: the
// privacy sentinel forbids orgpush.go from naming managed_pull_cache.
//
// ONE WRITER (SaveManagedPull / ClearManagedPull) and one reader
// (LoadManagedPull). The orgclient apply ladder calls Save only for a
// verified 200 it decided to install and Clear only for a signed empty body;
// every other answer writes nothing, which is what makes "only a SIGNED body
// may change a node's managed values" true by construction.
//
// A clear never deletes the row: it leaves a TOMBSTONE (an empty doc_json)
// that keeps the cleared document's version, so the anti-rollback floor
// survives the clear and an older document replayed afterwards is still
// refused (audit SHR-KIT finding 2).

// ErrManagedPullFloor is a write that would lower the stored anti-rollback
// floor of the same enrolment identity.
var ErrManagedPullFloor = errors.New("store: managed pull write below the stored version floor")

// managedPullFloorGuard keeps the highest accepted version per (rail,
// org_key, generation) OUTSIDE the signed document (audit SHR-KIT finding 2,
// the store half): an upsert for the same enrolment identity may keep or
// raise the stored version, never lower it, whatever document it carries. A
// row of another identity (a replaced enrolment) is replaced: the floor is
// per identity, and a new enrolment starts its own.
const managedPullFloorGuard = `WHERE excluded.version >= managed_pull_cache.version
			OR excluded.org_key <> managed_pull_cache.org_key
			OR excluded.generation <> managed_pull_cache.generation`

func managedPullFloorHeld(op string, res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if n == 0 {
		return fmt.Errorf("%s: %w", op, ErrManagedPullFloor)
	}
	return nil
}

// ManagedPullCache is one rail's stored document and its provenance.
type ManagedPullCache struct {
	Rail       string
	OrgKey     string
	Generation int64
	Version    int64
	// ExpiresAt is unix seconds; past it the document no longer applies.
	ExpiresAt int64
	BodyHash  string
	// DocJSON is the whole signed document, re-verified on every load.
	DocJSON string
	// SignerFingerprint is the pin hash of the org key that verified it.
	SignerFingerprint string
	FetchedAt         string
	// Tombstone marks a cleared rail: no document is stored (DocJSON is
	// empty), and Version and BodyHash are the signed empty body's, kept as
	// the anti-rollback floor.
	Tombstone bool
}

// LoadManagedPull returns rail's stored document. ok is false when none is
// stored, or when the stored one belongs to another enrolment identity
// (org_key or generation differ), which reads as absent.
func (s *Store) LoadManagedPull(ctx context.Context, rail, orgKey string, generation int64) (ManagedPullCache, bool, error) {
	var c ManagedPullCache
	err := s.db.QueryRowContext(ctx, `
		SELECT rail, org_key, generation, version, expires_at, body_hash, doc_json, signer_fingerprint, fetched_at
		FROM managed_pull_cache WHERE rail = ?`, rail).Scan(
		&c.Rail, &c.OrgKey, &c.Generation, &c.Version, &c.ExpiresAt, &c.BodyHash, &c.DocJSON, &c.SignerFingerprint, &c.FetchedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ManagedPullCache{}, false, nil
	}
	if err != nil {
		return ManagedPullCache{}, false, fmt.Errorf("store.LoadManagedPull: %w", err)
	}
	if c.OrgKey != orgKey || c.Generation != generation {
		return ManagedPullCache{}, false, nil
	}
	c.Tombstone = c.DocJSON == ""
	return c, true, nil
}

// SaveManagedPull replaces rail's stored document.
func (s *Store) SaveManagedPull(ctx context.Context, c ManagedPullCache) error {
	if c.Rail == "" || c.OrgKey == "" || c.Version <= 0 || c.DocJSON == "" {
		return errors.New("store.SaveManagedPull: rail, org key, a positive version and a document are required")
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO managed_pull_cache (rail, org_key, generation, version, expires_at, body_hash, doc_json, signer_fingerprint, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(rail) DO UPDATE SET
			org_key = excluded.org_key, generation = excluded.generation, version = excluded.version,
			expires_at = excluded.expires_at, body_hash = excluded.body_hash, doc_json = excluded.doc_json,
			signer_fingerprint = excluded.signer_fingerprint, fetched_at = excluded.fetched_at
		`+managedPullFloorGuard,
		c.Rail, c.OrgKey, c.Generation, c.Version, c.ExpiresAt, c.BodyHash, c.DocJSON, c.SignerFingerprint, c.FetchedAt)
	if err != nil {
		return fmt.Errorf("store.SaveManagedPull: %w", err)
	}
	return managedPullFloorHeld("store.SaveManagedPull", res)
}

// ClearManagedPull replaces rail's stored document with a tombstone (a
// signed empty body): no document, expires_at 0, and the empty body's
// version and body hash kept as the anti-rollback floor. c carries the
// rail, the enrolment identity, the empty body's version and hash, the
// signer and the fetch time; any DocJSON or ExpiresAt it carries is ignored.
func (s *Store) ClearManagedPull(ctx context.Context, c ManagedPullCache) error {
	if c.Rail == "" || c.OrgKey == "" || c.Version <= 0 {
		return errors.New("store.ClearManagedPull: rail, org key and a positive version are required")
	}
	c.DocJSON, c.ExpiresAt = "", 0
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO managed_pull_cache (rail, org_key, generation, version, expires_at, body_hash, doc_json, signer_fingerprint, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(rail) DO UPDATE SET
			org_key = excluded.org_key, generation = excluded.generation, version = excluded.version,
			expires_at = excluded.expires_at, body_hash = excluded.body_hash, doc_json = excluded.doc_json,
			signer_fingerprint = excluded.signer_fingerprint, fetched_at = excluded.fetched_at
		`+managedPullFloorGuard,
		c.Rail, c.OrgKey, c.Generation, c.Version, c.ExpiresAt, c.BodyHash, c.DocJSON, c.SignerFingerprint, c.FetchedAt)
	if err != nil {
		return fmt.Errorf("store.ClearManagedPull: %w", err)
	}
	return managedPullFloorHeld("store.ClearManagedPull", res)
}
