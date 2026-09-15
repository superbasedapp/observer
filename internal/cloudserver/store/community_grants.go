package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// community_grants.go is the SQL half of the W5 contribution-upload path
// (divergence-remediation plan §3 W5). It owns ONE table, community_grants
// (migration 0026): the server-side registration of a node's STANDING
// community_cohort_benchmarking grant. It is the leaner analogue of
// structural_grants — a contribution names its own UTC window explicitly, so
// there is no source-window rule to bind — and follows the same discipline:
// consent stays NODE-authoritative, the registration only tracks the declared
// generation monotonically and refuses an upload that has fallen behind it or
// whose terms differ from the ones recorded at the same generation.

// Sentinel errors the community upload path returns. They mirror the structural
// rail's taxonomy so the intake handler and the node classifier treat the two
// rails' refusals identically.
var (
	// ErrCommunityGrantRevoked means the account's standing-grant registration
	// for the purpose has been withdrawn. It is never silently re-registered.
	ErrCommunityGrantRevoked = errors.New("cloudserver/store: the community standing grant for this purpose is revoked")
	// ErrCommunityGenerationStale means the upload declared an OLDER consent
	// generation than the registration holds.
	ErrCommunityGenerationStale = errors.New("cloudserver/store: the upload declares an older consent generation than the registered community grant")
	// ErrCommunityDictionaryMismatch means the upload's data-dictionary digest is
	// not the one the registration was agreed against, at the same generation.
	ErrCommunityDictionaryMismatch = errors.New("cloudserver/store: the upload's data-dictionary digest does not match the registered community grant")
	// ErrCommunityGrantTermsMismatch means the upload declares the SAME consent
	// generation as the registration but a different binding (schema version or
	// declared timezone). Terms cannot change while the generation stands still.
	ErrCommunityGrantTermsMismatch = errors.New("cloudserver/store: the upload's community grant binding differs from the registered grant at the same consent generation")
	// ErrCommunityBindingIncomplete means the declared binding is missing a
	// component the registration must record (dictionary digest or schema
	// version). A registration with a hole in it cannot be checked against a
	// later upload.
	ErrCommunityBindingIncomplete = errors.New("cloudserver/store: the community standing-grant binding is incomplete")
	// ErrCommunityGrantMissing means no registration exists for the (account,
	// purpose) — surfaced if an insert path revalidated it and found it gone.
	ErrCommunityGrantMissing = errors.New("cloudserver/store: no community standing-grant registration exists for this purpose")
)

// CommunityGrantInput is the standing-grant binding an upload declares. The
// purpose is supplied by the CALLER from the route it served, never a client
// field. DeviceID is likewise supplied by the caller from the authenticated
// proof-of-possession principal — never a client-declared field (Sol F8: the
// registration is scoped per (account, device, purpose) so one device's
// consent generation can never stale or lock out another device under the
// same account).
type CommunityGrantInput struct {
	Purpose              string
	DeviceID             string
	DataDictionaryDigest string
	SchemaVersion        string
	ConsentGeneration    int64
	DeclaredTimezone     string
	Now                  time.Time
}

// CommunityGrant is a registered standing community grant as stored.
type CommunityGrant struct {
	Purpose              string     `json:"purpose"`
	DeviceID             string     `json:"device_id"`
	DataDictionaryDigest string     `json:"data_dictionary_digest"`
	SchemaVersion        string     `json:"schema_version"`
	ConsentGeneration    int64      `json:"consent_generation"`
	DeclaredTimezone     string     `json:"declared_timezone"`
	FirstSeenAt          time.Time  `json:"first_seen_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	RevokedAt            *time.Time `json:"revoked_at"`
}

// CommunityGrantLockKey is the advisory-lock key an (account, device, purpose)
// registration serializes on. It uses a DISTINCT prefix from the structural
// grant lock so the two registration paths never contend. Its argument to
// pg_advisory_xact_lock is hashtext(key)::bigint.
//
// DeviceID is part of the key (Sol F8): two devices registering the SAME
// purpose under the SAME account must serialize independently of one another,
// not fight over a single account-wide lock/row.
func CommunityGrantLockKey(accountID, deviceID, purpose string) string {
	return fmt.Sprintf("sbci-cgrant\x1f%s\x1f%s\x1f%s", accountID, deviceID, purpose)
}

// RegisterCommunityGrant validates an upload's declared standing-grant binding
// against the account's registration for the purpose, registering it on first
// sight. It is the leaner community analogue of RegisterStructuralGrant; the
// rule order is identical minus the source-window-rule component:
//
//   - incomplete binding ⇒ ErrCommunityBindingIncomplete
//   - no row             ⇒ register it → created
//   - revoked            ⇒ ErrCommunityGrantRevoked
//   - older gen          ⇒ ErrCommunityGenerationStale
//   - newer gen          ⇒ update the whole binding → updated
//   - same gen, same
//     binding            ⇒ accept → unchanged
//   - same gen, other
//     dictionary digest  ⇒ ErrCommunityDictionaryMismatch
//   - same gen, other
//     schema / timezone  ⇒ ErrCommunityGrantTermsMismatch
//
// The read-then-write is serialized by a transaction-scoped advisory lock on
// (account, device, purpose) taken BEFORE the read, and the ON CONFLICT arm is
// guarded so it can only ever move the generation forward — the same
// lost-update defence the structural registration carries. Scoping the lock
// and the row by DEVICE (Sol F8) means two devices under the same account
// register and advance independently: neither can stale or lock out the
// other by racing ahead on its own generation.
func (s *Store) RegisterCommunityGrant(ctx context.Context, accountID string, in CommunityGrantInput) (CommunityGrant, string, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	var (
		grant  CommunityGrant
		action string
	)
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		grant, action, e = registerCommunityGrantTx(ctx, tx, accountID, in)
		return e
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrCommunityGrantRevoked),
			errors.Is(err, ErrCommunityGenerationStale),
			errors.Is(err, ErrCommunityDictionaryMismatch),
			errors.Is(err, ErrCommunityGrantTermsMismatch),
			errors.Is(err, ErrCommunityBindingIncomplete):
			return CommunityGrant{}, "", err
		}
		return CommunityGrant{}, "", fmt.Errorf("cloudserver/store.RegisterCommunityGrant: %w", err)
	}
	return grant, action, nil
}

// registerCommunityGrantTx is the transaction-scoped body of the community
// standing-grant registration state machine (extracted for Sol N3 so
// AdmitCommunityContribution can register the grant in the SAME transaction as
// the contribution upsert, and roll BOTH back on any refusal). It takes the
// (account, device, purpose) advisory lock, reads the row FOR UPDATE, and applies
// the state machine described on RegisterCommunityGrant. The caller supplies the
// enclosing WithAccount transaction; the exported RegisterCommunityGrant is a
// thin wrapper that opens one and maps the errors.
//
// It defaults nothing: callers pass in.Now already set (both do). An incomplete
// binding is refused before any lock/read so a registration with a hole in it can
// never be checked against a later upload.
func registerCommunityGrantTx(ctx context.Context, tx pgx.Tx, accountID string, in CommunityGrantInput) (CommunityGrant, string, error) {
	if in.DataDictionaryDigest == "" || in.SchemaVersion == "" {
		return CommunityGrant{}, "", ErrCommunityBindingIncomplete
	}
	if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`,
		CommunityGrantLockKey(accountID, in.DeviceID, in.Purpose)); e != nil {
		return CommunityGrant{}, "", fmt.Errorf("lock community grant registration: %w", e)
	}
	existing, found, e := readCommunityGrantTx(ctx, tx, accountID, in.DeviceID, in.Purpose, true)
	if e != nil {
		return CommunityGrant{}, "", e
	}
	var (
		grant  CommunityGrant
		action string
	)
	switch {
	case !found:
		action = GrantRegistrationCreated
	case existing.RevokedAt != nil:
		return CommunityGrant{}, "", ErrCommunityGrantRevoked
	case in.ConsentGeneration < existing.ConsentGeneration:
		return CommunityGrant{}, "", ErrCommunityGenerationStale
	case in.ConsentGeneration == existing.ConsentGeneration:
		if in.DataDictionaryDigest != existing.DataDictionaryDigest {
			return CommunityGrant{}, "", ErrCommunityDictionaryMismatch
		}
		if in.SchemaVersion != existing.SchemaVersion ||
			in.DeclaredTimezone != existing.DeclaredTimezone {
			return CommunityGrant{}, "", ErrCommunityGrantTermsMismatch
		}
		return existing, GrantRegistrationUnchanged, nil
	default:
		action = GrantRegistrationUpdated
	}
	e = tx.QueryRow(ctx,
		`INSERT INTO community_grants
		   (account_id, device_id, purpose, data_dictionary_digest, schema_version,
		    consent_generation, declared_timezone, first_seen_at, updated_at)
		 VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $8)
		 ON CONFLICT (account_id, device_id, purpose) DO UPDATE SET
		   data_dictionary_digest = EXCLUDED.data_dictionary_digest,
		   schema_version         = EXCLUDED.schema_version,
		   consent_generation     = EXCLUDED.consent_generation,
		   declared_timezone      = EXCLUDED.declared_timezone,
		   updated_at             = EXCLUDED.updated_at
		 WHERE community_grants.consent_generation <= EXCLUDED.consent_generation
		   AND community_grants.revoked_at IS NULL
		 RETURNING purpose, device_id, data_dictionary_digest, schema_version, consent_generation,
		           declared_timezone, first_seen_at, updated_at, revoked_at`,
		accountID, in.DeviceID, in.Purpose, in.DataDictionaryDigest, in.SchemaVersion,
		in.ConsentGeneration, in.DeclaredTimezone, in.Now).
		Scan(&grant.Purpose, &grant.DeviceID, &grant.DataDictionaryDigest, &grant.SchemaVersion,
			&grant.ConsentGeneration, &grant.DeclaredTimezone,
			&grant.FirstSeenAt, &grant.UpdatedAt, &grant.RevokedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return CommunityGrant{}, "", ErrCommunityGenerationStale
	}
	if e != nil {
		return CommunityGrant{}, "", fmt.Errorf("register community grant: %w", e)
	}
	return grant, action, nil
}

// readCommunityGrantTx reads one registration for (account, device, purpose),
// optionally taking the row lock (forUpdate) so a concurrent upload for the
// SAME device+purpose serializes behind it. A different device's row is a
// different row and is never touched by this lock (Sol F8).
func readCommunityGrantTx(ctx context.Context, tx pgx.Tx, accountID, deviceID, purpose string, forUpdate bool) (CommunityGrant, bool, error) {
	q := `SELECT purpose, device_id, data_dictionary_digest, schema_version, consent_generation,
	             declared_timezone, first_seen_at, updated_at, revoked_at
	        FROM community_grants
	       WHERE account_id = $1::uuid AND device_id = $2 AND purpose = $3`
	if forUpdate {
		q += " FOR UPDATE"
	}
	var g CommunityGrant
	err := tx.QueryRow(ctx, q, accountID, deviceID, purpose).Scan(
		&g.Purpose, &g.DeviceID, &g.DataDictionaryDigest, &g.SchemaVersion, &g.ConsentGeneration,
		&g.DeclaredTimezone, &g.FirstSeenAt, &g.UpdatedAt, &g.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return CommunityGrant{}, false, nil
	}
	if err != nil {
		return CommunityGrant{}, false, fmt.Errorf("read community grant: %w", err)
	}
	return g, true, nil
}

// ListCommunityGrants returns the account's community standing-grant
// registrations — since 0028 (Sol F8) up to one PER DEVICE per purpose, not
// one per purpose account-wide — for its own-status surface.
func (s *Store) ListCommunityGrants(ctx context.Context, accountID string) ([]CommunityGrant, error) {
	var out []CommunityGrant
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT purpose, device_id, data_dictionary_digest, schema_version, consent_generation,
			        declared_timezone, first_seen_at, updated_at, revoked_at
			   FROM community_grants
			  WHERE account_id = $1::uuid
			  ORDER BY purpose, device_id`, accountID)
		if e != nil {
			return fmt.Errorf("list community grants: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			var g CommunityGrant
			if e := rows.Scan(&g.Purpose, &g.DeviceID, &g.DataDictionaryDigest, &g.SchemaVersion,
				&g.ConsentGeneration, &g.DeclaredTimezone, &g.FirstSeenAt,
				&g.UpdatedAt, &g.RevokedAt); e != nil {
				return fmt.Errorf("scan community grant: %w", e)
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListCommunityGrants: %w", err)
	}
	return out, nil
}
