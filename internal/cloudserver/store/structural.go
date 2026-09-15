package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
)

// structural.go is the SQL half of the structural-insights rail (divergence
// remediation plan rev 4.1 §3 W2 "Server half"). It owns three tables
// (migration 0013): the standing-grant registration, the immutable per-device
// snapshot store, and the server-derived account-day materialization.
//
// Why this file imports internal/cloudevidence: the coverage-band rule
// (CoverageBandFor) has exactly ONE owner, and it is the node-side builder that
// defined it. The account-day materialization must band the MERGED numerators
// over the MERGED session count — averaging per-device bands would be
// arithmetic on a closed vocabulary — so it needs that rule. Re-implementing
// the thresholds here would create a second owner that silently drifts. The
// import is of a pure function from a pure package; nothing else in
// cloudevidence is reachable from the hosted service.

// Sentinel errors the structural upload path returns.
var (
	// ErrStructuralDigestConflict means the same (account, device, window key,
	// revision) already exists with a DIFFERENT digest. A changed window is a
	// new revision, never an overwrite, so this is refused rather than merged.
	ErrStructuralDigestConflict = errors.New("cloudserver/store: a different snapshot already exists for this window revision")
	// ErrStructuralGrantRevoked means the account's standing-grant registration
	// for the purpose has been withdrawn. It is never silently re-registered.
	ErrStructuralGrantRevoked = errors.New("cloudserver/store: the standing grant for this purpose is revoked")
	// ErrStructuralGenerationStale means the upload declared an OLDER consent
	// generation than the registration holds — a client running on terms the
	// developer has already replaced.
	ErrStructuralGenerationStale = errors.New("cloudserver/store: the upload declares an older consent generation than the registered grant")
	// ErrStructuralDictionaryMismatch means the upload's data-dictionary digest
	// is not the one the registration was agreed against, at the same consent
	// generation. Changed terms require a NEW generation.
	ErrStructuralDictionaryMismatch = errors.New("cloudserver/store: the upload's data-dictionary digest does not match the registered grant")
	// ErrStructuralGrantTermsMismatch means the upload declares the SAME consent
	// generation as the registration but a different binding — schema version,
	// declared timezone, or source-window rule (F5). Terms cannot change while
	// the generation stands still: the developer must re-confirm the grant, which
	// bumps the generation and updates the whole binding.
	ErrStructuralGrantTermsMismatch = errors.New("cloudserver/store: the upload's grant binding differs from the registered grant at the same consent generation")
	// ErrStructuralBindingIncomplete means the declared binding is missing a
	// component the registration must record (declared timezone, source-window
	// rule, dictionary digest, schema version). A registration with a hole in it
	// cannot be compared against a later upload, so it is refused rather than
	// stored (F5).
	ErrStructuralBindingIncomplete = errors.New("cloudserver/store: the standing-grant binding is incomplete")
	// ErrStructuralGrantMissing means no registration exists for the (account,
	// purpose) at the moment a snapshot insert revalidated it — the row was
	// removed between registration and insert (F7).
	ErrStructuralGrantMissing = errors.New("cloudserver/store: no standing-grant registration exists for this purpose")
)

// Grant-registration outcomes, returned so the caller can audit which branch a
// request took without re-deriving it.
const (
	// GrantRegistrationCreated is the first upload for an (account, purpose).
	GrantRegistrationCreated = "created"
	// GrantRegistrationUnchanged is an upload on the already-registered terms.
	GrantRegistrationUnchanged = "unchanged"
	// GrantRegistrationUpdated is an upload carrying a NEWER consent generation:
	// the developer re-agreed, so the registered terms move with them.
	GrantRegistrationUpdated = "updated"
)

// StructuralGrantInput is the standing-grant binding an upload declares (R1).
// The purpose is supplied by the CALLER from the route it served, never read
// from a client field.
type StructuralGrantInput struct {
	Purpose              string
	DataDictionaryDigest string
	SchemaVersion        string
	ConsentGeneration    int64
	DeclaredTimezone     string
	SourceWindowRule     string
	Now                  time.Time
}

// StructuralGrant is a registered standing grant as stored.
type StructuralGrant struct {
	Purpose              string     `json:"purpose"`
	DataDictionaryDigest string     `json:"data_dictionary_digest"`
	SchemaVersion        string     `json:"schema_version"`
	ConsentGeneration    int64      `json:"consent_generation"`
	DeclaredTimezone     string     `json:"declared_timezone"`
	SourceWindowRule     string     `json:"source_window_rule"`
	FirstSeenAt          time.Time  `json:"first_seen_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	RevokedAt            *time.Time `json:"revoked_at"`
}

// StructuralGrantLockKey is the advisory-lock key an (account, purpose)
// registration serializes on. It is a DIFFERENT key space from the per-window
// and per-period snapshot locks (distinct prefix), so the three never contend.
// Its argument to pg_advisory_xact_lock is hashtext(key)::bigint.
//
// Exported for the same reason as StructuralPeriodLockKey: the F6 regression
// test holds this lock from an outside connection and asserts a registration
// blocks on it. Firing two first-registrations at once does NOT reliably
// reproduce the lost update — the window is milliseconds wide — so asserting
// that the lock is taken, before the read, is the only deterministic gate.
func StructuralGrantLockKey(accountID, purpose string) string {
	return fmt.Sprintf("sbci-grant\x1f%s\x1f%s", accountID, purpose)
}

// RegisterStructuralGrant validates an upload's declared standing-grant binding
// against the account's registration for that purpose, registering it on first
// sight. It is the server-side half of R1: the grant authorizes the SCHEMA, so
// the server has to hold a record of which schema, on which terms, at which
// consent generation — otherwise "the grant covers this" is a claim only the
// client can make.
//
// Consent is NODE-authoritative. This row is a REGISTRATION, not an
// account-owned consent state the server mints: it follows the generation the
// node declares, monotonically, and its only powers are to refuse an upload
// that has fallen behind that generation and to refuse one whose terms differ
// from the terms already recorded at it.
//
// The rules, in order:
//
//   - incomplete binding ⇒ ErrStructuralBindingIncomplete
//   - no row             ⇒ register it (first upload registers) → created
//   - revoked            ⇒ ErrStructuralGrantRevoked
//   - older gen          ⇒ ErrStructuralGenerationStale
//   - newer gen          ⇒ update the WHOLE binding to the new terms → updated
//   - same gen, same
//     FULL binding       ⇒ accept → unchanged
//   - same gen, other
//     dictionary digest  ⇒ ErrStructuralDictionaryMismatch
//   - same gen, other
//     schema / timezone /
//     window rule        ⇒ ErrStructuralGrantTermsMismatch
//
// F5: the equal-generation comparison covers the FULL R1 binding, not just the
// dictionary digest. Timezone and source-window rule are not decoration — the
// timezone is what gives a period label its meaning, and the window rule names
// WHICH activity the grant covers. Two devices at the same generation declaring
// different timezones describe different days, and merging them into one
// account-day row would silently add up windows that do not line up. A
// legitimate change to either is a terms change, so it arrives with a HIGHER
// generation (which updates the whole binding); at an unchanged generation it
// can only be a stale or misconfigured client, and is refused.
//
// F6: the read-then-write is serialized by a transaction-scoped ADVISORY LOCK on
// (account, purpose), taken BEFORE the read. `FOR UPDATE` cannot lock a row that
// does not exist, so two concurrent FIRST registrations both saw absence, both
// took the insert path, and the loser's ON CONFLICT update overwrote the
// winner's row — including with a LOWER generation. The lock closes that; the
// conditional ON CONFLICT below is the database-level backstop that makes a
// generation regression impossible even if the lock were ever dropped.
func (s *Store) RegisterStructuralGrant(ctx context.Context, accountID string, in StructuralGrantInput) (StructuralGrant, string, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	if in.DataDictionaryDigest == "" || in.SchemaVersion == "" ||
		in.DeclaredTimezone == "" || in.SourceWindowRule == "" {
		return StructuralGrant{}, "", ErrStructuralBindingIncomplete
	}
	var (
		grant  StructuralGrant
		action string
	)
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`,
			StructuralGrantLockKey(accountID, in.Purpose)); e != nil {
			return fmt.Errorf("lock grant registration: %w", e)
		}
		existing, found, e := readStructuralGrantTx(ctx, tx, accountID, in.Purpose, true)
		if e != nil {
			return e
		}
		switch {
		case !found:
			action = GrantRegistrationCreated
		case existing.RevokedAt != nil:
			return ErrStructuralGrantRevoked
		case in.ConsentGeneration < existing.ConsentGeneration:
			return ErrStructuralGenerationStale
		case in.ConsentGeneration == existing.ConsentGeneration:
			if in.DataDictionaryDigest != existing.DataDictionaryDigest {
				return ErrStructuralDictionaryMismatch
			}
			if in.SchemaVersion != existing.SchemaVersion ||
				in.DeclaredTimezone != existing.DeclaredTimezone ||
				in.SourceWindowRule != existing.SourceWindowRule {
				return ErrStructuralGrantTermsMismatch
			}
			grant = existing
			action = GrantRegistrationUnchanged
			return nil
		default:
			action = GrantRegistrationUpdated
		}
		// The ON CONFLICT arm is guarded so it can only ever move the generation
		// FORWARD. Without the WHERE, a racing lower-generation writer could
		// regress the registration; with it, that writer's RETURNING yields no
		// row and the caller is told its generation is stale — the same honest
		// answer the serialized read path gives.
		e = tx.QueryRow(ctx,
			`INSERT INTO structural_grants
			   (account_id, purpose, data_dictionary_digest, schema_version,
			    consent_generation, declared_timezone, source_window_rule,
			    first_seen_at, updated_at)
			 VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $8)
			 ON CONFLICT (account_id, purpose) DO UPDATE SET
			   data_dictionary_digest = EXCLUDED.data_dictionary_digest,
			   schema_version         = EXCLUDED.schema_version,
			   consent_generation     = EXCLUDED.consent_generation,
			   declared_timezone      = EXCLUDED.declared_timezone,
			   source_window_rule     = EXCLUDED.source_window_rule,
			   updated_at             = EXCLUDED.updated_at
			 WHERE structural_grants.consent_generation <= EXCLUDED.consent_generation
			   AND structural_grants.revoked_at IS NULL
			 RETURNING purpose, data_dictionary_digest, schema_version, consent_generation,
			           declared_timezone, source_window_rule, first_seen_at, updated_at, revoked_at`,
			accountID, in.Purpose, in.DataDictionaryDigest, in.SchemaVersion,
			in.ConsentGeneration, in.DeclaredTimezone, in.SourceWindowRule, in.Now).
			Scan(&grant.Purpose, &grant.DataDictionaryDigest, &grant.SchemaVersion,
				&grant.ConsentGeneration, &grant.DeclaredTimezone, &grant.SourceWindowRule,
				&grant.FirstSeenAt, &grant.UpdatedAt, &grant.RevokedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			// The guard refused the update: a registration at or beyond this
			// generation (or a revoked one) already stands.
			return ErrStructuralGenerationStale
		}
		if e != nil {
			return fmt.Errorf("register standing grant: %w", e)
		}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrStructuralGrantRevoked),
			errors.Is(err, ErrStructuralGenerationStale),
			errors.Is(err, ErrStructuralDictionaryMismatch),
			errors.Is(err, ErrStructuralGrantTermsMismatch),
			errors.Is(err, ErrStructuralBindingIncomplete):
			return StructuralGrant{}, "", err
		}
		return StructuralGrant{}, "", fmt.Errorf("cloudserver/store.RegisterStructuralGrant: %w", err)
	}
	return grant, action, nil
}

// readStructuralGrantTx reads one registration, optionally taking the row lock
// (forUpdate) so a concurrent upload for the same purpose serializes behind it
// rather than racing the read-then-write.
func readStructuralGrantTx(ctx context.Context, tx pgx.Tx, accountID, purpose string, forUpdate bool) (StructuralGrant, bool, error) {
	q := `SELECT purpose, data_dictionary_digest, schema_version, consent_generation,
	             declared_timezone, source_window_rule, first_seen_at, updated_at, revoked_at
	        FROM structural_grants
	       WHERE account_id = $1::uuid AND purpose = $2`
	if forUpdate {
		q += ` FOR UPDATE`
	}
	var g StructuralGrant
	e := tx.QueryRow(ctx, q, accountID, purpose).
		Scan(&g.Purpose, &g.DataDictionaryDigest, &g.SchemaVersion, &g.ConsentGeneration,
			&g.DeclaredTimezone, &g.SourceWindowRule, &g.FirstSeenAt, &g.UpdatedAt, &g.RevokedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return StructuralGrant{}, false, nil
	}
	if e != nil {
		return StructuralGrant{}, false, fmt.Errorf("read standing grant: %w", e)
	}
	return g, true, nil
}

// ListStructuralGrants returns every standing-grant registration the account
// holds, revoked ones included (the Privacy page states retention honestly, so
// it must be able to show a withdrawn grant as withdrawn rather than vanish it).
func (s *Store) ListStructuralGrants(ctx context.Context, accountID string) ([]StructuralGrant, error) {
	out := []StructuralGrant{}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT purpose, data_dictionary_digest, schema_version, consent_generation,
			        declared_timezone, source_window_rule, first_seen_at, updated_at, revoked_at
			   FROM structural_grants WHERE account_id = $1::uuid ORDER BY purpose`,
			accountID)
		if e != nil {
			return fmt.Errorf("list standing grants: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			var g StructuralGrant
			if e := rows.Scan(&g.Purpose, &g.DataDictionaryDigest, &g.SchemaVersion,
				&g.ConsentGeneration, &g.DeclaredTimezone, &g.SourceWindowRule,
				&g.FirstSeenAt, &g.UpdatedAt, &g.RevokedAt); e != nil {
				return e
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListStructuralGrants: %w", err)
	}
	return out, nil
}

// --- snapshots ---------------------------------------------------------------

// Snapshot storage outcomes.
const (
	// SnapshotStored means the snapshot is now the CURRENT row for its window.
	SnapshotStored = "stored"
	// SnapshotStoredSuperseded means the snapshot was stored but arrived AFTER a
	// higher revision of the same window, so it was written already-superseded
	// (the r2-before-r1 case). It is kept, not dropped: it is a real thing the
	// device sent, and discarding it would make the revision history lie.
	SnapshotStoredSuperseded = "stored_superseded"
	// SnapshotReplay means the exact same (window key, revision, digest) was
	// already held and the server re-acked rather than storing again.
	SnapshotReplay = "replay"
)

// StructuralSnapshotInput is one immutable window as received. CanonicalBytes
// are the EXACT bytes the request carried; Digest is the server's own
// recomputation over them, never the client's declared value.
type StructuralSnapshotInput struct {
	DeviceID string
	// Purpose is the consent purpose the route authorized. The insert
	// REVALIDATES the standing grant for it inside its own transaction (F7), so
	// it is supplied by the caller from the route it served — never a client
	// field, exactly like the registration's.
	Purpose           string
	Period            string
	PeriodRuleVersion int
	SchemaVersion     string
	Revision          int
	Digest            string
	CanonicalBytes    []byte
	DeclaredTimezone  string
	SourceWatermark   string
	ConsentGeneration int64
	Now               time.Time
}

// StructuralSnapshotResult is the acknowledgement of a stored (or replay-acked)
// window.
type StructuralSnapshotResult struct {
	SnapshotID string
	Status     string
	Replay     bool
}

// PutStructuralSnapshot stores one immutable window and recomputes the
// account-day materialization, in ONE transaction.
//
// Admission (F7): the account row and the standing-grant registration are
// REVALIDATED inside this transaction before anything is written. The caller
// registers the grant in its own earlier transaction, and between the two an
// account deletion (which fences the account 'closed' and revokes the
// registration) could otherwise commit — and this insert would then re-create
// activity data for an account whose data had just been purged. The accounts-row
// lock is taken FIRST, which is the same order deletionSkeletonTx takes it, so
// the two serialize: either this insert commits before the fence (and the
// deletion's own DELETE purges it) or it aborts here.
//
// Concurrency: the write body runs under a transaction-scoped ADVISORY LOCK
// keyed on the window (account, device, period, rule, schema). Two devices, or
// two retries, hitting the same window serialize; different windows do not
// contend. The lock is what makes "read the current row, supersede it, insert
// the new one" atomic — the partial unique index would otherwise turn a race
// into an error rather than a correct ordering. The unique constraints remain
// as the DATABASE-level truth (belt and braces): the lock orders writers, the
// constraints prove the ordering held.
//
// A SECOND advisory lock, on (account, period), is taken immediately before the
// account-day recompute (F8). The window lock cannot serialize that step: it is
// per-DEVICE, while the materialization merges EVERY device's current snapshot
// for the day, so two devices uploading the same period concurrently held
// disjoint window locks, each recomputed from a snapshot of the table that did
// not yet contain the other's row, and the later commit overwrote the earlier
// with a one-device answer. Under READ COMMITTED the period lock fixes it
// directly: whoever waits runs its recompute SELECT after the other's COMMIT and
// therefore sees both rows. The acquisition order is ALWAYS window lock then
// period lock, everywhere, so no cycle can form.
//
// Currency is by REVISION NUMBER, never arrival order:
//
//   - exact key already present, same digest ⇒ replay-ack, nothing written;
//   - exact key already present, other digest ⇒ ErrStructuralDigestConflict;
//   - arriving revision > current ⇒ supersede the current row, insert current;
//   - arriving revision < current ⇒ insert ALREADY superseded (r2-before-r1);
//   - no current row ⇒ insert current.
func (s *Store) PutStructuralSnapshot(ctx context.Context, accountID string, in StructuralSnapshotInput) (StructuralSnapshotResult, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	var out StructuralSnapshotResult
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		// 0) Re-admission, inside THIS transaction (F7).
		if e := revalidateStructuralAdmissionTx(ctx, tx, accountID, in); e != nil {
			return e
		}

		lockKey := fmt.Sprintf("sbci-struct\x1f%s\x1f%s\x1f%s\x1f%d\x1f%s",
			accountID, in.DeviceID, in.Period, in.PeriodRuleVersion, in.SchemaVersion)
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, lockKey); e != nil {
			return fmt.Errorf("lock window: %w", e)
		}

		// 1) Exact key already present?
		var (
			existingID     string
			existingDigest string
		)
		e := tx.QueryRow(ctx,
			`SELECT id::text, digest FROM structural_snapshots
			  WHERE account_id = $1::uuid AND device_id = $2::uuid AND period = $3
			    AND period_rule_version = $4 AND schema_version = $5 AND revision = $6`,
			accountID, in.DeviceID, in.Period, in.PeriodRuleVersion, in.SchemaVersion, in.Revision).
			Scan(&existingID, &existingDigest)
		switch {
		case e == nil && existingDigest == in.Digest:
			out = StructuralSnapshotResult{SnapshotID: existingID, Status: SnapshotReplay, Replay: true}
			return nil
		case e == nil:
			return ErrStructuralDigestConflict
		case !errors.Is(e, pgx.ErrNoRows):
			return fmt.Errorf("read existing revision: %w", e)
		}

		// 2) The window's CURRENT row, if any.
		var (
			currentID       string
			currentRevision int
			hasCurrent      bool
		)
		e = tx.QueryRow(ctx,
			`SELECT id::text, revision FROM structural_snapshots
			  WHERE account_id = $1::uuid AND device_id = $2::uuid AND period = $3
			    AND period_rule_version = $4 AND schema_version = $5 AND superseded_at IS NULL`,
			accountID, in.DeviceID, in.Period, in.PeriodRuleVersion, in.SchemaVersion).
			Scan(&currentID, &currentRevision)
		switch {
		case e == nil:
			hasCurrent = true
		case errors.Is(e, pgx.ErrNoRows):
		default:
			return fmt.Errorf("read current revision: %w", e)
		}

		// 3) Decide currency by revision number and write.
		var supersededAt any // NULL ⇒ this row becomes current
		out.Status = SnapshotStored
		if hasCurrent {
			if in.Revision > currentRevision {
				if _, e := tx.Exec(ctx,
					`UPDATE structural_snapshots SET superseded_at = $2
					  WHERE account_id = $3::uuid AND id = $1::uuid`,
					currentID, in.Now, accountID); e != nil {
					return fmt.Errorf("supersede current revision: %w", e)
				}
			} else {
				// A LOWER revision arriving after a higher one: keep it, but it
				// is not and never becomes the current view of the window.
				supersededAt = in.Now
				out.Status = SnapshotStoredSuperseded
			}
		}

		if e := tx.QueryRow(ctx,
			`INSERT INTO structural_snapshots
			   (account_id, device_id, period, period_rule_version, schema_version, revision,
			    digest, canonical_bytes, declared_timezone, source_watermark,
			    consent_generation, received_at, superseded_at)
			 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			 RETURNING id::text`,
			accountID, in.DeviceID, in.Period, in.PeriodRuleVersion, in.SchemaVersion, in.Revision,
			in.Digest, in.CanonicalBytes, in.DeclaredTimezone, in.SourceWatermark,
			in.ConsentGeneration, in.Now, supersededAt).Scan(&out.SnapshotID); e != nil {
			return fmt.Errorf("insert snapshot: %w", e)
		}

		// 4) Recompute the account-day materialization for THIS day only —
		// bounded work: one period, one row per contributing device. The
		// per-PERIOD lock (F8) is taken here, after the per-window lock, so a
		// concurrent upload from another DEVICE for the same day cannot compute
		// its merge from a table state that is missing this row.
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`,
			StructuralPeriodLockKey(accountID, in.Period)); e != nil {
			return fmt.Errorf("lock account day: %w", e)
		}
		return recomputeStructuralAccountDayTx(ctx, tx, accountID, in.Period, in.Now)
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrStructuralDigestConflict),
			errors.Is(err, ErrStructuralGrantRevoked),
			errors.Is(err, ErrStructuralGrantMissing),
			errors.Is(err, ErrStructuralGenerationStale),
			errors.Is(err, ErrAccountClosed):
			return StructuralSnapshotResult{}, err
		}
		return StructuralSnapshotResult{}, fmt.Errorf("cloudserver/store.PutStructuralSnapshot: %w", err)
	}
	return out, nil
}

// StructuralPeriodLockKey is the advisory-lock key an (account, period)
// materialization recompute serializes on (F8). Its argument to
// pg_advisory_xact_lock is hashtext(key)::bigint.
//
// It is EXPORTED for one reason, stated so nobody widens it: the F8 regression
// test holds this exact lock from an outside connection and asserts that an
// upload for that period blocks until it is released. The natural race window —
// between the leading writer's recompute SELECT and its COMMIT — is only a few
// milliseconds wide, so a test that merely fires two uploads at once passes on
// most machines whether the lock is there or not. Asserting the lock is TAKEN
// is deterministic; asserting a race is not.
func StructuralPeriodLockKey(accountID, period string) string {
	return fmt.Sprintf("sbci-struct-day\x1f%s\x1f%s", accountID, period)
}

// revalidateStructuralAdmissionTx re-checks, inside the insert's own
// transaction, the two facts the caller established in an EARLIER one: that the
// account still permits writes, and that the standing grant still authorizes
// this exact consent generation (F7).
//
// It is not a duplicate of RegisterStructuralGrant. That call decides what the
// registration SHOULD say and moves it; this one asserts that what it says has
// not changed underneath the upload. The account lock is taken first so this
// serializes against deletionSkeletonTx, which fences the accounts row before it
// revokes the grant and purges the tables.
func revalidateStructuralAdmissionTx(ctx context.Context, tx pgx.Tx, accountID string, in StructuralSnapshotInput) error {
	// FOR SHARE, deliberately, not FOR UPDATE. Both conflict with the deletion
	// fence's UPDATE of this row, so the fencing guarantee is identical: the
	// deletion either waits for this transaction (and its DELETE then purges what
	// was inserted) or this transaction waits for the deletion and reads
	// 'closed'. But FOR SHARE lockers do not block EACH OTHER, so two of the
	// account's own devices uploading at once still run in parallel. FOR UPDATE
	// here would serialize every structural upload an account makes — and, worse,
	// would silently do the (account, period) lock's job below, leaving that lock
	// untested and the F8 defect one refactor away from returning.
	var status string
	if e := tx.QueryRow(ctx,
		`SELECT status FROM accounts WHERE account_id = $1::uuid FOR SHARE`,
		accountID).Scan(&status); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrAccountClosed
		}
		return fmt.Errorf("lock account: %w", e)
	}
	if status != "active" {
		return ErrAccountClosed
	}
	grant, found, e := readStructuralGrantTx(ctx, tx, accountID, in.Purpose, false)
	if e != nil {
		return e
	}
	switch {
	case !found:
		return ErrStructuralGrantMissing
	case grant.RevokedAt != nil:
		return ErrStructuralGrantRevoked
	case grant.ConsentGeneration != in.ConsentGeneration:
		// The registration moved (or was rolled) while this upload was in
		// flight. Either direction is the same honest answer: these bytes were
		// authorized under terms that are no longer the registered ones.
		return ErrStructuralGenerationStale
	}
	return nil
}

// StructuralAccountDay is one materialized account-day as the portal reads it.
type StructuralAccountDay struct {
	Period                   string                             `json:"period"`
	DeviceCount              int                                `json:"device_count"`
	SessionCount             int                                `json:"session_count"`
	ActionCount              int                                `json:"action_count"`
	TokensIn                 int64                              `json:"tokens_in"`
	TokensOut                int64                              `json:"tokens_out"`
	CacheReadTokens          int64                              `json:"cache_read_tokens"`
	CostUSD                  float64                            `json:"cost_usd"`
	ToolMix                  []cloudcontract.StructuralMixEntry `json:"tool_mix"`
	ModelFamilyMix           []cloudcontract.StructuralMixEntry `json:"model_family_mix"`
	SessionsWithOutcomes     int                                `json:"sessions_with_outcomes"`
	SessionsWithVerification int                                `json:"sessions_with_verification"`
	VerificationCoverageBand string                             `json:"verification_coverage_band"`
	OutcomeEvidenceBand      string                             `json:"outcome_evidence_band"`
	ComputedAt               time.Time                          `json:"computed_at"`
}

// recomputeStructuralAccountDayTx rebuilds one (account, period) row of the
// materialization from the CURRENT snapshots of that day.
//
// Device selection: DISTINCT ON (device_id), preferring the highest
// (period_rule_version, schema_version). A period-rule or schema bump makes old
// and new windows COEXIST by design (the server keys on both), so a device
// could legitimately have two current rows for one day; summing both would
// double-count that device's sessions. Taking the newest per device is the
// honest merge — it reports the day once, on the newest rule the device has
// sent, and needs no migration when a version bump lands.
//
// The numbers are re-derived from the canonical BYTES rather than from
// denormalized columns, so the snapshot stays the single owner of the
// aggregates and the materialization can never drift from what was digested.
func recomputeStructuralAccountDayTx(ctx context.Context, tx pgx.Tx, accountID, period string, now time.Time) error {
	rows, err := tx.Query(ctx,
		`SELECT DISTINCT ON (device_id) canonical_bytes
		   FROM structural_snapshots
		  WHERE account_id = $1::uuid AND period = $2 AND superseded_at IS NULL
		  ORDER BY device_id, period_rule_version DESC, schema_version DESC`,
		accountID, period)
	if err != nil {
		return fmt.Errorf("read current snapshots: %w", err)
	}
	var payloads [][]byte
	for rows.Next() {
		var b []byte
		if e := rows.Scan(&b); e != nil {
			rows.Close()
			return fmt.Errorf("scan snapshot bytes: %w", e)
		}
		payloads = append(payloads, b)
	}
	rows.Close()
	if e := rows.Err(); e != nil {
		return fmt.Errorf("read current snapshots: %w", e)
	}

	if len(payloads) == 0 {
		// No current snapshot left for the day (only reachable if every row was
		// removed): the materialization must not outlive its inputs.
		if _, e := tx.Exec(ctx,
			`DELETE FROM structural_account_days WHERE account_id = $1::uuid AND period = $2`,
			accountID, period); e != nil {
			return fmt.Errorf("clear account day: %w", e)
		}
		return nil
	}

	day, err := mergeStructuralDay(period, payloads)
	if err != nil {
		return err
	}
	toolMix, err := json.Marshal(day.ToolMix)
	if err != nil {
		return fmt.Errorf("encode tool mix: %w", err)
	}
	familyMix, err := json.Marshal(day.ModelFamilyMix)
	if err != nil {
		return fmt.Errorf("encode model family mix: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO structural_account_days
		   (account_id, period, device_count, session_count, action_count,
		    tokens_in, tokens_out, cache_read_tokens, cost_usd,
		    tool_mix, model_family_mix, sessions_with_outcomes, sessions_with_verification,
		    verification_coverage_band, outcome_evidence_band, computed_at)
		 VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12, $13, $14, $15, $16)
		 ON CONFLICT (account_id, period) DO UPDATE SET
		   device_count = EXCLUDED.device_count,
		   session_count = EXCLUDED.session_count,
		   action_count = EXCLUDED.action_count,
		   tokens_in = EXCLUDED.tokens_in,
		   tokens_out = EXCLUDED.tokens_out,
		   cache_read_tokens = EXCLUDED.cache_read_tokens,
		   cost_usd = EXCLUDED.cost_usd,
		   tool_mix = EXCLUDED.tool_mix,
		   model_family_mix = EXCLUDED.model_family_mix,
		   sessions_with_outcomes = EXCLUDED.sessions_with_outcomes,
		   sessions_with_verification = EXCLUDED.sessions_with_verification,
		   verification_coverage_band = EXCLUDED.verification_coverage_band,
		   outcome_evidence_band = EXCLUDED.outcome_evidence_band,
		   computed_at = EXCLUDED.computed_at`,
		accountID, period, day.DeviceCount, day.SessionCount, day.ActionCount,
		day.TokensIn, day.TokensOut, day.CacheReadTokens, day.CostUSD,
		string(toolMix), string(familyMix), day.SessionsWithOutcomes, day.SessionsWithVerification,
		day.VerificationCoverageBand, day.OutcomeEvidenceBand, now); err != nil {
		return fmt.Errorf("upsert account day: %w", err)
	}
	return nil
}

// mergeStructuralDay folds one device's snapshots into an account-day. It is
// pure: the SQL above hands it bytes, it hands back a row.
func mergeStructuralDay(period string, payloads [][]byte) (StructuralAccountDay, error) {
	day := StructuralAccountDay{
		Period:      period,
		DeviceCount: len(payloads),
	}
	tools := map[string]int{}
	families := map[string]int{}
	for _, raw := range payloads {
		var snap cloudcontract.StructuralSnapshot
		if err := json.Unmarshal(raw, &snap); err != nil {
			return StructuralAccountDay{}, fmt.Errorf("cloudserver/store: decode stored snapshot for %s: %w", period, err)
		}
		day.SessionCount += snap.SessionCount
		day.ActionCount += snap.ActionCount
		day.TokensIn += int64(snap.TokensIn)
		day.TokensOut += int64(snap.TokensOut)
		day.CacheReadTokens += int64(snap.CacheReadTokens)
		day.CostUSD += snap.CostUSD
		day.SessionsWithOutcomes += snap.CoverageDenominators.SessionsWithOutcomes
		day.SessionsWithVerification += snap.CoverageDenominators.SessionsWithVerification
		for _, e := range snap.ToolMix {
			tools[e.Key] += e.Count
		}
		for _, e := range snap.ModelFamilyMix {
			families[e.Key] += e.Count
		}
	}
	day.ToolMix = sortedMix(tools)
	day.ModelFamilyMix = sortedMix(families)
	// Re-band from the MERGED numerators over the MERGED denominator. Averaging
	// the per-device bands would be arithmetic on a closed vocabulary.
	day.VerificationCoverageBand = string(cloudevidence.CoverageBandFor(day.SessionsWithVerification, day.SessionCount))
	day.OutcomeEvidenceBand = string(cloudevidence.CoverageBandFor(day.SessionsWithOutcomes, day.SessionCount))
	return day, nil
}

// sortedMix renders a merged categorical mix in the contract's canonical shape:
// key-ascending, zero counts dropped, never nil (an empty mix encodes as []).
func sortedMix(counts map[string]int) []cloudcontract.StructuralMixEntry {
	out := make([]cloudcontract.StructuralMixEntry, 0, len(counts))
	for k, n := range counts {
		if n <= 0 {
			continue
		}
		out = append(out, cloudcontract.StructuralMixEntry{Key: k, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// ListStructuralAccountDays returns the materialized days in [from, to]
// inclusive, oldest first. Both bounds are "YYYY-MM-DD" strings, which sort
// lexicographically = chronologically. A day with no data has NO row — the
// portal renders absence as absence rather than fabricating a zero.
func (s *Store) ListStructuralAccountDays(ctx context.Context, accountID, from, to string) ([]StructuralAccountDay, error) {
	out := []StructuralAccountDay{}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT period, device_count, session_count, action_count,
			        tokens_in, tokens_out, cache_read_tokens, cost_usd,
			        tool_mix, model_family_mix, sessions_with_outcomes, sessions_with_verification,
			        verification_coverage_band, outcome_evidence_band, computed_at
			   FROM structural_account_days
			  WHERE account_id = $1::uuid AND period >= $2 AND period <= $3
			  ORDER BY period`,
			accountID, from, to)
		if e != nil {
			return fmt.Errorf("list account days: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				d               StructuralAccountDay
				toolRaw, famRaw []byte
			)
			if e := rows.Scan(&d.Period, &d.DeviceCount, &d.SessionCount, &d.ActionCount,
				&d.TokensIn, &d.TokensOut, &d.CacheReadTokens, &d.CostUSD,
				&toolRaw, &famRaw, &d.SessionsWithOutcomes, &d.SessionsWithVerification,
				&d.VerificationCoverageBand, &d.OutcomeEvidenceBand, &d.ComputedAt); e != nil {
				return e
			}
			if e := json.Unmarshal(toolRaw, &d.ToolMix); e != nil {
				return fmt.Errorf("decode tool mix: %w", e)
			}
			if e := json.Unmarshal(famRaw, &d.ModelFamilyMix); e != nil {
				return fmt.Errorf("decode model family mix: %w", e)
			}
			if d.ToolMix == nil {
				d.ToolMix = []cloudcontract.StructuralMixEntry{}
			}
			if d.ModelFamilyMix == nil {
				d.ModelFamilyMix = []cloudcontract.StructuralMixEntry{}
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListStructuralAccountDays: %w", err)
	}
	return out, nil
}

// StructuralDaySummary is the whole-window rollup of a day list. It exists so
// the portal never has to re-derive an aggregate rule (mix merging, band
// derivation) that this package already owns.
type StructuralDaySummary struct {
	// ActiveDays is how many days in the window carry a materialized row at
	// all. Days with no data have NO row, so this is a count of evidence, not a
	// count of the calendar.
	ActiveDays               int                                `json:"active_days"`
	SessionCount             int                                `json:"session_count"`
	ActionCount              int                                `json:"action_count"`
	TokensIn                 int64                              `json:"tokens_in"`
	TokensOut                int64                              `json:"tokens_out"`
	CacheReadTokens          int64                              `json:"cache_read_tokens"`
	CostUSD                  float64                            `json:"cost_usd"`
	ToolMix                  []cloudcontract.StructuralMixEntry `json:"tool_mix"`
	ModelFamilyMix           []cloudcontract.StructuralMixEntry `json:"model_family_mix"`
	SessionsWithOutcomes     int                                `json:"sessions_with_outcomes"`
	SessionsWithVerification int                                `json:"sessions_with_verification"`
	VerificationCoverageBand string                             `json:"verification_coverage_band"`
	OutcomeEvidenceBand      string                             `json:"outcome_evidence_band"`
	// MaxDeviceCount is the most devices that contributed to any single day in
	// the window — the honest ceiling on "is this all of my machines".
	MaxDeviceCount int    `json:"max_device_count"`
	FirstDay       string `json:"first_day"`
	LastDay        string `json:"last_day"`
}

// SummarizeStructuralDays folds a day list into one window summary. Days are
// disjoint, so counts sum; mixes merge by key; the two bands are RE-DERIVED
// from the summed numerators over the summed session count (never averaged
// from the per-day bands).
func SummarizeStructuralDays(days []StructuralAccountDay) StructuralDaySummary {
	sum := StructuralDaySummary{
		ToolMix:                  []cloudcontract.StructuralMixEntry{},
		ModelFamilyMix:           []cloudcontract.StructuralMixEntry{},
		VerificationCoverageBand: string(cloudcontract.CoverageBandNone),
		OutcomeEvidenceBand:      string(cloudcontract.CoverageBandNone),
	}
	if len(days) == 0 {
		return sum
	}
	tools := map[string]int{}
	families := map[string]int{}
	for _, d := range days {
		sum.ActiveDays++
		sum.SessionCount += d.SessionCount
		sum.ActionCount += d.ActionCount
		sum.TokensIn += d.TokensIn
		sum.TokensOut += d.TokensOut
		sum.CacheReadTokens += d.CacheReadTokens
		sum.CostUSD += d.CostUSD
		sum.SessionsWithOutcomes += d.SessionsWithOutcomes
		sum.SessionsWithVerification += d.SessionsWithVerification
		if d.DeviceCount > sum.MaxDeviceCount {
			sum.MaxDeviceCount = d.DeviceCount
		}
		for _, e := range d.ToolMix {
			tools[e.Key] += e.Count
		}
		for _, e := range d.ModelFamilyMix {
			families[e.Key] += e.Count
		}
	}
	sum.ToolMix = sortedMix(tools)
	sum.ModelFamilyMix = sortedMix(families)
	sum.VerificationCoverageBand = string(cloudevidence.CoverageBandFor(sum.SessionsWithVerification, sum.SessionCount))
	sum.OutcomeEvidenceBand = string(cloudevidence.CoverageBandFor(sum.SessionsWithOutcomes, sum.SessionCount))
	sum.FirstDay = days[0].Period
	sum.LastDay = days[len(days)-1].Period
	return sum
}

// StructuralCoverage reports how many DEVICES have ever contributed a snapshot
// and the oldest/newest materialized day, so every portal card can state the
// window it actually covers instead of implying it covers everything.
type StructuralCoverage struct {
	Devices   int    `json:"devices"`
	FirstDay  string `json:"first_day"`
	LastDay   string `json:"last_day"`
	TotalDays int    `json:"total_days"`
	Snapshots int    `json:"snapshots"`
}

// StructuralWindowDeviceCount counts the DISTINCT devices that hold a current
// snapshot inside [from, to] — the window the Overview cards actually summarize
// (F13).
//
// StructuralCoverageFor's Devices is a whole-CORPUS figure, and rendering it in
// a line that names a bounded window ("N days with synced data, X to Y, from D
// devices") overstates the window: a machine that synced once a year ago and has
// been offline since counted toward D. This is the same [from, to] the day list
// is read over, so the two agree by construction. It reads the snapshots rather
// than max(structural_account_days.device_count) deliberately: the max is the
// busiest single DAY, which under-reports two machines that never overlapped on
// one day.
func (s *Store) StructuralWindowDeviceCount(ctx context.Context, accountID, from, to string) (int, error) {
	var n int
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(DISTINCT device_id) FROM structural_snapshots
			  WHERE account_id = $1::uuid AND superseded_at IS NULL
			    AND period >= $2 AND period <= $3`,
			accountID, from, to).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.StructuralWindowDeviceCount: %w", err)
	}
	return n, nil
}

// StructuralCoverageFor reads the account's whole-corpus coverage facts.
func (s *Store) StructuralCoverageFor(ctx context.Context, accountID string) (StructuralCoverage, error) {
	var c StructuralCoverage
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if e := tx.QueryRow(ctx,
			`SELECT count(DISTINCT device_id), count(*) FROM structural_snapshots
			  WHERE account_id = $1::uuid AND superseded_at IS NULL`,
			accountID).Scan(&c.Devices, &c.Snapshots); e != nil {
			return fmt.Errorf("count snapshot coverage: %w", e)
		}
		var first, last *string
		if e := tx.QueryRow(ctx,
			`SELECT min(period), max(period), count(*) FROM structural_account_days
			  WHERE account_id = $1::uuid`,
			accountID).Scan(&first, &last, &c.TotalDays); e != nil {
			return fmt.Errorf("read day coverage: %w", e)
		}
		if first != nil {
			c.FirstDay = *first
		}
		if last != nil {
			c.LastDay = *last
		}
		return nil
	})
	if err != nil {
		return StructuralCoverage{}, fmt.Errorf("cloudserver/store.StructuralCoverageFor: %w", err)
	}
	return c, nil
}
