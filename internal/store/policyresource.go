package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Plane-A P0-5 unified policy resource, agent-side scoped persistence
// (docs/plans/plane-a-p0-5-unified-policy-resource-v1-plan.md §6.2, §6.9,
// §6.10; migration 081). ONE OWNER: org_enrolment_generation and
// org_policy_resource_state are written exclusively from this file. Both
// are NODE-LOCAL control-plane state, pinned out of the org-push wire in
// tests/invariant/privacy_test.go's forbiddenCacheTables (never read by
// orgpush.go::SelectUnpushedSince).
//
// This file implements the STORE half of the plan's two write paths:
//
//  1. BumpEnrolmentGeneration — the durable cross-process fence transition
//     (§6.9), run with PRAGMA synchronous=FULL so a power loss can never
//     acknowledge a generation bump only in the WAL while a stale cache
//     from the OLD generation survives fsynced on disk.
//  2. WithPolicyResourceFence — the CAS-fenced fetch-and-install
//     transaction (§6.10): it re-reads the durable identity/floor/digest
//     inside a BEGIN IMMEDIATE, hands that snapshot to the caller (which
//     performs the durable cache-file fsync+rename WHILE the transaction
//     is still open — internal/orgclient owns that I/O), and only then
//     CAS-upserts the new state and commits.
//
// Phase-A note: neither primitive is yet wired into orgclient.Enroll /
// Unenroll / start.go (that integration is Phase W). The tests in
// policyresource_test.go exercise both directly.

// PolicyResourceState is one (org_key, family) durable replay-floor +
// last-verified-envelope row.
type PolicyResourceState struct {
	OrgKey       string
	Family       string
	Generation   int64
	FloorVersion int64
	LastVersion  int64
	BodyHash     string
	MsgDigest    string
	UpdatedAt    time.Time
}

// EnrolmentGeneration is the durable cross-process fence row (plan §6.9):
// one per enrolment identity, NEVER deleted, monotonically increasing.
type EnrolmentGeneration struct {
	OrgKey     string
	Generation int64
	Tombstoned bool
	UpdatedAt  time.Time
}

// querier is satisfied by both *sql.DB and *sql.Conn, letting the read
// helpers below run either against the pool or a pinned connection
// (WithPolicyResourceFence uses the latter, from inside its transaction).
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// LoadEnrolmentGeneration returns the durable generation row for orgKey, or
// ok=false when no row has ever been created for this identity (a fresh
// org_key that has never called BumpEnrolmentGeneration).
func (s *Store) LoadEnrolmentGeneration(ctx context.Context, orgKey string) (EnrolmentGeneration, bool, error) {
	g, ok, err := loadEnrolmentGeneration(ctx, s.db, orgKey)
	if err != nil {
		return EnrolmentGeneration{}, false, fmt.Errorf("store.LoadEnrolmentGeneration: %w", err)
	}
	return g, ok, nil
}

func loadEnrolmentGeneration(ctx context.Context, q querier, orgKey string) (EnrolmentGeneration, bool, error) {
	var (
		g  EnrolmentGeneration
		ts string
		tb int
	)
	g.OrgKey = orgKey
	err := q.QueryRowContext(ctx, `
		SELECT generation, tombstoned, updated_at FROM org_enrolment_generation WHERE org_key = ?`, orgKey).
		Scan(&g.Generation, &tb, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrolmentGeneration{}, false, nil
	}
	if err != nil {
		return EnrolmentGeneration{}, false, err
	}
	g.Tombstoned = tb != 0
	g.UpdatedAt = parseStamp(ts)
	return g, true, nil
}

// BumpEnrolmentGeneration durably advances orgKey's generation and sets its
// tombstone bit (plan §6.9): enrol/re-enrol pass tombstoned=false, unenrol
// passes tombstoned=true. A fresh org_key starts at generation 1.
//
// This is the ONE FULL-sync write in the policy-resource seam — the
// transition transaction runs with PRAGMA synchronous=FULL on a pinned
// connection, then restores NORMAL, so a power loss cannot durably record a
// fsynced cache/state row against a generation whose OWN transition only
// made it into the WAL. The normal policy-cache/state write path
// (WithPolicyResourceFence below) stays at the database's default
// synchronous=NORMAL; it is the generation FENCE that must survive a crash
// independently, because it is what makes a surviving old cache from a
// stale generation non-installable afterwards.
//
// Returns the NEW generation. Phase-A primitive: not yet wired into
// orgclient.Enroll/Unenroll (Phase W owns calling it from those paths and
// from re-enrolment's tombstone-old/activate-new transition) — the tests
// here exercise it directly.
func (s *Store) BumpEnrolmentGeneration(ctx context.Context, orgKey string, tombstoned bool) (int64, error) {
	if orgKey == "" {
		return 0, errors.New("store.BumpEnrolmentGeneration: orgKey required")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return 0, fmt.Errorf("store.BumpEnrolmentGeneration: conn: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, `PRAGMA synchronous = FULL`); err != nil {
		return 0, fmt.Errorf("store.BumpEnrolmentGeneration: set synchronous=FULL: %w", err)
	}
	// Restore NORMAL before the connection returns to the pool, using a
	// detached context so a cancelled ctx can't skip the restore.
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `PRAGMA synchronous = NORMAL`)
	}()

	if _, err := conn.ExecContext(ctx, `PRAGMA busy_timeout = 30000`); err != nil {
		return 0, fmt.Errorf("store.BumpEnrolmentGeneration: busy_timeout: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return 0, fmt.Errorf("store.BumpEnrolmentGeneration: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), `ROLLBACK`)
		}
	}()

	now := timestamp(time.Time{})
	tb := 0
	if tombstoned {
		tb = 1
	}
	if _, err := conn.ExecContext(ctx, `
		INSERT INTO org_enrolment_generation (org_key, generation, tombstoned, updated_at)
		VALUES (?, 1, ?, ?)
		ON CONFLICT(org_key) DO UPDATE SET
		  generation = org_enrolment_generation.generation + 1,
		  tombstoned = excluded.tombstoned,
		  updated_at = excluded.updated_at`,
		orgKey, tb, now); err != nil {
		return 0, fmt.Errorf("store.BumpEnrolmentGeneration: upsert: %w", err)
	}
	var newGen int64
	if err := conn.QueryRowContext(ctx, `
		SELECT generation FROM org_enrolment_generation WHERE org_key = ?`, orgKey).Scan(&newGen); err != nil {
		return 0, fmt.Errorf("store.BumpEnrolmentGeneration: read back: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return 0, fmt.Errorf("store.BumpEnrolmentGeneration: commit: %w", err)
	}
	committed = true
	return newGen, nil
}

// LoadPolicyResourceState returns the durable state row for (orgKey,
// family), or ok=false when no envelope has ever been durably accepted for
// this family under this identity. A plain (unfenced) read for callers that
// only need to report current state (e.g. `observer org status`); the
// authoritative, race-safe read is the one WithPolicyResourceFence performs
// inside its transaction.
func (s *Store) LoadPolicyResourceState(ctx context.Context, orgKey, family string) (PolicyResourceState, bool, error) {
	st := PolicyResourceState{OrgKey: orgKey, Family: family}
	var ts string
	err := s.db.QueryRowContext(ctx, `
		SELECT generation, floor_version, last_version, body_hash, msg_digest, updated_at
		FROM org_policy_resource_state WHERE org_key = ? AND family = ?`, orgKey, family).
		Scan(&st.Generation, &st.FloorVersion, &st.LastVersion, &st.BodyHash, &st.MsgDigest, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyResourceState{}, false, nil
	}
	if err != nil {
		return PolicyResourceState{}, false, fmt.Errorf("store.LoadPolicyResourceState: %w", err)
	}
	st.UpdatedAt = parseStamp(ts)
	return st, true, nil
}

// ClearPolicyResourceState deletes every org_policy_resource_state row and
// cached ETag for orgKey (all families) — called when the agent's org
// identity changes (a different org_key enrols) so no stale floor/digest
// from the OLD identity can satisfy a fetch against the NEW one.
//
// This does NOT touch org_enrolment_generation: the durable generation
// counter for the OLD org_key intentionally survives (plan §6.9) so a stale
// writer that still thinks it holds the old generation is fenced out rather
// than silently reused, should that org_key ever be re-enrolled. Callers
// that need to advance/tombstone the generation call
// BumpEnrolmentGeneration separately (Phase W wires the ordering: tombstone
// old + activate new in one enrolment transaction, THEN clear state).
func (s *Store) ClearPolicyResourceState(ctx context.Context, orgKey string) error {
	if orgKey == "" {
		return errors.New("store.ClearPolicyResourceState: orgKey required")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM org_policy_resource_state WHERE org_key = ?`, orgKey); err != nil {
		return fmt.Errorf("store.ClearPolicyResourceState: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM schema_meta WHERE key LIKE ? ESCAPE '\'`,
		escapeLike(policyResourceETagKeyPrefix(orgKey))+"%"); err != nil {
		return fmt.Errorf("store.ClearPolicyResourceState: clear etags: %w", err)
	}
	return nil
}

// --- ETag cache (schema_meta-backed, mirrors orgpush.go's Save/LoadOrgPolicyETag) ---

// policyResourceETagKeyPrefix returns the shared prefix for every ETag key
// scoped to orgKey, used both to build one key (PolicyResourceETagKey) and
// to bulk-delete all of them on identity change (ClearPolicyResourceState).
func policyResourceETagKeyPrefix(orgKey string) string {
	return "orgPolicyResourceETag:" + orgKey + ":"
}

// escapeLike escapes SQLite LIKE metacharacters (% _ \) in s so it can be
// used as a literal prefix in a `LIKE ? ESCAPE '\'` pattern. org_key is a
// hex digest so this is defense-in-depth rather than a live requirement.
func escapeLike(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '%', '_', '\\':
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return string(out)
}

// PolicyResourceETagKey returns the schema_meta key for the cached ETag of
// one (orgKey, generation, family) fetch (plan §6.2 key format). The
// generation is baked into the key — not just carried in the value — so a
// stale ETag minted under an OLD generation can never be read back and
// treated as valid for a NEW one; ClearPolicyResourceState's prefix delete
// also makes every such key disappear together on identity change.
func PolicyResourceETagKey(orgKey string, generation int64, family string) string {
	return fmt.Sprintf("%s%d:%s", policyResourceETagKeyPrefix(orgKey), generation, family)
}

// SavePolicyResourceETag records the ETag of the most recently verified
// policy resource for (orgKey, generation, family). Overwritten on every
// applied fetch.
func (s *Store) SavePolicyResourceETag(ctx context.Context, orgKey string, generation int64, family, etag string) error {
	key := PolicyResourceETagKey(orgKey, generation, family)
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO schema_meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, etag); err != nil {
		return fmt.Errorf("store.SavePolicyResourceETag: %w", err)
	}
	return nil
}

// LoadPolicyResourceETag returns the last verified fetch's ETag for
// (orgKey, generation, family), or "" when none has ever been recorded.
func (s *Store) LoadPolicyResourceETag(ctx context.Context, orgKey string, generation int64, family string) (string, error) {
	v, err := s.readMeta(ctx, PolicyResourceETagKey(orgKey, generation, family))
	if err != nil {
		return "", fmt.Errorf("store.LoadPolicyResourceETag: %w", err)
	}
	return v, nil
}

// --- TOFU signing-key pin establishment (compare-if-absent) ---

// testHookKeyPinBeforeInsert is a nil-in-production seam fired between
// EstablishOrgPolicyKeyPin's pin re-read and its insert. It exists so the
// concurrency test can hold that window open deterministically and prove
// the surrounding transaction — not scheduling luck — is what serializes
// establishment: with the BEGIN IMMEDIATE in place only ONE caller ever
// reaches this point (every later caller sees the committed pin and returns
// before it), whereas a non-atomic read-then-append lets every racer arrive
// here at once. Package-private and only ever assigned from
// policyresource_test.go; the nil check costs one comparison per first-pin.
var testHookKeyPinBeforeInsert func()

// EstablishOrgPolicyKeyPin atomically establishes the org policy
// signing-key pin recorded at (layer="org", path=pinPath) in
// guard_policy_state IF AND ONLY IF no pin row exists for that path yet —
// compare-if-absent, first writer wins (review finding B-B6,
// docs/audits/cursor-arc-code-review-2026-08-13.md §3).
//
// It returns the AUTHORITATIVE pin as of this call's commit: keyHash when
// this call established it, or the already-established hash (whoever won)
// otherwise. established reports which of the two happened. A caller whose
// keyHash differs from the returned pin MUST refuse the resource on exactly
// the same path it uses for a changed pin: it lost the establishment race
// to a DIFFERENT key, and TOFU has already resolved to that other key.
//
// The atomic primitive is the same one WithPolicyResourceFence uses — a
// BEGIN IMMEDIATE transaction on a pinned connection (SQLite's exclusive
// write lock, so the read and the insert cannot interleave with another
// process's) plus an `INSERT ... WHERE NOT EXISTS` predicate as
// defense-in-depth: if the predicate ever matches zero rows the pin is
// re-read and reported rather than silently overwritten. It replaces the
// read-then-append TOFU sequence, where two concurrent first-accepts could
// each read "no pin" and append their own DIFFERENT key, and both proceed.
//
// Table-ownership note: guard_policy_state is otherwise written through
// internal/store/guard.go's RecordGuardPolicyState (the append-only
// policy-CHANGE log, §14.4). This is a deliberate second, NARROWER writer
// scoped to ONE row shape — the org key-pin row — because "append if the
// content hash changed" is precisely the wrong semantics for a pin, which
// must be establish-once. Enrolment (orgclient.Enroll) still records a
// server-delivered key through RecordGuardPolicyState: that path is
// authoritative by construction (an authenticated enrolment response), not
// trust-on-first-use, so a legitimate re-enrol can still record a rotated
// key.
// The provenance is stamped into the row's version column so the trust-root
// resolver (orgclient.enrolmentTrustFor) can tell a fetch-established pin
// from one the enrolment channel wrote; the store does not interpret it.
func (s *Store) EstablishOrgPolicyKeyPin(ctx context.Context, pinPath, keyHash, provenance string) (pinned string, established bool, err error) {
	if pinPath == "" || keyHash == "" {
		return "", false, errors.New("store.EstablishOrgPolicyKeyPin: pinPath and keyHash required")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return "", false, fmt.Errorf("store.EstablishOrgPolicyKeyPin: conn: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `PRAGMA busy_timeout = 30000`); err != nil {
		return "", false, fmt.Errorf("store.EstablishOrgPolicyKeyPin: busy_timeout: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return "", false, fmt.Errorf("store.EstablishOrgPolicyKeyPin: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), `ROLLBACK`)
		}
	}()

	existing, hasPin, err := readOrgPolicyKeyPin(ctx, conn, pinPath)
	if err != nil {
		return "", false, fmt.Errorf("store.EstablishOrgPolicyKeyPin: %w", err)
	}
	if hasPin {
		// Already pinned — nothing to establish. The rollback in the defer
		// closes the read-only transaction.
		return existing, false, nil
	}
	if testHookKeyPinBeforeInsert != nil {
		testHookKeyPinBeforeInsert()
	}

	res, err := conn.ExecContext(ctx, `
		INSERT INTO guard_policy_state (layer, path, version, content_hash, signature, loaded_at)
		SELECT 'org', ?, ?, ?, NULL, ?
		WHERE NOT EXISTS (SELECT 1 FROM guard_policy_state WHERE layer = 'org' AND path = ?)`,
		pinPath, provenance, keyHash, timestamp(time.Time{}), pinPath)
	if err != nil {
		return "", false, fmt.Errorf("store.EstablishOrgPolicyKeyPin: insert: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		// Defense in depth: unreachable under BEGIN IMMEDIATE, but if the
		// predicate ever loses, report the winner instead of clobbering it.
		raced, hasRaced, rerr := readOrgPolicyKeyPin(ctx, conn, pinPath)
		if rerr != nil {
			return "", false, fmt.Errorf("store.EstablishOrgPolicyKeyPin: re-read after lost insert: %w", rerr)
		}
		if !hasRaced {
			return "", false, errors.New("store.EstablishOrgPolicyKeyPin: insert affected no rows and no pin exists")
		}
		return raced, false, nil
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return "", false, fmt.Errorf("store.EstablishOrgPolicyKeyPin: commit: %w", err)
	}
	committed = true
	return keyHash, true, nil
}

// LoadOrgPolicyKeyPin returns the established org policy signing-key pin
// for pinPath, or ok=false when none has ever been recorded. A plain
// (unfenced) read for the fast path and for reporting; the authoritative,
// race-safe establish-or-report is EstablishOrgPolicyKeyPin.
func (s *Store) LoadOrgPolicyKeyPin(ctx context.Context, pinPath string) (string, bool, error) {
	hash, ok, err := readOrgPolicyKeyPin(ctx, s.db, pinPath)
	if err != nil {
		return "", false, fmt.Errorf("store.LoadOrgPolicyKeyPin: %w", err)
	}
	return hash, ok, nil
}

// readOrgPolicyKeyPin reads the effective pin hash for (layer="org",
// pinPath) — the newest row, matching LatestGuardPolicyStates' MAX(id)
// per (layer, path) semantics. Runs against either the pool or a pinned
// connection inside a transaction.
func readOrgPolicyKeyPin(ctx context.Context, q querier, pinPath string) (string, bool, error) {
	var hash string
	err := q.QueryRowContext(ctx, `
		SELECT content_hash FROM guard_policy_state
		WHERE layer = 'org' AND path = ? ORDER BY id DESC LIMIT 1`, pinPath).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read key pin: %w", err)
	}
	return hash, true, nil
}

// --- CAS-fenced fetch and install (plan §6.10) ---

// PolicyResourceFence is the identity/floor/digest snapshot re-read inside
// the fenced transaction — the value fn (WithPolicyResourceFence's
// callback) must revalidate against the fetch context it captured before
// the transaction opened.
type PolicyResourceFence struct {
	// Generation is org_enrolment_generation.generation for the fence's
	// orgKey (0 when no generation row exists yet for this identity).
	Generation int64
	// Tombstoned mirrors org_enrolment_generation.tombstoned.
	Tombstoned bool
	// HasState reports whether a org_policy_resource_state row already
	// exists for (orgKey, family). When false, FloorVersion/MsgDigest are
	// the zero value (no prior floor to protect).
	HasState     bool
	FloorVersion int64
	MsgDigest    string
}

// PolicyResourceCommit is the new durable state fn asks
// WithPolicyResourceFence to write, still inside the same transaction that
// produced the PolicyResourceFence it was handed.
type PolicyResourceCommit struct {
	Generation   int64
	FloorVersion int64
	LastVersion  int64
	BodyHash     string
	MsgDigest    string
}

// ErrPolicyResourceFenceStale is returned by WithPolicyResourceFence's CAS
// upsert when the predicate matched zero rows — i.e. the fence changed
// between fn's revalidation and the upsert. Contract-internal race guard:
// under BEGIN IMMEDIATE's exclusive write lock this only fires if fn
// computed its commit against a stale snapshot, which is itself the bug
// the predicate exists to catch (defense in depth, plan §6.10 / R6-B1's
// mutation-proof requirement).
var ErrPolicyResourceFenceStale = errors.New("store: policy-resource fence changed during commit (concurrent generation/floor advance)")

// WithPolicyResourceFence runs fn inside ONE BEGIN IMMEDIATE transaction
// scoped to (orgKey, family) (plan §6.10 "CAS-fenced fetch and install"):
// it re-reads the durable (generation, tombstone, floor_version,
// msg_digest) and hands it to fn as the authoritative revalidation
// snapshot. fn should:
//
//  1. Compare the fence against the (org_key, generation) it captured when
//     the fetch/accept started, and re-run the downgrade + equal-floor
//     digest rules against fence.FloorVersion / fence.MsgDigest.
//  2. Perform any durable non-SQL I/O (the cache envelope fsync + rename)
//     WHILE this call is still running — that is the entire point of
//     holding the transaction open across the callback: no concurrent
//     commit can advance the generation or floor out from under the file
//     that is about to become the installable cache.
//  3. Return a non-nil *PolicyResourceCommit to durably record the new
//     state, or (nil, nil) to abort WITHOUT error (a legitimate reject —
//     e.g. version_replay, or the family not being accepted), or a
//     non-nil error to abort loudly (a local/IO failure).
//
// The CAS upsert predicate is redundant with BEGIN IMMEDIATE's exclusive
// write lock (nothing else can have changed the row underneath fn between
// the re-read and the upsert), but it is enforced anyway as a
// defense-in-depth self-check: if fn's commit disagrees with the fence it
// was just handed, the upsert affects zero rows and this returns
// ErrPolicyResourceFenceStale rather than silently clobbering with the
// wrong generation/floor.
func (s *Store) WithPolicyResourceFence(
	ctx context.Context, orgKey, family string,
	fn func(ctx context.Context, fence PolicyResourceFence) (*PolicyResourceCommit, error),
) error {
	if orgKey == "" || family == "" {
		return errors.New("store.WithPolicyResourceFence: orgKey and family required")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("store.WithPolicyResourceFence: conn: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `PRAGMA busy_timeout = 30000`); err != nil {
		return fmt.Errorf("store.WithPolicyResourceFence: busy_timeout: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("store.WithPolicyResourceFence: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), `ROLLBACK`)
		}
	}()

	fence, err := readPolicyResourceFence(ctx, conn, orgKey, family)
	if err != nil {
		return fmt.Errorf("store.WithPolicyResourceFence: %w", err)
	}

	commit, err := fn(ctx, fence)
	if err != nil {
		return err
	}
	if commit == nil {
		return nil // legitimate reject — rolled back via defer, no error
	}

	if err := casUpsertPolicyResourceState(ctx, conn, orgKey, family, fence, *commit); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("store.WithPolicyResourceFence: commit: %w", err)
	}
	committed = true
	return nil
}

func readPolicyResourceFence(ctx context.Context, conn *sql.Conn, orgKey, family string) (PolicyResourceFence, error) {
	var fence PolicyResourceFence
	var tb int
	genErr := conn.QueryRowContext(ctx, `
		SELECT generation, tombstoned FROM org_enrolment_generation WHERE org_key = ?`, orgKey).
		Scan(&fence.Generation, &tb)
	switch {
	case errors.Is(genErr, sql.ErrNoRows):
		// No enrolment-generation row yet: generation 0, not tombstoned.
		// A caller whose captured generation is nonzero against this
		// contractually cannot match, so it aborts via its own identity
		// check — that is a caller-contract violation, not a race this
		// function needs to special-case.
	case genErr != nil:
		return PolicyResourceFence{}, fmt.Errorf("read generation: %w", genErr)
	default:
		fence.Tombstoned = tb != 0
	}

	var floor int64
	var digest string
	stateErr := conn.QueryRowContext(ctx, `
		SELECT floor_version, msg_digest FROM org_policy_resource_state WHERE org_key = ? AND family = ?`,
		orgKey, family).Scan(&floor, &digest)
	switch {
	case errors.Is(stateErr, sql.ErrNoRows):
		// no state row yet — zero floor, no digest, HasState=false.
	case stateErr != nil:
		return PolicyResourceFence{}, fmt.Errorf("read state: %w", stateErr)
	default:
		fence.HasState = true
		fence.FloorVersion = floor
		fence.MsgDigest = digest
	}
	return fence, nil
}

func casUpsertPolicyResourceState(ctx context.Context, conn *sql.Conn, orgKey, family string, fence PolicyResourceFence, commit PolicyResourceCommit) error {
	now := timestamp(time.Time{})
	if !fence.HasState {
		res, err := conn.ExecContext(ctx, `
			INSERT INTO org_policy_resource_state
			  (org_key, family, generation, floor_version, last_version, body_hash, msg_digest, updated_at)
			SELECT ?, ?, ?, ?, ?, ?, ?, ?
			WHERE NOT EXISTS (SELECT 1 FROM org_policy_resource_state WHERE org_key = ? AND family = ?)`,
			orgKey, family, commit.Generation, commit.FloorVersion, commit.LastVersion, commit.BodyHash, commit.MsgDigest, now,
			orgKey, family)
		if err != nil {
			return fmt.Errorf("store.WithPolicyResourceFence: insert state: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrPolicyResourceFenceStale
		}
		return nil
	}
	res, err := conn.ExecContext(ctx, `
		UPDATE org_policy_resource_state
		SET generation = ?, floor_version = ?, last_version = ?, body_hash = ?, msg_digest = ?, updated_at = ?
		WHERE org_key = ? AND family = ? AND generation = ? AND floor_version = ? AND msg_digest = ?`,
		commit.Generation, commit.FloorVersion, commit.LastVersion, commit.BodyHash, commit.MsgDigest, now,
		orgKey, family, fence.Generation, fence.FloorVersion, fence.MsgDigest)
	if err != nil {
		return fmt.Errorf("store.WithPolicyResourceFence: update state: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrPolicyResourceFenceStale
	}
	return nil
}
