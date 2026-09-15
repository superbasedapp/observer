package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/aggregate"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// structuralinsights.go is the store seam for the STRUCTURAL-INSIGHTS rail
// (divergence-remediation plan rev 4.1 §2 R1 + §3 W2 "Node half" / "Revision
// model"; migration 098). It owns two halves:
//
//   - the WINDOW AGGREGATE READ (LoadStructuralDayFacts): bounded, content-free
//     per-day facts over PERSONAL-eligible sessions only; and
//   - the WINDOW PERSISTENCE (AllocateStructuralRevision /
//     EnqueueStructuralOutbox / ListSendableStructuralOutbox /
//     PrepareStructuralSend): revision allocation, the stored-bytes outbox row,
//     and the send preparation that replays those exact bytes.
//
// Dependency discipline matches cloudlocal.go: this seam does NOT import
// internal/cloudcontract or internal/cloudevidence. The snapshot bytes and
// their digest are produced by the PURE builder and handed in through a small
// injected func (StructuralPayloadBuild) — the same shape as cloudlocal.go's
// EnvelopeRebuild seam. It never imports the network lane (cloudclient /
// cloudpop / cloudcred); the zero-egress invariant
// (tests/invariant/cloud_egress_test.go) pins that.
//
// NODE-LOCAL: cloud_structural_windows never enters the org-push wire. Its name
// is in the forbidden-table denylist walked by tests/invariant/privacy_test.go.

// -- Authority filtering -----------------------------------------------------

// personalEligibleAuthority is the ONE authority value whose sessions may feed
// the personal cloud plane. It is derived from the pure dataauthority contract
// rather than hardcoded as a literal, and TestStructuralAuthorityFilterMatchesContract
// pins it against Classification.EligibleForPersonalEnrichment so the SQL
// filter and the contract can never drift.
//
// The filter lives IN the aggregate SQL (plan review finding 10): an org or
// unknown-authority session's actions, tokens, and cost never enter the sums in
// the first place, rather than being subtracted afterwards. A NULL authority
// (a pre-096 legacy row, or a capture whose live enrolment state could not be
// determined) is UNKNOWN and fails the equality test — fail closed.
var personalEligibleAuthority = string(dataauthority.AuthorityPersonal)

// -- Window aggregate read ---------------------------------------------------

// StructuralMixCount is one categorical count in a window's mix. Key is a RAW
// local value (a tool identifier, a coarse model family); the PURE builder
// normalizes and bounds it before it can reach the wire — the store never
// imports the contract package.
type StructuralMixCount struct {
	Key   string
	Count int
}

// StructuralDayFacts is the bounded, content-free DTO one window aggregates to.
// It carries counts, sums, categorical mixes, coverage numerators, and a
// watermark — no paths, no commands, no excerpts, no session identity.
type StructuralDayFacts struct {
	// SessionCount is how many PERSONAL-eligible sessions started in the window.
	SessionCount int
	// ActionCount is how many actions those sessions recorded (all of them, not
	// only the ones timestamped inside the window — see the membership rule on
	// LoadStructuralDayFacts).
	ActionCount int
	// ToolMix is sessions-per-tool. Unsorted; the builder sorts.
	ToolMix []StructuralMixCount
	// ModelFamilyMix is sessions-per-coarse-model-family, folded through
	// internal/aggregate.Family so a raw model string never leaves this seam.
	ModelFamilyMix []StructuralMixCount
	// TokensIn / TokensOut / CacheReadTokens are the summed token_usage columns.
	TokensIn        int
	TokensOut       int
	CacheReadTokens int
	// CostUSD is the summed token_usage.estimated_cost_usd. NOTE the column
	// name: token_usage has no `cost_usd` column — the estimate is the only
	// cost this table carries, and it is what every other node cost surface
	// sums too.
	CostUSD float64
	// SessionsWithOutcomes / SessionsWithVerification are the coverage
	// numerators. See the COVERAGE-NUMERATOR DEFINITIONS block below for what
	// each one counts and, just as importantly, what it does NOT.
	SessionsWithOutcomes     int
	SessionsWithVerification int
	// SourceWatermark is the maximum local event time INCLUDED in these facts:
	// the max over the window's session starts, their actions' timestamps, and
	// their token_usage timestamps. It may fall past the window's end (a
	// session that started inside the window and ran on past it) — that is
	// correct, it states what was included rather than what the window spans.
	// Zero when the window is empty.
	SourceWatermark time.Time
}

// COVERAGE-NUMERATOR DEFINITIONS. These are DEFINITIONAL CHOICES, made
// deliberately narrow and honest rather than impressive, because the bands
// built from them exist to say how thinly a window's aggregates are evidenced.
//
// SessionsWithVerification counts sessions with at least one action of type
// `run_command` — the agent invoked something outside itself whose exit status
// the harness recorded. It is an UPPER BOUND on "the work was checked": an `ls`
// counts. It deliberately does NOT inspect actions.target for test-shaped
// command strings. That would be unreliable (every project spells its test
// command differently, and `make` / `just` / a script name hide it entirely)
// AND it would drag command CONTENT into an aggregation whose whole point is
// to carry none.
//
// SessionsWithOutcomes counts sessions for which some evidence of HOW the work
// went was actually recorded — either
//
//	(a) the developer scored the session (session_annotations.rating > 0), or
//	(b) at least one action was recorded as FAILED (actions.success = 0).
//
// The asymmetry in (b) is not an oversight. actions.success is `INTEGER
// DEFAULT 1`, so a 1 means "nothing said otherwise", not "a success was
// observed" — it is the absence of evidence, and counting it would inflate the
// band to ~100% for every window. An explicitly recorded 0 IS evidence. The
// consequence is honest and intended: a clean, unrated day reports
// outcome-evidence band "none", which is a true statement about what the node
// knows, not a claim that nothing went well.

// structuralWindowCTE selects the window's PERSONAL-eligible session set. It is
// the single membership rule every aggregate below shares.
//
// MEMBERSHIP RULE (period-rule version 1): a session belongs to the window its
// START falls in, and every action / token row of that session belongs with it.
// The alternative — bucketing each action by its own timestamp — would split
// one session across two windows and make the per-session mixes and coverage
// numerators unattributable. A session that runs past midnight therefore lands
// wholly in the window it began in, and a session whose late data arrives after
// its window was snapshotted is picked up by re-snapshotting that window as
// revision N+1, which is precisely what the revision model is for.
//
// TIME COMPARISON: stamps are stored as RFC3339Nano UTC TEXT with a VARIABLE
// number of fractional digits, so a naive lexicographic compare against a
// boundary is wrong — '.' (0x2E) sorts BEFORE 'Z' (0x5A), so
// "…T00:00:00.5Z" < "…T00:00:00Z" and a sub-second event at the boundary
// second would fall on the wrong side. Comparing the first 19 characters
// ("YYYY-MM-DDTHH:MM:SS") removes the fractional part from both sides, and
// that fixed-width prefix does sort correctly. Boundaries are whole seconds
// (day starts), so the half-open [start, end) semantics are exact.
const structuralWindowCTE = `
WITH win AS (
    SELECT s.id                                    AS sid,
           COALESCE(NULLIF(s.tool, ''), 'unknown') AS tool,
           COALESCE(s.model, '')                   AS model,
           s.started_at                            AS started_at
      FROM sessions s
     WHERE s.authority = ?
       AND substr(s.started_at, 1, 19) >= ?
       AND substr(s.started_at, 1, 19) <  ?
)`

// structuralBoundLayout is the fixed-width prefix both the stored stamps and
// the window boundaries are compared on. See structuralWindowCTE.
const structuralBoundLayout = "2006-01-02T15:04:05"

// LoadStructuralDayFacts aggregates one window into a bounded, content-free
// DTO. dayStartRFC3339 / dayEndRFC3339 are the window's UTC boundaries
// (half-open: start inclusive, end exclusive) — the caller resolves them from
// the account's DECLARED timezone, so this seam never guesses a zone.
//
// Only PERSONAL-eligible sessions contribute (see personalEligibleAuthority);
// org and unknown-authority sessions are excluded IN the SQL, so their actions,
// tokens, and cost can never reach a sum.
func (s *Store) LoadStructuralDayFacts(ctx context.Context, dayStartRFC3339, dayEndRFC3339 string) (StructuralDayFacts, error) {
	start, err := structuralBound("dayStartRFC3339", dayStartRFC3339)
	if err != nil {
		return StructuralDayFacts{}, err
	}
	end, err := structuralBound("dayEndRFC3339", dayEndRFC3339)
	if err != nil {
		return StructuralDayFacts{}, err
	}
	if end <= start {
		return StructuralDayFacts{}, fmt.Errorf("store.LoadStructuralDayFacts: window end %q is not after start %q", dayEndRFC3339, dayStartRFC3339)
	}
	args := []any{personalEligibleAuthority, start, end}

	var facts StructuralDayFacts

	// Session count.
	if err := s.db.QueryRowContext(ctx, structuralWindowCTE+`
		SELECT COUNT(*) FROM win`, args...).Scan(&facts.SessionCount); err != nil {
		return StructuralDayFacts{}, fmt.Errorf("store.LoadStructuralDayFacts: session count: %w", err)
	}
	if facts.SessionCount == 0 {
		// Nothing in the window: every other aggregate is definitionally zero
		// and the watermark is the zero time. Short-circuit rather than run
		// five more queries that can only return zeros.
		return facts, nil
	}

	// Action count.
	if err := s.db.QueryRowContext(ctx, structuralWindowCTE+`
		SELECT COUNT(*)
		  FROM actions a JOIN win ON win.sid = a.session_id`, args...).Scan(&facts.ActionCount); err != nil {
		return StructuralDayFacts{}, fmt.Errorf("store.LoadStructuralDayFacts: action count: %w", err)
	}

	// Tool mix: sessions per tool.
	toolMix, err := s.structuralMix(ctx, structuralWindowCTE+`
		SELECT tool, COUNT(*) FROM win GROUP BY tool`, args)
	if err != nil {
		return StructuralDayFacts{}, fmt.Errorf("store.LoadStructuralDayFacts: tool mix: %w", err)
	}
	facts.ToolMix = toolMix

	// Model-family mix: sessions per RAW model, folded to the closed family
	// vocabulary here so a raw model string never leaves this seam.
	rawModelMix, err := s.structuralMix(ctx, structuralWindowCTE+`
		SELECT model, COUNT(*) FROM win GROUP BY model`, args)
	if err != nil {
		return StructuralDayFacts{}, fmt.Errorf("store.LoadStructuralDayFacts: model mix: %w", err)
	}
	byFamily := map[string]int{}
	for _, m := range rawModelMix {
		byFamily[aggregate.Family(m.Key)] += m.Count
	}
	for fam, n := range byFamily {
		facts.ModelFamilyMix = append(facts.ModelFamilyMix, StructuralMixCount{Key: fam, Count: n})
	}

	// Token + cost sums. COALESCE every aggregate: the columns are nullable and
	// a window with no token rows must sum to 0, never NULL.
	if err := s.db.QueryRowContext(ctx, structuralWindowCTE+`
		SELECT COALESCE(SUM(t.input_tokens), 0),
		       COALESCE(SUM(t.output_tokens), 0),
		       COALESCE(SUM(t.cache_read_tokens), 0),
		       COALESCE(SUM(t.estimated_cost_usd), 0)
		  FROM token_usage t JOIN win ON win.sid = t.session_id`, args...).
		Scan(&facts.TokensIn, &facts.TokensOut, &facts.CacheReadTokens, &facts.CostUSD); err != nil {
		return StructuralDayFacts{}, fmt.Errorf("store.LoadStructuralDayFacts: token sums: %w", err)
	}

	// Coverage numerators — see structuralCoverageDefinitions.
	if err := s.db.QueryRowContext(ctx, structuralWindowCTE+`
		SELECT COUNT(DISTINCT a.session_id)
		  FROM actions a JOIN win ON win.sid = a.session_id
		 WHERE a.action_type = 'run_command'`, args...).Scan(&facts.SessionsWithVerification); err != nil {
		return StructuralDayFacts{}, fmt.Errorf("store.LoadStructuralDayFacts: verification coverage: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, structuralWindowCTE+`
		SELECT COUNT(*) FROM win
		 WHERE EXISTS (SELECT 1 FROM session_annotations an
		                WHERE an.session_id = win.sid AND an.rating > 0)
		    OR EXISTS (SELECT 1 FROM actions a
		                WHERE a.session_id = win.sid AND a.success = 0)`, args...).
		Scan(&facts.SessionsWithOutcomes); err != nil {
		return StructuralDayFacts{}, fmt.Errorf("store.LoadStructuralDayFacts: outcome coverage: %w", err)
	}

	// Watermark: the max event time actually included.
	var wmSession, wmAction, wmToken sql.NullString
	if err := s.db.QueryRowContext(ctx, structuralWindowCTE+`
		SELECT (SELECT MAX(started_at) FROM win),
		       (SELECT MAX(a.timestamp) FROM actions a JOIN win ON win.sid = a.session_id),
		       (SELECT MAX(t.timestamp) FROM token_usage t JOIN win ON win.sid = t.session_id)`, args...).
		Scan(&wmSession, &wmAction, &wmToken); err != nil {
		return StructuralDayFacts{}, fmt.Errorf("store.LoadStructuralDayFacts: watermark: %w", err)
	}
	for _, v := range []sql.NullString{wmSession, wmAction, wmToken} {
		if !v.Valid {
			continue
		}
		if t := cloudParseTime(v.String); t.After(facts.SourceWatermark) {
			facts.SourceWatermark = t
		}
	}

	return facts, nil
}

// structuralMix runs a two-column (key, count) aggregate.
func (s *Store) structuralMix(ctx context.Context, query string, args []any) ([]StructuralMixCount, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []StructuralMixCount
	for rows.Next() {
		var m StructuralMixCount
		if err := rows.Scan(&m.Key, &m.Count); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// structuralBound parses an RFC3339 window boundary and renders the fixed-width
// prefix the SQL compares on. A boundary that does not parse is an error rather
// than a silently-wrong comparison.
func structuralBound(field, raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("store.LoadStructuralDayFacts: %s is empty", field)
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return "", fmt.Errorf("store.LoadStructuralDayFacts: %s %q is not RFC3339: %w", field, raw, err)
	}
	return t.UTC().Format(structuralBoundLayout), nil
}

// -- Structural outbox persistence -------------------------------------------

// CloudOutboxKind discriminates the outbox payload shapes (migration 098).
type CloudOutboxKind string

const (
	// CloudOutboxKindSessionEvidence is the 097 shape: NO body is stored, the
	// envelope is rebuilt at send from the live session.
	CloudOutboxKindSessionEvidence CloudOutboxKind = "session_evidence"
	// CloudOutboxKindStructuralInsights is the W2 shape: the exact canonical
	// snapshot bytes ARE stored and are resent verbatim, never re-aggregated.
	CloudOutboxKindStructuralInsights CloudOutboxKind = "structural_insights"
)

// CloudGrantMode is the consent-receipt grant mode (R1, migration 098).
type CloudGrantMode string

const (
	// CloudGrantPerUpload is the 097 semantics: the receipt binds ONE exact
	// upload's digest.
	CloudGrantPerUpload CloudGrantMode = "per_upload"
	// CloudGrantStanding authorizes a SCHEMA rather than a byte-string. Every
	// individual upload still gets its own digest, its own local row, and a
	// pre-send revocation check.
	CloudGrantStanding CloudGrantMode = "standing"
)

// cloudPurposeStructuralInsights mirrors
// cloudcontract.PurposeStructuralInsights. It is duplicated as a string
// constant rather than imported because this seam deliberately does not depend
// on the contract package (see the file header); the receipt's purpose column
// has always been a plain string here. TestStructuralPurposeConstantMatchesContract
// in tests/invariant pins the two together.
const cloudPurposeStructuralInsights = "structural_activity_insights"

// Sentinel errors specific to the structural rail.
var (
	// ErrCloudGrantNotStanding is returned when a structural enqueue or send
	// names a receipt that is not a STANDING grant. A per-upload receipt binds
	// one byte-string and cannot authorize a rail of snapshots.
	ErrCloudGrantNotStanding = errors.New("store: consent receipt is not a standing grant")
	// ErrCloudPurposeMismatch is returned when the bound receipt's purpose is
	// not the one the operation requires.
	ErrCloudPurposeMismatch = errors.New("store: consent receipt purpose does not authorize this operation")
	// ErrStructuralRevisionTaken is returned when the window's revision was
	// claimed concurrently. The caller re-enqueues, which allocates the next
	// revision. It can only surface if a future path bypasses the in-transaction
	// allocation below; the UNIQUE constraint is the backstop.
	ErrStructuralRevisionTaken = errors.New("store: structural window revision already allocated")
	// ErrCloudOutboxKindMismatch is returned when an outbox operation is asked
	// to act on a row of the wrong kind (e.g. preparing a structural row
	// through the session-evidence rebuild path).
	ErrCloudOutboxKindMismatch = errors.New("store: cloud outbox item is of a different kind")
	// ErrCloudPayloadKindForbidden is returned by the Go guard when a write
	// would attach payload bytes to a non-structural outbox row. Migration
	// 098's triggers enforce the same rule at the storage layer, for every
	// writer including raw SQL; this error exists so the seam fails with a
	// typed error instead of a constraint surprise.
	ErrCloudPayloadKindForbidden = errors.New("store: payload bytes are permitted only on structural_insights outbox items")
	// ErrCloudGrantGenerationDrift is returned when the standing grant's
	// consent generation or data-dictionary digest moved after a snapshot was
	// queued. The queued bytes were built under terms that no longer hold, so
	// the item requires reconfirmation rather than being sent.
	ErrCloudGrantGenerationDrift = errors.New("store: standing grant terms changed after the snapshot was queued")
	// ErrCloudGrantExpired is returned when the bound standing receipt's
	// review_at has passed. A lapsed grant is not a live authorization: the
	// developer agreed to revisit it by that date, and sending past it would
	// make the review date decorative.
	ErrCloudGrantExpired = errors.New("store: the standing grant's review date has passed")
	// ErrCloudStructuralSendUnauthorized is returned by
	// VerifyStructuralSendAuthorization when authorization changed after prepare
	// and before dispatch (receipt revoked or expired, terms drift, endpoint
	// drift, or the row cancelled out from under the send). The item is moved out
	// of `sending` and the transport aborts without a request.
	ErrCloudStructuralSendUnauthorized = errors.New("store: structural send authorization changed before dispatch")
)

// StructuralWindowKey identifies one snapshot window. Device identity is
// implicit — this is a single-node database.
type StructuralWindowKey struct {
	// Period is the "YYYY-MM-DD" calendar day in the account's declared zone.
	Period string
	// PeriodRuleVersion versions the activity→period mapping rule.
	PeriodRuleVersion int
	// SchemaVersion is the snapshot schema the bytes were built against.
	SchemaVersion string
}

// StructuralPayloadBuild produces the canonical snapshot bytes and their digest
// for a just-allocated revision. It is the injected seam that lets the store
// persist bytes the PURE builder produced without importing the builder — the
// same discipline as cloudlocal.go's EnvelopeRebuild.
//
// It is called INSIDE the enqueue transaction, immediately after the revision
// is allocated, because the revision is part of the bytes: the snapshot cannot
// be built before its revision is known, and the revision is not durable until
// the same transaction commits. It must therefore be PURE and fast — marshal
// and hash, nothing more. It must not touch the store (a nested write would
// deadlock against the transaction's own write lock) and must not do I/O.
type StructuralPayloadBuild func(revision int) (payloadBytes []byte, digest string, err error)

// StructuralWindowRow is one stored snapshot window row.
type StructuralWindowRow struct {
	Key       StructuralWindowKey
	Revision  int
	OutboxID  string
	Digest    string
	CreatedAt time.Time
}

// AllocateStructuralRevision reports the revision the NEXT snapshot of this
// window will receive (current max + 1, so 1 for a never-snapshotted window).
//
// It is an INSPECTION/preview read — a CLI that wants to say "this will be
// revision 3" calls it. It is NOT the authoritative allocation: a number
// returned here is not reserved, because reserving it would require writing a
// row this call has no bytes for. The authoritative allocation happens inside
// EnqueueStructuralOutbox's transaction, which reads the same max and inserts
// max+1 under the write lock it already holds.
//
// It runs in an explicit transaction so the read is taken under a consistent
// snapshot. Note precisely what that does and does not buy: the DSN's
// `_txlock=immediate` makes BeginTx acquire SQLite's write lock at BEGIN, so
// two concurrent calls serialize — but each releases the lock at commit, so two
// callers that both preview before either enqueues will legitimately see the
// same number. That is exactly why the enqueue re-reads inside its own
// transaction and why the UNIQUE(period, period_rule_version, schema_version,
// revision) constraint exists.
func (s *Store) AllocateStructuralRevision(ctx context.Context, key StructuralWindowKey) (int, error) {
	if err := key.validate(); err != nil {
		return 0, fmt.Errorf("store.AllocateStructuralRevision: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.AllocateStructuralRevision: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	next, err := nextStructuralRevisionTx(ctx, tx, key)
	if err != nil {
		return 0, fmt.Errorf("store.AllocateStructuralRevision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.AllocateStructuralRevision: %w", err)
	}
	return next, nil
}

// nextStructuralRevisionTx reads the window's current max revision through tx
// and returns max+1. Under `_txlock=immediate` the caller's transaction already
// holds the write lock, so this read cannot interleave with another
// transaction's allocation for the same window.
func nextStructuralRevisionTx(ctx context.Context, tx *sql.Tx, key StructuralWindowKey) (int, error) {
	var maxRev int
	err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(revision), 0)
		  FROM cloud_structural_windows
		 WHERE period = ? AND period_rule_version = ? AND schema_version = ?`,
		key.Period, key.PeriodRuleVersion, key.SchemaVersion).Scan(&maxRev)
	if err != nil {
		return 0, err
	}
	return maxRev + 1, nil
}

// validate checks a window key's required fields.
func (k StructuralWindowKey) validate() error {
	if k.Period == "" {
		return errors.New("period is required")
	}
	if k.PeriodRuleVersion < 1 {
		return fmt.Errorf("period_rule_version %d is not positive", k.PeriodRuleVersion)
	}
	if k.SchemaVersion == "" {
		return errors.New("schema_version is required")
	}
	return nil
}

// structuralGrantBinding is the grant state a queued snapshot was built under,
// recorded on the outbox row so a pre-send check can detect that the standing
// grant's terms moved. It rides in the existing feature_set_json column — a
// content-free JSON metadata column the row already had — so no schema column
// was added for it.
type structuralGrantBinding struct {
	ConsentGeneration    int    `json:"consent_generation"`
	DataDictionaryDigest string `json:"data_dictionary_digest"`
}

// EnqueueStructuralOutbox atomically allocates the window's next revision,
// builds the snapshot bytes for that revision, and stores BOTH the outbox row
// (kind='structural_insights', with the bytes) and the window row — in ONE
// transaction.
//
// Storing the bytes is the deliberate, named exception to "the outbox stores no
// content" (migration 098's header states the full argument). It is what makes
// a resend immune to late, backfilled, or pruned source rows: PrepareStructuralSend
// replays these exact bytes and NEVER re-aggregates.
//
// receiptID must name a LIVE STANDING grant for the structural-insights
// purpose; a missing receipt, an invalidated one, a per-upload grant, or a
// different purpose are all typed refusals. Note what is deliberately NOT
// checked here: the session-eligibility gate EnqueueCloudOutbox applies. A
// window has no single session — the personal-eligibility filter for this rail
// lives in LoadStructuralDayFacts' SQL, where org and unknown sessions are
// excluded before they can reach a sum.
//
// It returns the minted outbox id and the revision that was allocated.
func (s *Store) EnqueueStructuralOutbox(ctx context.Context, key StructuralWindowKey, receiptID string, build StructuralPayloadBuild) (outboxID string, revision int, err error) {
	const pfx = "store.EnqueueStructuralOutbox"
	if err := key.validate(); err != nil {
		return "", 0, fmt.Errorf("%s: %w", pfx, err)
	}
	if receiptID == "" {
		return "", 0, fmt.Errorf("%s: receipt id is required", pfx)
	}
	if build == nil {
		return "", 0, fmt.Errorf("%s: build func is required", pfx)
	}
	id, err := cloudRandomID("struct_")
	if err != nil {
		return "", 0, fmt.Errorf("%s: %w", pfx, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, fmt.Errorf("%s: %w", pfx, err)
	}
	defer func() { _ = tx.Rollback() }()

	// The standing-grant gate, re-read inside the transaction so a concurrent
	// revocation cannot slip between the check and the insert.
	grantState, err := standingGrantStateTx(ctx, tx, receiptID, time.Now().UTC())
	if err != nil {
		return "", 0, fmt.Errorf("%s: %w", pfx, err)
	}
	bindingJSON, err := marshalStructuralBinding(grantState.binding)
	if err != nil {
		return "", 0, fmt.Errorf("%s: %w", pfx, err)
	}

	// Allocate the revision under the write lock this transaction already
	// holds, then build the bytes FOR that revision — the revision is part of
	// what is digested, so it cannot be chosen afterwards.
	rev, err := nextStructuralRevisionTx(ctx, tx, key)
	if err != nil {
		return "", 0, fmt.Errorf("%s: allocate revision: %w", pfx, err)
	}
	payload, digest, err := build(rev)
	if err != nil {
		return "", 0, fmt.Errorf("%s: build snapshot: %w", pfx, err)
	}
	if len(payload) == 0 {
		return "", 0, fmt.Errorf("%s: build produced no bytes", pfx)
	}
	if digest == "" {
		return "", 0, fmt.Errorf("%s: build produced no digest", pfx)
	}
	if err := validateOutboxPayloadKind(CloudOutboxKindStructuralInsights, payload); err != nil {
		return "", 0, fmt.Errorf("%s: %w", pfx, err)
	}

	now := time.Now().UTC()
	// Both digest columns carry the ONE structural digest. The session-evidence
	// shape needs two because it is rebuilt at send (a content digest stable
	// across framing, plus a digest over the final bytes); a structural
	// snapshot is serialized once and its exact bytes are stored, so a separate
	// framing digest would be a second name for the same guarantee. The value
	// written here is the digest the SERVER recomputes from the received bytes.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cloud_outbox
		  (id, session_id, feature_set_json, evidence_content_digest, upload_digest,
		   receipt_id, state, retry_count, last_error, created_at, updated_at,
		   kind, payload_bytes)
		VALUES (?, '', ?, ?, ?, ?, ?, 0, '', ?, ?, ?, ?)`,
		id, bindingJSON, digest, digest, receiptID, string(CloudOutboxPending),
		cloudFormatTime(now), cloudFormatTime(now),
		string(CloudOutboxKindStructuralInsights), payload); err != nil {
		return "", 0, fmt.Errorf("%s: insert outbox: %w", pfx, err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cloud_structural_windows
		  (period, period_rule_version, schema_version, revision, outbox_id, digest, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		key.Period, key.PeriodRuleVersion, key.SchemaVersion, rev, id, digest,
		cloudFormatTime(now)); err != nil {
		if isUniqueConstraintErr(err) {
			return "", 0, fmt.Errorf("%s: %w: period %q rule %d revision %d",
				pfx, ErrStructuralRevisionTaken, key.Period, key.PeriodRuleVersion, rev)
		}
		return "", 0, fmt.Errorf("%s: insert window: %w", pfx, err)
	}

	if err := tx.Commit(); err != nil {
		return "", 0, fmt.Errorf("%s: %w", pfx, err)
	}
	return id, rev, nil
}

// standingReceiptState is the live standing-grant state a structural enqueue or
// send validates against. Only `binding` participates in the drift comparison
// (it is what the queued row recorded); the rest are terms the send path needs
// in order to declare, on the wire, exactly what THIS item was validated
// against.
type standingReceiptState struct {
	binding          structuralGrantBinding
	endpoint         string
	sourceWindowRule string
}

// standingGrantStateTx loads a receipt through tx and enforces the standing-
// grant gate: it must exist, be live, be UNEXPIRED, be a standing grant, and
// carry the structural-insights purpose.
//
// EXPIRY is enforced here, not only in the gateway. The gateway owns the clock
// for "does any grant authorize this lane at all"; this seam owns "does the
// receipt THIS item is bound to still authorize it". Without the check a queued
// snapshot bound to a receipt whose review date has passed would still prepare
// and send — the grant would have lapsed and the bytes would go anyway. An
// expired receipt is treated as not-live, so the item is parked for
// reconfirmation rather than sent.
func standingGrantStateTx(ctx context.Context, tx *sql.Tx, receiptID string, now time.Time) (standingReceiptState, error) {
	var (
		invalidatedAt sql.NullString
		reviewAt      sql.NullString
		purpose       string
		grantMode     string
		state         standingReceiptState
	)
	err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(invalidated_at, ''), purpose, grant_mode,
		       consent_generation, data_dictionary_digest,
		       endpoint, source_window_rule, review_at
		  FROM cloud_consent_receipts WHERE id = ?`, receiptID).
		Scan(&invalidatedAt, &purpose, &grantMode,
			&state.binding.ConsentGeneration, &state.binding.DataDictionaryDigest,
			&state.endpoint, &state.sourceWindowRule, &reviewAt)
	if errors.Is(err, sql.ErrNoRows) {
		return standingReceiptState{}, ErrCloudReceiptNotFound
	}
	if err != nil {
		return standingReceiptState{}, err
	}
	if invalidatedAt.Valid && invalidatedAt.String != "" {
		return standingReceiptState{}, fmt.Errorf("%w: receipt is invalidated", ErrCloudReconfirmationRequired)
	}
	if reviewAt.Valid && reviewAt.String != "" {
		if t := cloudParseTime(reviewAt.String); !t.IsZero() && !t.After(now) {
			return standingReceiptState{}, fmt.Errorf("%w: %w (review date %s has passed)",
				ErrCloudReconfirmationRequired, ErrCloudGrantExpired, t.UTC().Format(time.RFC3339))
		}
	}
	if CloudGrantMode(grantMode) != CloudGrantStanding {
		return standingReceiptState{}, fmt.Errorf("%w: grant_mode %q", ErrCloudGrantNotStanding, grantMode)
	}
	if purpose != cloudPurposeStructuralInsights {
		return standingReceiptState{}, fmt.Errorf("%w: purpose %q, want %q", ErrCloudPurposeMismatch, purpose, cloudPurposeStructuralInsights)
	}
	return state, nil
}

// ListSendableStructuralOutbox returns the structural snapshots awaiting a send
// attempt (pending / failed_retryable), in REVISION ORDER within each period —
// a window's revision 2 must never be sent before its revision 1, because
// currency is decided by revision number and an out-of-order arrival is stored
// already-superseded rather than replacing a newer row. Items awaiting
// reconfirmation or already terminal are deliberately excluded.
func (s *Store) ListSendableStructuralOutbox(ctx context.Context) ([]CloudOutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.id, o.kind, o.session_id, o.feature_set_json, o.evidence_content_digest, o.upload_digest,
		       o.receipt_id, o.state, o.retry_count, o.last_error, o.created_at, o.updated_at
		  FROM cloud_outbox o
		  LEFT JOIN cloud_structural_windows w ON w.outbox_id = o.id
		 WHERE o.kind = ? AND o.state IN (?, ?)
		 ORDER BY w.period ASC, w.revision ASC, o.created_at ASC, o.id ASC`,
		string(CloudOutboxKindStructuralInsights),
		string(CloudOutboxPending), string(CloudOutboxFailedRetryable))
	if err != nil {
		return nil, fmt.Errorf("store.ListSendableStructuralOutbox: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanCloudOutboxRows(rows, "store.ListSendableStructuralOutbox")
}

// PrepareStructuralSend is the structural rail's counterpart to
// PrepareCloudOutboxSend. The critical difference: it NEVER re-aggregates. It
// re-reads the STORED bytes — the exact bytes the digest was taken over at
// enqueue — so late, backfilled, or pruned source rows cannot change what a
// retry sends.
//
// It re-checks, in ONE immediate transaction (the DSN's `_txlock=immediate`
// holds the write lock from BEGIN, so nothing can change under it):
//
//   - the item exists, is a structural item, and is in a preparable state;
//   - the bound receipt is LIVE, STANDING, and for the structural purpose
//     (the pre-send revocation check R1 requires);
//   - the standing grant's consent generation and data-dictionary digest still
//     match what the snapshot was queued under (terms drift ⇒ reconfirmation,
//     never a silent send under changed terms);
//   - the send endpoint equals the endpoint the receipt bound (FD1);
//   - the stored digest still matches the stored bytes' recorded digest,
//
// then CASes pending/failed_retryable → sending. Any refusal moves the item to
// reconfirmation_required and returns a typed error; the digests are NEVER
// auto-updated and a mismatch is NEVER auto-sent.
func (s *Store) PrepareStructuralSend(ctx context.Context, id, sendEndpoint string) ([]byte, CloudSendLease, error) {
	const pfx = "store.PrepareStructuralSend"
	normSend := normalizeCloudEndpoint(sendEndpoint)
	if normSend == "" {
		return nil, CloudSendLease{}, fmt.Errorf("%s: send endpoint %q is not an absolute URL", pfx, sendEndpoint)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, CloudSendLease{}, fmt.Errorf("%s: %w", pfx, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var (
		kind        string
		state       string
		receiptID   string
		digest      string
		bindingJSON string
		payload     []byte
	)
	err = tx.QueryRowContext(ctx, `
		SELECT kind, state, receipt_id, upload_digest, feature_set_json, payload_bytes
		  FROM cloud_outbox WHERE id = ?`, id).
		Scan(&kind, &state, &receiptID, &digest, &bindingJSON, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, CloudSendLease{}, fmt.Errorf("%s: %w", pfx, ErrCloudOutboxNotFound)
	}
	if err != nil {
		return nil, CloudSendLease{}, fmt.Errorf("%s: %w", pfx, err)
	}
	if CloudOutboxKind(kind) != CloudOutboxKindStructuralInsights {
		return nil, CloudSendLease{}, fmt.Errorf("%s: %w: kind %q", pfx, ErrCloudOutboxKindMismatch, kind)
	}
	if CloudOutboxState(state) != CloudOutboxPending && CloudOutboxState(state) != CloudOutboxFailedRetryable {
		return nil, CloudSendLease{}, fmt.Errorf("%s: %w: state %q is not preparable", pfx, ErrIllegalCloudOutboxTransition, state)
	}
	if len(payload) == 0 {
		// A structural row with no stored bytes cannot be honestly resent (the
		// alternative — re-aggregating — is exactly what this path exists to
		// avoid), so it is a terminal-shaped refusal, not a retry.
		return nil, CloudSendLease{}, fmt.Errorf("%s: structural item %q has no stored payload bytes", pfx, id)
	}

	// The refusal path: park the item and report why. Every branch below uses
	// it, so a refusal can never leave the row preparable.
	refuse := func(reason string, cause error) ([]byte, CloudSendLease, error) {
		if _, uerr := tx.ExecContext(ctx, `
			UPDATE cloud_outbox
			   SET state = ?, last_error = ?, updated_at = ?
			 WHERE id = ? AND state IN (?, ?)`,
			string(CloudOutboxReconfirmationRequired), reason, cloudFormatTime(time.Now().UTC()), id,
			string(CloudOutboxPending), string(CloudOutboxFailedRetryable)); uerr != nil {
			return nil, CloudSendLease{}, fmt.Errorf("%s: park item: %w", pfx, uerr)
		}
		if cerr := tx.Commit(); cerr != nil {
			return nil, CloudSendLease{}, fmt.Errorf("%s: %w", pfx, cerr)
		}
		committed = true
		return nil, CloudSendLease{}, fmt.Errorf("%s: %w", pfx, cause)
	}

	// Receipt: live, UNEXPIRED, standing, right purpose (the pre-send revocation
	// check). The receipt read here is the one THIS item is bound to — never
	// "the newest grant for the purpose" — so the terms this send declares are
	// the terms it was actually validated against.
	grantState, gerr := standingGrantStateTx(ctx, tx, receiptID, time.Now().UTC())
	if gerr != nil {
		return refuse("grant_check_failed", gerr)
	}
	// Grant terms must be the ones the snapshot was built under.
	queued, perr := parseStructuralBinding(bindingJSON)
	if perr != nil {
		return refuse("grant_binding_unreadable", perr)
	}
	if queued != grantState.binding {
		return refuse("grant_generation_drift", ErrCloudGrantGenerationDrift)
	}

	// FD1: the send target must equal the endpoint the receipt bound.
	if normalizeCloudEndpoint(grantState.endpoint) != normSend {
		return refuse("endpoint_mismatch", fmt.Errorf("%w: bound %q, send %q", ErrCloudEndpointMismatch, grantState.endpoint, sendEndpoint))
	}

	// The window row's digest and the outbox row's digest must still agree —
	// the two were written in one transaction, so a divergence means someone
	// edited a row by hand.
	var windowDigest string
	switch err := tx.QueryRowContext(ctx,
		`SELECT digest FROM cloud_structural_windows WHERE outbox_id = ?`, id).Scan(&windowDigest); {
	case errors.Is(err, sql.ErrNoRows):
		return refuse("window_row_missing", ErrCloudReconfirmationRequired)
	case err != nil:
		return nil, CloudSendLease{}, fmt.Errorf("%s: %w", pfx, err)
	case windowDigest != digest:
		return refuse("digest_mismatch", ErrCloudReconfirmationRequired)
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE cloud_outbox SET state = ?, last_error = '', updated_at = ?
		 WHERE id = ? AND state IN (?, ?)`,
		string(CloudOutboxSending), cloudFormatTime(time.Now().UTC()), id,
		string(CloudOutboxPending), string(CloudOutboxFailedRetryable))
	if err != nil {
		return nil, CloudSendLease{}, fmt.Errorf("%s: %w", pfx, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, CloudSendLease{}, fmt.Errorf("%s: %w", pfx, err)
	}
	if n == 0 {
		return nil, CloudSendLease{}, fmt.Errorf("%s: %w: state changed under the CAS", pfx, ErrIllegalCloudOutboxTransition)
	}
	if err := tx.Commit(); err != nil {
		return nil, CloudSendLease{}, fmt.Errorf("%s: %w", pfx, err)
	}
	committed = true

	// Return a COPY of the stored bytes so a caller cannot mutate the slice the
	// scan handed back and believe it changed what is stored.
	out := make([]byte, len(payload))
	copy(out, payload)
	return out, CloudSendLease{
		OutboxID:     id,
		ReceiptID:    receiptID,
		SessionID:    "", // a window has no session
		UploadDigest: digest,
		Endpoint:     normSend,
		// The wire consent headers come from HERE — the receipt this item is
		// bound to, read under the transaction that just validated it.
		ConsentGeneration:    grantState.binding.ConsentGeneration,
		DataDictionaryDigest: grantState.binding.DataDictionaryDigest,
		SourceWindowRule:     grantState.sourceWindowRule,
	}, nil
}

// VerifyStructuralSendAuthorization is the structural rail's final pre-dispatch
// check — the counterpart to VerifyCloudSendAuthorization, and the hook the
// drain passes as PreAttempt so it runs immediately before EVERY physical POST
// and before every retry.
//
// It exists because the gateway's grant re-resolve happens once, BEFORE the
// callback. A `consent revoke` (or a supersede) issued during a long drain moves
// the row out of `sending` and invalidates the receipt, but nothing between the
// callback and the socket would notice. This re-reads, inside one immediate
// transaction:
//
//   - the outbox row still exists, is structural, and is still `sending`;
//   - the bound receipt is still live, unexpired, standing, and for the
//     structural purpose;
//   - its terms (generation + data-dictionary digest) still equal both what the
//     row was queued under and what the lease declares on the wire;
//   - its bound endpoint and the row's digest still match the lease.
//
// On any failure it moves the row out of `sending` to reconfirmation_required
// (when it is still `sending` to move) and returns ErrCloudStructuralSendUnauthorized,
// so the transport aborts before the body leaves. nil means still authorized.
func (s *Store) VerifyStructuralSendAuthorization(ctx context.Context, lease CloudSendLease) error {
	const pfx = "store.VerifyStructuralSendAuthorization"
	if lease.OutboxID == "" {
		return fmt.Errorf("%s: lease carries no outbox id", pfx)
	}
	reason, err := s.structuralSendStillAuthorized(ctx, lease)
	if err != nil {
		return fmt.Errorf("%s: %w", pfx, err)
	}
	if reason == "" {
		return nil
	}
	// Park the row so a later sync re-checks rather than silently retrying. A
	// row that is no longer `sending` (already cancelled by a revoke, say) has
	// nothing to move — that is the expected shape of this failure, not an
	// error, and the refusal below is the outcome that matters.
	if merr := s.moveCloudOutbox(ctx, lease.OutboxID,
		[]CloudOutboxState{CloudOutboxSending}, CloudOutboxReconfirmationRequired, false, "send_unauthorized"); merr != nil &&
		!errors.Is(merr, ErrIllegalCloudOutboxTransition) && !errors.Is(merr, ErrCloudOutboxNotFound) {
		return fmt.Errorf("%s: %w", pfx, merr)
	}
	return fmt.Errorf("%s: %w: %s", pfx, ErrCloudStructuralSendUnauthorized, reason)
}

// structuralSendStillAuthorized runs the read half of the pre-dispatch check.
// It returns a content-free reason string when authorization has changed, "" when
// the send may proceed, and an error only for an actual read failure.
func (s *Store) structuralSendStillAuthorized(ctx context.Context, lease CloudSendLease) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var kind, state, receiptID, digest, bindingJSON string
	err = tx.QueryRowContext(ctx, `
		SELECT kind, state, receipt_id, upload_digest, feature_set_json
		  FROM cloud_outbox WHERE id = ?`, lease.OutboxID).
		Scan(&kind, &state, &receiptID, &digest, &bindingJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return "outbox row gone", nil
	}
	if err != nil {
		return "", err
	}
	if CloudOutboxKind(kind) != CloudOutboxKindStructuralInsights {
		return "outbox row is not a structural snapshot", nil
	}
	if CloudOutboxState(state) != CloudOutboxSending {
		// The revoke path (CancelCloudOutboxForReceipt) covers `sending`, so this
		// is exactly how a revocation DURING the drain is caught.
		return fmt.Sprintf("outbox row is %q, no longer sending", state), nil
	}
	if receiptID != lease.ReceiptID {
		return "outbox row re-bound to a different receipt", nil
	}
	if digest != lease.UploadDigest {
		return "stored digest no longer matches the lease", nil
	}

	grantState, gerr := standingGrantStateTx(ctx, tx, receiptID, time.Now().UTC())
	if gerr != nil {
		switch {
		case errors.Is(gerr, ErrCloudGrantExpired):
			return "the standing grant's review date has passed", nil
		case errors.Is(gerr, ErrCloudReceiptNotFound):
			return "the bound consent receipt is gone", nil
		case errors.Is(gerr, ErrCloudReconfirmationRequired):
			return "the bound consent receipt was revoked", nil
		case errors.Is(gerr, ErrCloudGrantNotStanding), errors.Is(gerr, ErrCloudPurposeMismatch):
			return "the bound receipt no longer authorizes this rail", nil
		}
		return "", gerr
	}
	queued, perr := parseStructuralBinding(bindingJSON)
	if perr != nil {
		return "the queued grant binding is unreadable", nil
	}
	if queued != grantState.binding {
		return "the standing grant's terms changed after this snapshot was queued", nil
	}
	// The wire headers this attempt will carry must still be the receipt's own
	// terms. If they ever diverged, the upload would claim a binding the item was
	// not validated under — the exact defect this check exists to make impossible.
	if lease.ConsentGeneration != grantState.binding.ConsentGeneration ||
		lease.DataDictionaryDigest != grantState.binding.DataDictionaryDigest ||
		lease.SourceWindowRule != grantState.sourceWindowRule {
		return "the declared consent binding no longer matches the bound receipt", nil
	}
	if normalizeCloudEndpoint(grantState.endpoint) != lease.Endpoint {
		return "the receipt's bound endpoint changed", nil
	}
	return "", nil
}

// ListCapturedStructuralPeriods returns period -> highest captured revision for
// one (period rule, schema version) pair. It is the CAPTURE-ELIGIBILITY read: a
// window already present here has been snapshotted, so a capture pass skips it
// rather than minting a duplicate revision of unchanged data.
//
// It reports the max revision rather than a bare set because that is the number
// a late-data re-capture would increment — the N+1 path the background service
// lands. A capture pass that only captures each window ONCE needs just the
// membership, and gets it from the map's keys.
func (s *Store) ListCapturedStructuralPeriods(ctx context.Context, periodRuleVersion int, schemaVersion string) (map[string]int, error) {
	const pfx = "store.ListCapturedStructuralPeriods"
	if periodRuleVersion < 1 {
		return nil, fmt.Errorf("%s: period_rule_version %d is not positive", pfx, periodRuleVersion)
	}
	if schemaVersion == "" {
		return nil, fmt.Errorf("%s: schema_version is required", pfx)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT period, MAX(revision)
		  FROM cloud_structural_windows
		 WHERE period_rule_version = ? AND schema_version = ?
		 GROUP BY period`, periodRuleVersion, schemaVersion)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pfx, err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var (
			period string
			rev    int
		)
		if err := rows.Scan(&period, &rev); err != nil {
			return nil, fmt.Errorf("%s: scan: %w", pfx, err)
		}
		out[period] = rev
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", pfx, err)
	}
	return out, nil
}

// GetStructuralWindow returns the window row bound to an outbox id.
// ok=false means the id names no structural window.
func (s *Store) GetStructuralWindow(ctx context.Context, outboxID string) (StructuralWindowRow, bool, error) {
	var (
		row       StructuralWindowRow
		createdAt string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT period, period_rule_version, schema_version, revision, outbox_id, digest, created_at
		  FROM cloud_structural_windows WHERE outbox_id = ?`, outboxID).
		Scan(&row.Key.Period, &row.Key.PeriodRuleVersion, &row.Key.SchemaVersion,
			&row.Revision, &row.OutboxID, &row.Digest, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return StructuralWindowRow{}, false, nil
	}
	if err != nil {
		return StructuralWindowRow{}, false, fmt.Errorf("store.GetStructuralWindow: %w", err)
	}
	row.CreatedAt = cloudParseTime(createdAt)
	return row, true, nil
}

// isUniqueConstraintErr reports whether err is a SQLite UNIQUE-constraint
// violation. The driver reports it as a message rather than a typed error, so
// this matches on the stable SQLite wording.
func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// validateOutboxPayloadKind is the Go-level half of the payload/kind guard: an
// outbox row may carry payload bytes ONLY when its kind is
// 'structural_insights' (migration 098's named exception to "the outbox stores
// no content").
//
// The AUTHORITATIVE enforcement is migration 098's two BEFORE INSERT/UPDATE
// triggers, which bind every writer including raw SQL and a future code path
// that forgets to call this. This exists so the store seam refuses with a typed
// error instead of surfacing a constraint message, and so the rule is stated in
// Go where a reader of the write path will see it.
func validateOutboxPayloadKind(kind CloudOutboxKind, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	if kind != CloudOutboxKindStructuralInsights {
		return fmt.Errorf("%w: kind %q", ErrCloudPayloadKindForbidden, kind)
	}
	return nil
}

// marshalStructuralBinding renders the grant binding recorded on the outbox row.
func marshalStructuralBinding(b structuralGrantBinding) (string, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("marshal grant binding: %w", err)
	}
	return string(raw), nil
}

// parseStructuralBinding reads back the grant binding an enqueue recorded. An
// empty column is the zero binding (a row written before the binding existed),
// not an error; malformed JSON IS an error, because silently treating it as the
// zero binding would let real drift pass the pre-send check.
func parseStructuralBinding(raw string) (structuralGrantBinding, error) {
	if raw == "" {
		return structuralGrantBinding{}, nil
	}
	var b structuralGrantBinding
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return structuralGrantBinding{}, fmt.Errorf("parse grant binding: %w", err)
	}
	return b, nil
}

// scanCloudOutboxRows scans a full outbox-column result set. Shared by the
// structural and session-evidence listers so the column order is stated once.
func scanCloudOutboxRows(rows *sql.Rows, pfx string) ([]CloudOutboxItem, error) {
	var out []CloudOutboxItem
	for rows.Next() {
		var (
			it                 CloudOutboxItem
			kind               string
			state              string
			createdAt, updated string
		)
		if err := rows.Scan(&it.ID, &kind, &it.SessionID, &it.FeatureSetJSON, &it.EvidenceContentDigest,
			&it.UploadDigest, &it.ReceiptID, &state, &it.RetryCount, &it.LastError,
			&createdAt, &updated); err != nil {
			return nil, fmt.Errorf("%s: scan: %w", pfx, err)
		}
		it.Kind = CloudOutboxKind(kind)
		it.State = CloudOutboxState(state)
		it.CreatedAt = cloudParseTime(createdAt)
		it.UpdatedAt = cloudParseTime(updated)
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", pfx, err)
	}
	return out, nil
}
