package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// -- Contract pins -----------------------------------------------------------

// TestStructuralAuthorityFilterMatchesContract pins the SQL filter's authority
// value against the pure dataauthority contract. The aggregate filters in SQL
// (so an org session's rows never reach a sum), which means the contract's
// eligibility rule is expressed as a string literal in a query — this test is
// what stops the two from drifting.
func TestStructuralAuthorityFilterMatchesContract(t *testing.T) {
	t.Parallel()
	eligible := dataauthority.Classification{
		Authority: dataauthority.Authority(personalEligibleAuthority),
		Version:   dataauthority.Version,
	}
	if !eligible.EligibleForPersonalEnrichment() {
		t.Fatalf("the SQL filter selects authority %q, which the contract does NOT consider eligible", personalEligibleAuthority)
	}
	// And nothing else is eligible, so a single-value equality filter is a
	// faithful expression of the rule rather than an under-approximation.
	for _, a := range []dataauthority.Authority{dataauthority.AuthorityOrg, "", "unknown"} {
		if string(a) == personalEligibleAuthority {
			continue
		}
		c := dataauthority.Classification{Authority: a, Version: dataauthority.Version}
		if c.EligibleForPersonalEnrichment() {
			t.Errorf("authority %q is eligible per the contract but the SQL filter excludes it — the filter is no longer faithful", a)
		}
	}
}

// TestStructuralPurposeConstantMatchesContract pins the duplicated purpose
// string. The store seam deliberately does not import cloudcontract (the
// receipt's purpose column has always been a plain string here), so the
// constant is copied — and copies drift unless something checks.
func TestStructuralPurposeConstantMatchesContract(t *testing.T) {
	t.Parallel()
	if cloudPurposeStructuralInsights != string(cloudcontract.PurposeStructuralInsights) {
		t.Errorf("store's purpose constant %q != cloudcontract.PurposeStructuralInsights %q",
			cloudPurposeStructuralInsights, cloudcontract.PurposeStructuralInsights)
	}
}

// -- Fixtures ----------------------------------------------------------------

const structTestEndpoint = "https://cloud.example/v1/structural-insights"

// structSeedSession upserts a session (authority 'personal' on a fresh,
// unenrolled DB) and returns its project id.
func structSeedSession(t *testing.T, s *Store, id, tool, model string, startedAt time.Time) int64 {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/struct/p", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: id, ProjectID: pid, Tool: tool, Model: model, StartedAt: startedAt,
	}); err != nil {
		t.Fatalf("UpsertSession(%s): %v", id, err)
	}
	return pid
}

// structSetAuthority overrides a session's stored authority. Used to build the
// mixed-authority fixtures: 'org' for an enrolled capture, NULL for a pre-096
// legacy row (UNKNOWN).
func structSetAuthority(t *testing.T, db *sql.DB, sessionID string, authority any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		`UPDATE sessions SET authority = ? WHERE id = ?`, authority, sessionID); err != nil {
		t.Fatalf("set authority: %v", err)
	}
}

// structSeedAction inserts one action row directly. Raw SQL keeps the fixture
// exactly as wide as the aggregate reads.
func structSeedAction(t *testing.T, db *sql.DB, sessionID string, pid int64, at time.Time, actionType string, success int) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success)
		VALUES (?, ?, ?, ?, 'codex', ?)`,
		sessionID, pid, at.UTC().Format(time.RFC3339Nano), actionType, success); err != nil {
		t.Fatalf("seed action: %v", err)
	}
}

// structSeedTokens inserts one token_usage row directly.
func structSeedTokens(t *testing.T, db *sql.DB, sessionID string, at time.Time, in, out, cacheRead int, cost float64) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO token_usage
		  (session_id, timestamp, tool, model, input_tokens, output_tokens,
		   cache_read_tokens, estimated_cost_usd, source)
		VALUES (?, ?, 'codex', 'gpt-5', ?, ?, ?, ?, 'test')`,
		sessionID, at.UTC().Format(time.RFC3339Nano), in, out, cacheRead, cost); err != nil {
		t.Fatalf("seed tokens: %v", err)
	}
}

// structSeedRating records a developer rating for a session (the (a) half of
// the outcome-evidence definition).
func structSeedRating(t *testing.T, db *sql.DB, sessionID string, rating int) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO session_annotations (session_id, favorite, note, rating)
		VALUES (?, 0, '', ?)`, sessionID, rating); err != nil {
		t.Fatalf("seed rating: %v", err)
	}
}

// structSeedStandingReceipt inserts a LIVE STANDING grant for the
// structural-insights purpose and returns its id.
func structSeedStandingReceipt(t *testing.T, s *Store) string {
	t.Helper()
	id, err := s.InsertCloudConsentReceipt(context.Background(), CloudConsentReceipt{
		AccountPseudonym:      "acct-struct",
		Purpose:               cloudPurposeStructuralInsights,
		EnvelopeSchemaVersion: cloudcontract.StructuralSnapshotSchemaVersion,
		ScrubberVersion:       "scrub-v1",
		Endpoint:              structTestEndpoint,
		UploadDigest:          "sha256:dictionary",
		GrantMode:             CloudGrantStanding,
		DataDictionaryDigest:  "sha256:dictionary",
		DeclaredTimezone:      "Europe/Berlin",
		SourceWindowRule:      "day.v1",
		ConsentGeneration:     3,
	})
	if err != nil {
		t.Fatalf("InsertCloudConsentReceipt: %v", err)
	}
	return id
}

// structBuild returns a StructuralPayloadBuild producing deterministic fake
// bytes for a revision. The real one wraps cloudevidence.SerializeStructural;
// the store's contract with it is only "bytes + digest for this revision".
func structBuild(tag string) StructuralPayloadBuild {
	return func(revision int) ([]byte, string, error) {
		return []byte(fmt.Sprintf(`{"tag":%q,"revision":%d}`, tag, revision)),
			fmt.Sprintf("sha256:%s-r%d", tag, revision), nil
	}
}

// -- Aggregate read ----------------------------------------------------------

// TestLoadStructuralDayFactsMixedAuthority is the plan's review-finding-10 pin:
// org and unknown-authority sessions are excluded IN the SQL, so their actions,
// tokens, and cost can never reach a sum in the first place.
func TestLoadStructuralDayFactsMixedAuthority(t *testing.T) {
	s, db := cloudTestStore(t)
	ctx := context.Background()

	day := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	start, end := day.Format(time.RFC3339), day.AddDate(0, 0, 1).Format(time.RFC3339)

	// Two personal sessions in the window.
	p1 := structSeedSession(t, s, "p-1", "codex", "gpt-5.6", day.Add(9*time.Hour))
	structSeedSession(t, s, "p-2", "claude-code", "claude-sonnet-4.6", day.Add(14*time.Hour))
	structSeedAction(t, db, "p-1", p1, day.Add(9*time.Hour), "run_command", 1)
	structSeedAction(t, db, "p-1", p1, day.Add(9*time.Hour), "read_file", 1)
	structSeedAction(t, db, "p-2", p1, day.Add(14*time.Hour), "edit_file", 0) // an observed failure
	structSeedTokens(t, db, "p-1", day.Add(9*time.Hour), 1000, 100, 5000, 0.25)
	structSeedTokens(t, db, "p-2", day.Add(14*time.Hour), 2000, 200, 6000, 0.50)

	// An ORG session in the same window, with rich activity that must NOT be
	// counted anywhere.
	pOrg := structSeedSession(t, s, "org-1", "codex", "gpt-5.6", day.Add(10*time.Hour))
	structSetAuthority(t, db, "org-1", "org")
	structSeedAction(t, db, "org-1", pOrg, day.Add(10*time.Hour), "run_command", 0)
	structSeedTokens(t, db, "org-1", day.Add(10*time.Hour), 999_999, 999_999, 999_999, 999.99)
	structSeedRating(t, db, "org-1", 9)

	// An UNKNOWN-authority (pre-096 legacy) session — equally excluded.
	pUnk := structSeedSession(t, s, "unk-1", "cursor", "gpt-5.6", day.Add(11*time.Hour))
	structSetAuthority(t, db, "unk-1", nil)
	structSeedAction(t, db, "unk-1", pUnk, day.Add(11*time.Hour), "run_command", 1)
	structSeedTokens(t, db, "unk-1", day.Add(11*time.Hour), 777_777, 777_777, 777_777, 77.77)

	// A personal session on the NEXT day — outside the window.
	structSeedSession(t, s, "p-next", "codex", "gpt-5.6", day.AddDate(0, 0, 1).Add(time.Hour))

	facts, err := s.LoadStructuralDayFacts(ctx, start, end)
	if err != nil {
		t.Fatalf("LoadStructuralDayFacts: %v", err)
	}
	if facts.SessionCount != 2 {
		t.Errorf("session count = %d, want 2 (org + unknown + next-day excluded)", facts.SessionCount)
	}
	if facts.ActionCount != 3 {
		t.Errorf("action count = %d, want 3 — an org/unknown session's actions must never enter the sum", facts.ActionCount)
	}
	if facts.TokensIn != 3000 || facts.TokensOut != 300 || facts.CacheReadTokens != 11000 {
		t.Errorf("token sums = %d/%d/%d, want 3000/300/11000 — org/unknown tokens leaked",
			facts.TokensIn, facts.TokensOut, facts.CacheReadTokens)
	}
	if facts.CostUSD < 0.749 || facts.CostUSD > 0.751 {
		t.Errorf("cost = %v, want ~0.75 — org/unknown cost leaked", facts.CostUSD)
	}
	// Coverage: p-1 ran a command (verification); p-2 has a failed action
	// (outcome evidence). Neither number may include org-1 or unk-1.
	if facts.SessionsWithVerification != 1 {
		t.Errorf("sessions with verification = %d, want 1", facts.SessionsWithVerification)
	}
	if facts.SessionsWithOutcomes != 1 {
		t.Errorf("sessions with outcomes = %d, want 1", facts.SessionsWithOutcomes)
	}
	// Mixes are per-session, over eligible sessions only.
	if got := structMixMap(facts.ToolMix); got["codex"] != 1 || got["claude-code"] != 1 || len(got) != 2 {
		t.Errorf("tool mix = %v, want {codex:1, claude-code:1}", got)
	}
	if got := structMixMap(facts.ModelFamilyMix); len(got) != 2 {
		t.Errorf("model family mix = %v, want two families", got)
	}
	// The watermark is the max event time actually included (p-2's 14:00 rows).
	if want := day.Add(14 * time.Hour); !facts.SourceWatermark.Equal(want) {
		t.Errorf("watermark = %v, want %v", facts.SourceWatermark, want)
	}
}

// TestLoadStructuralDayFactsOutcomeEvidenceViaRating pins the (a) half of the
// outcome definition — a developer's own score is outcome evidence even when
// every action succeeded.
func TestLoadStructuralDayFactsOutcomeEvidenceViaRating(t *testing.T) {
	s, db := cloudTestStore(t)
	day := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	pid := structSeedSession(t, s, "r-1", "codex", "gpt-5.6", day.Add(time.Hour))
	structSeedSession(t, s, "r-2", "codex", "gpt-5.6", day.Add(2*time.Hour))
	structSeedAction(t, db, "r-1", pid, day.Add(time.Hour), "read_file", 1) // all green
	structSeedRating(t, db, "r-1", 8)

	facts, err := s.LoadStructuralDayFacts(context.Background(),
		day.Format(time.RFC3339), day.AddDate(0, 0, 1).Format(time.RFC3339))
	if err != nil {
		t.Fatalf("LoadStructuralDayFacts: %v", err)
	}
	if facts.SessionsWithOutcomes != 1 {
		t.Errorf("sessions with outcomes = %d, want 1 (the rated session)", facts.SessionsWithOutcomes)
	}
	if facts.SessionsWithVerification != 0 {
		t.Errorf("sessions with verification = %d, want 0 — no command was run", facts.SessionsWithVerification)
	}
}

// TestLoadStructuralDayFactsWindowBoundaries pins the half-open window AND the
// sub-second boundary correctness the fixed-width prefix comparison exists for:
// a naive lexicographic compare puts "…T00:00:00.5Z" BEFORE "…T00:00:00Z"
// ('.' < 'Z'), which would drop a session that started fractions of a second
// into the day.
func TestLoadStructuralDayFactsWindowBoundaries(t *testing.T) {
	s, _ := cloudTestStore(t)
	day := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	start, end := day.Format(time.RFC3339), day.AddDate(0, 0, 1).Format(time.RFC3339)

	structSeedSession(t, s, "b-exact-start", "codex", "m", day)                                  // in
	structSeedSession(t, s, "b-frac-start", "codex", "m", day.Add(500*time.Millisecond))         // in
	structSeedSession(t, s, "b-last", "codex", "m", day.Add(24*time.Hour-time.Millisecond))      // in
	structSeedSession(t, s, "b-exact-end", "codex", "m", day.AddDate(0, 0, 1))                   // out
	structSeedSession(t, s, "b-frac-end", "codex", "m", day.AddDate(0, 0, 1).Add(time.Second/2)) // out
	structSeedSession(t, s, "b-before", "codex", "m", day.Add(-time.Millisecond))                // out

	facts, err := s.LoadStructuralDayFacts(context.Background(), start, end)
	if err != nil {
		t.Fatalf("LoadStructuralDayFacts: %v", err)
	}
	if facts.SessionCount != 3 {
		t.Errorf("session count = %d, want 3 — the half-open window must include the exact start "+
			"and a sub-second offset from it, and exclude the exact end", facts.SessionCount)
	}
}

// TestLoadStructuralDayFactsEmptyWindow pins the zero case: an empty window is
// a truthful all-zero DTO, never an error.
func TestLoadStructuralDayFactsEmptyWindow(t *testing.T) {
	s, _ := cloudTestStore(t)
	day := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	facts, err := s.LoadStructuralDayFacts(context.Background(),
		day.Format(time.RFC3339), day.AddDate(0, 0, 1).Format(time.RFC3339))
	if err != nil {
		t.Fatalf("LoadStructuralDayFacts: %v", err)
	}
	if facts.SessionCount != 0 || facts.ActionCount != 0 || !facts.SourceWatermark.IsZero() {
		t.Errorf("empty window = %+v, want all zero", facts)
	}
}

// TestLoadStructuralDayFactsRejectsBadWindow pins the boundary validation.
func TestLoadStructuralDayFactsRejectsBadWindow(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	for _, tc := range []struct{ start, end string }{
		{"", "2026-09-02T00:00:00Z"},
		{"2026-09-01T00:00:00Z", ""},
		{"yesterday", "2026-09-02T00:00:00Z"},
		{"2026-09-02T00:00:00Z", "2026-09-01T00:00:00Z"}, // inverted
		{"2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"}, // empty range
	} {
		if _, err := s.LoadStructuralDayFacts(ctx, tc.start, tc.end); err == nil {
			t.Errorf("LoadStructuralDayFacts(%q, %q) = nil error, want a refusal", tc.start, tc.end)
		}
	}
}

func structMixMap(mix []StructuralMixCount) map[string]int {
	out := map[string]int{}
	for _, m := range mix {
		out[m.Key] = m.Count
	}
	return out
}

// -- Revision allocation -----------------------------------------------------

func structKey(period string) StructuralWindowKey {
	return StructuralWindowKey{
		Period:            period,
		PeriodRuleVersion: 1,
		SchemaVersion:     cloudcontract.StructuralSnapshotSchemaVersion,
	}
}

// TestStructuralRevisionAllocationIsMonotonic pins that re-snapshotting a
// window allocates N+1 rather than overwriting — including while revision N is
// still pending-unsent, which is the late-data case the revision model exists
// for.
func TestStructuralRevisionAllocationIsMonotonic(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	receipt := structSeedStandingReceipt(t, s)
	key := structKey("2026-09-01")

	if next, err := s.AllocateStructuralRevision(ctx, key); err != nil || next != 1 {
		t.Fatalf("first AllocateStructuralRevision = %d, %v; want 1, nil", next, err)
	}

	var ids []string
	for want := 1; want <= 3; want++ {
		id, rev, err := s.EnqueueStructuralOutbox(ctx, key, receipt, structBuild("w"))
		if err != nil {
			t.Fatalf("enqueue %d: %v", want, err)
		}
		if rev != want {
			t.Fatalf("enqueue %d allocated revision %d, want %d", want, rev, want)
		}
		ids = append(ids, id)
		// Every prior revision is STILL pending: a re-snapshot never replaces.
		item, ok, err := s.GetCloudOutbox(ctx, ids[0])
		if err != nil || !ok {
			t.Fatalf("GetCloudOutbox(first): ok=%v err=%v", ok, err)
		}
		if item.State != CloudOutboxPending {
			t.Fatalf("revision 1 moved to %q when revision %d was taken — a window is never overwritten", item.State, want)
		}
	}
	if next, err := s.AllocateStructuralRevision(ctx, key); err != nil || next != 4 {
		t.Fatalf("AllocateStructuralRevision after 3 = %d, %v; want 4, nil", next, err)
	}

	// A DIFFERENT window's revisions are independent.
	if next, err := s.AllocateStructuralRevision(ctx, structKey("2026-09-02")); err != nil || next != 1 {
		t.Fatalf("other-period AllocateStructuralRevision = %d, %v; want 1, nil", next, err)
	}
}

// TestStructuralRevisionAllocationIsConcurrentSafe drives concurrent snapshot
// builds of the SAME window and requires every one to receive a DISTINCT
// revision. This is the property the in-transaction allocation buys: allocating
// outside the insert would let two builds pick the same number, and the loser
// would either collide or silently overwrite.
func TestStructuralRevisionAllocationIsConcurrentSafe(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	receipt := structSeedStandingReceipt(t, s)
	key := structKey("2026-09-06")

	const n = 12
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		revs []int
		errs []error
	)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, rev, err := s.EnqueueStructuralOutbox(ctx, key, receipt, structBuild(fmt.Sprintf("c%d", i)))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			revs = append(revs, rev)
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		// A revision collision is an acceptable, TYPED outcome (the caller
		// retries); anything else is a real failure.
		if !errors.Is(err, ErrStructuralRevisionTaken) {
			t.Fatalf("concurrent enqueue failed with an unexpected error: %v", err)
		}
	}
	seen := map[int]bool{}
	for _, r := range revs {
		if seen[r] {
			t.Fatalf("revision %d was allocated twice — concurrent snapshot builds of one window must never share a revision", r)
		}
		seen[r] = true
		if r < 1 {
			t.Fatalf("revision %d is not positive", r)
		}
	}
	if len(revs) == 0 {
		t.Fatal("no concurrent enqueue succeeded")
	}
	// The window rows must agree with what the callers were told.
	var count int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cloud_structural_windows WHERE period = ?`, key.Period).Scan(&count); err != nil {
		t.Fatalf("count windows: %v", err)
	}
	if count != len(revs) {
		t.Errorf("%d window rows for %d successful allocations", count, len(revs))
	}
}

// -- Enqueue gating ----------------------------------------------------------

// TestEnqueueStructuralOutboxRequiresStandingGrant walks the R1 gate: a
// structural snapshot may only be queued under a LIVE STANDING grant for the
// structural-insights purpose.
func TestEnqueueStructuralOutboxRequiresStandingGrant(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	key := structKey("2026-09-07")

	// (1) missing receipt.
	_, _, err := s.EnqueueStructuralOutbox(ctx, key, "rcpt_nope", structBuild("x"))
	if !errors.Is(err, ErrCloudReceiptNotFound) {
		t.Errorf("missing receipt: err = %v, want ErrCloudReceiptNotFound", err)
	}

	// (2) a PER-UPLOAD receipt cannot authorize a rail of snapshots.
	perUpload, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
		AccountPseudonym: "a", Purpose: cloudPurposeStructuralInsights,
		UploadDigest: "sha256:x", Endpoint: structTestEndpoint,
	})
	if err != nil {
		t.Fatalf("insert per-upload receipt: %v", err)
	}
	if _, _, err := s.EnqueueStructuralOutbox(ctx, key, perUpload, structBuild("x")); !errors.Is(err, ErrCloudGrantNotStanding) {
		t.Errorf("per-upload grant: err = %v, want ErrCloudGrantNotStanding", err)
	}

	// (3) a standing grant for a DIFFERENT purpose does not authorize this one.
	wrongPurpose, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
		AccountPseudonym: "a", Purpose: string(cloudcontract.PurposeContextEnrichment),
		UploadDigest: "sha256:x", Endpoint: structTestEndpoint, GrantMode: CloudGrantStanding,
	})
	if err != nil {
		t.Fatalf("insert wrong-purpose receipt: %v", err)
	}
	if _, _, err := s.EnqueueStructuralOutbox(ctx, key, wrongPurpose, structBuild("x")); !errors.Is(err, ErrCloudPurposeMismatch) {
		t.Errorf("wrong purpose: err = %v, want ErrCloudPurposeMismatch", err)
	}

	// (4) an INVALIDATED standing grant is a revocation.
	revoked := structSeedStandingReceipt(t, s)
	if err := s.InvalidateCloudConsentReceipt(ctx, revoked); err != nil {
		t.Fatalf("InvalidateCloudConsentReceipt: %v", err)
	}
	if _, _, err := s.EnqueueStructuralOutbox(ctx, key, revoked, structBuild("x")); !errors.Is(err, ErrCloudReconfirmationRequired) {
		t.Errorf("revoked grant: err = %v, want ErrCloudReconfirmationRequired", err)
	}

	// Nothing was written by any refusal.
	var windows, outbox int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cloud_structural_windows`).Scan(&windows)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cloud_outbox`).Scan(&outbox)
	if windows != 0 || outbox != 0 {
		t.Errorf("a refused enqueue left rows behind: %d windows, %d outbox", windows, outbox)
	}

	// And the happy path still works. The generation is explicitly a NEW one:
	// migration 099 makes (purpose, consent_generation) unique for standing
	// grants across live AND invalidated rows, precisely so a retired generation
	// can never be reused for different terms.
	good := structSeedStandingReceiptAt(t, s, 4, nil)
	if _, _, err := s.EnqueueStructuralOutbox(ctx, key, good, structBuild("x")); err != nil {
		t.Fatalf("live standing grant must be accepted: %v", err)
	}
}

// TestStructuralPayloadKindGuard pins the Go-level half of the payload/kind
// rule. (The storage-layer triggers — the authoritative enforcement, covering
// raw SQL writers too — are pinned by
// tests/invariant.TestCloudOutboxPayloadOnlyOnStructuralKind.)
func TestStructuralPayloadKindGuard(t *testing.T) {
	t.Parallel()
	if err := validateOutboxPayloadKind(CloudOutboxKindStructuralInsights, []byte("bytes")); err != nil {
		t.Errorf("structural + payload must be allowed: %v", err)
	}
	if err := validateOutboxPayloadKind(CloudOutboxKindSessionEvidence, nil); err != nil {
		t.Errorf("session evidence without payload must be allowed: %v", err)
	}
	if err := validateOutboxPayloadKind(CloudOutboxKindSessionEvidence, []byte("session content")); !errors.Is(err, ErrCloudPayloadKindForbidden) {
		t.Errorf("session evidence + payload: err = %v, want ErrCloudPayloadKindForbidden", err)
	}
}

// -- Send preparation --------------------------------------------------------

// TestPrepareStructuralSendReplaysStoredBytes is the immutability pin, and the
// whole reason the outbox stores bytes at all: after a snapshot is queued, the
// SOURCE ROWS change — sessions are added, actions are deleted, tokens are
// rewritten — and the prepared send must still be the exact bytes the digest
// was taken over. A path that re-aggregated would silently upload different
// numbers under a digest the user consented to.
func TestPrepareStructuralSendReplaysStoredBytes(t *testing.T) {
	s, db := cloudTestStore(t)
	ctx := context.Background()
	receipt := structSeedStandingReceipt(t, s)
	key := structKey("2026-09-08")

	day := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	pid := structSeedSession(t, s, "im-1", "codex", "gpt-5.6", day.Add(time.Hour))
	structSeedAction(t, db, "im-1", pid, day.Add(time.Hour), "run_command", 1)
	structSeedTokens(t, db, "im-1", day.Add(time.Hour), 10, 5, 0, 0.01)

	original := []byte(`{"snapshot":"as-consented","session_count":1}`)
	id, _, err := s.EnqueueStructuralOutbox(ctx, key, receipt,
		func(int) ([]byte, string, error) { return original, "sha256:consented", nil })
	if err != nil {
		t.Fatalf("EnqueueStructuralOutbox: %v", err)
	}

	// Now mutate the world underneath: new sessions, deleted actions, rewritten
	// tokens. A re-aggregating implementation would produce different numbers.
	structSeedSession(t, s, "im-2", "claude-code", "claude-sonnet-4.6", day.Add(2*time.Hour))
	if _, err := db.ExecContext(ctx, `DELETE FROM actions WHERE session_id = 'im-1'`); err != nil {
		t.Fatalf("delete actions: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE token_usage SET input_tokens = 999999 WHERE session_id = 'im-1'`); err != nil {
		t.Fatalf("rewrite tokens: %v", err)
	}

	got, lease, err := s.PrepareStructuralSend(ctx, id, structTestEndpoint)
	if err != nil {
		t.Fatalf("PrepareStructuralSend: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("prepared bytes = %s, want the ORIGINAL stored bytes %s — a retry must never re-aggregate", got, original)
	}
	if lease.UploadDigest != "sha256:consented" {
		t.Errorf("lease digest = %q, want the digest the bytes were stored under", lease.UploadDigest)
	}
	if lease.SessionID != "" {
		t.Errorf("lease session id = %q, want empty — a window has no session", lease.SessionID)
	}

	// Mutating the returned slice must not change what is stored.
	got[0] = 'X'
	again, _, err := structPrepareAfterRetry(t, s, id)
	if err != nil {
		t.Fatalf("second prepare: %v", err)
	}
	if string(again) != string(original) {
		t.Errorf("stored bytes changed after a caller mutated the returned slice: %s", again)
	}
}

// structPrepareAfterRetry moves a `sending` item back to failed_retryable and
// re-prepares it — the crash-before-ack path. The replay must still hand back
// the original stored bytes.
func structPrepareAfterRetry(t *testing.T, st *Store, id string) ([]byte, CloudSendLease, error) {
	t.Helper()
	if err := st.MarkCloudOutboxRetryable(context.Background(), id, "network"); err != nil {
		t.Fatalf("MarkCloudOutboxRetryable: %v", err)
	}
	return st.PrepareStructuralSend(context.Background(), id, structTestEndpoint)
}

// TestPrepareStructuralSendRefusals walks every pre-send refusal. Each one must
// park the item in reconfirmation_required rather than leaving it preparable.
func TestPrepareStructuralSendRefusals(t *testing.T) {
	ctx := context.Background()

	newItem := func(t *testing.T) (*Store, string, string) {
		t.Helper()
		s, _ := cloudTestStore(t)
		receipt := structSeedStandingReceipt(t, s)
		id, _, err := s.EnqueueStructuralOutbox(ctx, structKey("2026-09-09"), receipt, structBuild("r"))
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		return s, id, receipt
	}

	t.Run("endpoint mismatch", func(t *testing.T) {
		s, id, _ := newItem(t)
		_, _, err := s.PrepareStructuralSend(ctx, id, "https://evil.example/v1/structural-insights")
		if !errors.Is(err, ErrCloudEndpointMismatch) {
			t.Fatalf("err = %v, want ErrCloudEndpointMismatch", err)
		}
		assertStructuralState(t, s, id, CloudOutboxReconfirmationRequired)
	})

	t.Run("revoked receipt", func(t *testing.T) {
		s, id, receipt := newItem(t)
		if err := s.InvalidateCloudConsentReceipt(ctx, receipt); err != nil {
			t.Fatalf("invalidate: %v", err)
		}
		_, _, err := s.PrepareStructuralSend(ctx, id, structTestEndpoint)
		if !errors.Is(err, ErrCloudReconfirmationRequired) {
			t.Fatalf("err = %v, want ErrCloudReconfirmationRequired", err)
		}
		assertStructuralState(t, s, id, CloudOutboxReconfirmationRequired)
	})

	t.Run("grant generation drift", func(t *testing.T) {
		s, id, receipt := newItem(t)
		// The developer re-confirmed under changed terms after the snapshot was
		// queued: the queued bytes were built under terms that no longer hold.
		if _, err := s.db.ExecContext(ctx,
			`UPDATE cloud_consent_receipts SET consent_generation = consent_generation + 1 WHERE id = ?`, receipt); err != nil {
			t.Fatalf("bump generation: %v", err)
		}
		_, _, err := s.PrepareStructuralSend(ctx, id, structTestEndpoint)
		if !errors.Is(err, ErrCloudGrantGenerationDrift) {
			t.Fatalf("err = %v, want ErrCloudGrantGenerationDrift", err)
		}
		assertStructuralState(t, s, id, CloudOutboxReconfirmationRequired)
	})

	t.Run("data dictionary drift", func(t *testing.T) {
		s, id, receipt := newItem(t)
		if _, err := s.db.ExecContext(ctx,
			`UPDATE cloud_consent_receipts SET data_dictionary_digest = 'sha256:new-schema' WHERE id = ?`, receipt); err != nil {
			t.Fatalf("bump dictionary: %v", err)
		}
		if _, _, err := s.PrepareStructuralSend(ctx, id, structTestEndpoint); !errors.Is(err, ErrCloudGrantGenerationDrift) {
			t.Fatalf("err = %v, want ErrCloudGrantGenerationDrift", err)
		}
	})

	t.Run("unknown item", func(t *testing.T) {
		s, _, _ := newItem(t)
		if _, _, err := s.PrepareStructuralSend(ctx, "nope", structTestEndpoint); !errors.Is(err, ErrCloudOutboxNotFound) {
			t.Fatalf("err = %v, want ErrCloudOutboxNotFound", err)
		}
	})

	t.Run("already sent", func(t *testing.T) {
		s, id, _ := newItem(t)
		if _, _, err := s.PrepareStructuralSend(ctx, id, structTestEndpoint); err != nil {
			t.Fatalf("first prepare: %v", err)
		}
		if err := s.MarkCloudOutboxSent(ctx, id); err != nil {
			t.Fatalf("mark sent: %v", err)
		}
		if _, _, err := s.PrepareStructuralSend(ctx, id, structTestEndpoint); !errors.Is(err, ErrIllegalCloudOutboxTransition) {
			t.Fatalf("err = %v, want ErrIllegalCloudOutboxTransition", err)
		}
	})
}

func assertStructuralState(t *testing.T, s *Store, id string, want CloudOutboxState) {
	t.Helper()
	item, ok, err := s.GetCloudOutbox(context.Background(), id)
	if err != nil || !ok {
		t.Fatalf("GetCloudOutbox: ok=%v err=%v", ok, err)
	}
	if item.State != want {
		t.Errorf("state = %q, want %q — a refused send must park the item, never leave it preparable", item.State, want)
	}
}

// -- Kind separation ---------------------------------------------------------

// TestStructuralAndEvidenceDrainSetsAreDisjoint pins that the two rails share a
// table but never each other's drain set or prepare path. Routing a structural
// row into the session-evidence path would rebuild an envelope from a session
// that does not exist — or, worse, re-aggregate.
func TestStructuralAndEvidenceDrainSetsAreDisjoint(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	// One structural item.
	structReceipt := structSeedStandingReceipt(t, s)
	structID, _, err := s.EnqueueStructuralOutbox(ctx, structKey("2026-09-10"), structReceipt, structBuild("d"))
	if err != nil {
		t.Fatalf("enqueue structural: %v", err)
	}

	// One session-evidence item, through the 097 path.
	seedEligibleSession(t, s, "ev-1")
	evReceipt := seedReceipt(t, s, "sha256:evidence")
	evID, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
		SessionID: "ev-1", ReceiptID: evReceipt,
		EvidenceContentDigest: "sha256:ev-content", UploadDigest: "sha256:evidence",
	})
	if err != nil {
		t.Fatalf("enqueue evidence: %v", err)
	}

	evDrain, err := s.ListSendableCloudOutbox(ctx)
	if err != nil {
		t.Fatalf("ListSendableCloudOutbox: %v", err)
	}
	if len(evDrain) != 1 || evDrain[0].ID != evID {
		t.Fatalf("session-evidence drain = %v, want only %q — a structural row must never appear here", ids(evDrain), evID)
	}

	structDrain, err := s.ListSendableStructuralOutbox(ctx)
	if err != nil {
		t.Fatalf("ListSendableStructuralOutbox: %v", err)
	}
	if len(structDrain) != 1 || structDrain[0].ID != structID {
		t.Fatalf("structural drain = %v, want only %q", ids(structDrain), structID)
	}

	// And the prepare paths refuse each other's rows.
	if _, _, err := s.PrepareCloudOutboxSend(ctx, structID, structTestEndpoint,
		func(context.Context) ([]byte, string, string, error) {
			t.Fatal("the session-evidence path must refuse a structural row BEFORE rebuilding")
			return nil, "", "", nil
		}); !errors.Is(err, ErrCloudOutboxKindMismatch) {
		t.Errorf("PrepareCloudOutboxSend(structural) = %v, want ErrCloudOutboxKindMismatch", err)
	}
	if _, _, err := s.PrepareStructuralSend(ctx, evID, cloudTestEndpoint); !errors.Is(err, ErrCloudOutboxKindMismatch) {
		t.Errorf("PrepareStructuralSend(evidence) = %v, want ErrCloudOutboxKindMismatch", err)
	}
}

// TestListSendableStructuralOutboxRevisionOrder pins the revision-order drain:
// currency is decided by revision number, so a window's revisions must leave in
// order even when their rows were created out of order.
func TestListSendableStructuralOutboxRevisionOrder(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	receipt := structSeedStandingReceipt(t, s)

	// Interleave two periods so the ordering has to consider both columns.
	type made struct {
		id     string
		period string
		rev    int
	}
	var all []made
	for _, period := range []string{"2026-09-12", "2026-09-11"} {
		for i := 0; i < 3; i++ {
			id, rev, err := s.EnqueueStructuralOutbox(ctx, structKey(period), receipt, structBuild(period))
			if err != nil {
				t.Fatalf("enqueue %s: %v", period, err)
			}
			all = append(all, made{id, period, rev})
		}
	}

	drain, err := s.ListSendableStructuralOutbox(ctx)
	if err != nil {
		t.Fatalf("ListSendableStructuralOutbox: %v", err)
	}
	if len(drain) != len(all) {
		t.Fatalf("drain has %d items, want %d", len(drain), len(all))
	}
	byID := map[string]made{}
	for _, m := range all {
		byID[m.id] = m
	}
	prevPeriod, prevRev := "", 0
	for _, item := range drain {
		m := byID[item.ID]
		switch {
		case m.period < prevPeriod:
			t.Fatalf("periods out of order: %s after %s", m.period, prevPeriod)
		case m.period == prevPeriod && m.rev <= prevRev:
			t.Fatalf("revision %d of %s drained after revision %d — a window's revisions must leave in order",
				m.rev, m.period, prevRev)
		}
		prevPeriod, prevRev = m.period, m.rev
	}
}

func ids(items []CloudOutboxItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.ID)
	}
	return out
}

// TestStructuralWindowLookup pins the window bookkeeping read.
func TestStructuralWindowLookup(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	receipt := structSeedStandingReceipt(t, s)
	key := structKey("2026-09-13")
	id, rev, err := s.EnqueueStructuralOutbox(ctx, key, receipt, structBuild("w"))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	row, ok, err := s.GetStructuralWindow(ctx, id)
	if err != nil || !ok {
		t.Fatalf("GetStructuralWindow: ok=%v err=%v", ok, err)
	}
	if row.Key != key || row.Revision != rev || row.OutboxID != id {
		t.Errorf("window row = %+v, want key %+v revision %d outbox %q", row, key, rev, id)
	}
	if !strings.HasPrefix(row.Digest, "sha256:") {
		t.Errorf("window digest = %q", row.Digest)
	}
	if _, ok, err := s.GetStructuralWindow(ctx, "nope"); err != nil || ok {
		t.Errorf("GetStructuralWindow(unknown) = ok %v, err %v; want false, nil", ok, err)
	}
}

// TestStandingGrantRoundTrip pins that the R1 binding columns survive a write/
// read cycle, and that an unset grant mode defaults to per-upload so a pre-098
// caller keeps its old meaning.
func TestStandingGrantRoundTrip(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	id := structSeedStandingReceipt(t, s)
	got, ok, err := s.GetCloudConsentReceipt(ctx, id)
	if err != nil || !ok {
		t.Fatalf("GetCloudConsentReceipt: ok=%v err=%v", ok, err)
	}
	if got.GrantMode != CloudGrantStanding {
		t.Errorf("grant mode = %q, want %q", got.GrantMode, CloudGrantStanding)
	}
	if got.DataDictionaryDigest != "sha256:dictionary" || got.DeclaredTimezone != "Europe/Berlin" ||
		got.SourceWindowRule != "day.v1" || got.ConsentGeneration != 3 {
		t.Errorf("standing binding did not round-trip: %+v", got)
	}

	legacyID, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
		AccountPseudonym: "a", Purpose: "bounded_context_enrichment", UploadDigest: "sha256:one",
	})
	if err != nil {
		t.Fatalf("insert legacy receipt: %v", err)
	}
	legacy, _, err := s.GetCloudConsentReceipt(ctx, legacyID)
	if err != nil {
		t.Fatalf("get legacy receipt: %v", err)
	}
	if legacy.GrantMode != CloudGrantPerUpload {
		t.Errorf("a receipt written without a grant mode = %q, want %q", legacy.GrantMode, CloudGrantPerUpload)
	}

	if _, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
		AccountPseudonym: "a", Purpose: "p", UploadDigest: "sha256:x", GrantMode: "forever",
	}); err == nil {
		t.Error("an unknown grant mode must be refused")
	}
}

// -- F2/F3/F4 regressions ------------------------------------------------------

// structSeedStandingReceiptAt inserts a live standing grant with an explicit
// consent generation and review date, so the expiry and multi-receipt cases can
// be built deliberately.
func structSeedStandingReceiptAt(t *testing.T, s *Store, generation int, reviewAt *time.Time) string {
	t.Helper()
	id, err := s.InsertCloudConsentReceipt(context.Background(), CloudConsentReceipt{
		AccountPseudonym:      "acct-struct",
		Purpose:               cloudPurposeStructuralInsights,
		EnvelopeSchemaVersion: cloudcontract.StructuralSnapshotSchemaVersion,
		ScrubberVersion:       "scrub-v1",
		Endpoint:              structTestEndpoint,
		UploadDigest:          "sha256:dictionary",
		GrantMode:             CloudGrantStanding,
		DataDictionaryDigest:  "sha256:dictionary",
		DeclaredTimezone:      "Europe/Berlin",
		SourceWindowRule:      "day.v1",
		ReviewAt:              reviewAt,
		ConsentGeneration:     generation,
	})
	if err != nil {
		t.Fatalf("InsertCloudConsentReceipt(gen %d): %v", generation, err)
	}
	return id
}

// TestVerifyStructuralSendAuthorizationStopsARevokedDispatch is the F2
// regression. The gateway resolves the grant ONCE, before the drain callback
// runs; a `consent revoke` issued during the drain moves the row out of
// `sending` but nothing between the callback and the socket noticed it, so the
// POST — and every retry of it — went ahead. This is the check the drain now
// passes as PreAttempt.
func TestVerifyStructuralSendAuthorizationStopsARevokedDispatch(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		// revoke performs the mid-drain change, after prepare and before dispatch.
		revoke func(t *testing.T, s *Store, receiptID, outboxID string)
	}{
		{
			name: "revoke cancels the in-flight row",
			revoke: func(t *testing.T, s *Store, receiptID, _ string) {
				// Exactly what `observer cloud consent revoke` does.
				if err := s.InvalidateCloudConsentReceipt(ctx, receiptID); err != nil {
					t.Fatalf("invalidate: %v", err)
				}
				if _, err := s.CancelCloudOutboxForReceipt(ctx, receiptID); err != nil {
					t.Fatalf("cancel: %v", err)
				}
			},
		},
		{
			name: "receipt invalidated with the row left sending",
			revoke: func(t *testing.T, s *Store, receiptID, _ string) {
				if err := s.InvalidateCloudConsentReceipt(ctx, receiptID); err != nil {
					t.Fatalf("invalidate: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := cloudTestStore(t)
			receipt := structSeedStandingReceipt(t, s)
			id, _, err := s.EnqueueStructuralOutbox(ctx, structKey("2026-09-01"), receipt, structBuild("f2"))
			if err != nil {
				t.Fatalf("EnqueueStructuralOutbox: %v", err)
			}
			_, lease, err := s.PrepareStructuralSend(ctx, id, structTestEndpoint)
			if err != nil {
				t.Fatalf("PrepareStructuralSend: %v", err)
			}
			// Authorized right up to this point — the check must not be a blanket
			// refusal.
			if verr := s.VerifyStructuralSendAuthorization(ctx, lease); verr != nil {
				t.Fatalf("an unchanged send must still be authorized: %v", verr)
			}

			tc.revoke(t, s, receipt, id)

			verr := s.VerifyStructuralSendAuthorization(ctx, lease)
			if !errors.Is(verr, ErrCloudStructuralSendUnauthorized) {
				t.Fatalf("want ErrCloudStructuralSendUnauthorized after revocation, got %v", verr)
			}
			// The row must not be left in `sending`, where the stale-sending
			// reclaim would later hand it back for a retry.
			it, ok, err := s.GetCloudOutbox(ctx, id)
			if err != nil || !ok {
				t.Fatalf("GetCloudOutbox: %v ok=%v", err, ok)
			}
			if it.State == CloudOutboxSending {
				t.Errorf("the refused item is still %q", it.State)
			}
		})
	}
}

// TestPrepareStructuralSendRefusesAnExpiredGrant is the F3 review_at half. The
// gateway applies expiry when it asks "does anything authorize this lane"; this
// pins the per-item question — a snapshot bound to a receipt whose review date
// has passed must not prepare, because the developer agreed to revisit the grant
// by that date and sending past it would make the date decorative.
func TestPrepareStructuralSendRefusesAnExpiredGrant(t *testing.T) {
	s, database := cloudTestStore(t)
	ctx := context.Background()

	future := time.Now().UTC().AddDate(0, 6, 0)
	receipt := structSeedStandingReceiptAt(t, s, 1, &future)
	id, _, err := s.EnqueueStructuralOutbox(ctx, structKey("2026-09-02"), receipt, structBuild("exp"))
	if err != nil {
		t.Fatalf("EnqueueStructuralOutbox: %v", err)
	}

	// The review date passes while the snapshot sits queued.
	past := time.Now().UTC().AddDate(0, 0, -1)
	if _, err := database.ExecContext(ctx,
		`UPDATE cloud_consent_receipts SET review_at = ? WHERE id = ?`,
		past.Format(time.RFC3339Nano), receipt); err != nil {
		t.Fatalf("expire receipt: %v", err)
	}

	_, _, perr := s.PrepareStructuralSend(ctx, id, structTestEndpoint)
	if !errors.Is(perr, ErrCloudGrantExpired) {
		t.Fatalf("want ErrCloudGrantExpired, got %v", perr)
	}
	if !errors.Is(perr, ErrCloudReconfirmationRequired) {
		t.Errorf("an expired grant must read as needing reconfirmation: %v", perr)
	}
	it, ok, err := s.GetCloudOutbox(ctx, id)
	if err != nil || !ok {
		t.Fatalf("GetCloudOutbox: %v ok=%v", err, ok)
	}
	if it.State != CloudOutboxReconfirmationRequired {
		t.Errorf("item state = %q, want reconfirmation_required", it.State)
	}

	// And an enqueue under the same lapsed grant is refused too, so the rail
	// cannot quietly keep capturing under it.
	if _, _, eerr := s.EnqueueStructuralOutbox(ctx, structKey("2026-09-03"), receipt, structBuild("exp2")); !errors.Is(eerr, ErrCloudGrantExpired) {
		t.Fatalf("capture under an expired grant: want ErrCloudGrantExpired, got %v", eerr)
	}
}

// TestPrepareStructuralSendDeclaresTheBoundReceiptsTerms is the F3 wire-header
// half. With two live standing receipts the drain used to resolve the NEWEST for
// the wire headers while validating each item against its OLDER bound receipt —
// an old-terms snapshot shipping a new-terms claim. The lease must carry the
// terms of the receipt the item is actually bound to.
//
// The two coexisting receipts are seeded directly, because `consent grant` now
// supersedes: the point is that the SEND path no longer depends on that rule
// holding.
func TestPrepareStructuralSendDeclaresTheBoundReceiptsTerms(t *testing.T) {
	s, database := cloudTestStore(t)
	ctx := context.Background()

	older := structSeedStandingReceiptAt(t, s, 7, nil)
	id, _, err := s.EnqueueStructuralOutbox(ctx, structKey("2026-09-04"), older, structBuild("bound"))
	if err != nil {
		t.Fatalf("EnqueueStructuralOutbox: %v", err)
	}
	// A newer live standing receipt for the same purpose, with different terms.
	newer := structSeedStandingReceiptAt(t, s, 8, nil)
	if _, err := database.ExecContext(ctx,
		`UPDATE cloud_consent_receipts SET data_dictionary_digest = 'sha256:NEW-DICTIONARY', source_window_rule = 'day.v2' WHERE id = ?`,
		newer); err != nil {
		t.Fatalf("retune newer receipt: %v", err)
	}

	_, lease, err := s.PrepareStructuralSend(ctx, id, structTestEndpoint)
	if err != nil {
		t.Fatalf("PrepareStructuralSend: %v", err)
	}
	if lease.ReceiptID != older {
		t.Fatalf("lease bound receipt = %q, want the item's own %q", lease.ReceiptID, older)
	}
	if lease.ConsentGeneration != 7 {
		t.Errorf("lease consent generation = %d, want 7 (the bound receipt's, not the newest grant's)", lease.ConsentGeneration)
	}
	if lease.DataDictionaryDigest != "sha256:dictionary" {
		t.Errorf("lease data-dictionary digest = %q, want the bound receipt's", lease.DataDictionaryDigest)
	}
	if lease.SourceWindowRule != "day.v1" {
		t.Errorf("lease source window rule = %q, want the bound receipt's", lease.SourceWindowRule)
	}

	// And the pre-dispatch check refuses a lease whose declared terms have been
	// swapped for the newer grant's — the exact shape of the old defect.
	forged := lease
	forged.ConsentGeneration = 8
	if verr := s.VerifyStructuralSendAuthorization(ctx, forged); !errors.Is(verr, ErrCloudStructuralSendUnauthorized) {
		t.Fatalf("a lease declaring another grant's generation must be refused, got %v", verr)
	}
}

// TestReplaceStandingConsentGrantSupersedes is the F3 single-live-receipt rule:
// re-granting a purpose retires the grant in force, in the same transaction as
// the insert, and parks (never silently cancels) what was queued under it.
func TestReplaceStandingConsentGrantSupersedes(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	first := structSeedStandingReceiptAt(t, s, 1, nil)
	queued, _, err := s.EnqueueStructuralOutbox(ctx, structKey("2026-09-05"), first, structBuild("sup"))
	if err != nil {
		t.Fatalf("EnqueueStructuralOutbox: %v", err)
	}

	rep, err := s.ReplaceStandingConsentGrant(ctx, CloudConsentReceipt{
		AccountPseudonym:     "acct-struct",
		Purpose:              cloudPurposeStructuralInsights,
		Endpoint:             structTestEndpoint,
		UploadDigest:         "sha256:dictionary-v2",
		DataDictionaryDigest: "sha256:dictionary-v2",
		DeclaredTimezone:     "Europe/Berlin",
		SourceWindowRule:     "day.v1",
	})
	if err != nil {
		t.Fatalf("ReplaceStandingConsentGrant: %v", err)
	}
	if rep.ConsentGeneration != 2 {
		t.Errorf("generation = %d, want 2 (allocated inside the transaction)", rep.ConsentGeneration)
	}
	if len(rep.SupersededReceiptIDs) != 1 || rep.SupersededReceiptIDs[0] != first {
		t.Errorf("superseded = %v, want [%s]", rep.SupersededReceiptIDs, first)
	}
	if rep.RequeuedForReconfirmation != 1 {
		t.Errorf("requeued = %d, want 1", rep.RequeuedForReconfirmation)
	}

	// Exactly one live standing receipt for the purpose, and it is the new one.
	live, err := s.ListLiveCloudConsentReceipts(ctx, cloudPurposeStructuralInsights)
	if err != nil {
		t.Fatalf("ListLiveCloudConsentReceipts: %v", err)
	}
	var standing []CloudConsentReceipt
	for _, r := range live {
		if r.GrantMode == CloudGrantStanding {
			standing = append(standing, r)
		}
	}
	if len(standing) != 1 || standing[0].ID != rep.ReceiptID {
		t.Fatalf("live standing receipts = %d, want exactly the new one", len(standing))
	}

	// The queued snapshot is parked for reconfirmation — not cancelled (which
	// would destroy a captured window) and not sendable under the new terms.
	it, ok, err := s.GetCloudOutbox(ctx, queued)
	if err != nil || !ok {
		t.Fatalf("GetCloudOutbox: %v ok=%v", err, ok)
	}
	if it.State != CloudOutboxReconfirmationRequired {
		t.Fatalf("queued item state = %q, want reconfirmation_required", it.State)
	}
	sendable, err := s.ListSendableStructuralOutbox(ctx)
	if err != nil {
		t.Fatalf("ListSendableStructuralOutbox: %v", err)
	}
	if len(sendable) != 0 {
		t.Fatalf("a re-grant left %d snapshot(s) sendable under the new terms", len(sendable))
	}
}

// TestStandingConsentGenerationIsUnique is the F4 backstop: migration 099's
// partial index refuses a duplicate (purpose, generation) for a standing grant,
// so a future path that bypasses the allocating transaction fails loudly instead
// of minting two different sets of terms under one generation number.
func TestStandingConsentGenerationIsUnique(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	structSeedStandingReceiptAt(t, s, 5, nil)
	_, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
		AccountPseudonym:     "acct-struct",
		Purpose:              cloudPurposeStructuralInsights,
		Endpoint:             structTestEndpoint,
		UploadDigest:         "sha256:other",
		GrantMode:            CloudGrantStanding,
		DataDictionaryDigest: "sha256:other",
		ConsentGeneration:    5,
	})
	if err == nil {
		t.Fatal("a second standing receipt with the same purpose+generation was accepted")
	}
	if !isUniqueConstraintErr(err) {
		t.Fatalf("want a UNIQUE constraint failure, got %v", err)
	}

	// The index is deliberately PARTIAL. Per-upload receipts never consult the
	// counter and legitimately share generation 0 — constraining them would break
	// ordinary per-session consent.
	for i := 0; i < 2; i++ {
		if _, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
			AccountPseudonym: "acct-struct",
			Purpose:          cloudPurposeStructuralInsights,
			Endpoint:         structTestEndpoint,
			UploadDigest:     fmt.Sprintf("sha256:per-upload-%d", i),
		}); err != nil {
			t.Fatalf("per-upload receipt %d must not be constrained by the standing index: %v", i, err)
		}
	}
	// ...and generation 0 on a standing row is an ABSENCE, not a value, so it
	// must not collide with itself either.
	for i := 0; i < 2; i++ {
		if _, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
			AccountPseudonym:     "acct-struct",
			Purpose:              cloudPurposeStructuralInsights,
			Endpoint:             structTestEndpoint,
			UploadDigest:         fmt.Sprintf("sha256:ungenerationed-%d", i),
			GrantMode:            CloudGrantStanding,
			DataDictionaryDigest: "sha256:x",
		}); err != nil {
			t.Fatalf("standing receipt %d with no allocated generation must be allowed: %v", i, err)
		}
	}
}
