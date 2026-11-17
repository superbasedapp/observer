package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/enrichbudget"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// tokenbudget_test.go pins ruling R-AI1 on the live schema: the default free
// plan (v5) budgets session enrichment in TOKENS (per-account day and month,
// per-session cumulative), keeps the concurrency cap, has no cap on the
// number of enrichments, and a tier can only name a bound, attested route.

const (
	luna       = "session_enrichment.luna.v1" // max_output_tokens 1024 (0005)
	gptOSS20b  = "session_enrichment.gpt-oss-20b.v1"
	gptOSS120b = "session_enrichment.gpt-oss-120b.v1"
)

// submitTokenJob submits one enrichment of session on the luna route with an
// envelope of size bytes.
func submitTokenJob(s *store.Store, acct, key, session string, size int64, now time.Time) (store.JobSubmission, error) {
	return s.SubmitJob(context.Background(), store.SubmitJobInput{
		AccountID: acct, CloudProjectID: "p", CloudSessionID: session,
		Tool: "codex", ModelFamily: "gpt-5.6", Feature: store.FeatureSessionEnrichment,
		RouteID: luna, RouteVersion: 1, PromptVersion: 1,
		CanonicalKey: key, UploadDigest: "sha256:" + key, ContentDigest: "sha256:c",
		BlobRef: "evidence/" + key, SizeBytes: size, EvidenceBytes: []byte(`{"a":1}`), Now: now,
	})
}

func lunaHold(size int64) int64 { return enrichbudget.WorstCaseTokens(size, 1024) }

func sessionLedger(t *testing.T, pool *pgxpool.Pool, acct, session string) int64 {
	t.Helper()
	var v int64
	if err := pool.QueryRow(context.Background(),
		`SELECT enrichment_tokens_committed FROM cloud_sessions WHERE account_id=$1::uuid AND cloud_session_id=$2`,
		acct, session).Scan(&v); err != nil {
		t.Fatalf("read session ledger: %v", err)
	}
	return v
}

// publishTier writes a tier version directly (the migrator's privilege), for
// tests that need budgets other than the seeded defaults.
func publishTier(t *testing.T, pool *pgxpool.Pool, tier enrichbudget.Tier) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO enrichment_tiers (tier, version, route_id, evidence_token_budget, session_token_budget, daily_token_budget, monthly_token_budget)
		 SELECT $1, coalesce(max(version), 0) + 1, $2, $3, $4, $5, $6 FROM enrichment_tiers WHERE tier = $1`,
		tier.Name, tier.RouteID, tier.EvidenceTokens, tier.SessionTokens, tier.DailyTokens, tier.MonthlyTokens); err != nil {
		t.Fatalf("publish tier: %v", err)
	}
}

func TestDefaultFreePlanIsTokenBudgeted(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := time.Now()

	allow, err := s.ResolveAllowance(ctx, acct, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("ResolveAllowance: %v", err)
	}
	if allow.Plan.Version != store.DefaultFreePlanVersion || allow.Plan.EnrichmentTier != "free" || allow.Tier == nil {
		t.Fatalf("default free plan = v%d tier %q (%v), want v%d on tier free", allow.Plan.Version, allow.Plan.EnrichmentTier, allow.Tier, store.DefaultFreePlanVersion)
	}
	if allow.Tier.RouteID != gptOSS20b || allow.Tier.EvidenceTokens != 4000 {
		t.Fatalf("free tier = %+v, want gpt-oss-20b with 4,000 evidence tokens", *allow.Tier)
	}
	if allow.DailyCap != 0 || allow.MonthlyCap != 0 || allow.ConcurrencyCap != 2 {
		t.Fatalf("count caps %d/%d concurrency %d, want 0/0 (not enforced) and concurrency 2", allow.DailyCap, allow.MonthlyCap, allow.ConcurrencyCap)
	}
	// A bare unit reservation cannot slip past the token budgets.
	if _, err := s.ReserveAllowance(ctx, acct, store.FeatureSessionEnrichment, now); !errors.Is(err, store.ErrTokenHoldMissing) {
		t.Fatalf("ReserveAllowance on a token plan: %v, want ErrTokenHoldMissing", err)
	}
	snap, err := s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if snap.BudgetUnit != "tokens" || snap.EnrichmentTier != "free" || snap.EvidenceTokenBudget != 4000 ||
		snap.DailyTokenBudget <= 0 || snap.MonthlyTokenBudget < snap.DailyTokenBudget || snap.SessionTokenBudget <= 0 {
		t.Fatalf("usage = %+v", snap)
	}
	if len(snap.Warnings) != 0 {
		t.Fatalf("an unused token plan must not warn (its count caps read 0 and are not enforced): %+v", snap.Warnings)
	}
}

// TestTokenReservationHoldSettleAndRelease: a submission holds its worst case
// in the day, month and session windows; settle books the provider's actual
// and gives the rest back; a release gives everything back; the concurrency
// slot comes back either way.
func TestTokenReservationHoldSettleAndRelease(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := time.Now()
	const size = 6000
	hold := lunaHold(size)

	sub, err := submitTokenJob(s, acct, "k1", "sess-a", size, now)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	snap, _ := s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if snap.DailyTokensUsed != hold || snap.MonthlyTokensUsed != hold || snap.ConcurrencyUsed != 1 {
		t.Fatalf("after submit: day %d month %d in-flight %d, want %d/%d/1", snap.DailyTokensUsed, snap.MonthlyTokensUsed, snap.ConcurrencyUsed, hold, hold)
	}
	if got := sessionLedger(t, pool, acct, "sess-a"); got != hold {
		t.Fatalf("session ledger = %d, want the hold %d", got, hold)
	}

	// Complete it: the provider reported 5,000 in + 1,200 out.
	lj, err := s.LeaseNextJob(ctx, "w1", []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || lj == nil || lj.JobID != sub.JobID {
		t.Fatalf("lease: %v (%v)", err, lj)
	}
	if err := s.MarkJobRunning(ctx, acct, lj.JobID, now); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.CompleteJobWithResult(ctx, acct, lj.JobID, lj.EvidencePK, lj.ReservationID, "w1", lj.LeaseGeneration,
		"session_enrichment.v2-candidate", []byte(`{"title":"t","schema_version":"session_enrichment.v2-candidate"}`),
		store.ResultProvenance{ModelRouteID: luna, TokensIn: 5000, TokensOut: 1200}, now); err != nil || !ok {
		t.Fatalf("complete: %v %v", ok, err)
	}
	snap, _ = s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if snap.DailyTokensUsed != 6200 || snap.MonthlyTokensUsed != 6200 || snap.ConcurrencyUsed != 0 {
		t.Fatalf("after settle: day %d month %d in-flight %d, want 6200/6200/0", snap.DailyTokensUsed, snap.MonthlyTokensUsed, snap.ConcurrencyUsed)
	}
	if got := sessionLedger(t, pool, acct, "sess-a"); got != 6200 {
		t.Fatalf("session ledger after settle = %d, want 6200", got)
	}

	// A second job that never runs is released: everything it held comes back.
	sub2, err := submitTokenJob(s, acct, "k2", "sess-b", size, now)
	if err != nil {
		t.Fatalf("submit 2: %v", err)
	}
	if err := s.CancelJob(ctx, acct, sub2.JobID, now); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	snap, _ = s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if snap.DailyTokensUsed != 6200 || snap.ConcurrencyUsed != 0 {
		t.Fatalf("after release: day %d in-flight %d, want 6200/0", snap.DailyTokensUsed, snap.ConcurrencyUsed)
	}
	if got := sessionLedger(t, pool, acct, "sess-b"); got != 0 {
		t.Fatalf("released session ledger = %d, want 0", got)
	}
}

// TestTokenSettleWithoutMeterBooksTheHold: a provider that reports no prompt
// tokens never makes a call free (A12): the settle keeps the whole hold.
func TestTokenSettleWithoutMeterBooksTheHold(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := time.Now()
	sub, err := submitTokenJob(s, acct, "k1", "sess", 4000, now)
	if err != nil {
		t.Fatal(err)
	}
	lj, err := s.LeaseNextJob(ctx, "w1", []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || lj == nil || lj.JobID != sub.JobID {
		t.Fatalf("lease: %v", err)
	}
	_ = s.MarkJobRunning(ctx, acct, lj.JobID, now)
	if _, ok, err := s.CompleteJobWithResult(ctx, acct, lj.JobID, lj.EvidencePK, lj.ReservationID, "w1", lj.LeaseGeneration,
		"session_enrichment.v2-candidate", []byte(`{"title":"t","schema_version":"session_enrichment.v2-candidate"}`),
		store.ResultProvenance{}, now); err != nil || !ok {
		t.Fatalf("complete: %v %v", ok, err)
	}
	if got := sessionLedger(t, pool, acct, "sess"); got != lunaHold(4000) {
		t.Fatalf("a missing meter booked %d, want the hold %d", got, lunaHold(4000))
	}
}

// TestSessionBudgetIsCumulativeAcrossReEnrichments: re-enriching a grown
// session charges against what that session already used and stops when its
// budget is spent, while another session of the same account still runs and
// the number of sessions is not capped.
func TestSessionBudgetIsCumulativeAcrossReEnrichments(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := time.Now()
	const size = 2000
	hold := lunaHold(size) // 1000 + 3072 + 1024 = 5096
	// Session budget: room for exactly two holds of this size.
	publishTier(t, pool, enrichbudget.Tier{
		Name: "free", RouteID: gptOSS20b, EvidenceTokens: 4000,
		SessionTokens: 2 * hold, DailyTokens: 1_000_000, MonthlyTokens: 10_000_000,
	})

	for i, key := range []string{"v1", "v2"} {
		sub, err := submitTokenJob(s, acct, key, "grows", size, now)
		if err != nil {
			t.Fatalf("enrichment %d of the session: %v", i+1, err)
		}
		if err := s.SettleReservation(ctx, acct, sub.ReservationID); err != nil {
			t.Fatal(err)
		}
	}
	// The third re-enrichment of the SAME session (a new upload: it grew) is
	// over its cumulative budget.
	if _, err := submitTokenJob(s, acct, "v3", "grows", size, now); !errors.Is(err, store.ErrSessionTokenBudget) {
		t.Fatalf("third enrichment of a spent session: %v, want ErrSessionTokenBudget", err)
	}
	// No cap on the number of sessions: twenty other sessions still run.
	for i := 0; i < 20; i++ {
		sub, err := submitTokenJob(s, acct, "other-"+string(rune('a'+i)), "other-"+string(rune('a'+i)), size, now)
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		if err := s.SettleReservation(ctx, acct, sub.ReservationID); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAccountTokenBudgetsAndConcurrency: the daily budget refuses the hold
// that would pass it (a hold landing exactly on it is admitted), and the
// concurrency cap still bounds jobs in flight.
func TestAccountTokenBudgetsAndConcurrency(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := time.Now()
	const size = 2000
	hold := lunaHold(size)
	publishTier(t, pool, enrichbudget.Tier{
		Name: "free", RouteID: gptOSS20b, EvidenceTokens: 4000,
		SessionTokens: 1_000_000, DailyTokens: 3 * hold, MonthlyTokens: 10_000_000,
	})

	// Concurrency 2 (the plan's): the third in-flight job is refused.
	a, err := submitTokenJob(s, acct, "a", "sa", size, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := submitTokenJob(s, acct, "b", "sb", size, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := submitTokenJob(s, acct, "c", "sc", size, now); !errors.Is(err, store.ErrConcurrency) {
		t.Fatalf("third in-flight: %v, want ErrConcurrency", err)
	}
	for _, sub := range []store.JobSubmission{a, b} {
		if err := s.SettleReservation(ctx, acct, sub.ReservationID); err != nil {
			t.Fatal(err)
		}
	}
	// The third hold lands exactly on the daily budget: admitted.
	c, err := submitTokenJob(s, acct, "c", "sc", size, now)
	if err != nil {
		t.Fatalf("hold landing on the budget: %v", err)
	}
	if err := s.SettleReservation(ctx, acct, c.ReservationID); err != nil {
		t.Fatal(err)
	}
	_, err = submitTokenJob(s, acct, "d", "sd", size, now)
	if !errors.Is(err, store.ErrDailyTokenBudget) || !errors.Is(err, store.ErrDailyLimit) {
		t.Fatalf("over the daily budget: %v, want ErrDailyTokenBudget (wrapping ErrDailyLimit)", err)
	}
	// The next UTC day resets the daily window (same month, far below its
	// budget). Pinned mid-month so the day step never crosses a month.
	mid := time.Date(now.Year(), now.Month(), 14, 12, 0, 0, 0, time.UTC)
	acct2 := makeAccount(t, s)
	for i, key := range []string{"m1", "m2", "m3"} {
		sub, err := submitTokenJob(s, acct2, key, "m-"+key, size, mid)
		if err != nil {
			t.Fatalf("day one, job %d: %v", i, err)
		}
		_ = s.SettleReservation(ctx, acct2, sub.ReservationID)
	}
	if _, err := submitTokenJob(s, acct2, "m4", "m-m4", size, mid); !errors.Is(err, store.ErrDailyTokenBudget) {
		t.Fatalf("day one over budget: %v", err)
	}
	if _, err := submitTokenJob(s, acct2, "m5", "m-m5", size, mid.Add(24*time.Hour)); err != nil {
		t.Fatalf("the next day must reset the daily window: %v", err)
	}
}

// TestTokenPathKeepsThePoolSpendCeiling: the shared Free pool's USD ceiling
// (0044) still refuses a token-budgeted submission once it is reached, and
// the refusal writes nothing.
func TestTokenPathKeepsThePoolSpendCeiling(t *testing.T) {
	s, pool := newStore(t)
	acct := makeAccount(t, s)
	now := time.Now()
	setSpend(t, pool, store.FreeBudgetPool, "daily", store.DailyWindowKey(now), store.DefaultFreeDailyUSD)
	before := poolBalance(t, pool, store.FreeBudgetPool)
	if _, err := submitTokenJob(s, acct, "k", "sess", 2000, now); !errors.Is(err, store.ErrSpendCeiling) {
		t.Fatalf("token submission at the pool ceiling: %v, want ErrSpendCeiling", err)
	}
	if got := poolBalance(t, pool, store.FreeBudgetPool); got != before {
		t.Fatalf("a refused submission moved the pool: %d -> %d", before, got)
	}
	snap, _ := s.Usage(context.Background(), acct, store.FeatureSessionEnrichment, now)
	if snap.DailyTokensUsed != 0 || snap.ConcurrencyUsed != 0 {
		t.Fatalf("a refused submission held tokens: %+v", snap)
	}
}

// TestPublishTierRefusesUnboundAndUnattestedRoutes is the R-AI1 rule that a
// tier only SELECTS among bound, attested routes: the seeded gpt-oss-20b
// route is unbound, so publishing a tier on it is refused and nothing is
// written; once bound, priced and active it is still refused without an
// attestation for its CURRENT generation; with one it publishes v2.
func TestPublishTierRefusesUnboundAndUnattestedRoutes(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	want := enrichbudget.Tier{
		Name: "free", RouteID: gptOSS20b, EvidenceTokens: 5000,
		SessionTokens: 80000, DailyTokens: 300000, MonthlyTokens: 3_000_000,
	}

	route, err := s.RouteByID(ctx, gptOSS20b)
	if err != nil {
		t.Fatal(err)
	}
	verified := store.RouteAttestation{Verified: true, Reason: "disclosed", Generation: route.Generation}
	_, err = s.PublishTier(ctx, store.TierPublish{Tier: want, Attestation: verified})
	if !errors.Is(err, enrichbudget.ErrInvalidTier) || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("publish on the unbound, inactive seed route: %v, want a refusal", err)
	}
	// Active but unbound is still refused.
	if err := s.SetRouteActive(ctx, gptOSS20b, true); err != nil {
		t.Fatal(err)
	}
	route, _ = s.RouteByID(ctx, gptOSS20b)
	verified.Generation = route.Generation
	if _, err := s.PublishTier(ctx, store.TierPublish{Tier: want, Attestation: verified}); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("publish on an active, unbound route: %v, want a refusal", err)
	}

	// Bind it the way `route bind-openai-compatible` does (no api_version:
	// the openai_compatible dialect has none) and price it.
	if err := s.SetRouteBinding(ctx, gptOSS20b, store.RouteBinding{
		TenantID: "openai_compatible", SubscriptionID: "default", ARMResourceID: "openai_compatible:chat:gpt-oss-20b",
		EndpointAudience: "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1", Endpoint: "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRoutePrice(ctx, gptOSS20b, 0.05, 0.2, "test-prices"); err != nil {
		t.Fatal(err)
	}
	route, _ = s.RouteByID(ctx, gptOSS20b)
	if !store.RouteBound(route) {
		t.Fatalf("a bound openai_compatible route (empty api_version) must read as bound: %+v", route)
	}
	// An attestation taken before the bind (an older generation) does not count.
	if _, err := s.PublishTier(ctx, store.TierPublish{Tier: want, Attestation: verified}); err == nil || !strings.Contains(err.Error(), "not attested") {
		t.Fatalf("publish with a stale attestation: %v, want a refusal", err)
	}
	// An unhealthy verdict does not count either.
	if _, err := s.PublishTier(ctx, store.TierPublish{Tier: want, Attestation: store.RouteAttestation{Reason: "no disclosure", Generation: route.Generation}}); err == nil || !strings.Contains(err.Error(), "no disclosure") {
		t.Fatalf("publish with an unhealthy attestation: %v, want a refusal", err)
	}
	var versions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM enrichment_tiers WHERE tier='free'`).Scan(&versions); err != nil || versions != 1 {
		t.Fatalf("refused publishes wrote rows: %d (%v), want the seed only", versions, err)
	}

	got, err := s.PublishTier(ctx, store.TierPublish{
		Tier:        want,
		Attestation: store.RouteAttestation{Verified: true, Reason: "disclosed", Generation: route.Generation}, PublishedBy: "test",
	})
	if err != nil {
		t.Fatalf("publish on a bound, priced, attested route: %v", err)
	}
	if got.Version != 2 {
		t.Fatalf("published v%d, want v2", got.Version)
	}
	inForce, err := s.ResolveTier(ctx, "free")
	if err != nil || inForce.Version != 2 || inForce.EvidenceTokens != 5000 {
		t.Fatalf("tier in force = %+v (%v), want v2", inForce, err)
	}
	// A tier pinning the bound openai_compatible route now resolves to it
	// rather than degrading as "unbound".
	resolved, fb, err := s.ResolveRouteForPlan(ctx, store.FeatureSessionEnrichment, gptOSS20b)
	if err != nil || fb.Fell() || resolved.RouteID != gptOSS20b {
		t.Fatalf("ResolveRouteForPlan(20b) = %s fallback %+v err %v, want the 20b route itself", resolved.RouteID, fb, err)
	}
	// A paid tier on the 120b route that is still unbound is refused.
	paid := want
	paid.Name, paid.RouteID = "paid", gptOSS120b
	if _, err := s.PublishTier(ctx, store.TierPublish{Tier: paid, Attestation: store.RouteAttestation{Verified: true, Generation: 0}}); err == nil {
		t.Fatal("a tier on the unbound 120b route was published")
	}
}
