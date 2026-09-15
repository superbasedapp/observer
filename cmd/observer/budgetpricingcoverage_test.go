package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// THE LIVE DEFECT, AS A TEST (ruling A1/A2/A3, 2026-09-15).
//
// On a managed node with an org hard cap of $2/day, a developer's Muse and
// OpenCode rows all named models the org had never quoted. The node's own
// dashboard priced the day at $0.97 through the cost engine's fallback ladder;
// the managed budget read accepted only exact and org rates, called the very
// same rows unpriced, reported the daily window unavailable, and the guard
// TERMed the running processes and refused every relaunch at "$0.26 of $2".
//
// Three truths about one day's usage on one machine. These tests pin the one
// that replaced them: the same ladder, the same dollars, and unpriced usage
// reported rather than enforced.

// fallbackPricedModel is a real model id the builtin table resolves through
// its FAMILY rung - the exact shape the live defect turned on. It is asserted
// rather than assumed below, so a future seed table that starts quoting it
// exactly fails loudly instead of quietly making the test vacuous.
const fallbackPricedModel = "muse-spark-1.3-contributor"

// TestManagedBudgetPricesWithTheSameLadderAsTheDashboard is the equality A4
// asks for: the dollars the MANAGED budget read counts and the dollars the
// dashboard's own engine computes for the same row must be the same number.
func TestManagedBudgetPricesWithTheSameLadderAsTheDashboard(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	engine := cost.NewEngine(config.IntelligenceConfig{})
	table := engine.Table()

	pricing, source, ok := table.LookupWithSourceAt(fallbackPricedModel, time.Time{})
	if !ok || source == cost.PricingSourceExact || source == cost.PricingSourceOrg {
		t.Fatalf("%q resolved as %q (ok=%v); this test needs a FALLBACK rung", fallbackPricedModel, source, ok)
	}
	split := store.PushTokenSplit{Input: 102_000, Output: 2_000}
	// What the dashboard would charge for exactly these counters.
	want := cost.ComputeBreakdown(pricing, cost.TokenBundle{Input: split.Input, Output: split.Output}).Total
	if want <= 0 {
		t.Fatalf("fallback rate produced no dollars: %v", want)
	}

	database, err := db.Open(ctx, db.Options{Path: t.TempDir() + "/observer.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	now := time.Now().UTC()
	if _, err := st.IngestBudgetUsage(ctx, nil, []models.TokenEvent{{
		SessionID: "muse-session", SourceEventID: "one", Tool: "muse", Model: fallbackPricedModel,
		ProjectRoot: t.TempDir(), SourceFile: "fixture", Timestamp: now,
		InputTokens: split.Input, OutputTokens: split.Output,
		Source: "jsonl", Reliability: "approximate",
	}}, nil); err != nil {
		t.Fatal(err)
	}

	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	spend, err := st.GuardBudgetSpendPriced(ctx, "", day, day.AddDate(0, 0, -7), day.AddDate(0, -1, 0),
		managedBudgetTablePricer(table, ""), store.GuardBudgetReadOptions{Managed: true})
	if err != nil {
		t.Fatal(err)
	}
	if spend.DailyUSD != want {
		t.Fatalf("managed daily = %v, dashboard = %v; the two must price one row identically", spend.DailyUSD, want)
	}
	if spend.UnpricedRows != 0 {
		t.Fatalf("a fallback-priced row was still counted as unpriced: %+v", spend)
	}

	// ... and the gap is REPORTED, which is what replaced the denial. It is a
	// FALLBACK-priced row (BUDGET-COV-3): it names its model on the fallback
	// list, not the true-miss list, because its dollars DO count against the
	// cap - the coverage is `fallback`, never `partial`, and no row is unpriced.
	cov := budgetPricingCoverageOf(spend)
	if cov.Coverage != orgcontract.PricingCoverageFallback || cov.FallbackRows != 1 ||
		len(cov.FallbackModels) != 1 || cov.FallbackModels[0] != fallbackPricedModel {
		t.Fatalf("coverage = %+v, want one fallback-priced row naming %q", cov, fallbackPricedModel)
	}
	if cov.UnpricedRows != 0 || len(cov.UnpricedModels) != 0 {
		t.Fatalf("coverage = %+v, want zero true misses for a fallback-priced day", cov)
	}
	if line := budgetPricingCoverageLine(cov); line == "" {
		t.Fatal("status line said nothing about a fallback-priced day")
	}
}

// TestBudgetPricingCoverageSplitsFallbackFromTrueMiss is the BUDGET-COV-3
// regression: a day carrying BOTH a fallback-priced model and a true miss must
// report them on SEPARATE lists, and the model that WAS priced (and so counted
// toward the cap) must never appear as "no rate at all". Both models are `muse`
// / `opencode` shapes from the live proof.
func TestBudgetPricingCoverageSplitsFallbackFromTrueMiss(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	engine := cost.NewEngine(config.IntelligenceConfig{})
	table := engine.Table()
	if _, source, ok := table.LookupWithSourceAt(fallbackPricedModel, time.Time{}); !ok ||
		source == cost.PricingSourceExact || source == cost.PricingSourceOrg {
		t.Fatalf("%q is not a fallback rung; this test needs one", fallbackPricedModel)
	}

	database, err := db.Open(ctx, db.Options{Path: t.TempDir() + "/observer.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	now := time.Now().UTC()
	root := t.TempDir()
	if _, err := st.IngestBudgetUsage(ctx, nil, []models.TokenEvent{
		{
			SessionID: "muse-session", SourceEventID: "fallback-one", Tool: "muse", Model: fallbackPricedModel,
			ProjectRoot: root, SourceFile: "fixture", Timestamp: now,
			InputTokens: 50_000, OutputTokens: 1_000, Source: "jsonl", Reliability: "approximate",
		},
		{
			SessionID: "muse-session", SourceEventID: "fallback-two", Tool: "muse", Model: fallbackPricedModel,
			ProjectRoot: root, SourceFile: "fixture", Timestamp: now,
			InputTokens: 52_000, OutputTokens: 1_000, Source: "jsonl", Reliability: "approximate",
		},
		{
			SessionID: "opencode-session", SourceEventID: "miss-one", Tool: "opencode", Model: "big-pickle",
			ProjectRoot: root, SourceFile: "fixture", Timestamp: now,
			InputTokens: 1_000, OutputTokens: 10, Source: "jsonl", Reliability: "approximate",
		},
	}, nil); err != nil {
		t.Fatal(err)
	}

	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	spend, err := st.GuardBudgetSpendPriced(ctx, "", day, day.AddDate(0, 0, -7), day.AddDate(0, -1, 0),
		managedBudgetTablePricer(table, ""), store.GuardBudgetReadOptions{Managed: true})
	if err != nil {
		t.Fatal(err)
	}
	cov := budgetPricingCoverageOf(spend)
	// A true miss makes the ENUM partial, but the fallback model stays on the
	// fallback list with its own count - never conflated into "no rate at all".
	if cov.Coverage != orgcontract.PricingCoveragePartial {
		t.Fatalf("coverage = %q, want partial (a true miss is present)", cov.Coverage)
	}
	if cov.FallbackRows != 2 || len(cov.FallbackModels) != 1 || cov.FallbackModels[0] != fallbackPricedModel {
		t.Fatalf("fallback list = rows %d models %v, want 2 rows naming %q only", cov.FallbackRows, cov.FallbackModels, fallbackPricedModel)
	}
	if cov.UnpricedRows != 1 || len(cov.UnpricedModels) != 1 || cov.UnpricedModels[0] != "big-pickle" {
		t.Fatalf("true-miss list = rows %d models %v, want 1 row naming big-pickle only", cov.UnpricedRows, cov.UnpricedModels)
	}
	line := budgetPricingCoverageLine(cov)
	if !strings.Contains(line, "fallback_rows=2") || !strings.Contains(line, "fallback_models="+fallbackPricedModel) ||
		!strings.Contains(line, "unpriced_rows=1") || !strings.Contains(line, "unpriced_models=big-pickle") {
		t.Fatalf("status line = %q, want both class pairs printed separately", line)
	}
}

// TestManagedBudgetTrueMissFlagsPartialWithoutDenial pins the OTHER half: a
// model nothing can price counts as $0 - honestly, because inventing a number
// would be worse - and says so, and still does not stop anybody.
func TestManagedBudgetTrueMissFlagsPartialWithoutDenial(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: t.TempDir() + "/observer.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	now := time.Now().UTC()
	if _, err := st.IngestBudgetUsage(ctx, nil, []models.TokenEvent{{
		SessionID: "unknown-session", SourceEventID: "one", Tool: "muse",
		Model: "definitely-not-a-model-xyz", ProjectRoot: t.TempDir(), SourceFile: "fixture",
		Timestamp: now, InputTokens: 1000, OutputTokens: 10,
		Source: "jsonl", Reliability: "approximate",
	}}, nil); err != nil {
		t.Fatal(err)
	}
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	spend, err := st.GuardBudgetSpendPriced(ctx, "", day, day.AddDate(0, 0, -7), day.AddDate(0, -1, 0),
		managedBudgetTablePricer(cost.NewEngine(config.IntelligenceConfig{}).Table(), ""),
		store.GuardBudgetReadOptions{Managed: true})
	if err != nil {
		t.Fatal(err)
	}
	if spend.DailyUSD != 0 || spend.UnpricedRows != 1 {
		t.Fatalf("an unpriceable row invented dollars or lost its flag: %+v", spend)
	}
	cov := budgetPricingCoverageOf(spend)
	if cov.Coverage != orgcontract.PricingCoveragePartial || cov.UnpricedRows != 1 {
		t.Fatalf("coverage = %+v, want partial with one row", cov)
	}
}

// TestBudgetLaunchAllowsFallbackPricedUsageUnderCap is the end-to-end
// regression: the launch boundary, under a MANAGED USD hard cap, with the live
// defect's own usage shape - models the org's signed price document does not
// quote - must START THE PROCESS.
//
// It goes through enforceBudgetControlledLaunch rather than calling
// CheckInterventionBudget directly precisely because that is the path the
// developer hit: the same guard, the same rules, the same accounting seam,
// reached from a cold launcher process.
func TestBudgetLaunchAllowsFallbackPricedUsageUnderCap(t *testing.T) {
	for _, tc := range []struct {
		name  string
		model string
	}{
		{name: "fallback rate", model: fallbackPricedModel},
		// A model NOTHING prices counts as $0, which is under any cap. It is
		// flagged on the posture, never at the launch gate.
		{name: "no rate at all", model: "definitely-not-a-model-xyz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, false, "enforce")
			seedManagedUSDCapAndOrgPrices(t, dbPath)
			// The usage is recorded under the SAME tool that is launching.
			// That is what makes this a regression and not a bystander test:
			// the old accounting attributed an unpriceable row to its tool, so
			// this is exactly the pair - a tool, and its own usage that the
			// org's rates do not quote - that used to stop the launch.
			recordManagedBudgetUsage(t, dbPath, "claude-code", tc.model)
			if err := enforceBudgetControlledLaunch(context.Background(), cfgPath, "claude-code",
				budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://127.0.0.1:8820"}); err != nil {
				t.Fatalf("a launch under a $2 cap was refused over %s: %v", tc.name, err)
			}
		})
	}
}

// seedManagedUSDCapAndOrgPrices gives the fixture a signed $2/day hard cap AND
// a verified org price document.
//
// BOTH are required and neither is the thing under test. The cap must be
// DOLLAR-denominated (the shared fixture's cap is token-denominated, which
// exercises no pricing at all), and a managed dollar decision is fail-closed
// without a durable pricing witness - so the org document exists to satisfy
// that rule, and it deliberately quotes a model the usage does not use. That is
// the live shape: the org's rates are real, verified and applied, and they
// price none of this developer's traffic.
func seedManagedUSDCapAndOrgPrices(t *testing.T, dbPath string) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	identity, active, err := orgclient.CurrentBudgetIdentity(ctx, st)
	if err != nil || !active {
		t.Fatalf("fixture identity: active=%v err=%v", active, err)
	}
	now := time.Now().UTC()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertOrgRoutingPolicy(ctx, store.OrgRoutingPolicyRow{
		Version: 1, Body: "{}", BodyHash: "fixture",
		ServerPubkey: base64.StdEncoding.EncodeToString(pub), ReceivedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	doc, err := orgcontract.SignBudgetPolicy(priv, identity.OrgID, identity.UserID, orgcontract.BudgetPolicyBody{
		Version: 1, IssuedAt: now.Format(time.RFC3339),
		Caps: []orgcontract.BudgetPolicyCap{{
			Period: orgcontract.BudgetPolicyPeriodCalendarDay, Timezone: "UTC",
			CapUSD: 2, Enforcement: orgcontract.BudgetPolicyEnforcementHard,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveOrgBudget(ctx, doc, `"fixture"`, orgcontract.PublicKeyPinHash(pub), identity); err != nil {
		t.Fatal(err)
	}
	priceDoc, err := orgcontract.SignPricingPolicy(priv, identity.OrgID, orgcontract.PricingPolicyBody{
		Version: 1,
		Rows: []orgcontract.PricingPolicyRow{{
			Model: "a-model-this-developer-never-uses", InputPerMTok: orgcontract.Rate(1),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Saved under the SAME pinned key the budget document is signed with, so
	// the cold launcher's own loader verifies it exactly as a live node does.
	if _, err := st.SaveOrgPricingWithWitness(ctx, priceDoc, orgcontract.PublicKeyPinHash(pub),
		orgcontract.PricingFetchVerified, identity); err != nil {
		t.Fatal(err)
	}
}

// recordManagedBudgetUsage records one well-formed native row: every counter
// present, a source and reliability a managed read accepts. Only the MODEL
// varies, which is the whole point - the row is perfectly good evidence, and
// the org simply never quoted a rate for what produced it.
func recordManagedBudgetUsage(t *testing.T, dbPath, tool, model string) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	if _, err := store.New(database).IngestBudgetUsage(ctx, nil, []models.TokenEvent{{
		SessionID: "usage-" + tool, SourceEventID: "usage-1", Tool: tool, Model: model,
		ProjectRoot: t.TempDir(), SourceFile: "fixture", Timestamp: time.Now().UTC(),
		InputTokens: 102_000, OutputTokens: 2_000, Source: "jsonl", Reliability: "approximate",
	}}, nil); err != nil {
		t.Fatal(err)
	}
}
