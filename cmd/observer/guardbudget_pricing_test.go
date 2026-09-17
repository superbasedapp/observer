package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestGuardBudgetPricerPinsOneTableForWholeRead(t *testing.T) {
	engine := cost.NewEngine(config.IntelligenceConfig{})
	row := cost.OrgPrice{Model: "fixture-model", Pricing: cost.Pricing{Input: 1, Output: 2}, Set: cost.OrgPriceSet{Input: true, Output: true}}
	engine.SetOrgRows([]cost.OrgPrice{row}, 1, true)
	read := guardBudgetPricer(engine)
	split := store.PushTokenSplit{Input: 1_000_000}
	first, source, ok := read(row.Model, time.Now(), split)
	if !ok || source != "org" || first != 1 {
		t.Fatalf("first price=%v source=%q ok=%v", first, source, ok)
	}
	row.Input = 100
	engine.SetOrgRows([]cost.OrgPrice{row}, 2, true)
	second, _, ok := read(row.Model, time.Now(), split)
	if !ok || second != first {
		t.Fatalf("in-flight read mixed price revisions: %v then %v", first, second)
	}
	latest, _, ok := guardBudgetPricer(engine)(row.Model, time.Now(), split)
	if !ok || latest != 100 {
		t.Fatalf("next read missed new price: %v ok=%v", latest, ok)
	}
}

func TestGuardBudgetAccountingCarriesDurablePricingWitness(t *testing.T) {
	ctx := context.Background()
	_, dbPath := writeManagedBudgetLaunchFixture(t, false, "enforce")
	t.Setenv("HOME", t.TempDir())
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	identity, active, err := orgclient.CurrentBudgetIdentity(ctx, st)
	if err != nil || !active {
		t.Fatalf("fixture identity: active=%v err=%v", active, err)
	}
	budgetDoc := orgcontract.BudgetPolicyDoc{BudgetPolicyBody: orgcontract.BudgetPolicyBody{
		Version: 1, Caps: []orgcontract.BudgetPolicyCap{{
			Period: orgcontract.BudgetPolicyPeriodCalendarDay, Timezone: "UTC",
			CapUSD: 0.35, Enforcement: orgcontract.BudgetPolicyEnforcementHard,
		}},
	}}
	budgetWitness, err := st.SaveOrgBudgetWithWitness(ctx, budgetDoc, "fixture", "fixture", identity)
	if err != nil {
		t.Fatal(err)
	}
	priceDoc := orgcontract.PricingPolicyDoc{PricingPolicyBody: orgcontract.PricingPolicyBody{
		Version: 1, Rows: []orgcontract.PricingPolicyRow{{Model: "fixture-model", InputPerMTok: orgcontract.Rate(1), OutputPerMTok: orgcontract.Rate(0)}},
	}}
	priceWitness, err := st.SaveOrgPricingWithWitness(ctx, priceDoc, "fixture", orgcontract.PricingFetchVerified, identity)
	if err != nil {
		t.Fatal(err)
	}
	engine := cost.NewEngine(config.IntelligenceConfig{})
	engine.SetOrgRowsWithWitness(orgPriceRowsOf(priceDoc.Rows), 1, true, identity.Binding,
		cost.PricingDocumentWitness{Known: priceWitness.Known, Present: priceWitness.Present, SHA256: priceWitness.SHA256})
	processCostEngines.mu.Lock()
	processCostEngines.m[dbPath] = engine
	processCostEngines.mu.Unlock()
	t.Cleanup(func() {
		processCostEngines.mu.Lock()
		delete(processCostEngines.m, dbPath)
		processCostEngines.mu.Unlock()
	})
	_, err = st.IngestBudgetUsage(ctx, nil, []models.TokenEvent{{
		SessionID: "priced-native", SourceEventID: "one", Tool: "muse", Model: "fixture-model",
		ProjectRoot: t.TempDir(), SourceFile: "fixture", Timestamp: time.Now().UTC(),
		InputTokens: 1_000_000, Source: "jsonl", Reliability: "approximate",
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Observer.DBPath, cfg.Guard.Enabled, cfg.Guard.Mode = dbPath, true, "enforce"
	gd := buildGuardForStore(ctx, cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if gd == nil {
		t.Fatal("production guard composition failed")
	}
	if err := gd.ApplyOrgBudgetWithWitness(config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true}, nil, false,
		policy.BudgetProtection{DailyUSD: true}, identity.Binding, guardBudgetDocumentWitness(budgetWitness)); err != nil {
		t.Fatal(err)
	}
	decision := gd.CheckInterventionBudget(guard.InterventionBudgetInput{SourceReady: true, Now: time.Now().UTC(), BudgetBinding: identity.Binding})
	if !decision.Deny || !decision.PricingDocumentRequired || decision.AccountingEvidence == nil || decision.AccountingEvidence.PricingDocumentWitness.SHA256 != priceWitness.SHA256 {
		t.Fatalf("production lookup lost exact price witness: %+v", decision)
	}
	w := intervention.Workload{SurfaceID: "muse/cli", Identity: intervention.Identity{UID: 1000}}
	pending, err := nodeInterventionBudget(ctx, st, cfg, gd, w, nodeInterventionSource{Tool: "muse", Ready: true, Reason: "ready"}, time.Now().UTC())
	if err != nil || !pending.Stop {
		t.Fatalf("production policy did not require cutoff: %+v err=%v", pending, err)
	}
	// Persist a lower rate without publishing it into the engine. The old
	// table pointer still matches, so only the durable pricing witness can
	// prevent its stale USD denial from reaching a process operation.
	priceDoc.Version++
	priceDoc.Rows[0].InputPerMTok = orgcontract.Rate(0.1)
	if _, err := st.SaveOrgPricingWithWitness(ctx, priceDoc, "fixture", orgcontract.PricingFetchVerified, identity); err != nil {
		t.Fatal(err)
	}
	actionCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	called := false
	_, err = nodeInterventionSignalFence(st, gd)(actionCtx, w, pending, func(context.Context) (intervention.ExitResult, error) {
		called = true
		return intervention.ExitResult{Observed: true}, nil
	})
	if err == nil || called {
		t.Fatalf("new durable prices did not fence the old guard calculation: called=%v err=%v", called, err)
	}
	// A price table without durable provenance is unavailable accounting, not
	// a measured breach whose impossible witness would disable physical cutoff.
	engine.SetOrgRowsWithWitness(orgPriceRowsOf(priceDoc.Rows), priceDoc.Version, true, identity.Binding, cost.PricingDocumentWitness{})
	unknown := gd.CheckInterventionBudget(guard.InterventionBudgetInput{SourceReady: true, Now: time.Now().UTC(), BudgetBinding: identity.Binding})
	if !unknown.Deny || unknown.PricingDocumentRequired || unknown.RuleID != "B-602" {
		t.Fatalf("unverified pricing did not produce an accounting-unavailable refusal: %+v", unknown)
	}
	if _, err := database.ExecContext(ctx, `UPDATE token_usage SET model = 'gpt-5-mini', input_tokens = 1000 WHERE session_id = 'priced-native'`); err != nil {
		t.Fatal(err)
	}
	engine.SetOrgRowsWithWitness(nil, 0, true, identity.Binding, cost.PricingDocumentWitness{Known: true})
	currentEmpty := gd.CheckInterventionBudget(guard.InterventionBudgetInput{SourceReady: true, Now: time.Now().UTC(), BudgetBinding: identity.Binding})
	if currentEmpty.Deny {
		t.Fatalf("known current pricing absence rejected priced below-cap usage: %+v", currentEmpty)
	}
	engine.SetOrgRowsWithWitness(nil, 0, true, "previous-enrollment", cost.PricingDocumentWitness{Known: true})
	foreignEmpty := gd.CheckInterventionBudget(guard.InterventionBudgetInput{SourceReady: true, Now: time.Now().UTC(), BudgetBinding: identity.Binding})
	if !foreignEmpty.Deny || foreignEmpty.PricingDocumentRequired || foreignEmpty.RuleID != "B-602" {
		t.Fatalf("another enrollment's empty pricing table established measured spend: %+v", foreignEmpty)
	}
}

func TestManagedBudgetPricerRejectsAnotherEnrollmentRate(t *testing.T) {
	engine := cost.NewEngine(config.IntelligenceConfig{})
	row := cost.OrgPrice{Model: "fixture-model", Pricing: cost.Pricing{Input: 1, Output: 2}, Set: cost.OrgPriceSet{Input: true, Output: true}}
	engine.SetOrgRows([]cost.OrgPrice{row}, 1, true, "enrollment-one")
	table := engine.Table()
	for _, binding := range []string{"", "enrollment-two", "enrollment-one"} {
		usd, source, ok := managedBudgetTablePricer(table, binding)(row.Model, time.Now(), store.PushTokenSplit{Input: 1_000_000})
		if binding == "enrollment-one" {
			if !ok || usd != 1 || source != "org" {
				t.Fatalf("current org rate refused: usd=%v source=%q ok=%v", usd, source, ok)
			}
		} else if ok || usd != 0 || source != "unverified_org" {
			t.Fatalf("wrong enrollment accepted %q: usd=%v source=%q ok=%v", binding, usd, source, ok)
		}
	}
}
