package main

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/pricingfeedgate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestPricingAutoSyncOnce_RePricesTheLiveEngine pins finding F5: one in-process
// poller tick, driven by a fake fetcher returning a signed feed, re-prices the
// PROCESS-WIDE cost engine IN PLACE — so a RUNNING daemon applies the feed
// without a restart. The defect it guards against is the old subprocess poller,
// which rebuilt only its own short-lived engine and left the daemon's stamping
// api_turns.cost_usd at the previous feed until a (runbook-forbidden) restart.
func TestPricingAutoSyncOnce_RePricesTheLiveEngine(t *testing.T) {
	ctx := context.Background()
	keys, priv := feedTestKeys(t)

	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	cfg := config.Config{}
	cfg.Observer.DBPath = dbPath
	cfg.Pricing.Feed.Enabled = true
	cfg.Pricing.Feed.Auto = true
	cfg.Pricing.Feed.URL = "http://x"

	// Register the process engine the way buildProxy does, keyed by db path. With
	// no feed synced yet it carries no org/feed rate for the model.
	engine := acquireProcessCostEngine(ctx, cfg, database, slog.Default())
	if engine == nil {
		t.Fatal("acquireProcessCostEngine returned nil")
	}
	if p, src, ok := engine.LookupWithSource(feedTestModel); ok && src == cost.PricingSourceOrg {
		t.Fatalf("pre-sync engine already has an org/feed rate for %s: %v", feedTestModel, p)
	}

	// One poller tick: a fake fetcher returns a signed v5 feed at input rate 7.
	const rate = 7.0
	var errOut bytes.Buffer
	pricingAutoSyncOnce(ctx, cfg, pricingfeedgate.Options{
		URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: signedFeed(t, priv, 5, rate)},
	}, &errOut)
	if errOut.Len() != 0 {
		t.Fatalf("unexpected error output from the tick: %q", errOut.String())
	}

	// The live engine (LOOKED UP, not rebuilt) now reflects the feed rate.
	got := lookupProcessCostEngine(dbPath)
	if got == nil {
		t.Fatal("lookupProcessCostEngine returned nil after the tick")
	}
	if got != engine {
		t.Fatal("the tick replaced the engine instead of re-pricing it in place — a daemon would still be on the old table")
	}
	p, src, ok := got.LookupWithSource(feedTestModel)
	if !ok || src != cost.PricingSourceOrg || p.Input != rate {
		t.Fatalf("engine lookup after sync = %v %q %v, want the feed rate %v at source org (the live daemon must re-price)", p, src, ok, rate)
	}
	if got.OrgPricingVersion() != 5 {
		t.Fatalf("engine org version after sync = %d, want the feed v5", got.OrgPricingVersion())
	}
}

// TestPricingAutoSyncOnce_EnrolledRefusesAndDoesNotReprice pins that the
// in-process tick inherits runPricingSync's enrolled refusal: an enrolled node
// never writes the public-feed cache and never touches the engine.
func TestPricingAutoSyncOnce_EnrolledRefusesAndDoesNotReprice(t *testing.T) {
	ctx := context.Background()
	keys, priv := feedTestKeys(t)

	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := store.New(database).WriteEnrolment(ctx, store.Enrolment{
		OrgID: "org-1", OrgServerURL: "https://org.example",
	}); err != nil {
		t.Fatalf("enrol: %v", err)
	}

	cfg := config.Config{}
	cfg.Observer.DBPath = dbPath
	engine := acquireProcessCostEngine(ctx, cfg, database, slog.Default())

	var errOut bytes.Buffer
	pricingAutoSyncOnce(ctx, cfg, pricingfeedgate.Options{
		URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: signedFeed(t, priv, 5, 7)},
	}, &errOut)

	if engine.HasOrgPricing() {
		t.Fatal("an enrolled node applied the public feed to the cost engine")
	}
	if cache, _ := store.New(database).LoadPricingFeed(ctx); cache.Have {
		t.Fatal("an enrolled node wrote the public-feed cache")
	}
}
