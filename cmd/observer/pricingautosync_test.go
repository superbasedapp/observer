package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
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
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
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
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
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

// TestPricingAutoSyncOnce_HotAppliesMinCacheable pins review finding 8: a
// successfully persisted feed sync re-composes the cachetrack min-cacheable
// registry in the RUNNING process, through the same mincacheable_wire.go seam
// startup uses. Before the fix only the cost engine was refreshed, so a live
// daemon kept the thresholds it installed at startup until a restart.
func TestPricingAutoSyncOnce_HotAppliesMinCacheable(t *testing.T) {
	ctx := context.Background()
	keys, priv := feedTestKeys(t)
	cachetrack.SetMinCacheableOverrides(nil)
	t.Cleanup(func() { cachetrack.SetMinCacheableOverrides(nil) })

	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	cfg := config.Config{}
	cfg.Observer.DBPath = dbPath
	cfg.Pricing.Feed.Enabled = true
	cfg.Pricing.Feed.Auto = true
	cfg.Pricing.Feed.URL = "http://x"
	_ = acquireProcessCostEngine(ctx, cfg, database, slog.Default())

	before := cachetrack.MinCacheableTokens(feedTestModel)
	const published = 3333 // deliberately unlike any compiled-table value
	if before == published {
		t.Fatalf("test precondition: compiled min-cacheable for %s already %d", feedTestModel, published)
	}

	env := signedFeed(t, priv, 6, 7)
	minTok := int64(published)
	env.Rows[0].Economics.MinCacheableTokens = &minTok
	digest, err := pricingfeed.Digest(env.Rows)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	env.Digest = digest
	env.Signature = ""
	sig, err := pricingfeed.Sign(priv, env)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	env.Signature = sig

	var errOut bytes.Buffer
	pricingAutoSyncOnce(ctx, cfg, pricingfeedgate.Options{
		URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: env},
	}, &errOut)
	if errOut.Len() != 0 {
		t.Fatalf("unexpected error output from the tick: %q", errOut.String())
	}
	if got := cachetrack.MinCacheableTokens(feedTestModel); got != published {
		t.Fatalf("MinCacheableTokens(%s) after sync = %d, want the published %d (hot-applied, no restart)", feedTestModel, got, published)
	}

	// A refused tick (a replayed OLDER version) leaves the registry alone.
	cachetrack.SetMinCacheableOverrides(nil)
	pricingAutoSyncOnce(ctx, cfg, pricingfeedgate.Options{
		URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: signedFeed(t, priv, 2, 7)},
	}, &errOut)
	if got := cachetrack.MinCacheableTokens(feedTestModel); got != before {
		t.Fatalf("MinCacheableTokens(%s) after a refused tick = %d, want untouched %d", feedTestModel, got, before)
	}
}

// TestPricingAutoSyncOnce_FeedRowKeepsSeedLongContextTier is coordinator test
// (b): a signed Tokenomics feed row for grok-4.7 quoting ONLY input / cached /
// output (the operator-captured lane carries no long-context fields) applied
// through the RUNTIME feed rail leaves the seed's >=200K tier in force. Before
// the one-overlay-rule fix the org overlay read the row's threshold 0 as "tier
// OFF" and a 300K prompt billed at the base rate.
func TestPricingAutoSyncOnce_FeedRowKeepsSeedLongContextTier(t *testing.T) {
	ctx := context.Background()
	keys, priv := feedTestKeys(t)

	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	cfg := config.Config{}
	cfg.Observer.DBPath = dbPath
	cfg.Pricing.Feed.Enabled = true
	cfg.Pricing.Feed.Auto = true
	cfg.Pricing.Feed.URL = "http://x"
	engine := acquireProcessCostEngine(ctx, cfg, database, slog.Default())
	seed, ok := engine.Lookup("grok-4.7")
	if !ok || seed.LongContextThreshold != 199_999 || seed.LongContextInput != 4 {
		t.Fatalf("precondition: seed grok-4.7 = %+v", seed)
	}

	env := signedFeed(t, priv, 7, 2)
	env.Rows[0].Model = "grok-4.7"
	env.Rows[0].InputPerMTok = orgcontract.Rate(2)
	env.Rows[0].OutputPerMTok = orgcontract.Rate(6)
	env.Rows[0].CacheReadPerMTok = orgcontract.Rate(0.50)
	if env.Digest, err = pricingfeed.Digest(env.Rows); err != nil {
		t.Fatalf("digest: %v", err)
	}
	env.Signature = ""
	if env.Signature, err = pricingfeed.Sign(priv, env); err != nil {
		t.Fatalf("sign: %v", err)
	}

	var errOut bytes.Buffer
	pricingAutoSyncOnce(ctx, cfg, pricingfeedgate.Options{
		URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: env},
	}, &errOut)
	if errOut.Len() != 0 {
		t.Fatalf("unexpected error output from the tick: %q", errOut.String())
	}
	p, src, ok := engine.LookupWithSource("grok-4.7")
	if !ok || src != cost.PricingSourceOrg {
		t.Fatalf("grok-4.7 after sync = %+v %q %v, want the feed row applied (source org)", p, src, ok)
	}
	if p.LongContextThreshold != 199_999 || p.LongContextInput != 4 || p.LongContextOutput != 12 || p.LongContextCacheRead != 1.00 {
		t.Errorf("grok-4.7 >=200K tier cleared by a feed row that did not state it: %+v", p)
	}
	if bd, _ := engine.ComputeBreakdown("grok-4.7", cost.TokenBundle{Input: 300_000}); bd.InputCost < 1.2-1e-9 {
		t.Errorf("a 300K grok-4.7 prompt billed input %v, want the long-context $4/1M = 1.20", bd.InputCost)
	}
}

// TestOrgPriceRowsOf_PresenceAtTheWireBoundary pins how each rail's wire row
// projects onto the one overlay's presence flags, through a JSON round trip.
//
// ORG rail (review finding F1, 2026-09-26): an ABSENT threshold / peak keeps
// the legacy meaning every pre-175 node gave it - quoted flat - and only the
// `*_unquoted` markers a post-175 server writes for a NULL column mean "not
// quoted, keep the seed's"; a positive threshold and a windowed peak are
// quoted as themselves.
//
// FEED rail: absence has always meant "not quoted", and a stated value (a 0
// threshold, an empty peak object) is quoted.
func TestOrgPriceRowsOf_PresenceAtTheWireBoundary(t *testing.T) {
	unquoted := orgcontract.PricingPolicyRow{Model: "a", InputPerMTok: orgcontract.Rate(1), OutputPerMTok: orgcontract.Rate(2)}
	unquoted.SetOrgThreshold(nil)
	unquoted.SetOrgPeak(nil)
	tiered := orgcontract.PricingPolicyRow{Model: "b", InputPerMTok: orgcontract.Rate(1), OutputPerMTok: orgcontract.Rate(2)}
	tiered.SetOrgThreshold(orgcontract.Threshold(300_000))
	tiered.SetOrgPeak(&orgcontract.PeakRates{Schedule: orgcontract.PeakSchedule{Windows: []orgcontract.PeakWindow{{StartUTC: "01:00", EndUTC: "02:00"}}}})
	flat := orgcontract.PricingPolicyRow{Model: "c", InputPerMTok: orgcontract.Rate(1), OutputPerMTok: orgcontract.Rate(2)}
	flat.SetOrgThreshold(orgcontract.Threshold(0))
	flat.SetOrgPeak(&orgcontract.PeakRates{})

	roundTrip := func(in []orgcontract.PricingPolicyRow) []orgcontract.PricingPolicyRow {
		t.Helper()
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var wire []orgcontract.PricingPolicyRow
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return wire
	}

	org := orgPriceRowsOf(roundTrip([]orgcontract.PricingPolicyRow{unquoted, tiered, flat}))
	if org[0].Set.Peak || org[0].Set.LongContextThreshold {
		t.Errorf("org row a: a NULL (marked unquoted) peak/threshold was read as quoted: %+v", org[0].Set)
	}
	if !org[1].Set.Peak || org[1].Peak == nil || !org[1].Set.LongContextThreshold || org[1].LongContextThreshold != 300_000 {
		t.Errorf("org row b: a quoted peak/threshold was not carried: %+v", org[1])
	}
	if !org[2].Set.LongContextThreshold || org[2].LongContextThreshold != 0 || !org[2].Set.Peak || org[2].Peak != nil {
		t.Errorf("org row c: a quoted flat threshold/peak must be quoted and flat: %+v", org[2])
	}

	feedRows := roundTrip([]orgcontract.PricingPolicyRow{
		{Model: "a", InputPerMTok: orgcontract.Rate(1), OutputPerMTok: orgcontract.Rate(2)},
		{Model: "c", InputPerMTok: orgcontract.Rate(1), OutputPerMTok: orgcontract.Rate(2), LongContextThreshold: orgcontract.Threshold(0), Peak: &orgcontract.PeakRates{}},
	})
	feed := feedPriceRowsOf(feedRows)
	if feed[0].Set.Peak || feed[0].Set.LongContextThreshold {
		t.Errorf("feed row a: an absent peak/threshold was read as quoted: %+v", feed[0].Set)
	}
	if !feed[1].Set.Peak || !feed[1].Set.LongContextThreshold || feed[1].LongContextThreshold != 0 {
		t.Errorf("feed row c: a stated 0 threshold / empty peak must be quoted: %+v", feed[1])
	}
}

// TestPricingAutoSyncOnce_FeedFastMultiplierPresence pins that the RUNTIME
// feed applies its own economics.fast_multiplier under the same presence rule:
// stated -> applies; absent -> the seed's value stays (gpt-6-astra seed = 2).
func TestPricingAutoSyncOnce_FeedFastMultiplierPresence(t *testing.T) {
	ctx := context.Background()
	keys, priv := feedTestKeys(t)
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	cfg := config.Config{}
	cfg.Observer.DBPath = dbPath
	cfg.Pricing.Feed.Enabled = true
	cfg.Pricing.Feed.Auto = true
	cfg.Pricing.Feed.URL = "http://x"
	engine := acquireProcessCostEngine(ctx, cfg, database, slog.Default())

	tick := func(version int64, fast *float64) {
		t.Helper()
		env := signedFeed(t, priv, version, 10)
		env.Rows[0].Model = "gpt-6-astra"
		env.Rows[0].Economics.FastMultiplier = fast
		if env.Digest, err = pricingfeed.Digest(env.Rows); err != nil {
			t.Fatalf("digest: %v", err)
		}
		env.Signature = ""
		if env.Signature, err = pricingfeed.Sign(priv, env); err != nil {
			t.Fatalf("sign: %v", err)
		}
		var errOut bytes.Buffer
		pricingAutoSyncOnce(ctx, cfg, pricingfeedgate.Options{URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: env}}, &errOut)
		if errOut.Len() != 0 {
			t.Fatalf("tick v%d: %q", version, errOut.String())
		}
	}
	tick(8, nil)
	if p, _ := engine.Lookup("gpt-6-astra"); p.FastMultiplier != 2 || p.LongContextThreshold != 272_000 {
		t.Errorf("absent fast multiplier: %+v, want the seed's 2 and LC tier kept", p)
	}
	three := 3.0
	tick(9, &three)
	if p, _ := engine.Lookup("gpt-6-astra"); p.FastMultiplier != 3 {
		t.Errorf("stated fast multiplier: %v, want the feed's 3", p.FastMultiplier)
	}
}

// TestPricingFeed_CompiledFloorAtFetchAndConsumption pins round-2 finding 1 on
// BOTH runtime paths. (1) A FRESH node offered a validly signed feed below
// cost.SnapshotMinFeedVersion refuses it: nothing is persisted and the engine
// keeps the seed. (2) A node that already CACHED such a body (persisted by an
// older binary) does not apply it on restart - neither to prices nor to the
// min-cacheable registry. (3) The same version with a different digest is
// refused at fetch, exactly as the snapshot generator refuses it.
func TestPricingFeed_CompiledFloorAtFetchAndConsumption(t *testing.T) {
	ctx := context.Background()
	keys, priv := feedTestKeys(t)
	below := cost.SnapshotMinFeedVersion - 1

	t.Run("fresh node refuses a below-floor fetch", func(t *testing.T) {
		st, _ := feedTestStore(t)
		res, err := runPricingSync(ctx, st, false, pricingfeedgate.Options{
			URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: signedFeed(t, priv, below, 7)},
		})
		if err != nil {
			t.Fatalf("runPricingSync: %v", err)
		}
		if res.Applied || res.State != pricingSyncUnverified {
			t.Fatalf("result = %+v, want a refusal", res)
		}
		if cache, _ := st.LoadPricingFeed(ctx); cache.Have {
			t.Fatalf("a below-floor feed was persisted: v%d", cache.Version)
		}
	})

	t.Run("already-cached below-floor feed is not applied on restart", func(t *testing.T) {
		cachetrack.SetMinCacheableOverrides(nil)
		t.Cleanup(func() { cachetrack.SetMinCacheableOverrides(nil) })
		st, database := feedTestStore(t)
		env := signedFeed(t, priv, below, 7)
		minTok := int64(4444)
		env.Rows[0].Economics.MinCacheableTokens = &minTok
		var err error
		if env.Digest, err = pricingfeed.Digest(env.Rows); err != nil {
			t.Fatalf("digest: %v", err)
		}
		env.Signature = ""
		if env.Signature, err = pricingfeed.Sign(priv, env); err != nil {
			t.Fatalf("sign: %v", err)
		}
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := st.SavePricingFeedRaw(ctx, env, raw, pricingSyncVerified); err != nil {
			t.Fatalf("seed the cache as an older binary would have: %v", err)
		}
		if _, ok := feedOrgRows(ctx, st, slog.Default()); ok {
			t.Fatal("feedOrgRows applied a cached below-floor feed")
		}
		cfg := config.Config{}
		cfg.Observer.DBPath = filepath.Join(t.TempDir(), "restart.db")
		engine := acquireProcessCostEngine(ctx, cfg, database, slog.Default())
		if p, src, _ := engine.LookupWithSource(feedTestModel); src == cost.PricingSourceOrg {
			t.Fatalf("restart applied the cached below-floor feed: %+v", p)
		}
		applyMinCacheableOverrides(ctx, st, slog.Default())
		if got := cachetrack.MinCacheableTokens(feedTestModel); got == int(minTok) {
			t.Fatal("min-cacheable took the cached below-floor feed's value")
		}
	})

	t.Run("same version, different digest is refused at fetch", func(t *testing.T) {
		st, _ := feedTestStore(t)
		if res, err := runPricingSync(ctx, st, false, pricingfeedgate.Options{
			URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: signedFeed(t, priv, 5, 4)},
		}); err != nil || !res.Applied {
			t.Fatalf("seed v5: %+v %v", res, err)
		}
		res, err := runPricingSync(ctx, st, false, pricingfeedgate.Options{
			URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: signedFeed(t, priv, 5, 9)},
		})
		if err != nil {
			t.Fatalf("runPricingSync: %v", err)
		}
		if res.Applied {
			t.Fatalf("a same-version different-digest body was applied: %+v", res)
		}
		if cache, _ := st.LoadPricingFeed(ctx); !cache.Have || cache.Version != 5 {
			t.Fatalf("cache = %+v, want the original v5 kept", cache)
		}
	})
}
