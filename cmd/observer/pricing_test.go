package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed/client"
	"github.com/marmutapp/superbased-observer/internal/pricingfeedgate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

const feedTestModel = "claude-opus-4-8"

// fakeFeedFetcher is a client.Fetcher double: it returns a pre-built result
// without any network. notModifiedDigest, when non-empty, makes a conditional
// request with that exact LastDigest short-circuit to 304.
type fakeFeedFetcher struct {
	env               pricingfeed.Envelope
	notModifiedDigest string
	err               error
	lastSeenDigest    string
}

func (f *fakeFeedFetcher) Fetch(_ context.Context, _ string, lastDigest string) (client.Result, error) {
	f.lastSeenDigest = lastDigest
	if f.err != nil {
		return client.Result{}, f.err
	}
	if f.notModifiedDigest != "" && lastDigest == f.notModifiedDigest {
		return client.Result{NotModified: true}, nil
	}
	return client.Result{Envelope: f.env}, nil
}

// feedTestKeys builds a throwaway key set and the private half to sign with.
func feedTestKeys(t *testing.T) (pricingfeed.KeySet, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keys, err := pricingfeed.NewKeySet(map[string]string{"test-key": hex.EncodeToString(pub)})
	if err != nil {
		t.Fatalf("key set: %v", err)
	}
	return keys, priv
}

// signedFeed builds a signed envelope for one model at the given feed version
// and input rate.
func signedFeed(t *testing.T, priv ed25519.PrivateKey, feedVersion int64, inputRate float64) pricingfeed.Envelope {
	t.Helper()
	rows := []pricingfeed.Row{{
		PricingPolicyRow: orgcontract.PricingPolicyRow{
			Model:         feedTestModel,
			InputPerMTok:  orgcontract.Rate(inputRate),
			OutputPerMTok: orgcontract.Rate(inputRate * 5),
			Source:        "list",
		},
		Grade:     "verified",
		Economics: &pricingfeed.Economics{CacheMode: pricingfeed.CacheModeExplicit, ReasoningBilling: pricingfeed.ReasoningBillingOutputRate},
	}}
	digest, err := pricingfeed.Digest(rows)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	env := pricingfeed.Envelope{
		SchemaVersion: pricingfeed.SupportedSchemaVersion,
		FeedVersion:   feedVersion,
		GeneratedAt:   "2026-09-11T00:00:00Z",
		Rows:          rows,
		Digest:        digest,
		KeyID:         "test-key",
	}
	sig, err := pricingfeed.Sign(priv, env)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	env.Signature = sig
	return env
}

func feedTestStore(t *testing.T) (*store.Store, *sql.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database), database
}

// The ladder: a signed 200 applies; a 304 keeps; an unsigned body is refused
// with the cache untouched; a bad signature is refused; a lower feed_version is
// refused as a replay.
func TestPricingSyncLadder(t *testing.T) {
	keys, priv := feedTestKeys(t)
	ctx := context.Background()

	t.Run("200 applies", func(t *testing.T) {
		st, _ := feedTestStore(t)
		env := signedFeed(t, priv, 5, 4)
		res, err := runPricingSync(ctx, st, false, pricingfeedgate.Options{
			URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: env},
		})
		if err != nil {
			t.Fatalf("runPricingSync: %v", err)
		}
		if res.State != pricingSyncVerified || !res.Applied || res.FeedVersion != 5 {
			t.Fatalf("result = %+v, want verified v5 applied", res)
		}
		cache, _ := st.LoadPricingFeed(ctx)
		if !cache.Have || cache.Version != 5 {
			t.Fatalf("cache = %+v, want the applied v5 feed", cache)
		}
	})

	t.Run("304 keeps", func(t *testing.T) {
		st, _ := feedTestStore(t)
		env := signedFeed(t, priv, 5, 4)
		// First apply so there is a cache (and a digest to match on).
		if _, err := runPricingSync(ctx, st, false, pricingfeedgate.Options{
			URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: env},
		}); err != nil {
			t.Fatalf("seed apply: %v", err)
		}
		// Now a fetcher that 304s when the last digest matches the applied one.
		res, err := runPricingSync(ctx, st, false, pricingfeedgate.Options{
			URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{notModifiedDigest: env.Digest},
		})
		if err != nil {
			t.Fatalf("runPricingSync: %v", err)
		}
		if res.State != pricingSyncNotModified || res.Applied {
			t.Fatalf("result = %+v, want not_modified, not applied", res)
		}
	})

	t.Run("unsigned refused, cache untouched", func(t *testing.T) {
		st, _ := feedTestStore(t)
		env := signedFeed(t, priv, 5, 4)
		env.Signature = ""
		res, err := runPricingSync(ctx, st, false, pricingfeedgate.Options{
			URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: env},
		})
		if err != nil {
			t.Fatalf("runPricingSync: %v", err)
		}
		if res.State != pricingSyncUnverified || res.Applied {
			t.Fatalf("result = %+v, want unverified, not applied", res)
		}
		cache, _ := st.LoadPricingFeed(ctx)
		if cache.Have {
			t.Fatal("an unsigned body must leave the cache empty")
		}
	})

	t.Run("bad signature refused", func(t *testing.T) {
		st, _ := feedTestStore(t)
		env := signedFeed(t, priv, 5, 4)
		env.Signature = "QUJD" // valid base64, wrong signature
		res, err := runPricingSync(ctx, st, false, pricingfeedgate.Options{
			URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: env},
		})
		if err != nil {
			t.Fatalf("runPricingSync: %v", err)
		}
		if res.State != pricingSyncUnverified || res.Applied {
			t.Fatalf("result = %+v, want unverified", res)
		}
	})

	t.Run("version regression refused", func(t *testing.T) {
		st, _ := feedTestStore(t)
		// Apply v5, then offer a correctly-signed v3 (same key) — a replay.
		if _, err := runPricingSync(ctx, st, false, pricingfeedgate.Options{
			URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: signedFeed(t, priv, 5, 4)},
		}); err != nil {
			t.Fatalf("seed v5: %v", err)
		}
		res, err := runPricingSync(ctx, st, false, pricingfeedgate.Options{
			URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: signedFeed(t, priv, 3, 99)},
		})
		if err != nil {
			t.Fatalf("runPricingSync: %v", err)
		}
		if res.State != pricingSyncUnverified || res.Applied {
			t.Fatalf("result = %+v, want the replay refused", res)
		}
		cache, _ := st.LoadPricingFeed(ctx)
		if cache.Version != 5 {
			t.Fatalf("cache version = %d, want the kept v5 (replay must not overwrite)", cache.Version)
		}
	})
}

// An enrolled node refuses sync and never writes the feed cache.
func TestPricingSyncRefusesWhenEnrolled(t *testing.T) {
	keys, priv := feedTestKeys(t)
	ctx := context.Background()
	st, _ := feedTestStore(t)

	res, err := runPricingSync(ctx, st, true /* enrolled */, pricingfeedgate.Options{
		URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: signedFeed(t, priv, 5, 4)},
	})
	if err != nil {
		t.Fatalf("runPricingSync: %v", err)
	}
	if res.State != pricingSyncRefusedEnrolled || res.Applied {
		t.Fatalf("result = %+v, want refused_enrolled", res)
	}
	cache, _ := st.LoadPricingFeed(ctx)
	if cache.Have {
		t.Fatal("an enrolled node must never write the public-feed cache")
	}
}

// The precedence ladder, end to end through the real orgPricingLoader + cost
// engine: seed only; seed+feed; seed+feed+local; and enrolled -> feed ignored.
func TestPricingFeedPrecedence(t *testing.T) {
	keys, priv := feedTestKeys(t)
	ctx := context.Background()
	logger := slog.Default()

	// seed only: no feed cache, no local override, not enrolled.
	t.Run("seed only", func(t *testing.T) {
		_, database := feedTestStore(t)
		cfg := config.Config{}
		if rows, ok := orgPricingLoaderRows(ctx, cfg, database, logger); ok {
			t.Fatalf("a fresh standalone node must have no org/feed rows, got %+v", rows)
		}
		e := cost.NewEngine(cfg.Intelligence)
		_, src, ok := e.LookupWithSource(feedTestModel)
		// Seed resolution is exact/date-stripped/family/miss — anything that is
		// neither org nor local. The point is simply that nothing org/feed is in
		// force with no cache and no enrolment.
		if ok && (src == cost.PricingSourceOrg || src == cost.PricingSourceLocal) {
			t.Fatalf("seed-only source = %q, want a seed-table source (not org/local)", src)
		}
	})

	// seed+feed: a synced feed row composes NON-authoritatively (source org/feed).
	t.Run("seed plus feed", func(t *testing.T) {
		st, database := feedTestStore(t)
		if _, err := runPricingSync(ctx, st, false, pricingfeedgate.Options{
			URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: signedFeed(t, priv, 5, 7)},
		}); err != nil {
			t.Fatalf("apply feed: %v", err)
		}
		cfg := config.Config{}
		rows, ok := orgPricingLoaderRows(ctx, cfg, database, logger)
		if !ok || len(rows.Rows) != 1 || rows.Authoritative {
			t.Fatalf("loader rows = %+v ok=%v, want one NON-authoritative feed row", rows, ok)
		}
		e := cost.NewEngine(cfg.Intelligence, cost.WithOrgRows(func() (cost.OrgRows, bool) { return rows, true }))
		p, src, ok := e.LookupWithSource(feedTestModel)
		if !ok || src != cost.PricingSourceOrg || p.Input != 7 {
			t.Fatalf("feed lookup = %v %q %v, want the feed rate at source org", p, src, ok)
		}
	})

	// seed+feed+local: a developer's own override wins over the public feed.
	t.Run("seed plus feed plus local wins", func(t *testing.T) {
		st, database := feedTestStore(t)
		if _, err := runPricingSync(ctx, st, false, pricingfeedgate.Options{
			URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: signedFeed(t, priv, 5, 7)},
		}); err != nil {
			t.Fatalf("apply feed: %v", err)
		}
		cfg := config.Config{}
		cfg.Intelligence.Pricing.Models = map[string]config.ModelPricing{
			feedTestModel: {Input: 42, Output: 420},
		}
		rows, ok := orgPricingLoaderRows(ctx, cfg, database, logger)
		if !ok {
			t.Fatal("loader must still return the feed rows")
		}
		e := cost.NewEngine(cfg.Intelligence, cost.WithOrgRows(func() (cost.OrgRows, bool) { return rows, true }))
		p, src, ok := e.LookupWithSource(feedTestModel)
		if !ok || src != cost.PricingSourceLocal || p.Input != 42 {
			t.Fatalf("lookup = %v %q %v, want the LOCAL override to win over the feed", p, src, ok)
		}
	})

	// un-enrolled with from_org STILL set in TOML -> seed pricing, no org rows
	// (finding F6). A node that LEFT its org has no claim on the org's rates.
	// This exercises BOTH halves of the fix: DeleteEnrolment clears
	// org_pricing_cache (store half), and the loader checks enrolment FIRST so a
	// stale org document present on a non-enrolled node is never applied (loader
	// half — the clause the prior code reached on from_org alone).
	t.Run("un-enrolled with from_org still set falls to seed", func(t *testing.T) {
		st, database := feedTestStore(t)
		in := 100.0
		orgDoc := func(version int64) orgcontract.PricingPolicyDoc {
			return orgcontract.PricingPolicyDoc{
				PricingPolicyBody: orgcontract.PricingPolicyBody{
					Version: version,
					Rows: []orgcontract.PricingPolicyRow{{
						Model: feedTestModel, InputPerMTok: &in, Source: "negotiated",
					}},
				},
				Signature: "c2lnbmVk",
			}
		}
		// This node WAS enrolled and had accepted the org's signed document.
		if err := st.SaveOrgPricing(ctx, orgDoc(9), "fingerprint", orgcontract.PricingFetchVerified); err != nil {
			t.Fatalf("SaveOrgPricing: %v", err)
		}
		if err := st.WriteEnrolment(ctx, store.Enrolment{OrgID: "org-1", OrgServerURL: "https://org.example"}); err != nil {
			t.Fatalf("enrol: %v", err)
		}
		// Now it leaves the org.
		if err := st.DeleteEnrolment(ctx); err != nil {
			t.Fatalf("unenrol: %v", err)
		}
		// STORE half: unenrolment cleared the org's document.
		if cached, err := st.LoadOrgPricing(ctx); err != nil || cached.Have {
			t.Fatalf("org pricing document survived unenrolment: have=%v err=%v", cached.Have, err)
		}
		// LOADER half: even with a stale org document present again on a
		// non-enrolled node, the enrolment-first loader applies no org rows.
		if err := st.SaveOrgPricing(ctx, orgDoc(9), "fingerprint", orgcontract.PricingFetchVerified); err != nil {
			t.Fatalf("re-save stale doc: %v", err)
		}
		cfg := config.Config{}
		cfg.Guard.Budget.FromOrg = true // left on in TOML after leaving the org
		if rows, ok := orgPricingLoaderRows(ctx, cfg, database, logger); ok {
			t.Fatalf("an un-enrolled node with from_org still set must apply no org rows, got %+v", rows)
		}
	})

	// enrolled -> feed ignored: the loader returns no rows even with a synced feed.
	t.Run("enrolled ignores the feed", func(t *testing.T) {
		st, database := feedTestStore(t)
		if _, err := runPricingSync(ctx, st, false, pricingfeedgate.Options{
			URL: "http://x", Keys: keys, Fetcher: &fakeFeedFetcher{env: signedFeed(t, priv, 5, 7)},
		}); err != nil {
			t.Fatalf("apply feed (pre-enrolment): %v", err)
		}
		if err := st.WriteEnrolment(ctx, store.Enrolment{OrgID: "org-1", OrgServerURL: "https://org.example"}); err != nil {
			t.Fatalf("enrol: %v", err)
		}
		cfg := config.Config{} // from_org false by default
		if rows, ok := orgPricingLoaderRows(ctx, cfg, database, logger); ok {
			t.Fatalf("an enrolled node must ignore the public feed, got %+v", rows)
		}
	})
}

// orgPricingLoaderRows invokes the real loader against a DB and returns its
// resolved rows. It goes through the production orgPricingLoader so the
// precedence decision under test is the one the daemon and CLI actually use.
func orgPricingLoaderRows(ctx context.Context, cfg config.Config, database *sql.DB, logger *slog.Logger) (cost.OrgRows, bool) {
	return orgPricingLoader(ctx, cfg, database, logger)()
}
