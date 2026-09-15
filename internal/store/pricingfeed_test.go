package store

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

// A fresh node has the seeded row and NO feed; a verified envelope round-trips
// with its provenance (version, key id, digest, state) and its rows.
func TestPricingFeedCacheRoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	got, err := s.LoadPricingFeed(ctx)
	if err != nil {
		t.Fatalf("LoadPricingFeed on a fresh node: %v", err)
	}
	if got.Have {
		t.Fatalf("a fresh node reports a stored feed: %+v", got)
	}

	env := pricingfeed.Envelope{
		SchemaVersion: pricingfeed.SupportedSchemaVersion,
		FeedVersion:   7,
		GeneratedAt:   "2026-09-11T00:00:00Z",
		KeyID:         pricingfeed.PricingFeedKeyIDV1,
		Digest:        "sha-digest-abc",
		Signature:     "c2ln",
		Rows: []pricingfeed.Row{{
			PricingPolicyRow: orgcontract.PricingPolicyRow{
				Model:         "claude-opus-4-8",
				InputPerMTok:  orgcontract.Rate(4),
				OutputPerMTok: orgcontract.Rate(20),
				Source:        "list",
			},
			Grade: "verified",
			Economics: &pricingfeed.Economics{
				CacheMode:        pricingfeed.CacheModeExplicit,
				ReasoningBilling: pricingfeed.ReasoningBillingOutputRate,
			},
		}},
	}
	if err := s.SavePricingFeed(ctx, env, "verified"); err != nil {
		t.Fatalf("SavePricingFeed: %v", err)
	}

	got, err = s.LoadPricingFeed(ctx)
	if err != nil {
		t.Fatalf("LoadPricingFeed: %v", err)
	}
	if !got.Have || got.Version != 7 || got.State != "verified" {
		t.Fatalf("cache = %+v, want the applied v7 feed", got)
	}
	if got.KeyID != pricingfeed.PricingFeedKeyIDV1 || got.Digest != "sha-digest-abc" {
		t.Errorf("provenance = key %q digest %q, want the stored values", got.KeyID, got.Digest)
	}
	if len(got.Envelope.Rows) != 1 || got.Envelope.Rows[0].InputPerMTok == nil || *got.Envelope.Rows[0].InputPerMTok != 4 {
		t.Fatalf("rows = %+v, want the stored rate", got.Envelope.Rows)
	}
	if got.Envelope.Rows[0].Economics == nil || got.Envelope.Rows[0].Economics.CacheMode != pricingfeed.CacheModeExplicit {
		t.Errorf("economics did not round-trip: %+v", got.Envelope.Rows[0].Economics)
	}
	if got.FetchedAt.IsZero() {
		t.Error("fetched_at did not round-trip")
	}
}

// The table is a singleton: a second save UPDATEs in place rather than adding a
// row, so a node always holds exactly one applied feed.
func TestPricingFeedCacheStaysASingleton(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()

	for _, v := range []int64{1, 2, 3} {
		env := pricingfeed.Envelope{
			SchemaVersion: pricingfeed.SupportedSchemaVersion,
			FeedVersion:   v,
			KeyID:         pricingfeed.PricingFeedKeyIDV1,
			Digest:        "d",
			Signature:     "s",
			Rows:          []pricingfeed.Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "m", InputPerMTok: orgcontract.Rate(1)}}},
		}
		if err := s.SavePricingFeed(ctx, env, "verified"); err != nil {
			t.Fatalf("SavePricingFeed v%d: %v", v, err)
		}
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pricing_feed_cache`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("pricing_feed_cache holds %d rows, want exactly 1", n)
	}
	got, err := s.LoadPricingFeed(ctx)
	if err != nil {
		t.Fatalf("LoadPricingFeed: %v", err)
	}
	if got.Version != 3 {
		t.Fatalf("version = %d, want the last-written 3", got.Version)
	}
}

// A corrupt body is reported as an error WITH an empty cache, so a caller
// degrades to the seed table rather than mistaking a bad blob for a node that
// never synced.
func TestPricingFeedCacheDegradesOnACorruptBody(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		`UPDATE pricing_feed_cache SET body_json = '{not json', version = 5 WHERE id = 1`); err != nil {
		t.Fatalf("seed corrupt body: %v", err)
	}
	got, err := s.LoadPricingFeed(ctx)
	if err == nil {
		t.Fatal("a corrupt body must be reported as an error")
	}
	if got.Have {
		t.Fatalf("a corrupt body must degrade to an empty cache, got %+v", got)
	}
}
