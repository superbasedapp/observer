package store

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

// TestLoadModelContextWindows pins the composition the routing capability
// filter and the session gauge share: a model the persisted feed's economics
// states a window for resolves known; a model no rung names resolves UNKNOWN
// (never a default size); and a fresh node with no feed and no org document
// loads without error.
func TestLoadModelContextWindows(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	fresh, err := s.LoadModelContextWindows(ctx)
	if err != nil {
		t.Fatalf("fresh node: %v", err)
	}
	if _, known := fresh.Resolve("model-nobody-names"); known {
		t.Fatal("fresh node: an unnamed model must resolve unknown")
	}

	win := int64(400_000)
	env := pricingfeed.Envelope{
		SchemaVersion: pricingfeed.SupportedSchemaVersion,
		FeedVersion:   7,
		KeyID:         pricingfeed.PricingFeedKeyIDV1,
		Digest:        "d",
		Signature:     "s",
		Rows: []pricingfeed.Row{
			{
				PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "feed-model", InputPerMTok: orgcontract.Rate(1)},
				Economics:        &pricingfeed.Economics{ContextWindowTokens: &win},
			},
			{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "no-window-model", InputPerMTok: orgcontract.Rate(1)}},
		},
	}
	if err := s.SavePricingFeed(ctx, env, "verified"); err != nil {
		t.Fatalf("SavePricingFeed: %v", err)
	}
	w, err := s.LoadModelContextWindows(ctx)
	if err != nil {
		t.Fatalf("LoadModelContextWindows: %v", err)
	}
	cases := []struct {
		model     string
		wantToks  int64
		wantKnown bool
	}{
		{"feed-model", 400_000, true},
		{"vendor/feed-model", 400_000, true},
		{"feed-model-20260901", 400_000, true},
		{"no-window-model", 0, false},
		{"model-nobody-names", 0, false},
	}
	for _, tc := range cases {
		toks, known := w.Resolve(tc.model)
		if toks != tc.wantToks || known != tc.wantKnown {
			t.Errorf("Resolve(%q) = (%d,%v), want (%d,%v)", tc.model, toks, known, tc.wantToks, tc.wantKnown)
		}
	}
}
