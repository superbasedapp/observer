package store

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

func TestOrgPricingCacheRoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// A fresh node has the seeded row and NO document. The distinction is the
	// whole reason Have exists: version 0 with an empty body is not a
	// document priced at nothing, it is the absence of one.
	got, err := s.LoadOrgPricing(ctx)
	if err != nil {
		t.Fatalf("LoadOrgPricing on a fresh node: %v", err)
	}
	if got.Have {
		t.Fatalf("a fresh node reports a stored document: %+v", got)
	}
	if got.Witness != (OrgPricingWitness{Known: true}) {
		t.Fatalf("fresh cache witness = %+v, want known absence", got.Witness)
	}

	doc := orgcontract.PricingPolicyDoc{
		PricingPolicyBody: orgcontract.PricingPolicyBody{
			Version:     4,
			GeneratedAt: "2026-09-08T00:00:00Z",
			Rows: []orgcontract.PricingPolicyRow{
				{Model: "claude-opus-4-8", InputPerMTok: orgcontract.Rate(4), OutputPerMTok: orgcontract.Rate(20), Source: "negotiated"},
			},
		},
		Signature: "c2ln",
	}
	if err := s.SaveOrgPricing(ctx, doc, "fp-abc", orgcontract.PricingFetchVerified); err != nil {
		t.Fatalf("SaveOrgPricing: %v", err)
	}

	got, err = s.LoadOrgPricing(ctx)
	if err != nil {
		t.Fatalf("LoadOrgPricing: %v", err)
	}
	if !got.Have || got.Version != 4 || got.State != orgcontract.PricingFetchVerified {
		t.Fatalf("cache = %+v, want the applied v4 document", got)
	}
	if got.KeyFingerprint != "fp-abc" {
		t.Errorf("key fingerprint = %q — a rotation must stay diagnosable", got.KeyFingerprint)
	}
	if len(got.Body.Rows) != 1 || got.Body.Rows[0].InputPerMTok == nil || *got.Body.Rows[0].InputPerMTok != 4 {
		t.Fatalf("rows = %+v, want the stored rate", got.Body.Rows)
	}
	if got.FetchedAt.IsZero() {
		t.Error("fetched_at did not round-trip")
	}
	if !got.Witness.Valid() || !got.Witness.Present {
		t.Fatalf("stored document witness = %+v, want known present", got.Witness)
	}
}

func TestOrgPricingWitnessStableAndChangesForSameVersionDocument(t *testing.T) {
	t.Parallel()
	st, _ := newTestStore(t)
	ctx := context.Background()
	old := orgcontract.PricingPolicyDoc{
		PricingPolicyBody: orgcontract.PricingPolicyBody{
			Version: 9,
			Rows:    []orgcontract.PricingPolicyRow{{Model: "m", InputPerMTok: orgcontract.Rate(1)}},
		},
		Signature: "old-signature",
	}
	first, err := st.SaveOrgPricingWithWitness(ctx, old, "fp", orgcontract.PricingFetchVerified)
	if err != nil || !first.Valid() || !first.Present {
		t.Fatalf("first witness = %+v err=%v, want known present", first, err)
	}
	loaded, err := st.LoadOrgPricing(ctx)
	if err != nil || loaded.Witness != first {
		t.Fatalf("loaded witness = %+v err=%v, want %+v", loaded.Witness, err, first)
	}
	same, err := st.SaveOrgPricingWithWitness(ctx, old, "fp", orgcontract.PricingFetchVerified)
	if err != nil || same != first {
		t.Fatalf("same document witness = %+v err=%v, want stable %+v", same, err, first)
	}
	updated := old
	updated.PricingPolicyBody.Rows[0].InputPerMTok = orgcontract.Rate(2)
	changed, err := st.SaveOrgPricingWithWitness(ctx, updated, "fp", orgcontract.PricingFetchVerified)
	if err != nil || !changed.Valid() || changed == first {
		t.Fatalf("same-version changed document witness = %+v err=%v, want a different known witness from %+v", changed, err, first)
	}
	loaded, err = st.LoadOrgPricing(ctx)
	if err != nil || loaded.Witness != changed {
		t.Fatalf("changed loaded witness = %+v err=%v, want %+v", loaded.Witness, err, changed)
	}
}

// A SIGNED EMPTY document is a save, not a delete. It is the org saying "we
// negotiated nothing", and a restarted node must be able to tell that apart
// from "we have never asked" — which is exactly the difference between
// no_pricing and a fresh row.
func TestOrgPricingCacheStoresASignedEmptyDocument(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	full := orgcontract.PricingPolicyDoc{
		PricingPolicyBody: orgcontract.PricingPolicyBody{
			Version: 2,
			Rows:    []orgcontract.PricingPolicyRow{{Model: "m", InputPerMTok: orgcontract.Rate(1), OutputPerMTok: orgcontract.Rate(2)}},
		},
		Signature: "c2ln",
	}
	if err := s.SaveOrgPricing(ctx, full, "fp", orgcontract.PricingFetchVerified); err != nil {
		t.Fatalf("save full: %v", err)
	}
	empty := orgcontract.PricingPolicyDoc{
		PricingPolicyBody: orgcontract.PricingPolicyBody{Version: 3, Rows: []orgcontract.PricingPolicyRow{}},
		Signature:         "c2ln",
	}
	if err := s.SaveOrgPricing(ctx, empty, "fp", orgcontract.PricingFetchNoPricing); err != nil {
		t.Fatalf("save empty: %v", err)
	}

	got, err := s.LoadOrgPricing(ctx)
	if err != nil {
		t.Fatalf("LoadOrgPricing: %v", err)
	}
	if !got.Have {
		t.Fatal("a signed empty document must still be a STORED document — otherwise a restart re-reads the rates the org just withdrew")
	}
	if len(got.Body.Rows) != 0 {
		t.Errorf("rows = %+v, want the withdrawal to have emptied them", got.Body.Rows)
	}
	if got.State != orgcontract.PricingFetchNoPricing || got.Version != 3 {
		t.Errorf("cache = %+v, want state no_pricing at v3", got)
	}
}

// The singleton invariant: two saves leave ONE row. Two rows would be two
// answers to "what prices is this node applying".
func TestOrgPricingCacheStaysASingleton(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	for v := int64(1); v <= 3; v++ {
		doc := orgcontract.PricingPolicyDoc{
			PricingPolicyBody: orgcontract.PricingPolicyBody{Version: v},
			Signature:         "c2ln",
		}
		if err := s.SaveOrgPricing(ctx, doc, "fp", orgcontract.PricingFetchVerified); err != nil {
			t.Fatalf("save v%d: %v", v, err)
		}
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_pricing_cache`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("org_pricing_cache holds %d rows, want exactly 1", n)
	}
	got, _ := s.LoadOrgPricing(ctx)
	if got.Version != 3 {
		t.Errorf("version = %d, want the newest save", got.Version)
	}
}

// A corrupted blob degrades to an ABSENCE plus an error: the engine falls back
// to the seed table (never to prices of zero), and the operator still gets a
// line in the log rather than a silent "this node has never enrolled".
func TestOrgPricingCacheDegradesOnACorruptBody(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		`UPDATE org_pricing_cache SET body_json = '{not json', version = 5 WHERE id = 1`); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	got, err := s.LoadOrgPricing(ctx)
	if err == nil {
		t.Error("a corrupt stored document reported no error — it would be indistinguishable from a fresh node")
	}
	if got.Have {
		t.Errorf("a corrupt stored document reported as present: %+v", got)
	}
	if !got.Witness.Valid() || !got.Witness.Present {
		t.Fatalf("corrupt document witness = %+v, want known present for the malformed durable bytes", got.Witness)
	}
}
