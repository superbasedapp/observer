package orgcontract

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

// TestRoundPrice pins the 1e-10 grid: an on-grid value survives bit-identical,
// float noise below the grid is snapped away, and non-finite values pass.
func TestRoundPrice(t *testing.T) {
	cases := []struct {
		name string
		in   float64
		want float64
	}{
		{"on-grid integer", 3, 3},
		{"on-grid decimal", 0.3, 0.3},
		{"on-grid small rate", 1.25e-7, 1.25e-7},
		{"float noise snapped", 0.1 + 0.2, 0.3},
		{"below the grid", 1e-11, 0},
		{"zero stays zero", 0, 0},
	}
	for _, tc := range cases {
		if got := RoundPrice(tc.in); got != tc.want {
			t.Errorf("%s: RoundPrice(%v) = %v, want %v", tc.name, tc.in, got, tc.want)
		}
	}
}

// TestRoundedRatesKeepsPresence: rounding never turns nil into 0 or 0 into
// nil, rounds the extended fields, the multiplier, the peak and the history,
// and leaves the input row untouched.
func TestRoundedRatesKeepsPresence(t *testing.T) {
	noisy := 0.1 + 0.2
	r := PricingPolicyRow{
		Model: "m", InputPerMTok: Rate(noisy), OutputPerMTok: Rate(0),
		ReasoningPerMTok: Rate(noisy), FastMultiplier: Rate(noisy),
		Peak:    &PeakRates{RateSet: RateSet{Input: noisy}},
		History: []PricingPolicyRow{{Model: "m", AudioOutputPerMTok: Rate(noisy)}},
	}
	got := r.RoundedRates()
	switch {
	case *got.InputPerMTok != 0.3, *got.ReasoningPerMTok != 0.3, *got.FastMultiplier != 0.3:
		t.Fatalf("rates not rounded: %+v", got)
	case got.OutputPerMTok == nil || *got.OutputPerMTok != 0:
		t.Fatal("a quoted 0 lost its presence")
	case got.CacheReadPerMTok != nil || got.RequestFeeUSD != nil:
		t.Fatal("an unquoted rate became quoted")
	case got.Peak.Input != 0.3 || *got.History[0].AudioOutputPerMTok != 0.3:
		t.Fatalf("peak/history not rounded: %+v / %+v", got.Peak, got.History[0])
	case *r.InputPerMTok != noisy || r.Peak.Input != noisy:
		t.Fatal("RoundedRates mutated its input")
	}
}

// TestExtendedFieldsAreAdditiveOnTheWire: a row that quotes none of the new
// fields marshals exactly as before them; a row that quotes them signs and
// verifies with the unchanged domain (the rows are inside the signed body).
func TestExtendedFieldsAreAdditiveOnTheWire(t *testing.T) {
	plain, err := json.Marshal(PricingPolicyRow{Model: "m", InputPerMTok: Rate(1)})
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != `{"model":"m","input_per_mtok":1}` {
		t.Fatalf("a row without the new fields changed bytes: %s", plain)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := PricingPolicyBody{Version: 3, GeneratedAt: "2026-09-30T00:00:00Z", Rows: []PricingPolicyRow{{
		Model: "m", InputPerMTok: Rate(1), OutputPerMTok: Rate(2),
		ReasoningPerMTok: Rate(3), RequestFeeUSD: Rate(0), FastMultiplier: Rate(2), Grade: "verified",
	}}}
	doc, err := SignPricingPolicy(priv, "org-1", body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"reasoning_per_mtok":3`, `"request_fee_usd":0`, `"fast_multiplier":2`, `"grade":"verified"`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("signed document lacks %s: %s", k, raw)
		}
	}
	var back PricingPolicyDoc
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPricingPolicy(pub, "org-1", back); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if back.Rows[0].FastMultiplier == nil || *back.Rows[0].FastMultiplier != 2 || back.Rows[0].Grade != "verified" {
		t.Fatalf("decoded row lost the new fields: %+v", back.Rows[0])
	}
	// Tampering with a new field breaks the signature: the domain covers it.
	back.Rows[0].FastMultiplier = Rate(1)
	tampered, _ := json.Marshal(back)
	var again PricingPolicyDoc
	if err := json.Unmarshal(tampered, &again); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPricingPolicy(pub, "org-1", again); err == nil {
		t.Fatal("a tampered fast multiplier still verified")
	}
}
