package planlimits

import (
	"testing"
	"time"
)

// headlineOf runs a snapshot through Merge and the headline table for its
// provider's group, as the page does.
func headlineOf(t *testing.T, s Snapshot) Headline {
	t.Helper()
	p, ok := ProviderByID(s.Provider)
	if !ok {
		t.Fatalf("unknown provider %q", s.Provider)
	}
	return HeadlineOf(p.Group, Merge([]Snapshot{s}), t0)
}

// wantLeft pins the remaining-first rule (D-681): the headline is the
// amount left in unit, with the amount used second when the vendor says.
func wantLeft(t *testing.T, name string, h Headline, unit Unit, left float64, used *float64) {
	t.Helper()
	if h.Kind != HeadlineLeft || h.Unit != unit || h.Value == nil || !approx(*h.Value, left) {
		t.Errorf("%s: headline %+v, want %v left in %s", name, h, left, unit)
		return
	}
	if used != nil && (h.Used == nil || !approx(*h.Used, *used)) {
		t.Errorf("%s: used %v, want %v", name, h.Used, *used)
	}
}

// TestBalanceVendorsLeadWithWhatIsLeft: one case per balance vendor built in
// the first lane. Every later lane adds its balance vendors in its own file.
func TestBalanceVendorsLeadWithWhatIsLeft(t *testing.T) {
	// OpenRouter: total_credits 40, total_usage 21.58 -> 18.42 left of 40.
	s, err := parseOpenRouter(ParseInput{Now: t0, Responses: map[string]Response{
		"key":     {Status: 200, Body: fixture(t, "openrouter_key_capped.json")},
		"credits": {Status: 200, Body: fixture(t, "openrouter_credits.json")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h := headlineOf(t, s)
	wantLeft(t, "openrouter", h, UnitUSDMicros, 18_420_000, F(21_580_000))
	if h.Of == nil || *h.Of != 40_000_000 || h.Basis != "balance:prepaid" {
		t.Errorf("openrouter of/basis %+v", h)
	}

	// OpenRouter without a credits answer: the key cap's remaining leads.
	s, err = parseOpenRouter(ParseInput{Now: t0, Responses: map[string]Response{
		"key": {Status: 200, Body: fixture(t, "openrouter_key_capped.json")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h = headlineOf(t, s)
	if h.Kind != HeadlineLeft || h.Basis != "window:key_cap" {
		t.Errorf("openrouter key cap headline %+v", h)
	}

	// DeepSeek: per-currency balances (see TestBalanceHeadlineNeverMixesCurrencies).
	s, _ = ParseDeepSeekBalance([]byte(`{"is_available":true,"balance_infos":[{"currency":"USD","total_balance":"3.12","granted_balance":"0.12","topped_up_balance":"3.00"}]}`), t0)
	wantLeft(t, "deepseek", headlineOf(t, s), UnitUSDMicros, 3_120_000, nil)

	// Moonshot: the available balance.
	s, _ = ParseMoonshotBalance("global", []byte(`{"code":0,"data":{"available_balance":49.58894,"voucher_balance":46.58893,"cash_balance":3.00001},"status":true}`), t0)
	wantLeft(t, "moonshot", headlineOf(t, s), UnitUSDMicros, 49_588_940, nil)

	// xAI: the live estimate left (posted minus this cycle's invoice), spend second.
	amt, lim := int64(5_000_000), int64(100_000_000)
	s = XAISnapshot(274_810_000, &XAIInvoice{AmountAfterVatMicros: &amt, SpendingLimitMicros: &lim, Year: 2026, Month: 10}, t0)
	wantLeft(t, "xai", headlineOf(t, s), UnitUSDMicros, 269_810_000, F(5_000_000))
}

func TestHeadlineRules(t *testing.T) {
	reset := t0.Add(2 * time.Hour)
	plan := newSnap(ProviderClaude, "", KindOfficialAPI, ConfExact, t0)
	plan.Windows = []Window{
		{Key: "5h", Unit: UnitPercent, UsedFrac: F(0.30), ResetsAt: &reset},
		{Key: "weekly", Unit: UnitPercent, UsedFrac: F(0.64)},
	}
	h := headlineOf(t, plan)
	if h.Kind != HeadlinePercentLeft || !approx(*h.Value, 0.36) || h.Basis != "window:weekly" {
		t.Errorf("tightest window leads: %+v", h)
	}

	expired := t0.Add(-time.Minute)
	plan.Windows = []Window{{Key: "5h", Unit: UnitPercent, UsedFrac: F(0.99), ResetsAt: &expired}, {Key: "weekly", Unit: UnitPercent, UsedFrac: F(0.2)}}
	if h := headlineOf(t, plan); h.Basis != "window:weekly" {
		t.Errorf("an expired window never leads: %+v", h)
	}

	amounts := newSnap(ProviderCopilot, "", KindOfficialAPI, ConfExact, t0)
	amounts.Windows = []Window{{Key: "monthly:premium_requests", Unit: UnitRequests, Used: F(120), Limit: F(300), UsedFrac: F(0.4)}}
	h = headlineOf(t, amounts)
	if h.Kind != HeadlineLeft || *h.Value != 180 || *h.Of != 300 || *h.Used != 120 {
		t.Errorf("amount window: %+v", h)
	}

	usage := newSnap("fireworks", "", KindOfficialAPI, ConfExact, t0)
	usage.Spend = []Spend{{Period: "all_time", Unit: UnitUSDMicros, Amount: 9}, {Period: "month", Unit: UnitUSDMicros, Amount: 4}}
	h = headlineOf(t, usage)
	if h.Kind != HeadlineUsedOnly || *h.Value != 4 || h.Basis != "spend:month" {
		t.Errorf("usage only says so: %+v", h)
	}

	if h := HeadlineOf(GroupBalance, Merge(nil), t0); h.Kind != HeadlineNone {
		t.Errorf("no reading: %+v", h)
	}
}

// TestBalanceHeadlineNeverMixesCurrencies: the headline is in the currency the
// account holds, every other held currency is its own line, nothing is
// converted or summed, and each currency's breakdown adds up to its total.
func TestBalanceHeadlineNeverMixesCurrencies(t *testing.T) {
	ds := func(infos string) Snapshot {
		t.Helper()
		s, err := ParseDeepSeekBalance([]byte(`{"is_available":true,"balance_infos":[`+infos+`]}`), t0)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	usd := `{"currency":"USD","total_balance":"3.12","granted_balance":"0.12","topped_up_balance":"3.00"}`
	cny := `{"currency":"CNY","total_balance":"52.30","granted_balance":"10.00","topped_up_balance":"42.30"}`
	usd0 := `{"currency":"USD","total_balance":"0.00","granted_balance":"0.00","topped_up_balance":"0.00"}`
	cases := []struct {
		name  string
		snap  Snapshot
		unit  Unit
		value float64
		also  []HeadlineAmount
	}{
		{"cny only", ds(cny), UnitCNYMicros, 52_300_000, nil},
		{"usd only", ds(usd), UnitUSDMicros, 3_120_000, nil},
		{"both held", ds(cny + "," + usd), UnitUSDMicros, 3_120_000, []HeadlineAmount{{UnitCNYMicros, 52_300_000}}},
		{"usd empty, cny held", ds(usd0 + "," + cny), UnitCNYMicros, 52_300_000, nil},
	}
	for _, c := range cases {
		h := headlineOf(t, c.snap)
		if h.Kind != HeadlineLeft || h.Unit != c.unit || h.Value == nil || *h.Value != c.value {
			t.Errorf("%s: headline %+v, want %v in %s", c.name, h, c.value, c.unit)
		}
		if len(h.Also) != len(c.also) {
			t.Errorf("%s: also %+v, want %+v", c.name, h.Also, c.also)
			continue
		}
		for i := range c.also {
			if h.Also[i] != c.also[i] {
				t.Errorf("%s: also %+v, want %+v", c.name, h.Also, c.also)
			}
		}
		// Per currency, total == granted + topped up: the rows reconcile.
		by := map[Unit]map[string]int64{}
		for _, b := range c.snap.Balances {
			if by[b.Unit] == nil {
				by[b.Unit] = map[string]int64{}
			}
			by[b.Unit][b.Kind] = b.Amount
		}
		for u, k := range by {
			if k["total"] != k["granted"]+k["topup"] {
				t.Errorf("%s %s: total %d != granted %d + topup %d", c.name, u, k["total"], k["granted"], k["topup"])
			}
		}
	}
}
