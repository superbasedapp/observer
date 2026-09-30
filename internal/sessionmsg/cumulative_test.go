package sessionmsg

import "testing"

// TestReconcileCumulative is the table of the session-cumulative
// reconciliation (ported from the node cost engine's
// TestReconcileSessionAggregates when the rule moved into Derive): the
// larger coverage set by billable total wins WHOLESALE, the other is dropped
// entirely, and the per-turn side is deduplicated BEFORE the comparison.
func TestReconcileCumulative(t *testing.T) {
	ts := func(s int) string { return "2026-09-22T12:00:" + string(rune('0'+s/10)) + string(rune('0'+s%10)) + "Z" }
	cum := func(in, out, cr int64) TokenRow {
		return TokenRow{SourceEventID: "tokens:s", Timestamp: ts(30), Model: "m", Input: in, Output: out, CacheRead: cr}
	}
	tok := func(id string, sec int, in, out int64) TokenRow {
		return TokenRow{SourceEventID: id, Timestamp: ts(sec), Model: "m", Input: in, Output: out}
	}
	prx := func(id string, sec int, in, out int64) ProxyRow {
		return ProxyRow{RequestID: id, Timestamp: ts(sec), Model: "m", Input: in, Output: out}
	}
	cases := []struct {
		name       string
		cumulative bool
		proxies    []ProxyRow
		tokens     []TokenRow
		wantProxy  []bool
		wantToken  []bool
		wantTotal  int64 // billable total of what counts
	}{
		{
			name: "cumulative exceeds the proxy: cumulative wins, proxy dropped", cumulative: true,
			proxies: []ProxyRow{prx("resp_1", 1, 100, 50)}, tokens: []TokenRow{cum(1000, 500, 0)},
			wantProxy: []bool{false}, wantToken: []bool{true}, wantTotal: 1500,
		},
		{
			name: "proxy covers at least as much: cumulative dropped", cumulative: true,
			proxies:   []ProxyRow{prx("resp_1", 1, 1000, 400), prx("resp_2", 2, 500, 100)},
			tokens:    []TokenRow{cum(100, 50, 0)},
			wantProxy: []bool{true, true}, wantToken: []bool{false}, wantTotal: 2000,
		},
		{
			name: "no other signal: cumulative kept", cumulative: true,
			tokens: []TokenRow{cum(10, 5, 0)}, wantToken: []bool{true}, wantTotal: 15,
		},
		{
			name: "cache-dominant cumulative beats a proxy on input+output alone", cumulative: true,
			proxies: []ProxyRow{prx("resp_1", 1, 100, 100)}, tokens: []TokenRow{cum(100, 0, 10_000)},
			wantProxy: []bool{false}, wantToken: []bool{true}, wantTotal: 10_100,
		},
		{
			name: "proxy and its own transcript twin dedup before the comparison", cumulative: true,
			proxies:   []ProxyRow{prx("resp_1", 1, 600, 0)},
			tokens:    []TokenRow{cum(1000, 0, 0), tok("resp_1", 2, 600, 0)},
			wantProxy: []bool{false}, wantToken: []bool{true, false}, wantTotal: 1000,
		},
		{
			name: "capability off (aider): a tokens: row is an ordinary per-turn row", cumulative: false,
			proxies:   []ProxyRow{prx("resp_1", 1, 1000, 400)},
			tokens:    []TokenRow{{SourceEventID: "tokens:chat1:0", Timestamp: ts(40), Model: "m", Input: 10, Output: 5}},
			wantProxy: []bool{true}, wantToken: []bool{true}, wantTotal: 1415,
		},
		{
			name: "cumulative + per-turn, no proxy: the larger per-turn capture wins", cumulative: true,
			tokens:    []TokenRow{cum(1000, 0, 0), tok("msg_1", 1, 900, 200), tok("msg_2", 2, 300, 100)},
			wantToken: []bool{false, true, true}, wantTotal: 1500,
		},
		{
			name: "cumulative + a thin per-turn row: cumulative wins, per-turn dropped", cumulative: true,
			tokens:    []TokenRow{cum(1000, 0, 0), tok("msg_1", 1, 300, 200)},
			wantToken: []bool{true, false}, wantTotal: 1000,
		},
		{
			name: "the review's double-count shape: per-turn + partial proxy out-cover the cumulative", cumulative: true,
			proxies:   []ProxyRow{prx("resp_1", 1, 60, 40)},
			tokens:    []TokenRow{cum(1000, 0, 0), tok("msg_1", 2, 700, 300)},
			wantProxy: []bool{true}, wantToken: []bool{false, true}, wantTotal: 1100,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := DeriveInput{ProxyRows: c.proxies, TokenRows: c.tokens, SessionCumulative: c.cumulative}
			v := DeriveVerdicts(in)
			for i, want := range c.wantProxy {
				if v.ProxyCounted[i] != want {
					t.Errorf("ProxyCounted[%d] = %v, want %v", i, v.ProxyCounted[i], want)
				}
			}
			for i, want := range c.wantToken {
				if v.TokenCounted[i] != want {
					t.Errorf("TokenCounted[%d] = %v, want %v", i, v.TokenCounted[i], want)
				}
			}
			totals := SumContributions(Derive(in), "")
			b := totals.Bundle
			got := b.Input + b.Output + b.Reasoning + b.CacheRead + b.CacheCreation + b.CacheCreation1h + b.WebSearchRequests
			if got != c.wantTotal {
				t.Errorf("Derive billable total = %d, want %d", got, c.wantTotal)
			}
		})
	}
}

// TestReconcileCumulative_DroppedProxyKeepsItsMessageRow pins that a proxy
// row the reconciliation dropped still renders as a message (a real turn,
// with its timing) but carries no spend.
func TestReconcileCumulative_DroppedProxyKeepsItsMessageRow(t *testing.T) {
	in := DeriveInput{
		ProxyRows:         []ProxyRow{{RequestID: "resp_1", Timestamp: "2026-09-22T12:00:01Z", Model: "m", Input: 10, Output: 5, TotalMs: 900, CostUSD: 0.5}},
		TokenRows:         []TokenRow{{SourceEventID: "tokens:s", Timestamp: "2026-09-22T12:00:30Z", Model: "m", Input: 1000}},
		SessionCumulative: true,
	}
	rows := Derive(in)
	var proxyRow *Row
	for _, r := range rows {
		if r.Key == "resp_1" {
			proxyRow = r
		}
	}
	if proxyRow == nil {
		t.Fatalf("the dropped proxy row's message row is missing: %+v", rows)
	}
	if len(proxyRow.Contributions) != 0 || proxyRow.Bundle != (TokenBundle{}) || proxyRow.RecordedCostUSD != 0 {
		t.Fatalf("a dropped proxy row must carry no spend: %+v", proxyRow)
	}
	if proxyRow.TotalMs != 900 {
		t.Errorf("TotalMs = %d, want the turn's own 900", proxyRow.TotalMs)
	}
}

// TestDeriveVerdicts_ProxyPartner pins the attribution link: a shape twin
// first, else the transcript row carrying the proxy's request id, else -1 -
// against the caller's own token indexes.
func TestDeriveVerdicts_ProxyPartner(t *testing.T) {
	in := DeriveInput{
		ProxyRows: []ProxyRow{
			{RequestID: "msg_a", Timestamp: "2026-09-27T10:00:00Z", Model: "m", Input: 1, Output: 9},   // id match
			{RequestID: "resp_b", Timestamp: "2026-09-27T10:01:00Z", Model: "m", Input: 2, Output: 30}, // shape twin
			{RequestID: "resp_c", Timestamp: "2026-09-27T10:02:00Z", Model: "m", Input: 3, Output: 7},  // proxy-only
		},
		TokenRows: []TokenRow{
			{SourceEventID: "tk:b", Timestamp: "2026-09-27T10:01:03Z", Model: "m", Input: 2, Output: 20, Reasoning: 10},
			{SourceEventID: "msg_a", Timestamp: "2026-09-27T10:00:02Z", Model: "m", Input: 1, Output: 8},
		},
	}
	v := DeriveVerdicts(in)
	if got := v.ProxyPartner; got[0] != 1 || got[1] != 0 || got[2] != -1 {
		t.Fatalf("ProxyPartner = %v, want [1 0 -1]", got)
	}
}
