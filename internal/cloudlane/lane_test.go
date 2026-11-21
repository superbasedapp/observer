package cloudlane

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func bucket(t *testing.T, l Lane, name string) Bucket {
	t.Helper()
	for _, b := range l.Buckets {
		if b.Location == name {
			return b
		}
	}
	t.Fatalf("no %q bucket in %+v", name, l.Buckets)
	return Bucket{}
}

func TestBuildBucketsByLocationInFixedOrder(t *testing.T) {
	lane := Build(Input{
		Sessions: []Session{
			{ID: "u1"},
			{ID: "c1", Location: models.ExecutionVendorCloud},
			{ID: "l1", Location: models.ExecutionLocal},
			{ID: "w1", Location: models.ExecutionCustomerWorker},
			{ID: "x1", Location: "mars"}, // out of vocabulary reads as unknown
			{ID: "l1", Location: models.ExecutionLocal},
		},
	})
	var got []string
	for _, b := range lane.Buckets {
		got = append(got, b.Location)
	}
	want := []string{"local", "vendor_cloud", "customer_worker", "unknown"}
	if len(got) != len(want) {
		t.Fatalf("buckets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("buckets = %v, want %v", got, want)
		}
	}
	if lane.OffMachineSessions != 2 || lane.UnknownSessions != 2 {
		t.Fatalf("off-machine %d unknown %d, want 2 and 2", lane.OffMachineSessions, lane.UnknownSessions)
	}
	if b := bucket(t, lane, "local"); b.Sessions != 1 {
		t.Fatalf("duplicate session row counted twice: %d", b.Sessions)
	}
}

func TestBuildMissingFiguresAreNeverZero(t *testing.T) {
	lane := Build(Input{
		Sessions: []Session{
			{ID: "c1", Location: models.ExecutionVendorCloud},
			{ID: "c2", Location: models.ExecutionVendorCloud},
		},
	})
	b := bucket(t, lane, "vendor_cloud")
	if b.Tokens != nil || b.CostUSD != nil {
		t.Fatalf("a bucket with no turns must carry no token or cost figure: %+v", b)
	}
	if b.TokenCoverage != CoverageUnknown || b.CostCoverage != CoverageUnknown {
		t.Fatalf("coverage = %s / %s, want unknown / unknown", b.TokenCoverage, b.CostCoverage)
	}
}

func TestBuildTokenAndCostCoverage(t *testing.T) {
	cases := []struct {
		name      string
		turns     []Turn
		wantTok   Coverage
		wantCost  Coverage
		wantTotal int64
	}{
		{
			name:      "every session reported and priced",
			turns:     []Turn{{SessionID: "c1", Input: 10, Output: 5, Priced: true, CostUSD: 1}, {SessionID: "c2", Input: 1, Priced: true, CostUSD: 2}},
			wantTok:   CoverageFull,
			wantCost:  CoverageFull,
			wantTotal: 16,
		},
		{
			name:      "every turn priced but one session has none",
			turns:     []Turn{{SessionID: "c1", Input: 10, Priced: true, CostUSD: 1}},
			wantTok:   CoveragePartial,
			wantCost:  CoveragePartial,
			wantTotal: 10,
		},
		{
			name:      "one session silent, one turn unpriced",
			turns:     []Turn{{SessionID: "c1", Input: 10, Priced: true, CostUSD: 1}, {SessionID: "c1", Output: 3}},
			wantTok:   CoveragePartial,
			wantCost:  CoveragePartial,
			wantTotal: 13,
		},
		{
			name:      "tokens but nothing priced",
			turns:     []Turn{{SessionID: "c1", Input: 10}, {SessionID: "c2", Input: 1}},
			wantTok:   CoverageFull,
			wantCost:  CoverageUnknown,
			wantTotal: 11,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lane := Build(Input{
				Sessions: []Session{{ID: "c1", Location: "vendor_cloud"}, {ID: "c2", Location: "vendor_cloud"}},
				Turns:    tc.turns,
			})
			b := bucket(t, lane, "vendor_cloud")
			if b.TokenCoverage != tc.wantTok || b.CostCoverage != tc.wantCost {
				t.Fatalf("coverage = %s / %s, want %s / %s", b.TokenCoverage, b.CostCoverage, tc.wantTok, tc.wantCost)
			}
			if b.Tokens == nil || b.Tokens.Total != tc.wantTotal {
				t.Fatalf("tokens = %+v, want total %d", b.Tokens, tc.wantTotal)
			}
			if tc.wantCost == CoverageUnknown && b.CostUSD != nil {
				t.Fatalf("an unpriced bucket must carry no dollar figure, got %v", *b.CostUSD)
			}
		})
	}
}

func TestBuildOrphanTurnsLandInUnknownAndProvenanceCounts(t *testing.T) {
	lane := Build(Input{
		Sessions: []Session{{ID: "l1", Location: "local"}},
		Turns: []Turn{
			{SessionID: "l1", Input: 1, Source: "proxy", Priced: true},
			{SessionID: "l1", Input: 1, Source: "jsonl", Priced: true},
			{SessionID: "l1", Input: 1, Source: "jsonl", Priced: true},
			{SessionID: "", Input: 4, Source: "proxy", Priced: true, CostUSD: 0.5},
		},
	})
	local := bucket(t, lane, "local")
	if len(local.Provenance) != 2 || local.Provenance[0] != (Provenance{Source: "jsonl", Turns: 2}) {
		t.Fatalf("provenance = %+v", local.Provenance)
	}
	unk := bucket(t, lane, "unknown")
	if unk.Sessions != 0 || unk.Tokens == nil || unk.Tokens.Total != 4 || unk.TokenCoverage != CoverageFull {
		t.Fatalf("orphan turn bucket = %+v", unk)
	}
	if lane.UnknownSessions != 0 {
		t.Fatalf("an orphan turn is not a session")
	}
}

func TestLedgerRollupRules(t *testing.T) {
	t0 := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	sessions := []Session{{ID: "c1", Location: "vendor_cloud"}, {ID: "c2", Location: "vendor_cloud"}, {ID: "c3", Location: "vendor_cloud"}}
	e := func(id int64, sess, vt string, v float64, at time.Duration) LedgerEntry {
		return LedgerEntry{
			ID: id, SessionID: sess, Connector: "devin", Unit: "acu", ValueType: vt,
			MeasurementSource: "provider_run_total", MonetaryStatus: "not_monetary", Value: v, ReportedAt: t0.Add(at),
		}
	}
	cases := []struct {
		name     string
		entries  []LedgerEntry
		wantRule Rollup
		want     float64
		wantCov  Coverage
	}{
		{"delta sums", []LedgerEntry{e(1, "c1", "delta", 2, 0), e(2, "c1", "delta", 3, time.Minute), e(3, "c2", "delta", 1, 0)}, RollupSum, 6, CoveragePartial},
		{"interval sums", []LedgerEntry{e(1, "c1", "interval", 2, 0), e(2, "c2", "interval", 3, 0), e(3, "c3", "interval", 1, 0)}, RollupSum, 6, CoverageFull},
		{"cumulative keeps newest per session", []LedgerEntry{e(1, "c1", "cumulative", 2, 0), e(2, "c1", "cumulative", 5, time.Minute), e(3, "c2", "cumulative", 1, 0)}, RollupLatestPerSession, 6, CoveragePartial},
		{"snapshot keeps newest per session", []LedgerEntry{e(1, "c1", "snapshot", 9, time.Minute), e(2, "c1", "snapshot", 4, 0)}, RollupLatestPerSession, 9, CoveragePartial},
		{"gauge keeps only the newest", []LedgerEntry{e(1, "c1", "gauge", 50, 0), e(2, "c2", "gauge", 40, time.Hour)}, RollupLatest, 40, CoveragePartial},
		{"unknown value type never adds", []LedgerEntry{e(1, "c1", "mystery", 7, 0), e(2, "c2", "mystery", 8, 0)}, RollupLatest, 8, CoveragePartial},
		{"superseded rows drop out", []LedgerEntry{e(1, "c1", "delta", 2, 0), {ID: 2, SupersedesID: 1, SessionID: "c1", Connector: "devin", Unit: "acu", ValueType: "delta", MeasurementSource: "provider_run_total", MonetaryStatus: "not_monetary", Value: 2.5, ReportedAt: t0}}, RollupSum, 2.5, CoveragePartial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lane := Build(Input{Sessions: sessions, Ledger: tc.entries})
			b := bucket(t, lane, "vendor_cloud")
			if len(b.Ledger) != 1 {
				t.Fatalf("figures = %+v, want one", b.Ledger)
			}
			f := b.Ledger[0]
			if f.Rollup != tc.wantRule || f.Value != tc.want || f.Coverage != tc.wantCov {
				t.Fatalf("figure = %+v, want rule %s value %v coverage %s", f, tc.wantRule, tc.want, tc.wantCov)
			}
		})
	}
}

func TestLedgerNeverMixesUnits(t *testing.T) {
	lane := Build(Input{
		Sessions: []Session{{ID: "c1", Location: "vendor_cloud"}},
		Ledger: []LedgerEntry{
			{ID: 1, SessionID: "c1", Connector: "devin", Unit: "acu", ValueType: "delta", MeasurementSource: "provider_run_total", MonetaryStatus: "not_monetary", Value: 2},
			{ID: 2, SessionID: "c1", Connector: "devin", Unit: "usd", ValueType: "delta", MeasurementSource: "provider_run_total", MonetaryStatus: "reported_charge", Value: 4},
			{ID: 3, SessionID: "elsewhere", Connector: "devin", Unit: "acu", ValueType: "delta", MeasurementSource: "provider_run_total", MonetaryStatus: "not_monetary", Value: 99},
		},
	})
	b := bucket(t, lane, "vendor_cloud")
	if len(b.Ledger) != 2 || b.Ledger[0].Unit != "acu" || b.Ledger[0].Value != 2 || b.Ledger[1].Unit != "usd" || b.Ledger[1].Value != 4 {
		t.Fatalf("figures = %+v", b.Ledger)
	}
}

func TestBuildEmptyInput(t *testing.T) {
	lane := Build(Input{})
	if lane.Buckets == nil || len(lane.Buckets) != 0 {
		t.Fatalf("empty input must give an empty, non-nil bucket list: %+v", lane.Buckets)
	}
}

func TestAccountsSorted(t *testing.T) {
	lane := Build(Input{Accounts: []Account{{Connector: "copilot-agent"}, {Connector: "codex-cloud", CoverageState: "partial_history"}}})
	if lane.Accounts[0].Connector != "codex-cloud" {
		t.Fatalf("accounts = %+v", lane.Accounts)
	}
}
