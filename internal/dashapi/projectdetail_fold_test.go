package dashapi

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudlane"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
)

func fp(v float64) *float64 { return &v }

func TestSpendSplitLines(t *testing.T) {
	if got := SpendSplitLines(nil); got != nil {
		t.Fatalf("nil split: got %v", got)
	}
	got := SpendSplitLines(&APIProjectSpendLocations{
		Buckets: []cloudlane.Bucket{
			{Location: "local", CostUSD: fp(3.96), CostCoverage: cloudlane.CoverageFull},
			{
				Location: "vendor_cloud", CostUSD: fp(3.47), CostCoverage: cloudlane.CoveragePartial,
				Ledger: []cloudlane.LedgerFigure{{Connector: "codex-cloud", Unit: "credit", Value: 14}},
			},
			{Location: "customer_worker", CostUSD: fp(0.61), CostCoverage: cloudlane.CoverageFull},
			{Location: "unknown", CostCoverage: cloudlane.CoverageUnknown},
		},
		Folded:          []FoldedProject{{ID: 2, RootPath: "cloud:github.com/acme/app", Synthetic: true}},
		SupersededTurns: 2,
	})
	want := []string{
		"where it ran: local $3.96, cloud $3.47 (partial), worker $0.61, unknown not reported",
		"provider usage, own units (not in the dollar total): cloud 14 credit (codex-cloud)",
		"includes cloud project cloud:github.com/acme/app",
		"2 turns set aside: a better rail reported the same session",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
}

func TestStampTwinCaveat(t *testing.T) {
	tiles := []apiProjectRoiTile{
		{Key: "a", Unit: "usd"},
		{Key: "b", Unit: "usd_per_commit", Caveat: "commit capture unavailable"},
		{Key: "c", Unit: "pct"},
		{Key: "d", Unit: "usdx"},
		{Key: "e", Unit: "usd", Caveat: "Partial window."},
	}
	stampTwinCaveat(tiles)
	want := map[string]string{
		"a": twinCaveat,
		"b": "commit capture unavailable. " + twinCaveat,
		"c": "",
		"d": "",
		"e": "Partial window. " + twinCaveat,
	}
	for _, tile := range tiles {
		if tile.Caveat != want[tile.Key] {
			t.Errorf("tile %s (unit %s): caveat %q, want %q", tile.Key, tile.Unit, tile.Caveat, want[tile.Key])
		}
	}
}

func TestPricedSpend(t *testing.T) {
	sp := pricedSpend(
		[]projectroi.Turn{{SessionID: "a", CostUSD: 1, Priced: true}, {SessionID: "a", CostUSD: 0.5, Priced: true}, {SessionID: "b", Priced: false}, {CostUSD: 2, Priced: true}},
		[]projectroi.Session{{ID: "a", CostUSD: 99}, {ID: "b", CostUSD: 99}, {ID: "c", CostUSD: 99}},
	)
	if sp.UnpricedTurns != 1 {
		t.Errorf("unpriced = %d", sp.UnpricedTurns)
	}
	want := map[string]float64{"a": 1.5, "b": 0, "c": 0}
	for _, s := range sp.Sessions {
		if s.CostUSD != want[s.ID] {
			t.Errorf("session %s cost %v, want %v", s.ID, s.CostUSD, want[s.ID])
		}
	}
}
