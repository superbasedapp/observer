package store

import (
	"reflect"
	"testing"
)

// TestPickDefaultRoute is the pure, Postgres-free half of the migration-0039
// ordering-trap fix (docs/handovers/next-session-kickoff-2026-09-16-post-v1330-release.md
// §3): the day session_enrichment.sol.v1 is activated there are two active
// session_enrichment routes at route_version 1, and the resolver must still
// pick a winner deterministically. This drives pickDefaultRoute directly with
// literal RouteInfo slices, so it needs no database and cannot skip.
//
// The plan_pinned filter itself is exercised against real Postgres in
// planroute_test.go (TestResolveRouteScenarios) because plan_pinned narrows
// the SQL WHERE clause before rows ever reach this function - pickDefaultRoute
// itself does not re-check the flag.
func TestPickDefaultRoute(t *testing.T) {
	route := func(id string, version int64) RouteInfo {
		return RouteInfo{RouteID: id, RouteVersion: version}
	}

	tests := []struct {
		name       string
		candidates []RouteInfo
		wantID     string
		wantFound  bool
	}{
		{
			name:       "no candidates",
			candidates: nil,
			wantFound:  false,
		},
		{
			name:       "one active route",
			candidates: []RouteInfo{route("session_enrichment.luna.v1", 1)},
			wantID:     "session_enrichment.luna.v1",
			wantFound:  true,
		},
		{
			name: "two same version - tiebreak on route_id ascending",
			candidates: []RouteInfo{
				route("session_enrichment.sol.v1", 1),
				route("session_enrichment.luna.v1", 1),
			},
			// "luna" < "sol" lexically, so luna wins the tie regardless of
			// slice order - proven again below with the order reversed.
			wantID:    "session_enrichment.luna.v1",
			wantFound: true,
		},
		{
			name: "two same version - order reversed, same winner",
			candidates: []RouteInfo{
				route("session_enrichment.luna.v1", 1),
				route("session_enrichment.sol.v1", 1),
			},
			wantID:    "session_enrichment.luna.v1",
			wantFound: true,
		},
		{
			name: "higher route_version wins regardless of route_id",
			candidates: []RouteInfo{
				route("session_enrichment.aaa.v1", 1),
				route("session_enrichment.zzz.v2", 2),
			},
			wantID:    "session_enrichment.zzz.v2",
			wantFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := pickDefaultRoute(tt.candidates)
			if found != tt.wantFound {
				t.Fatalf("pickDefaultRoute(%v) found = %v, want %v", tt.candidates, found, tt.wantFound)
			}
			if found && got.RouteID != tt.wantID {
				t.Fatalf("pickDefaultRoute(%v) = %q, want %q", tt.candidates, got.RouteID, tt.wantID)
			}
		})
	}
}

// TestClassifyFeatureCoverage is the pure, Postgres-free half of the
// readiness follow-up: excluding plan_pinned routes from ResolveRoute's
// candidate set (pickDefaultRoute, above) is safe only as long as some
// non-pinned route stays active per feature. This drives
// classifyFeatureCoverage directly with literal row facts, so it needs no
// database and cannot skip.
func TestClassifyFeatureCoverage(t *testing.T) {
	row := func(feature string, active, pinned bool) routeCoverageRow {
		return routeCoverageRow{Feature: feature, Active: active, PlanPinned: pinned}
	}

	tests := []struct {
		name string
		rows []routeCoverageRow
		want []FeatureCoverage
	}{
		{
			name: "no rows at all",
			rows: nil,
			want: []FeatureCoverage{},
		},
		{
			name: "one active non-pinned route - covered",
			rows: []routeCoverageRow{row("session_enrichment", true, false)},
			want: []FeatureCoverage{{Feature: "session_enrichment", HasDefault: true}},
		},
		{
			name: "active default plus an inactive-or-pinned extra - still covered",
			rows: []routeCoverageRow{
				row("session_enrichment", true, false),
				row("session_enrichment", true, true), // the Sol shape
			},
			want: []FeatureCoverage{{Feature: "session_enrichment", HasDefault: true}},
		},
		{
			name: "only route is plan_pinned - the outage the review flagged",
			rows: []routeCoverageRow{row("session_enrichment", true, true)},
			want: []FeatureCoverage{{Feature: "session_enrichment", HasDefault: false}},
		},
		{
			name: "only route is inactive - also uncovered",
			rows: []routeCoverageRow{row("project_digest", false, false)},
			want: []FeatureCoverage{{Feature: "project_digest", HasDefault: false}},
		},
		{
			name: "pinned-and-inactive route only - uncovered (both reasons at once)",
			rows: []routeCoverageRow{row("session_enrichment", false, true)},
			want: []FeatureCoverage{{Feature: "session_enrichment", HasDefault: false}},
		},
		{
			name: "multiple features - sorted, independent, one covered one not",
			rows: []routeCoverageRow{
				row("session_enrichment", true, false),
				row("project_digest", true, true),
			},
			want: []FeatureCoverage{
				{Feature: "project_digest", HasDefault: false},
				{Feature: "session_enrichment", HasDefault: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyFeatureCoverage(tt.rows)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("classifyFeatureCoverage(%v) = %+v, want %+v", tt.rows, got, tt.want)
			}
		})
	}
}
