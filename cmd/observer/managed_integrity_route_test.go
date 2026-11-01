package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/routeattest"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/winrelay"
)

// The node store is the step's production source.
var _ routeObservationSource = (*store.Store)(nil)

// fakeRouteObservation is a canned routeObservationSource that records the
// window start it was asked for.
type fakeRouteObservation struct {
	rows  []store.RouteObservedRow
	err   error
	since time.Time
}

func (f *fakeRouteObservation) RouteObservedSince(_ context.Context, since time.Time) ([]store.RouteObservedRow, error) {
	f.since = since
	return f.rows, f.err
}

// everySurfaceRoutable is a policy under which every stamped surface is
// routable and measurable, so the test can reach a desktop or a foreign-tool
// bypass the registry does not ground yet.
func everySurfaceRoutable(string, string, string) routeattest.SurfaceFacts {
	return routeattest.SurfaceFacts{Routable: true, Correlation: integration.CorrelationRequestID}
}

// TestAddRouteObservation: one row per case of the node step (OBS-6).
func TestAddRouteObservation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	row := func(tool, kind string, sessions, proxied int) store.RouteObservedRow {
		return store.RouteObservedRow{Tool: tool, Surface: kind, Sessions: sessions, ProxiedSessions: proxied}
	}
	cases := []struct {
		name         string
		src          *fakeRouteObservation
		policy       routeattest.SurfacePolicy
		wantVersion  int
		wantSurfaces []string
	}{
		{name: "no store", src: nil, wantVersion: 0},
		{name: "query fails", src: &fakeRouteObservation{err: errors.New("database is locked")}, wantVersion: 0},
		{name: "no sessions is a clean reading", src: &fakeRouteObservation{}, wantVersion: orgcontract.ManagedRouteObservationVersion},
		{
			name:         "registry: CLI ran around the proxy",
			src:          &fakeRouteObservation{rows: []store.RouteObservedRow{row("claude-code", "cli", 3, 0)}},
			wantVersion:  orgcontract.ManagedRouteObservationVersion,
			wantSurfaces: []string{"claude-code/cli"},
		},
		{
			name:         "registry: CLI partly proxied",
			src:          &fakeRouteObservation{rows: []store.RouteObservedRow{row("codex", "cli", 4, 1)}},
			wantVersion:  orgcontract.ManagedRouteObservationVersion,
			wantSurfaces: []string{"codex/cli"},
		},
		{
			name:        "registry: CLI fully proxied",
			src:         &fakeRouteObservation{rows: []store.RouteObservedRow{row("claude-code", "cli", 5, 5)}},
			wantVersion: orgcontract.ManagedRouteObservationVersion,
		},
		{
			name:        "registry: desktop not judged is not a bypass",
			src:         &fakeRouteObservation{rows: []store.RouteObservedRow{row("claude-code", "cli", 5, 5), row("claude-code", "desktop", 3, 0)}},
			wantVersion: orgcontract.ManagedRouteObservationVersion,
		},
		{
			name:         "grounded desktop bypass beside a proxied CLI",
			src:          &fakeRouteObservation{rows: []store.RouteObservedRow{row("claude-code", "cli", 5, 5), row("claude-code", "desktop", 3, 0)}},
			policy:       everySurfaceRoutable,
			wantVersion:  orgcontract.ManagedRouteObservationVersion,
			wantSurfaces: []string{"claude-code/desktop"},
		},
		{
			name:        "unstamped sessions with a proxied session are not a bypass",
			src:         &fakeRouteObservation{rows: []store.RouteObservedRow{row("claude-code", "", 4, 1)}},
			policy:      everySurfaceRoutable,
			wantVersion: orgcontract.ManagedRouteObservationVersion,
		},
		{
			// DEC-4 addendum (P-172): the group is a tool-level bypass, and an
			// unstamped group has no closed wire label, so the observation
			// reads not reported (never clean), as any unlabelled-only bypass.
			name:        "unstamped sessions with none proxied: a tool-level bypass reads not reported, never clean",
			src:         &fakeRouteObservation{rows: []store.RouteObservedRow{row("claude-code", "", 4, 0)}},
			policy:      everySurfaceRoutable,
			wantVersion: 0,
		},
		{
			name:         "a tool-level unstamped bypass beside a labelled one keeps the label",
			src:          &fakeRouteObservation{rows: []store.RouteObservedRow{row("codex", "", 2, 0), row("claude-code", "cli", 3, 0)}},
			wantVersion:  orgcontract.ManagedRouteObservationVersion,
			wantSurfaces: []string{"claude-code/cli"},
		},
		{
			name:         "registry: an unstamped single-surface tool's bypass is labelled as its CLI",
			src:          &fakeRouteObservation{rows: []store.RouteObservedRow{row("opencode", "", 3, 0)}},
			wantVersion:  orgcontract.ManagedRouteObservationVersion,
			wantSurfaces: []string{"opencode/cli"},
		},
		{
			name:        "only an unlabelled bypass reads not reported, never clean",
			src:         &fakeRouteObservation{rows: []store.RouteObservedRow{row("some-other-tool", "cli", 2, 0)}},
			policy:      everySurfaceRoutable,
			wantVersion: 0,
		},
		{
			name:         "an unlabelled bypass beside a labelled one keeps the label",
			src:          &fakeRouteObservation{rows: []store.RouteObservedRow{row("codex", "ide", 2, 0), row("some-other-tool", "cli", 2, 0)}},
			policy:       everySurfaceRoutable,
			wantVersion:  orgcontract.ManagedRouteObservationVersion,
			wantSurfaces: []string{"codex/ide"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The settings-layer reading (DEC-7) is reported clean, so the
			// overall health below reads the route observation alone.
			report := orgcontract.ManagedIntegrityReport{CaptureCheckVersion: orgcontract.ManagedCaptureCheckVersion, ConfigLayerVersion: orgcontract.ManagedConfigLayerVersion}
			var src routeObservationSource
			if tc.src != nil {
				src = tc.src
			}
			addRouteObservation(context.Background(), src, nil, now, tc.policy, &report)
			if tc.src != nil && tc.src.err == nil && !tc.src.since.Equal(now.Add(-routeattest.ObservedWindow)) {
				t.Fatalf("window start = %v, want %v", tc.src.since, now.Add(-routeattest.ObservedWindow))
			}
			norm := report.NormalizeLabels()
			if norm.RouteObservationVersion != tc.wantVersion {
				t.Fatalf("version = %d, want %d", norm.RouteObservationVersion, tc.wantVersion)
			}
			if !reflect.DeepEqual(norm.UnroutedSurfaces, tc.wantSurfaces) {
				t.Fatalf("unrouted surfaces = %#v, want %#v", norm.UnroutedSurfaces, tc.wantSurfaces)
			}
			hasLabel := false
			for _, l := range norm.CaptureRisks {
				hasLabel = hasLabel || l == orgcontract.CaptureRiskRouteBypassObserved
			}
			if hasLabel != (len(tc.wantSurfaces) > 0) {
				t.Fatalf("capture risks = %v, want route_bypass_observed exactly when a surface is unrouted", norm.CaptureRisks)
			}
			wantHealth := orgcontract.ManagedHealthOK
			switch {
			case len(tc.wantSurfaces) > 0:
				wantHealth = orgcontract.ManagedHealthAtRisk
			case tc.wantVersion == 0:
				wantHealth = orgcontract.ManagedHealthNotReported
			}
			if got := norm.OverallHealth().Health; got != wantHealth {
				t.Fatalf("overall health = %s, want %s", got, wantHealth)
			}
		})
	}
}

// TestAddRouteObservationRelayBypass pins CC-9 / D12 on the managed report:
// a fail-open forward the relay recorded inside the window is an observed
// bypass with no closed surface label, so alone it reads "not reported"
// (never clean), and beside a labelled bypass the label stands. An
// unreadable journal counts the same way; an empty one changes nothing.
func TestAddRouteObservationRelayBypass(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	recorded := func(since time.Time) diag.RelayJournal {
		if !since.Equal(now.Add(-routeattest.ObservedWindow)) {
			t.Errorf("relay window start = %v", since)
		}
		return diag.RelayJournal{Found: true, Summary: winrelay.Summary{Tools: []winrelay.ToolSummary{{Tool: "claude-code", Count: 2}}}}
	}
	unreadable := func(time.Time) diag.RelayJournal {
		return diag.RelayJournal{Found: true, Unreadable: []string{"/mnt/c/Users/u/.observer/relay/bypass.jsonl"}}
	}
	empty := func(time.Time) diag.RelayJournal { return diag.RelayJournal{Found: true} }
	cli := store.RouteObservedRow{Tool: "claude-code", Surface: "cli", Sessions: 3, ProxiedSessions: 0}
	cases := []struct {
		name         string
		rows         []store.RouteObservedRow
		relay        relayBypassReader
		wantVersion  int
		wantSurfaces []string
	}{
		{"a recorded relay bypass alone is never clean", nil, recorded, 0, nil},
		{"an unreadable journal is never clean", nil, unreadable, 0, nil},
		{"an empty journal changes nothing", nil, empty, orgcontract.ManagedRouteObservationVersion, nil},
		{"beside a labelled bypass the label stands", []store.RouteObservedRow{cli}, recorded, orgcontract.ManagedRouteObservationVersion, []string{"claude-code/cli"}},
	}
	for _, tc := range cases {
		report := orgcontract.ManagedIntegrityReport{}
		addRouteObservation(context.Background(), &fakeRouteObservation{rows: tc.rows}, tc.relay, now, nil, &report)
		norm := report.NormalizeLabels()
		if norm.RouteObservationVersion != tc.wantVersion || !reflect.DeepEqual(norm.UnroutedSurfaces, tc.wantSurfaces) {
			t.Errorf("%s: version %d surfaces %v; want %d %v", tc.name, norm.RouteObservationVersion, norm.UnroutedSurfaces, tc.wantVersion, tc.wantSurfaces)
		}
	}
}
