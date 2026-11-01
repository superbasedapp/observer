package integration

import (
	"regexp"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// knownRouteStatuses is the closed RouteStatus set (RouteStatuses). A new
// value is added there deliberately, with its consumers.
var knownRouteStatuses = func() map[RouteStatus]bool {
	m := map[RouteStatus]bool{}
	for _, s := range RouteStatuses() {
		m[s] = true
	}
	return m
}()

// surfaceHostToken is the shape of a declared host token: the same bounded,
// lowercase token an adapter stamps in sessions.surface_host.
var surfaceHostToken = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// TestRouteSurfacesAreRegistryRows pins the RouteSurfaces column's table:
// every key is a registry tool (a typo would silently drop the rows) and the
// registry row carries exactly the declared rows.
func TestRouteSurfacesAreRegistryRows(t *testing.T) {
	for tool, rows := range routeSurfaces {
		c, ok := For(tool)
		if !ok {
			t.Errorf("routeSurfaces[%q] has no registry row", tool)
			continue
		}
		if !slices.Equal(c.RouteSurfaces, rows) {
			t.Errorf("%s: registry row does not carry its RouteSurfaces column", tool)
		}
	}
	for _, c := range Capabilities() {
		if _, declared := routeSurfaces[c.Tool]; !declared && len(c.RouteSurfaces) != 0 {
			t.Errorf("%s: carries RouteSurfaces that the routeSurfaces table does not declare", c.Tool)
		}
	}
}

// TestRouteSurfaceRowsWellFormed checks every declared row against the
// closed vocabularies and the honesty rule (a non-zero fact is grounded).
func TestRouteSurfaceRowsWellFormed(t *testing.T) {
	for tool, rows := range routeSurfaces {
		seen := map[[2]string]bool{}
		for i, r := range rows {
			where := tool + "[" + r.Kind + "/" + r.Host + "]"
			if !models.KnownSurface(r.Kind) {
				t.Errorf("%s row %d: kind %q is not a models.Surface* kind", tool, i, r.Kind)
			}
			if r.Host != "" && !surfaceHostToken.MatchString(r.Host) {
				t.Errorf("%s: host %q is not a bounded lowercase token", where, r.Host)
			}
			key := [2]string{r.Kind, r.Host}
			if seen[key] {
				t.Errorf("%s: duplicate (kind, host)", where)
			}
			seen[key] = true
			if !knownRouteStatuses[r.Routability] {
				t.Errorf("%s: undeclared RouteStatus %q", where, r.Routability)
			}
			if !r.CorrelationMode.Known() {
				t.Errorf("%s: undeclared CorrelationMode %q", where, r.CorrelationMode)
			}
			hasFact := r.Routability != RouteStatusUnknown || r.CorrelationMode != CorrelationUnknown
			if hasFact && r.Grounding == "" {
				t.Errorf("%s: declares a fact without Grounding", where)
			}
			if !hasFact {
				t.Errorf("%s: declares no fact (a row with neither Routability nor CorrelationMode is noise)", where)
			}
			if r.Note == "" {
				t.Errorf("%s: no Note", where)
			}
		}
	}
}

// TestRouteSurfaceForMatchTable has one row per match rule, plus the
// ordering cases (an exact row beats a kind row wherever it is listed).
func TestRouteSurfaceForMatchTable(t *testing.T) {
	cliAny := SurfaceRoute{Kind: models.SurfaceCLI, CorrelationMode: CorrelationRequestID, Note: "n", Grounding: "g"}
	desktopAny := SurfaceRoute{Kind: models.SurfaceDesktop, Routability: RouteStatusProbeRequired, Note: "n", Grounding: "g"}
	desktopClaude := SurfaceRoute{Kind: models.SurfaceDesktop, Host: "claude-desktop", Routability: RouteStatusNativeExempt, Note: "n", Grounding: "g"}
	c := Capability{
		Tool:          "t",
		Routability:   RouteStatusRoutableNow,
		RouteSurfaces: []SurfaceRoute{desktopAny, cliAny, desktopClaude},
	}
	cases := []struct {
		name       string
		kind, host string
		want       SurfaceRoute
		wantMatch  SurfaceMatch
	}{
		{"exact host beats a kind row listed first", models.SurfaceDesktop, "claude-desktop", desktopClaude, SurfaceMatchExact},
		{"kind row for an undeclared host", models.SurfaceDesktop, "codex-desktop", desktopAny, SurfaceMatchKind},
		{"kind row for an empty host", models.SurfaceCLI, "", cliAny, SurfaceMatchKind},
		{"kind row when a host is given", models.SurfaceCLI, "cli", cliAny, SurfaceMatchKind},
		{
			"no row falls back to the tool", models.SurfaceIDE, "vscode",
			SurfaceRoute{Kind: models.SurfaceIDE, Host: "vscode", Routability: RouteStatusRoutableNow},
			SurfaceMatchTool,
		},
		{
			"empty kind falls back to the tool", "", "claude-desktop",
			SurfaceRoute{Host: "claude-desktop", Routability: RouteStatusRoutableNow},
			SurfaceMatchTool,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, match := c.RouteSurfaceFor(tc.kind, tc.host)
			if got != tc.want || match != tc.wantMatch {
				t.Errorf("RouteSurfaceFor(%q, %q) = %+v, %s; want %+v, %s", tc.kind, tc.host, got, match, tc.want, tc.wantMatch)
			}
		})
	}
	var none Capability
	if got, match := none.RouteSurfaceFor(models.SurfaceCLI, ""); match != SurfaceMatchTool || got.Routability != RouteStatusUnknown {
		t.Errorf("zero Capability: got %+v, %s; want the unknown tool fallback", got, match)
	}
}

func TestEffectiveRoutability(t *testing.T) {
	c := Capability{Routability: RouteStatusRoutableNow}
	cases := []struct {
		name string
		row  SurfaceRoute
		want RouteStatus
	}{
		{"zero inherits the tool", SurfaceRoute{Kind: models.SurfaceCLI}, RouteStatusRoutableNow},
		{"own value wins", SurfaceRoute{Kind: models.SurfaceDesktop, Routability: RouteStatusNativeExempt}, RouteStatusNativeExempt},
	}
	for _, tc := range cases {
		if got := tc.row.EffectiveRoutability(c); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestCorrelationModeTable(t *testing.T) {
	cases := []struct {
		mode                     CorrelationMode
		known, measurable, every bool
	}{
		{CorrelationUnknown, true, false, false},
		{CorrelationRequestID, true, true, true},
		{CorrelationProcessBridge, true, true, false},
		{CorrelationUnavailable, true, false, false},
		{CorrelationMode("guessed"), false, false, false},
	}
	for _, tc := range cases {
		if tc.mode.Known() != tc.known || tc.mode.Measurable() != tc.measurable || tc.mode.JoinsEveryTurn() != tc.every {
			t.Errorf("%q: Known=%v Measurable=%v JoinsEveryTurn=%v; want %v %v %v", tc.mode,
				tc.mode.Known(), tc.mode.Measurable(), tc.mode.JoinsEveryTurn(), tc.known, tc.measurable, tc.every)
		}
	}
}

func TestRouteSurfaceHostsOf(t *testing.T) {
	table := map[string][]SurfaceRoute{
		"a": {{Kind: models.SurfaceDesktop, Host: "zeta"}, {Kind: models.SurfaceCLI}},
		"b": {{Kind: models.SurfaceIDE, Host: "alpha"}, {Kind: models.SurfaceDesktop, Host: "zeta"}},
	}
	if got, want := routeSurfaceHostsOf(table), []string{"alpha", "zeta"}; !slices.Equal(got, want) {
		t.Errorf("routeSurfaceHostsOf = %v, want %v", got, want)
	}
	if got := routeSurfaceHostsOf(nil); got == nil || len(got) != 0 {
		t.Errorf("empty table: got %#v, want an empty non-nil slice", got)
	}
}

// TestRouteStatusesClosed pins the closed vocabulary: no duplicate, the
// zero value first, and the surface-only value present.
func TestRouteStatusesClosed(t *testing.T) {
	got := RouteStatuses()
	if len(got) == 0 || got[0] != RouteStatusUnknown {
		t.Fatalf("RouteStatuses() = %v, want the zero value first", got)
	}
	if len(knownRouteStatuses) != len(got) {
		t.Errorf("RouteStatuses() has a duplicate: %v", got)
	}
	if !knownRouteStatuses[RouteStatusSettingsIgnored] {
		t.Error("RouteStatusSettingsIgnored is not in RouteStatuses()")
	}
}

// TestSettingsIgnoredIsSurfaceOnly: settings_ignored describes one surface
// ignoring the tool's settings route, so it never stands for a whole tool.
func TestSettingsIgnoredIsSurfaceOnly(t *testing.T) {
	for _, c := range Capabilities() {
		if c.Routability == RouteStatusSettingsIgnored {
			t.Errorf("%s: tool-level Routability is settings_ignored; it is a SurfaceRoute value only", c.Tool)
		}
	}
}

// multiSurfaceProxiedTools are the proxied tools whose adapter stamps more
// than one capture surface, so an unstamped session could be any of them
// and stays "unknown surface" (no Unstamped row). Every other proxied tool's
// adapter stamps no surface and declares the Unstamped row. Grounding:
// internal/adapter/claudecode/surface.go, codex/surface.go,
// copilotcli/surface.go, clinecli/surface.go.
var multiSurfaceProxiedTools = map[string]bool{
	"claude-code": true,
	"codex":       true,
	"copilot-cli": true,
	"cline-cli":   true,
}

// TestProxiedToolsDeclareCorrelation is the Wave 3 gate-strength rule: every
// tool whose capability routes through the proxy declares the surface its
// route reaches with a known CorrelationMode, so a bypass of that surface
// can block Gateway Mode again. A routed surface (effective routable_now)
// may leave correlation unknown only while it names the pending live check
// that would ground it, and every proxied tool has at least one routed
// surface whose correlation is known. Unstamped sessions are decided per
// tool: an Unstamped row on a routed, measurable surface, or a listed
// multi-surface adapter.
func TestProxiedToolsDeclareCorrelation(t *testing.T) {
	for _, c := range Capabilities() {
		if c.Proxy == nil {
			if len(c.RouteSurfaces) > 0 && multiSurfaceProxiedTools[c.Tool] {
				t.Errorf("%s: listed as a proxied multi-surface tool but routes nothing", c.Tool)
			}
			continue
		}
		var knownRouted, unstamped int
		for _, r := range c.RouteSurfaces {
			where := c.Tool + "[" + r.Kind + "/" + r.Host + "]"
			routed := r.EffectiveRoutability(c) == RouteStatusRoutableNow
			if routed && r.CorrelationMode == CorrelationUnknown && r.LiveCheck == "" {
				t.Errorf("%s: a routed surface with unknown correlation names no live check", where)
			}
			if routed && r.CorrelationMode != CorrelationUnknown {
				knownRouted++
			}
			if r.Unstamped {
				unstamped++
				if !routed || !r.CorrelationMode.Measurable() {
					t.Errorf("%s: the Unstamped row must be a routed, measurable surface", where)
				}
			}
		}
		if knownRouted == 0 {
			t.Errorf("%s: Proxy != nil but no routed surface declares a known CorrelationMode (its bypass could never block)", c.Tool)
		}
		switch {
		case unstamped > 1:
			t.Errorf("%s: %d Unstamped rows, want at most one", c.Tool, unstamped)
		case unstamped == 1 && multiSurfaceProxiedTools[c.Tool]:
			t.Errorf("%s: a multi-surface adapter declares an Unstamped row", c.Tool)
		case unstamped == 0 && !multiSurfaceProxiedTools[c.Tool]:
			t.Errorf("%s: no decision for unstamped sessions (add an Unstamped row, or list it as a multi-surface adapter)", c.Tool)
		}
	}
}

// TestUnstampedSurface: the accessor answers the Unstamped row, or false.
func TestUnstampedSurface(t *testing.T) {
	cli := SurfaceRoute{Kind: models.SurfaceCLI, CorrelationMode: CorrelationProcessBridge, Unstamped: true}
	cases := []struct {
		name   string
		rows   []SurfaceRoute
		wantOK bool
	}{
		{"no rows", nil, false},
		{"rows without the flag", []SurfaceRoute{{Kind: models.SurfaceCLI, CorrelationMode: CorrelationRequestID}}, false},
		{"the flagged row", []SurfaceRoute{{Kind: models.SurfaceIDE}, cli}, true},
	}
	for _, tc := range cases {
		got, ok := Capability{RouteSurfaces: tc.rows}.UnstampedSurface()
		if ok != tc.wantOK || (ok && got != cli) {
			t.Errorf("%s: got %+v, %v", tc.name, got, ok)
		}
	}
}

// TestSurfaceRouteGroundedRows pins the Wave 3 facts that the acceptance
// names: Claude Desktop ignores the settings route (CC-1a), the SDK route is
// unproven (CC-3), and the CLI of both flagship tools is request-id joined.
func TestSurfaceRouteGroundedRows(t *testing.T) {
	cases := []struct {
		tool, kind, host string
		routability      RouteStatus
		correlation      CorrelationMode
	}{
		{"claude-code", models.SurfaceCLI, "claude", RouteStatusRoutableNow, CorrelationRequestID},
		{"claude-code", models.SurfaceDesktop, "claude-desktop", RouteStatusSettingsIgnored, CorrelationUnknown},
		{"claude-code", models.SurfaceSDK, "ts", RouteStatusProbeRequired, CorrelationUnknown},
		{"claude-code", models.SurfaceIDE, "vscode", RouteStatusProbeRequired, CorrelationUnknown},
		{"codex", models.SurfaceCLI, "codex-cli", RouteStatusRoutableNow, CorrelationRequestID},
		{"codex", models.SurfaceDesktop, "codex-desktop", RouteStatusRoutableNow, CorrelationUnknown},
		{"gemini-cli", models.SurfaceCLI, "", RouteStatusRoutableNow, CorrelationProcessBridge},
	}
	for _, tc := range cases {
		c, _ := For(tc.tool)
		row, _ := c.RouteSurfaceFor(tc.kind, tc.host)
		if got := row.EffectiveRoutability(c); got != tc.routability || row.CorrelationMode != tc.correlation {
			t.Errorf("%s %s/%s: routability %q correlation %q; want %q %q", tc.tool, tc.kind, tc.host, got, row.CorrelationMode, tc.routability, tc.correlation)
		}
	}
}
