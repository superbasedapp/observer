package routeattest

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// fixedPolicy returns the same facts for every group.
func fixedPolicy(f SurfaceFacts) SurfacePolicy {
	return func(string, string, string) SurfaceFacts { return f }
}

// TestAttestSurfacesRuleTable has one row per rule of surfaceRules (rows 0
// to 8), plus the ordering rows that pin which rule wins when two hold.
func TestAttestSurfacesRuleTable(t *testing.T) {
	measured := SurfaceFacts{Routable: true, Correlation: integration.CorrelationRequestID}
	cases := []struct {
		name  string
		row   SurfaceTraffic
		facts SurfaceFacts
		want  SurfaceState
	}{
		// Rule 0: invalid input.
		{"0 more proxied than sessions (turns were counted)", SurfaceTraffic{Kind: models.SurfaceCLI, Sessions: 2, ProxiedSessions: 5}, measured, SurfaceInvalidInput},
		{"0 negative sessions", SurfaceTraffic{Kind: models.SurfaceCLI, Sessions: -1}, measured, SurfaceInvalidInput},
		{"0 negative proxied", SurfaceTraffic{Kind: models.SurfaceCLI, Sessions: 1, ProxiedSessions: -1}, measured, SurfaceInvalidInput},
		{"0 invalid beats unknown surface", SurfaceTraffic{Sessions: 1, ProxiedSessions: 2}, measured, SurfaceInvalidInput},
		// Rule 1: unknown surface.
		// An unstamped group with a proxied session: with none, the tool-level
		// fallback (TestAttestSurfacesToolLevelFallback, P-172) would judge it.
		{"1 unstamped sessions", SurfaceTraffic{Sessions: 3, ProxiedSessions: 1}, measured, SurfaceUnknownSurface},
		{"1 kind outside the vocabulary", SurfaceTraffic{Kind: "tui", Sessions: 3}, measured, SurfaceUnknownSurface},
		{"1 unknown surface beats exempt", SurfaceTraffic{Sessions: 3}, SurfaceFacts{Exempt: true}, SurfaceUnknownSurface},
		// Rule 2: exempt.
		{"2 exempt with sessions", SurfaceTraffic{Kind: models.SurfaceDesktop, Sessions: 4}, SurfaceFacts{Exempt: true}, SurfaceExempt},
		{"2 exempt beats unobserved", SurfaceTraffic{Kind: models.SurfaceDesktop}, SurfaceFacts{Exempt: true}, SurfaceExempt},
		// Rule 3: unobserved.
		{"3 no sessions, measured", SurfaceTraffic{Kind: models.SurfaceCLI}, measured, SurfaceUnobserved},
		{"3 unobserved beats unknown correlation", SurfaceTraffic{Kind: models.SurfaceIDE}, SurfaceFacts{}, SurfaceUnobserved},
		// Rule 4: unknown measurability.
		{"4 correlation unknown, none proxied", SurfaceTraffic{Kind: models.SurfaceDesktop, Sessions: 3}, SurfaceFacts{Routable: true}, SurfaceUnknownMeasurability},
		{"4 correlation unknown, some proxied", SurfaceTraffic{Kind: models.SurfaceDesktop, Sessions: 3, ProxiedSessions: 1}, SurfaceFacts{Routable: true}, SurfaceUnknownMeasurability},
		{"4 undeclared correlation reads as unknown", SurfaceTraffic{Kind: models.SurfaceCLI, Sessions: 3}, SurfaceFacts{Correlation: "guessed"}, SurfaceUnknownMeasurability},
		// Rule 5: not measurable.
		{"5 correlation unavailable", SurfaceTraffic{Kind: models.SurfaceSDK, Sessions: 3}, SurfaceFacts{Correlation: integration.CorrelationUnavailable}, SurfaceNotMeasurable},
		// Rule 6: bypass suspect.
		{"6 none proxied", SurfaceTraffic{Kind: models.SurfaceDesktop, Sessions: 3}, measured, SurfaceBypassSuspect},
		// Rule 7: partial.
		{"7 one of two proxied (request_id)", SurfaceTraffic{Kind: models.SurfaceCLI, Sessions: 2, ProxiedSessions: 1}, measured, SurfacePartial},
		{"7 partial through the process bridge", SurfaceTraffic{Kind: models.SurfaceCLI, Sessions: 5, ProxiedSessions: 4}, SurfaceFacts{Correlation: integration.CorrelationProcessBridge}, SurfacePartial},
		// Rule 8: attested.
		{"8 all proxied", SurfaceTraffic{Kind: models.SurfaceCLI, Sessions: 5, ProxiedSessions: 5}, measured, SurfaceAttested},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AttestSurfaces([]SurfaceTraffic{tc.row}, fixedPolicy(tc.facts))
			if len(got) != 1 {
				t.Fatalf("got %d verdicts, want 1", len(got))
			}
			v := got[0]
			if v.State != tc.want {
				t.Errorf("state = %s (%s), want %s", v.State, v.Reason, tc.want)
			}
			if v.Reason == "" {
				t.Errorf("empty reason")
			}
			if v.SurfaceTraffic != tc.row || v.Facts != tc.facts {
				t.Errorf("verdict does not carry its input row and facts")
			}
		})
	}
}

// TestEverySurfaceRuleIsReachable keeps the rule table and the test above in
// step: every state the table can produce appears in it exactly once.
func TestEverySurfaceRuleIsReachable(t *testing.T) {
	want := []SurfaceState{
		SurfaceInvalidInput, SurfaceUnknownSurface, SurfaceExempt, SurfaceUnobserved,
		SurfaceUnknownMeasurability, SurfaceNotMeasurable, SurfaceBypassSuspect,
		SurfacePartial, SurfaceAttested,
	}
	if len(surfaceRules) != len(want) {
		t.Fatalf("surfaceRules has %d rows, the documented order has %d", len(surfaceRules), len(want))
	}
	for i, rule := range surfaceRules {
		if rule.state != want[i] {
			t.Errorf("rule %d is %s, want %s", i, rule.state, want[i])
		}
	}
}

// TestObservedBypass crosses every state with routable and not, and with
// each correlation: a routable surface's bypass_suspect always blocks
// (decision D11), its partial blocks only where every proxied turn carries
// the session id (request_id), never through the process bridge, which
// misses first turns and one-shot runs (surface-gap Wave 3).
func TestObservedBypass(t *testing.T) {
	correlations := []integration.CorrelationMode{
		integration.CorrelationUnknown, integration.CorrelationRequestID,
		integration.CorrelationProcessBridge, integration.CorrelationUnavailable,
	}
	for _, rule := range surfaceRules {
		for _, routable := range []bool{true, false} {
			for _, corr := range correlations {
				v := SurfaceVerdict{State: rule.state, Facts: SurfaceFacts{Routable: routable, Correlation: corr}}
				want := routable && (rule.state == SurfaceBypassSuspect ||
					(rule.state == SurfacePartial && corr == integration.CorrelationRequestID))
				if got := v.ObservedBypass(); got != want {
					t.Errorf("state %s routable=%v correlation=%q: ObservedBypass=%v, want %v", rule.state, routable, corr, got, want)
				}
			}
		}
	}
}

// TestAttestSurfacesUnstamped (Wave 3 decision): an unstamped group is
// judged by the tool's Unstamped row when its adapter stamps no surface, and
// stays unknown_surface for a multi-surface adapter unless the tool-level
// fallback applies (no proxied session and no stamped sibling, P-172).
func TestAttestSurfacesUnstamped(t *testing.T) {
	cases := []struct {
		name        string
		facts       SurfaceFacts
		proxied     int
		want        SurfaceState
		wantBlocks  bool
		wantInfixes string
	}{
		// With no proxied session and no stamped sibling, the tool-level
		// fallback blocks (P-172, TestAttestSurfacesToolLevelFallback); a
		// proxied session keeps the group unknown_surface.
		{"no Unstamped row, none proxied: tool-level bypass blocks", SurfaceFacts{Routable: true, Correlation: integration.CorrelationRequestID}, 0, SurfaceBypassSuspect, true, "tool-level reading"},
		{"no Unstamped row, some proxied: unknown surface", SurfaceFacts{Routable: true, Correlation: integration.CorrelationRequestID}, 1, SurfaceUnknownSurface, false, "no surface stamp"},
		{"Unstamped row, none joined: bypass blocks", SurfaceFacts{Routable: true, Correlation: integration.CorrelationProcessBridge, UnstampedAs: models.SurfaceCLI}, 0, SurfaceBypassSuspect, true, "judged as cli"},
		{"Unstamped row, some joined: partial, not a block", SurfaceFacts{Routable: true, Correlation: integration.CorrelationProcessBridge, UnstampedAs: models.SurfaceCLI}, 2, SurfacePartial, false, "process bridge"},
	}
	for _, tc := range cases {
		v := AttestSurfaces([]SurfaceTraffic{{Tool: "t", Sessions: 4, ProxiedSessions: tc.proxied}}, fixedPolicy(tc.facts))[0]
		if v.State != tc.want || v.ObservedBypass() != tc.wantBlocks || !strings.Contains(v.Reason, tc.wantInfixes) {
			t.Errorf("%s: state %s blocks %v reason %q; want %s blocks %v reason containing %q",
				tc.name, v.State, v.ObservedBypass(), v.Reason, tc.want, tc.wantBlocks, tc.wantInfixes)
		}
	}
}

// TestRegistrySurfacePolicyWave3 pins the registry facts Wave 3 declared:
// Claude Desktop is not routable (settings ignored) and not exempt, an
// unstamped session of a tool whose adapter stamps nothing is judged as its
// CLI row, and an unstamped session of a multi-surface tool is not.
func TestRegistrySurfacePolicyWave3(t *testing.T) {
	desk := RegistrySurfacePolicy("claude-code", models.SurfaceDesktop, "claude-desktop")
	if desk.Routable || desk.Exempt {
		t.Errorf("claude-code desktop: %+v, want neither routable nor exempt", desk)
	}
	for _, c := range integration.Capabilities() {
		u, ok := c.UnstampedSurface()
		f := RegistrySurfacePolicy(c.Tool, "", "")
		switch {
		case ok && (f.UnstampedAs != u.Kind || f.Correlation != u.CorrelationMode || !f.Routable):
			t.Errorf("%s unstamped: %+v, want judged as its %s row", c.Tool, f, u.Kind)
		case !ok && f.UnstampedAs != "":
			t.Errorf("%s unstamped: %+v, want no UnstampedAs without an Unstamped row", c.Tool, f)
		}
	}
	if f := RegistrySurfacePolicy("claude-code", "", ""); f.UnstampedAs != "" {
		t.Errorf("claude-code unstamped: %+v, want unknown surface (multi-surface adapter)", f)
	}
}

// TestAttestSurfacesKeepsOrderAndDefaultsToRegistry checks the batch shape:
// one verdict per row, in input order, with the registry policy when nil.
func TestAttestSurfacesKeepsOrderAndDefaultsToRegistry(t *testing.T) {
	rows := []SurfaceTraffic{
		{Tool: "claude-code", Kind: models.SurfaceCLI, Sessions: 5, ProxiedSessions: 5},
		{Tool: "claude-code", Kind: models.SurfaceDesktop, Host: "claude-desktop", Sessions: 3},
		{Tool: "no-such-tool", Kind: models.SurfaceCLI, Sessions: 1},
	}
	got := AttestSurfaces(rows, nil)
	want := []SurfaceState{SurfaceAttested, SurfaceUnknownMeasurability, SurfaceUnknownMeasurability}
	if len(got) != len(want) {
		t.Fatalf("got %d verdicts, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].SurfaceTraffic != rows[i] || got[i].State != want[i] {
			t.Errorf("row %d: got %+v %s, want %s", i, got[i].SurfaceTraffic, got[i].State, want[i])
		}
	}
	if got := AttestSurfaces(nil, nil); len(got) != 0 {
		t.Errorf("no rows: got %d verdicts", len(got))
	}
}

// TestRegistrySurfacePolicy checks the registry resolution against real rows,
// found by shape rather than named, so a reclassification does not break it.
func TestRegistrySurfacePolicy(t *testing.T) {
	cc := RegistrySurfacePolicy("claude-code", models.SurfaceCLI, "")
	if cc.Exempt || !cc.Routable || cc.Correlation != integration.CorrelationRequestID {
		t.Errorf("claude-code cli: got %+v, want routable, request_id, not exempt", cc)
	}
	ccDesktop := RegistrySurfacePolicy("claude-code", models.SurfaceDesktop, "claude-desktop")
	if ccDesktop.Correlation != integration.CorrelationUnknown {
		t.Errorf("claude-code desktop: correlation %q, want unknown until a live check grounds it", ccDesktop.Correlation)
	}
	if got := RegistrySurfacePolicy("no-such-tool", models.SurfaceCLI, ""); got != (SurfaceFacts{}) {
		t.Errorf("unknown tool: got %+v, want zero facts", got)
	}

	var sawExempt, sawBrowser bool
	for _, c := range integration.Capabilities() {
		f := RegistrySurfacePolicy(c.Tool, models.SurfaceCLI, "")
		if c.Routability == integration.RouteStatusNativeExempt && len(c.RouteSurfaces) == 0 {
			sawExempt = true
			if !f.Exempt || f.Routable {
				t.Errorf("%s (native_exempt): got %+v, want exempt and not routable", c.Tool, f)
			}
		}
		if c.Hook.Mechanism == integration.HookBrowserExtension {
			sawBrowser = true
			if !f.Exempt {
				t.Errorf("%s (browser extension): got %+v, want exempt", c.Tool, f)
			}
		}
	}
	if !sawExempt || !sawBrowser {
		t.Errorf("registry has no native_exempt row (%v) or no browser-extension row (%v) to check", sawExempt, sawBrowser)
	}
}

// TestRegistrySurfacePolicySurfaceOverride proves exemption is judged on the
// surface's effective routability: a surface row can make an otherwise
// routable tool exempt on that surface, and the reverse.
func TestRegistrySurfacePolicySurfaceOverride(t *testing.T) {
	routableTool := integration.Capability{
		Tool:        "t",
		Routability: integration.RouteStatusRoutableNow,
		RouteSurfaces: []integration.SurfaceRoute{
			{Kind: models.SurfaceDesktop, Routability: integration.RouteStatusNativeExempt},
			{Kind: models.SurfaceIDE, Routability: integration.RouteStatusProbeRequired, CorrelationMode: integration.CorrelationRequestID},
		},
	}
	exemptTool := integration.Capability{
		Tool:        "u",
		Routability: integration.RouteStatusNativeExempt,
		RouteSurfaces: []integration.SurfaceRoute{
			{Kind: models.SurfaceCLI, Routability: integration.RouteStatusRoutableNow, CorrelationMode: integration.CorrelationRequestID},
		},
	}
	browserTool := integration.Capability{
		Tool:        "w",
		Routability: integration.RouteStatusRoutableNow,
		Hook:        integration.HookSpec{Mechanism: integration.HookBrowserExtension},
	}
	cases := []struct {
		name string
		c    integration.Capability
		kind string
		want SurfaceFacts
	}{
		{"surface row makes a routable tool exempt", routableTool, models.SurfaceDesktop, SurfaceFacts{Exempt: true}},
		{"surface row makes a surface not yet routable", routableTool, models.SurfaceIDE, SurfaceFacts{Correlation: integration.CorrelationRequestID}},
		{"no row inherits the routable tool", routableTool, models.SurfaceCLI, SurfaceFacts{Routable: true}},
		{"surface row makes an exempt tool routable", exemptTool, models.SurfaceCLI, SurfaceFacts{Routable: true, Correlation: integration.CorrelationRequestID}},
		{"no row inherits the exempt tool", exemptTool, models.SurfaceDesktop, SurfaceFacts{Exempt: true}},
		{"browser-extension capture is exempt, and so never routable", browserTool, models.SurfaceWeb, SurfaceFacts{Exempt: true}},
	}
	for _, tc := range cases {
		if got := surfaceFactsFor(tc.c, tc.kind, ""); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestAttestSurfacesToolLevelFallback is the DEC-4 addendum (orchestrator
// ruling P-172, never weaker than before the arc): an unstamped group of a
// tool with no Unstamped row, with sessions and none proxied, is judged at
// tool level as bypass_suspect, which blocks on a routable tool, unless a
// stamped routable group of the same tool can speak for it (a proxied
// session, or a measurable correlation that judges itself). Before the arc,
// AttestByTraffic blocked every such (user, tool).
func TestAttestSurfacesToolLevelFallback(t *testing.T) {
	measured := SurfaceFacts{Routable: true, Correlation: integration.CorrelationRequestID}
	unmeasured := SurfaceFacts{Routable: true}
	notRoutable := SurfaceFacts{Correlation: integration.CorrelationRequestID}
	toolLevel := SurfaceFacts{Routable: true}
	byKind := func(m map[string]SurfaceFacts) SurfacePolicy {
		return func(_, kind, _ string) SurfaceFacts { return m[kind] }
	}
	unstamped := func(tool string, sessions, proxied int) SurfaceTraffic {
		return SurfaceTraffic{Tool: tool, Sessions: sessions, ProxiedSessions: proxied}
	}
	stamped := func(tool, kind string, sessions, proxied int) SurfaceTraffic {
		return SurfaceTraffic{Tool: tool, Kind: kind, Sessions: sessions, ProxiedSessions: proxied}
	}
	cases := []struct {
		name       string
		rows       []SurfaceTraffic
		policy     map[string]SurfaceFacts
		want       SurfaceState
		wantBlocks bool
	}{
		{
			"alone, none proxied: blocks",
			[]SurfaceTraffic{unstamped("t", 3, 0)},
			map[string]SurfaceFacts{"": toolLevel},
			SurfaceBypassSuspect, true,
		},
		{
			"alone, one proxied: unknown surface",
			[]SurfaceTraffic{unstamped("t", 3, 1)},
			map[string]SurfaceFacts{"": toolLevel},
			SurfaceUnknownSurface, false,
		},
		{
			"tool not routable: unknown surface",
			[]SurfaceTraffic{unstamped("t", 3, 0)},
			map[string]SurfaceFacts{"": notRoutable},
			SurfaceUnknownSurface, false,
		},
		{
			"tool exempt: unknown surface",
			[]SurfaceTraffic{unstamped("t", 3, 0)},
			map[string]SurfaceFacts{"": {Exempt: true}},
			SurfaceUnknownSurface, false,
		},
		{
			"stamped measurable CLI attested: unknown surface",
			[]SurfaceTraffic{unstamped("t", 3, 0), stamped("t", models.SurfaceCLI, 2, 2)},
			map[string]SurfaceFacts{"": toolLevel, models.SurfaceCLI: measured},
			SurfaceUnknownSurface, false,
		},
		{
			"stamped measurable CLI bypassed: it blocks itself, unstamped stays unknown",
			[]SurfaceTraffic{unstamped("t", 3, 0), stamped("t", models.SurfaceCLI, 2, 0)},
			map[string]SurfaceFacts{"": toolLevel, models.SurfaceCLI: measured},
			SurfaceUnknownSurface, false,
		},
		{
			"only a stamped non-routable desktop: blocks",
			[]SurfaceTraffic{unstamped("t", 3, 0), stamped("t", models.SurfaceDesktop, 2, 0)},
			map[string]SurfaceFacts{"": toolLevel, models.SurfaceDesktop: notRoutable},
			SurfaceBypassSuspect, true,
		},
		{
			"stamped routable IDE of unknown correlation, none proxied: blocks",
			[]SurfaceTraffic{unstamped("t", 3, 0), stamped("t", models.SurfaceIDE, 2, 0)},
			map[string]SurfaceFacts{"": toolLevel, models.SurfaceIDE: unmeasured},
			SurfaceBypassSuspect, true,
		},
		{
			"stamped routable IDE of unknown correlation, one proxied: unknown surface",
			[]SurfaceTraffic{unstamped("t", 3, 0), stamped("t", models.SurfaceIDE, 2, 1)},
			map[string]SurfaceFacts{"": toolLevel, models.SurfaceIDE: unmeasured},
			SurfaceUnknownSurface, false,
		},
		{
			"declared CLI with no session does not speak: blocks",
			[]SurfaceTraffic{unstamped("t", 3, 0), stamped("t", models.SurfaceCLI, 0, 0)},
			map[string]SurfaceFacts{"": toolLevel, models.SurfaceCLI: measured},
			SurfaceBypassSuspect, true,
		},
		{
			"another tool's attested CLI does not speak for this one: blocks",
			[]SurfaceTraffic{unstamped("t", 3, 0), stamped("u", models.SurfaceCLI, 2, 2)},
			map[string]SurfaceFacts{"": toolLevel, models.SurfaceCLI: measured},
			SurfaceBypassSuspect, true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := AttestSurfaces(tc.rows, byKind(tc.policy))[0]
			if v.Kind != "" {
				t.Fatalf("first verdict is %q, want the unstamped group", v.Kind)
			}
			if v.State != tc.want || v.ObservedBypass() != tc.wantBlocks {
				t.Fatalf("state %s blocks %v (%s), want %s blocks %v", v.State, v.ObservedBypass(), v.Reason, tc.want, tc.wantBlocks)
			}
			if tc.wantBlocks && !strings.Contains(v.Reason, "tool-level reading") {
				t.Fatalf("reason %q does not name the tool-level reading", v.Reason)
			}
		})
	}
}

// TestRegistryToolLevelFallback drives the fallback from the registry rows:
// every routable, non-exempt tool that declares no Unstamped row has its
// lone unproxied unstamped group blocked, and that set includes the
// multi-surface tools the audit named (finding 1). A tool with an Unstamped
// row is judged by that row instead.
func TestRegistryToolLevelFallback(t *testing.T) {
	blocked := map[string]bool{}
	for _, c := range integration.Capabilities() {
		f := RegistrySurfacePolicy(c.Tool, "", "")
		v := AttestSurfaces([]SurfaceTraffic{{Tool: c.Tool, Sessions: 2}}, nil)[0]
		_, hasRow := c.UnstampedSurface()
		switch {
		case hasRow:
			if strings.Contains(v.Reason, "tool-level reading") {
				t.Errorf("%s: an Unstamped row tool took the tool-level fallback: %+v", c.Tool, v)
			}
		case f.Routable:
			if v.State != SurfaceBypassSuspect || !v.ObservedBypass() {
				t.Errorf("%s: unstamped 0/2 = %s blocks %v, want a blocking tool-level bypass_suspect", c.Tool, v.State, v.ObservedBypass())
			}
			blocked[c.Tool] = true
		default:
			if v.ObservedBypass() {
				t.Errorf("%s: a tool that is not routable blocked: %+v", c.Tool, v)
			}
		}
	}
	for _, tool := range []string{"claude-code", "codex", "copilot-cli", "cline-cli"} {
		if !blocked[tool] {
			t.Errorf("%s: unproxied unstamped sessions do not block the gate (P-172)", tool)
		}
	}
}
