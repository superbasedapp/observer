package controlcoverage

import (
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestRouteProofForSurface (OBS-4): proven only for a routed surface. One
// row per rule of RouteProofFor, on synthetic capabilities, plus the
// registry rows the acceptance names.
func TestRouteProofForSurface(t *testing.T) {
	proven := &integration.ProxyRoute{Kind: integration.RouteLauncher, Proof: integration.RouteProofLauncherRoute}
	unproven := &integration.ProxyRoute{Kind: integration.RouteLauncher}
	cli := integration.SurfaceRoute{Kind: models.SurfaceCLI, CorrelationMode: integration.CorrelationRequestID}
	desk := integration.SurfaceRoute{Kind: models.SurfaceDesktop, Routability: integration.RouteStatusSettingsIgnored}
	multi := integration.Capability{Proxy: proven, Routability: integration.RouteStatusRoutableNow, RouteSurfaces: []integration.SurfaceRoute{cli, desk}}
	bare := integration.Capability{Proxy: proven, Routability: integration.RouteStatusRoutableNow}
	unstampedCLI := cli
	unstampedCLI.Unstamped = true
	single := integration.Capability{Proxy: proven, Routability: integration.RouteStatusRoutableNow, RouteSurfaces: []integration.SurfaceRoute{unstampedCLI}}
	cases := []struct {
		name       string
		c          integration.Capability
		kind, host string
		want       RouteProofState
	}{
		{"no proxy route", integration.Capability{}, models.SurfaceCLI, "", RouteProofStateNone},
		{"route not proven", integration.Capability{Proxy: unproven, Routability: integration.RouteStatusRoutableNow, RouteSurfaces: []integration.SurfaceRoute{cli}}, models.SurfaceCLI, "", RouteProofStateUnproven},
		{"routed, declared surface", multi, models.SurfaceCLI, "claude", RouteProofStateProven},
		{"surface ignores the route", multi, models.SurfaceDesktop, "claude-desktop", RouteProofStateUnproven},
		{"undeclared surface of a tool that declares surfaces", multi, models.SurfaceIDE, "vscode", RouteProofStateUnproven},
		{"no surface rows: the tool answer", bare, models.SurfaceIDE, "", RouteProofStateProven},
		{"unstamped, multi-surface: tool-wide (one surface ignores it)", multi, "", "", RouteProofStateUnproven},
		{"unstamped, judged as the Unstamped row", single, "", "", RouteProofStateProven},
	}
	for _, tc := range cases {
		if got := RouteProofFor(tc.c, tc.kind, tc.host); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}

	registry := []struct {
		tool, kind, host string
		want             RouteProofState
	}{
		{"claude-code", models.SurfaceCLI, "claude", RouteProofStateProven},
		{"claude-code", models.SurfaceDesktop, "claude-desktop", RouteProofStateUnproven},
		{"claude-code", models.SurfaceSDK, "ts", RouteProofStateUnproven}, // CC-3: sdk-* route_unproven
		{"claude-code", models.SurfaceIDE, "vscode", RouteProofStateUnproven},
		{"codex", models.SurfaceCLI, "codex-cli", RouteProofStateProven},
		{"codex", models.SurfaceDesktop, "codex-desktop", RouteProofStateProven},
		{"cursor", models.SurfaceIDE, "", RouteProofStateNone},
	}
	for _, tc := range registry {
		c, _ := integration.For(tc.tool)
		if got := RouteProofFor(c, tc.kind, tc.host); got != tc.want {
			t.Errorf("%s %s/%s: got %s, want %s", tc.tool, tc.kind, tc.host, got, tc.want)
		}
	}
}

// TestPostureText is the Wave 3 acceptance: the posture renders "cli gated,
// desktop ungated" for claude-code (the proxy route) and codex (the tool
// gate), and names a replayed gate's host registration (W-2b).
func TestPostureText(t *testing.T) {
	cases := []struct {
		tool   string
		wants  []string
		absent []string
	}{
		{"claude-code", []string{"proxy route: cli gated", "desktop ungated", "sdk unproven", "tool gate: cli gated"}, nil},
		{"codex", []string{"tool gate: cli gated", "desktop ungated", "ide ungated", "proxy route: cli gated"}, nil},
		{"junie", []string{"tool gate: cli gated", "ide ungated"}, []string{"proxy route"}},
		{"poolside", []string{"ide unknown"}, nil},
		{"cortex-code", []string{"gates ride the claude-code hook registration"}, nil},
		{"aider", []string{"proxy route: cli unproven"}, nil}, // an ambient per-model backend switch escapes the launcher route
	}
	for _, tc := range cases {
		row, ok := For(tc.tool)
		if !ok {
			t.Fatalf("%s: no row", tc.tool)
		}
		got := row.PostureText()
		for _, w := range tc.wants {
			if !strings.Contains(got, w) {
				t.Errorf("%s: posture %q lacks %q", tc.tool, got, w)
			}
		}
		for _, a := range tc.absent {
			if strings.Contains(got, a) {
				t.Errorf("%s: posture %q has %q", tc.tool, got, a)
			}
		}
	}
	// The claude-code route clause says desktop ungated, its gate clause
	// does not (the Code tab runs the hooks).
	row, _ := For("claude-code")
	gate, route, _ := strings.Cut(row.PostureText(), "; proxy route: ")
	if strings.Contains(gate, "desktop ungated") || !strings.Contains(route, "desktop ungated") {
		t.Errorf("claude-code: gate clause %q / route clause %q, want desktop ungated on the route only", gate, route)
	}
}

// TestSurfaceGateTables has one row per hook-run mapping and per route
// mapping rule.
func TestSurfaceGateTables(t *testing.T) {
	gate := integration.HookBinding{Cap: integration.HookCapToolGate, Wired: true}
	hooked := integration.Capability{Hook: integration.HookSpec{
		Bindings: []integration.HookBinding{gate},
		Surfaces: []integration.HookSurface{
			{Kind: models.SurfaceCLI, Runs: integration.HookSurfaceRuns},
			{Kind: models.SurfaceIDE, Runs: integration.HookSurfaceSkipped},
			{Kind: models.SurfaceSDK},
		},
	}}
	toolCases := []struct {
		name string
		c    integration.Capability
		kind string
		want SurfaceGate
	}{
		{"no wired gate", integration.Capability{}, models.SurfaceCLI, SurfaceGateNone},
		{"hooks run", hooked, models.SurfaceCLI, SurfaceGated},
		{"hooks skipped", hooked, models.SurfaceIDE, SurfaceUngated},
		{"hooks unknown", hooked, models.SurfaceSDK, SurfaceGateUnknown},
		{"no row: tool answer", hooked, models.SurfaceDesktop, SurfaceGated},
	}
	for _, tc := range toolCases {
		if got := toolGateFor(tc.c, tc.kind, ""); got != tc.want {
			t.Errorf("tool gate %s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	proven := &integration.ProxyRoute{Proof: integration.RouteProofLauncherRoute}
	routed := integration.Capability{Proxy: proven, Routability: integration.RouteStatusRoutableNow, RouteSurfaces: []integration.SurfaceRoute{
		{Kind: models.SurfaceCLI, CorrelationMode: integration.CorrelationRequestID},
		{Kind: models.SurfaceDesktop, Routability: integration.RouteStatusSettingsIgnored},
		{Kind: models.SurfaceSDK, Routability: integration.RouteStatusProbeRequired},
		{Kind: models.SurfaceWeb, Routability: integration.RouteStatusNativeExempt},
	}}
	routeCases := []struct {
		name string
		c    integration.Capability
		kind string
		want SurfaceGate
	}{
		{"no proxy route", integration.Capability{}, models.SurfaceCLI, SurfaceGateNone},
		{"proven", routed, models.SurfaceCLI, SurfaceGated},
		{"settings ignored", routed, models.SurfaceDesktop, SurfaceUngated},
		{"exempt", routed, models.SurfaceWeb, SurfaceUngated},
		{"probe required", routed, models.SurfaceSDK, SurfaceUnproven},
	}
	for _, tc := range routeCases {
		if got := routeGateFor(tc.c, tc.kind, ""); got != tc.want {
			t.Errorf("route %s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestRuleCoverageCarriesSurfaceCaveat (CX-1, W-5): the hook surface scope
// reaches the admin rule coverage of codex (CLI-only gates) and stays the
// one Junie / Poolside statement.
func TestRuleCoverageCarriesSurfaceCaveat(t *testing.T) {
	for _, tool := range []string{"codex", "junie", "poolside"} {
		c, _ := integration.For(tool)
		want := c.Hook.SurfaceCaveat()
		facts := RuleSeamFacts{ToolAskProbed: func(string) bool { return false }}
		lane := toolCallRuleCoverage(c, guard.ConformanceMatrix(), facts)
		n := 0
		for _, cav := range lane.Caveats {
			if cav == want {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: surface caveat appears %d times in %v, want once", tool, n, lane.Caveats)
		}
	}
}

// TestCollapseHostFamilies: three or more product hosts of one family with
// one kind and one gate read as one clause; fewer, or a different gate, stay
// per host.
func TestCollapseHostFamilies(t *testing.T) {
	cases := []struct {
		name string
		in   []postureEntry
		want []string
	}{
		{"family of three", []postureEntry{
			{"cli", "", SurfaceGated},
			{"ide", "jetbrains-idea", SurfaceUngated},
			{"ide", "jetbrains-goland", SurfaceUngated},
			{"ide", "jetbrains-rider", SurfaceUngated},
			{"desktop", "", SurfaceGated},
		}, []string{"cli gated", "ide/jetbrains-* ungated", "desktop gated"}},
		{"two stay per host", []postureEntry{
			{"ide", "jetbrains-idea", SurfaceUngated},
			{"ide", "jetbrains-goland", SurfaceUngated},
		}, []string{"ide/jetbrains-idea ungated", "ide/jetbrains-goland ungated"}},
		{"a different gate is its own clause", []postureEntry{
			{"ide", "jetbrains-idea", SurfaceUngated},
			{"ide", "jetbrains-goland", SurfaceUngated},
			{"ide", "jetbrains-rider", SurfaceUngated},
			{"ide", "jetbrains-clion", SurfaceGated},
		}, []string{"ide/jetbrains-* ungated", "ide/jetbrains-clion gated"}},
		{"hosts without a family", []postureEntry{
			{"ide", "vscode", SurfaceGated}, {"ide", "zed", SurfaceGated}, {"ide", "kiro", SurfaceGated},
		}, []string{"ide/vscode gated", "ide/zed gated", "ide/kiro gated"}},
	}
	for _, tc := range cases {
		if got := collapseHostFamilies(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestToolRouteProofCountsOnlyObservedSurfaces is AW-48 in both directions,
// on the real Codex row: with no Xcode session observed the ide/xcode
// surface (settings_ignored, MAC-1) is skipped, Codex stays proven and the
// skip is named; one observed Xcode session makes Codex unproven.
func TestToolRouteProofCountsOnlyObservedSurfaces(t *testing.T) {
	cli := SurfaceSession{Kind: models.SurfaceCLI, Host: "codex-cli", Sessions: 12}
	cases := []struct {
		name        string
		groups      []SurfaceSession
		wantProof   RouteProofState
		wantSkipped []string
	}{
		{
			"no xcode session: proven, xcode named",
			[]SurfaceSession{cli},
			RouteProofStateProven,
			[]string{"ide/xcode", "ide", "desktop"},
		},
		{
			"a zero count is not a session",
			[]SurfaceSession{cli, {Kind: models.SurfaceIDE, Host: "xcode", Sessions: 0}},
			RouteProofStateProven,
			[]string{"ide/xcode", "ide", "desktop"},
		},
		{
			"one xcode session: unproven",
			[]SurfaceSession{cli, {Kind: models.SurfaceIDE, Host: "xcode", Sessions: 1}},
			RouteProofStateUnproven,
			[]string{"ide", "desktop"},
		},
		{
			"an IDE session on another host marks the IDE kind row only",
			[]SurfaceSession{cli, {Kind: models.SurfaceIDE, Host: "vscode", Sessions: 3}},
			RouteProofStateProven,
			[]string{"ide/xcode", "desktop"},
		},
	}
	for _, tc := range cases {
		row, ok := ForObserved("codex", tc.groups)
		if !ok {
			t.Fatal("no codex row")
		}
		if row.RouteProof != tc.wantProof || !slices.Equal(row.RouteNotObserved, tc.wantSkipped) {
			t.Errorf("%s: RouteProof %q, skipped %v; want %q, %v", tc.name, row.RouteProof, row.RouteNotObserved, tc.wantProof, tc.wantSkipped)
		}
		text := row.PostureText()
		if len(tc.wantSkipped) > 0 && !strings.Contains(text, "route proof skips "+strings.Join(tc.wantSkipped, ", ")+": no sessions observed") {
			t.Errorf("%s: posture %q does not name the skip", tc.name, text)
		}
	}
	// The registry-only view skips only the NoProducer surfaces.
	reg, _ := For("codex")
	if reg.RouteProof != RouteProofStateProven || !slices.Equal(reg.RouteNotObserved, []string{"ide/xcode"}) {
		t.Errorf("registry view: %q skipped %v; want proven skipping ide/xcode", reg.RouteProof, reg.RouteNotObserved)
	}
	// An unstamped session group marks the tool's Unstamped row (goose's CLI).
	g, _ := ForObserved("goose", []SurfaceSession{{Sessions: 2}})
	if slices.Contains(g.RouteNotObserved, "cli") || !slices.Contains(g.RouteNotObserved, "ide") {
		t.Errorf("goose unstamped: skipped %v; want ide skipped, cli seen", g.RouteNotObserved)
	}
}

// TestNoProducerRowsAreNamedSurfaces: a NoProducer row names its surface
// by host, the only way a later adapter could start stamping it.
func TestNoProducerRowsAreNamedSurfaces(t *testing.T) {
	for _, c := range integration.Capabilities() {
		for _, r := range c.RouteSurfaces {
			if r.NoProducer && r.Host == "" {
				t.Errorf("%s %s: NoProducer row without a host", c.Tool, r.Kind)
			}
		}
	}
}

// TestObservedBasisRules has one case per observedBasisRules row, plus the
// observed case no rule catches. All skipped is never evidence: a node with
// no session of the tool, or with sessions it cannot place on a declared
// surface, shows the registry proof and says why.
func TestObservedBasisRules(t *testing.T) {
	cases := []struct {
		name      string
		tool      string
		groups    []SurfaceSession
		basis     RouteProofBasis
		proof     RouteProofState
		noteHas   string
		postureIn string
	}{
		{
			// Every proxied tool declares a route surface
			// (TestProxiedToolsDeclareCorrelation), so this row is reached
			// by a tool with none: the registry answer is the whole answer.
			name: "no route surfaces declared: plain registry, no note", tool: "cursor",
			groups: nil, basis: RouteBasisRegistry, proof: RouteProofStateNone,
		},
		{
			name: "no session observed: registry fallback", tool: "codex",
			groups: nil, basis: RouteBasisRegistryFallback, proof: RouteProofStateProven,
			noteHas:   "no session of this tool on this node",
			postureIn: "route proof skips ide/xcode: no adapter captures it yet",
		},
		{
			name: "only zero counts: registry fallback", tool: "codex",
			groups: []SurfaceSession{{Kind: models.SurfaceCLI, Host: "codex-cli", Sessions: 0}},
			basis:  RouteBasisRegistryFallback, proof: RouteProofStateProven, noteHas: "no session of this tool",
		},
		{
			// Claude Code has no Unstamped row: Claude Desktop sessions from
			// before surface stamping must not let it flip to proven.
			name: "unstamped sessions on a tool with no Unstamped row: registry fallback", tool: "claude-code",
			groups: []SurfaceSession{{Kind: models.SurfaceCLI, Host: "claude", Sessions: 5}, {Kind: "", Sessions: 3}},
			basis:  RouteBasisRegistryFallback, proof: RouteProofStateUnproven, noteHas: "3 session(s) carry no surface stamp",
			postureIn: "route proof from the registry: 3 session(s)",
		},
		{
			name: "a surface the tool declares no row for: registry fallback", tool: "codex",
			groups: []SurfaceSession{{Kind: models.SurfaceCLI, Host: "codex-cli", Sessions: 5}, {Kind: models.SurfaceWeb, Host: "chatgpt", Sessions: 1}},
			basis:  RouteBasisRegistryFallback, proof: RouteProofStateProven, noteHas: "1 session(s)",
		},
		{
			name: "every session placed: observed", tool: "claude-code",
			groups: []SurfaceSession{{Kind: models.SurfaceCLI, Host: "claude", Sessions: 5}},
			basis:  RouteBasisObserved, proof: RouteProofStateProven,
			postureIn: "no sessions observed on this node",
		},
	}
	for _, tc := range cases {
		row, ok := ForObserved(tc.tool, tc.groups)
		if !ok {
			t.Fatalf("%s: no row", tc.name)
		}
		if row.RouteProofBasis != tc.basis || row.RouteProof != tc.proof {
			t.Errorf("%s: basis %q proof %q, want %q %q", tc.name, row.RouteProofBasis, row.RouteProof, tc.basis, tc.proof)
		}
		if (tc.noteHas == "") != (row.RouteBasisNote == "") || !strings.Contains(row.RouteBasisNote, tc.noteHas) {
			t.Errorf("%s: note %q, want it to carry %q", tc.name, row.RouteBasisNote, tc.noteHas)
		}
		if tc.postureIn != "" && !strings.Contains(row.PostureText(), tc.postureIn) {
			t.Errorf("%s: posture %q lacks %q", tc.name, row.PostureText(), tc.postureIn)
		}
	}
	if n := len(observedBasisRules); n != 3 {
		t.Errorf("observedBasisRules has %d rows; add a case above for each new one", n)
	}
}

// TestSkipReasonPerView: the registry views word a skip as "no adapter
// captures it yet", the observed view as "no sessions observed on this
// node", and every basis has wording.
func TestSkipReasonPerView(t *testing.T) {
	reg, _ := For("codex")
	if reg.RouteProofBasis != RouteBasisRegistry || !strings.Contains(reg.PostureText(), "route proof skips ide/xcode: no adapter captures it yet") {
		t.Errorf("registry view: basis %q posture %q", reg.RouteProofBasis, reg.PostureText())
	}
	for _, b := range []RouteProofBasis{RouteBasisRegistry, RouteBasisObserved, RouteBasisRegistryFallback} {
		if skipReason[b] == "" {
			t.Errorf("basis %q has no skip wording", b)
		}
	}
}
