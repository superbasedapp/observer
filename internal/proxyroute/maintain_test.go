package proxyroute

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// maintain_test.go: managed-node route maintenance (lane P1).

// TestDecideMaintenanceTable is the maintenance decision table, one case per
// maintainRules row, in row order.
func TestDecideMaintenanceTable(t *testing.T) {
	writable := RouteStatus{State: RouteAbsent, ArtifactPresent: true, Routability: RoutabilityWritable}
	with := func(f func(*RouteStatus)) RouteStatus {
		s := writable
		f(&s)
		return s
	}
	cases := []struct {
		name string
		in   MaintainInput
		want MaintainDecision
	}{
		{
			"individual node or org without a proxy enforcement point",
			MaintainInput{Required: false, ProxyHealthy: true, Status: writable},
			MaintainDecision{MaintainSkip, ReasonNotRequired},
		},
		{
			"a route Observer provably wrote at an old port, proxy not serving (D-745)",
			MaintainInput{Required: true, ProxyHealthy: false, ProxyPort: 8820, Status: with(func(s *RouteStatus) { s.State, s.Port, s.OrgWrittenExact = RouteOurs, 9999, true })},
			MaintainDecision{MaintainSkip, ReasonProxyUnavailable},
		},
		{
			"a route Observer provably wrote at an old port is moved to this proxy's port (D-745)",
			MaintainInput{Required: true, ProxyHealthy: true, ProxyPort: 8820, Status: with(func(s *RouteStatus) { s.State, s.Port, s.OrgWrittenExact = RouteOurs, 9999, true })},
			MaintainDecision{MaintainWrite, ReasonPortMoved},
		},
		{
			"loopback route at another port than this proxy is never overwritten (T-901)",
			MaintainInput{Required: true, ProxyHealthy: true, ProxyPort: 8820, Status: with(func(s *RouteStatus) { s.State, s.Port = RouteOurs, 9999 })},
			MaintainDecision{MaintainSkip, ReasonOtherPort},
		},
		{
			"route file unknown: a relocation variable is a relative path (R-188 F6)",
			MaintainInput{Required: true, ProxyHealthy: true, Status: with(func(s *RouteStatus) {
				s.State, s.ArtifactPresent, s.UnresolvedBy, s.ConfigPath = RouteUnknown, false, "CODEX_HOME", ""
			})},
			MaintainDecision{MaintainSkip, ReasonRouteFileUnknown},
		},
		{
			"the organization's plain route while the daemon writes the client token form, proxy not serving (OSH-R-009)",
			MaintainInput{Required: true, ProxyHealthy: false, WantClientAuth: true, Status: with(func(s *RouteStatus) {
				s.State, s.ClientAuthWritable, s.OrgRouted = RouteOurs, true, true
			})},
			MaintainDecision{MaintainSkip, ReasonProxyUnavailable},
		},
		{
			"the organization's plain route is rewritten to the client token form (OSH-R-009)",
			MaintainInput{Required: true, ProxyHealthy: true, WantClientAuth: true, Status: with(func(s *RouteStatus) {
				s.State, s.ClientAuthWritable, s.OrgRouted = RouteOurs, true, true
			})},
			MaintainDecision{MaintainWrite, ReasonClientAuthForm},
		},
		{
			"already routed through an observer proxy",
			MaintainInput{Required: true, ProxyHealthy: true, Status: with(func(s *RouteStatus) { s.State = RouteOurs })},
			MaintainDecision{MaintainSkip, ReasonRouted},
		},
		{
			"CLI-3: the route is in the file but another provider is active (report only)",
			MaintainInput{Required: true, ProxyHealthy: true, Status: with(func(s *RouteStatus) { s.State = RouteInactiveProvider })},
			MaintainDecision{MaintainSkip, ReasonInactiveProvider},
		},
		{
			"routed at an authorized org gateway",
			MaintainInput{Required: true, ProxyHealthy: true, Status: with(func(s *RouteStatus) { s.State = RouteOrgGateway })},
			MaintainDecision{MaintainSkip, ReasonOrgGateway},
		},
		{
			"wrong host is never overwritten",
			MaintainInput{Required: true, ProxyHealthy: true, Status: with(func(s *RouteStatus) { s.State = RouteDrifted })},
			MaintainDecision{MaintainSkip, ReasonWrongHost},
		},
		{
			"third-party provider a route lane carries, proxy not serving",
			MaintainInput{Required: true, ProxyHealthy: false, Status: with(func(s *RouteStatus) { s.State, s.LaneWritable = RouteDrifted, true })},
			MaintainDecision{MaintainSkip, ReasonProxyUnavailable},
		},
		{
			"third-party provider a route lane carries: routed through the lane",
			MaintainInput{Required: true, ProxyHealthy: true, Status: with(func(s *RouteStatus) { s.State, s.LaneWritable = RouteDrifted, true })},
			MaintainDecision{MaintainWrite, ReasonProviderLane},
		},
		{
			"tool not installed",
			MaintainInput{Required: true, ProxyHealthy: true, Status: with(func(s *RouteStatus) { s.ArtifactPresent = false })},
			MaintainDecision{MaintainSkip, ReasonNotInstalled},
		},
		{
			"capability has no unattended route",
			MaintainInput{Required: true, ProxyHealthy: true, Status: with(func(s *RouteStatus) { s.Routability = RoutabilityNotRoutable })},
			MaintainDecision{MaintainSkip, ReasonNotRoutable},
		},
		{
			"writer does not cover this config",
			MaintainInput{Required: true, ProxyHealthy: true, Status: with(func(s *RouteStatus) { s.Routability = RoutabilityConfigNotCovered })},
			MaintainDecision{MaintainSkip, ReasonConfigNotCovered},
		},
		{
			"routability not evaluated",
			MaintainInput{Required: true, ProxyHealthy: true, Status: with(func(s *RouteStatus) { s.Routability = RoutabilityUnknown })},
			MaintainDecision{MaintainSkip, ReasonNotEvaluated},
		},
		{
			"proxy not listening or draining",
			MaintainInput{Required: true, ProxyHealthy: false, Status: writable},
			MaintainDecision{MaintainSkip, ReasonProxyUnavailable},
		},
		{
			"routable, missing, proxy healthy",
			MaintainInput{Required: true, ProxyHealthy: true, Status: writable},
			MaintainDecision{MaintainWrite, ReasonRouteMissing},
		},
	}
	if len(cases) != len(maintainRules) {
		t.Fatalf("%d cases for %d maintainRules rows: add one case per row", len(cases), len(maintainRules))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecideMaintenance(tc.in); got != tc.want {
				t.Fatalf("DecideMaintenance = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// maintained is the drift policy of a node whose org requires routes
// (posture maintain), with ports not compared.
var maintained = DriftPolicy{Mode: DriftModeMaintained}

// TestRouteVerdictRules is the drift table, one case per routeVerdictRules
// row, in row order.
func TestRouteVerdictRules(t *testing.T) {
	onPort := DriftPolicy{Mode: DriftModeMaintained, ProxyPort: 8820}
	orgRoutes := DriftPolicy{Mode: DriftModeOrgRoutes, ProxyPort: 8820}
	cases := []struct {
		name string
		rs   RouteStatus
		p    DriftPolicy
		want routeVerdict
	}{
		{
			"route maintenance off: even a wrong host is not drift (T-900)",
			RouteStatus{State: RouteDrifted, ArtifactPresent: true, OrgRouted: true, WasRouted: true},
			DriftPolicy{Mode: DriftModeOff, ProxyPort: 8820},
			verdictClear,
		},
		{
			"a route file Observer cannot name is never drift, even routed before (R-188 F6)",
			RouteStatus{Tool: "codex", State: RouteUnknown, UnresolvedBy: "CODEX_HOME", WasRouted: true, OrgRouted: true},
			onPort, verdictClear,
		},
		{
			"installed with routing switched off by policy is not drift, even on a wrong host (D-771)",
			RouteStatus{Tool: "codex", State: RouteDrifted, ArtifactPresent: true, OrgRouted: true, WasRouted: true},
			DriftPolicy{Mode: DriftModeMaintained, ProxyPort: 8820, Selection: Selection{RoutingOff: true}},
			verdictRoutingOff,
		},
		{
			"installed but not selected by policy is not drift, even on a wrong host (T-915)",
			RouteStatus{Tool: "codex", State: RouteDrifted, ArtifactPresent: true, OrgRouted: true, WasRouted: true},
			DriftPolicy{Mode: DriftModeMaintained, ProxyPort: 8820, Selection: Selection{Tool: func(string) bool { return false }}},
			verdictUnselected,
		},
		{
			"an authorized org gateway is clear",
			RouteStatus{State: RouteOrgGateway, ArtifactPresent: true},
			onPort, verdictClear,
		},
		{
			"no posture: a route the organization never wrote is the developer's setup",
			RouteStatus{State: RouteDrifted, ArtifactPresent: true, WasRouted: true},
			orgRoutes, verdictClear,
		},
		{
			"wrong host is drift",
			RouteStatus{State: RouteDrifted, ArtifactPresent: true},
			onPort, verdictDrift,
		},
		{
			"loopback route at another port than this proxy is drift (T-901)",
			RouteStatus{State: RouteOurs, ArtifactPresent: true, Port: 9999},
			onPort, verdictDrift,
		},
		{
			"an inactive provider has its own reading, never drift (DEC-7)",
			RouteStatus{Tool: "crush", State: RouteInactiveProvider, ArtifactPresent: true, OrgRouted: true, WasRouted: true, Port: 9999},
			onPort, verdictInactiveProvider,
		},
		{
			"ours on this proxy's port is clear",
			RouteStatus{State: RouteOurs, ArtifactPresent: true, Port: 8820},
			onPort, verdictClear,
		},
		{
			"not installed is clear",
			RouteStatus{State: RouteAbsent, ArtifactPresent: false, Routability: RoutabilityWritable},
			onPort, verdictClear,
		},
		{
			"routed before and removed is drift, even when the writer no longer covers the config",
			RouteStatus{State: RouteAbsent, ArtifactPresent: true, WasRouted: true, Routability: RoutabilityConfigNotCovered},
			onPort, verdictDrift,
		},
		{
			"never routed and not routable is coverage, not drift",
			RouteStatus{State: RouteAbsent, ArtifactPresent: true, Routability: RoutabilityNotRoutable},
			onPort, verdictUnroutable,
		},
		{
			"writable and missing is drift until the daemon repairs it",
			RouteStatus{State: RouteAbsent, ArtifactPresent: true, Routability: RoutabilityWritable},
			onPort, verdictDrift,
		},
	}
	if len(cases) != len(routeVerdictRules) {
		t.Fatalf("%d cases for %d routeVerdictRules rows: add one case per row", len(cases), len(routeVerdictRules))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeVerdictFor(tc.rs, tc.p); got != tc.want {
				t.Fatalf("routeVerdictFor = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDriftModesOverOneHost reads one host's inspected routes under each
// drift mode: what the admin sees for the same configs depends only on the
// posture (T-900), and a port is compared only against the daemon's own
// listener (T-901).
func TestDriftModesOverOneHost(t *testing.T) {
	statuses := []RouteStatus{
		// The org wrote it, it is in place on this proxy.
		{Tool: "claude-code", State: RouteOurs, ArtifactPresent: true, Port: 8820, WasRouted: true, OrgRouted: true},
		// The org wrote it, the developer removed it.
		{Tool: "codex", State: RouteAbsent, ArtifactPresent: true, WasRouted: true, OrgRouted: true, Routability: RoutabilityWritable},
		// The developer's own provider host, never routed by the org (kimi
		// and qwen after the admin turned maintenance off).
		{Tool: "kimi-code", State: RouteDrifted, ArtifactPresent: true, LaneWritable: true},
		{Tool: "qwen-code", State: RouteDrifted, ArtifactPresent: true, LaneWritable: true},
		// The org wrote it, now at another loopback port.
		{Tool: "crush", State: RouteOurs, ArtifactPresent: true, Port: 9999, WasRouted: true, OrgRouted: true},
	}
	cases := []struct {
		mode DriftMode
		want []string
	}{
		{DriftModeOff, nil},
		{DriftModeOrgRoutes, []string{"codex", "crush"}},
		{DriftModeMaintained, []string{"codex", "crush", "kimi-code", "qwen-code"}},
	}
	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			got := DriftedTools(statuses, DriftPolicy{Mode: tc.mode, ProxyPort: 8820})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("DriftedTools = %v, want %v", got, tc.want)
			}
		})
	}
	// Ports not compared: the other-port route reads as ours.
	if got := DriftedTools(statuses, maintained); !reflect.DeepEqual(got, []string{"codex", "kimi-code", "qwen-code"}) {
		t.Fatalf("ProxyPort 0: DriftedTools = %v", got)
	}
}

// TestUnselectedToolsByPosture is T-915 (D-770): the same predicate route
// maintenance filters its writes with decides whether an installed tool is
// read at all. Selected, unselected and not installed rows, under every
// drift mode: an unselected installed tool is never drift and is listed as
// unselected wherever routes are read; a tool that is not installed is in no
// list; under DriftModeOff nothing changes (no drift, no unselected list).
func TestUnselectedToolsByPosture(t *testing.T) {
	statuses := []RouteStatus{
		// Selected, installed, the org's route removed: drift where read.
		{Tool: "claude-code", State: RouteAbsent, ArtifactPresent: true, WasRouted: true, OrgRouted: true, Routability: RoutabilityWritable},
		// Unselected, installed, never routed, writable: maintenance never
		// routes it, so it must not stay drift forever.
		{Tool: "codex", State: RouteAbsent, ArtifactPresent: true, Routability: RoutabilityWritable},
		// Unselected, installed, the org's route removed earlier.
		{Tool: "kimi-code", State: RouteAbsent, ArtifactPresent: true, WasRouted: true, OrgRouted: true, Routability: RoutabilityWritable},
		// Unselected, installed, not routable here: unselected, not unroutable.
		{Tool: "crush", State: RouteAbsent, ArtifactPresent: true, Routability: RoutabilityNotRoutable},
		// Unselected and not installed: in no list.
		{Tool: "qwen-code", State: RouteAbsent, ArtifactPresent: false},
	}
	selected := Selection{Tool: func(tool string) bool { return tool == "claude-code" }}
	routingOff := Selection{RoutingOff: true, Tool: selected.Tool}
	installed := []string{"claude-code", "codex", "crush", "kimi-code"}
	cases := []struct {
		name                        string
		p                           DriftPolicy
		drift, unsel, unroute, roff []string
		switchedOff                 bool
	}{
		{"maintained", DriftPolicy{Mode: DriftModeMaintained, Selection: selected}, []string{"claude-code"}, []string{"codex", "crush", "kimi-code"}, nil, nil, false},
		{"org routes (no posture)", DriftPolicy{Mode: DriftModeOrgRoutes, Selection: selected}, []string{"claude-code"}, []string{"codex", "crush", "kimi-code"}, nil, nil, false},
		{"off (release): nothing changes", DriftPolicy{Mode: DriftModeOff, Selection: selected}, nil, nil, []string{"crush"}, nil, false},
		{"maintained, every tool selected (zero selection)", DriftPolicy{Mode: DriftModeMaintained}, []string{"claude-code", "codex", "kimi-code"}, nil, []string{"crush"}, nil, false},
		// D-771: the route writer component is not active. No drift, every
		// installed tool listed once, selected or not.
		{"maintained, routing switched off", DriftPolicy{Mode: DriftModeMaintained, Selection: routingOff}, nil, nil, nil, installed, true},
		{"org routes, routing switched off", DriftPolicy{Mode: DriftModeOrgRoutes, Selection: routingOff}, nil, nil, nil, installed, true},
		{"off (release), routing switched off: nothing changes", DriftPolicy{Mode: DriftModeOff, Selection: routingOff}, nil, nil, []string{"crush"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DriftedTools(statuses, tc.p); !reflect.DeepEqual(got, tc.drift) {
				t.Errorf("DriftedTools = %v, want %v", got, tc.drift)
			}
			if got := UnselectedTools(statuses, tc.p); !reflect.DeepEqual(got, tc.unsel) {
				t.Errorf("UnselectedTools = %v, want %v", got, tc.unsel)
			}
			if got := UnroutableTools(statuses, tc.p); !reflect.DeepEqual(got, tc.unroute) {
				t.Errorf("UnroutableTools = %v, want %v", got, tc.unroute)
			}
			if got := RoutingOffTools(statuses, tc.p); !reflect.DeepEqual(got, tc.roff) {
				t.Errorf("RoutingOffTools = %v, want %v", got, tc.roff)
			}
			if got := RoutingSwitchedOff(tc.p); got != tc.switchedOff {
				t.Errorf("RoutingSwitchedOff = %v, want %v", got, tc.switchedOff)
			}
		})
	}
}

// maintainHome is an isolated home with every tool's env override pointed
// inside it.
func maintainHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("CRUSH_GLOBAL_CONFIG", "")
	t.Setenv("KIMI_CODE_HOME", "")
	t.Setenv("QWEN_HOME", "")
	return home
}

func maintainRegistrar(t *testing.T, home string) *Registrar {
	t.Helper()
	r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, Writer: routeprov.WriterManaged})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func always(v bool) func() bool { return func() bool { return v } }

func readBytes(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func resultFor(rs []MaintainResult, tool string) MaintainResult {
	for _, r := range rs {
		if r.Tool == tool {
			return r
		}
	}
	return MaintainResult{}
}

// claudeSettingsFixture is a settings.json carrying hooks, permissions and an
// unrelated env key that maintenance must keep.
const claudeSettingsFixture = `{
  "env": {
    "OTHER": "keep-me"
  },
  "hooks": {
    "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "observer hook claude-code pre"}]}]
  },
  "permissions": {
    "allow": ["Bash(ls:*)"]
  }
}
`

// codexConfigFixture carries a comment and keys maintenance must keep
// byte for byte.
const codexConfigFixture = "# my codex settings\nmodel = \"gpt-5\"\napproval_policy = \"on-request\"\n\n[mcp_servers.other]\ncommand = \"other\"\n"

// TestMaintainRoutesWritesPreservesAndIsIdempotent: a managed pass writes
// the routes of the installed, routable tools, keeps every other setting,
// and a second pass changes nothing.
func TestMaintainRoutesWritesPreservesAndIsIdempotent(t *testing.T) {
	home := maintainHome(t)
	writeFile(t, filepath.Join(home, ".claude"), "settings.json", claudeSettingsFixture)
	writeFile(t, filepath.Join(home, ".codex"), "config.toml", codexConfigFixture)
	r := maintainRegistrar(t, home)

	got := r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)})
	for _, tool := range []string{"claude-code", "codex"} {
		res := resultFor(got, tool)
		if !res.Written || res.Repaired || res.Error != nil {
			t.Fatalf("%s: %+v, want a first write", tool, res)
		}
	}
	for _, tool := range []string{"kimi-code", "qwen-code", "crush"} {
		if res := resultFor(got, tool); res.Written || res.Decision.Reason != ReasonNotInstalled {
			t.Fatalf("%s: %+v, want not_installed", tool, res)
		}
	}

	// Claude Code: the route and the hint switch are added; hooks,
	// permissions and the other env key are kept.
	var settings map[string]any
	if err := json.Unmarshal([]byte(readBytes(t, filepath.Join(home, ".claude", "settings.json"))), &settings); err != nil {
		t.Fatal(err)
	}
	env, _ := settings["env"].(map[string]any)
	if env["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:8820" || env["OTHER"] != "keep-me" {
		t.Fatalf("env after maintenance = %v", env)
	}
	var want map[string]any
	_ = json.Unmarshal([]byte(claudeSettingsFixture), &want)
	for _, k := range []string{"hooks", "permissions"} {
		if !reflect.DeepEqual(settings[k], want[k]) {
			t.Fatalf("%s changed: %v -> %v", k, want[k], settings[k])
		}
	}
	// Codex: every original line survives, in order.
	codex := readBytes(t, filepath.Join(home, ".codex", "config.toml"))
	if !strings.HasPrefix(codex, "# my codex settings\n") {
		t.Fatalf("codex comment lost:\n%s", codex)
	}
	for _, line := range strings.Split(strings.TrimSpace(codexConfigFixture), "\n") {
		if !strings.Contains(codex, line) {
			t.Fatalf("codex line %q lost:\n%s", line, codex)
		}
	}
	if s := statusFor(InspectRoutes(home), "codex"); s.State != RouteOurs {
		t.Fatalf("codex after maintenance: %q, want ours", s.State)
	}

	// Idempotent: a second pass writes nothing and leaves both files
	// byte-identical.
	beforeClaude := readBytes(t, filepath.Join(home, ".claude", "settings.json"))
	beforeCodex := codex
	again := r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)})
	for _, res := range again {
		if res.Written || res.Error != nil {
			t.Fatalf("second pass touched %s: %+v", res.Tool, res)
		}
	}
	if readBytes(t, filepath.Join(home, ".claude", "settings.json")) != beforeClaude || readBytes(t, filepath.Join(home, ".codex", "config.toml")) != beforeCodex {
		t.Fatal("second pass changed a file")
	}
	if d := DriftedTools(InspectRoutes(home), maintained); len(d) != 0 {
		t.Fatalf("drift after maintenance = %v, want none", d)
	}
	// The managed daemon owns what it wrote, so leaving the organization (or
	// the admin turning maintenance off) removes it.
	acts := RecentRouteActs(home, time.Now(), 24*time.Hour)
	if len(acts) != 2 || acts[0].Kind != RouteActWritten || acts[1].Kind != RouteActWritten {
		t.Fatalf("RecentRouteActs = %+v, want two written acts", acts)
	}
}

// TestMaintainRoutesWritesNothingWhenNotRequired: an individual node (and a
// managed node whose org needs no proxy) keeps `observer start`'s default of
// writing no routes.
func TestMaintainRoutesWritesNothingWhenNotRequired(t *testing.T) {
	home := maintainHome(t)
	writeFile(t, filepath.Join(home, ".claude"), "settings.json", claudeSettingsFixture)
	writeFile(t, filepath.Join(home, ".codex"), "config.toml", codexConfigFixture)
	r := maintainRegistrar(t, home)
	for _, res := range r.MaintainRoutes(MaintainOptions{Required: false, ProxyHealthy: always(true)}) {
		if res.Written || res.Decision.Reason != ReasonNotRequired {
			t.Fatalf("%s: %+v, want not_required", res.Tool, res)
		}
	}
	if readBytes(t, filepath.Join(home, ".claude", "settings.json")) != claudeSettingsFixture ||
		readBytes(t, filepath.Join(home, ".codex", "config.toml")) != codexConfigFixture {
		t.Fatal("a pass that is not required changed a file")
	}
	if _, err := os.Stat(filepath.Join(home, ".observer", ProvenanceFileName)); !os.IsNotExist(err) {
		t.Fatalf("a pass that is not required recorded provenance (stat err %v)", err)
	}
}

// TestMaintainRoutesNeverWritesTowardADeadProxy: when the proxy is not
// listening (or is draining), nothing is written, both at the pass probe and
// when the proxy goes away between the probe and the write.
func TestMaintainRoutesNeverWritesTowardADeadProxy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		healthy func() bool
	}{
		{"not listening", always(false)},
		{"no probe wired", nil},
		{"stops between probe and write", func() func() bool {
			calls := 0
			return func() bool { calls++; return calls == 1 }
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := maintainHome(t)
			writeFile(t, filepath.Join(home, ".claude"), "settings.json", claudeSettingsFixture)
			r := maintainRegistrar(t, home)
			res := resultFor(r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: tc.healthy}), "claude-code")
			if res.Written || res.Decision.Reason != ReasonProxyUnavailable {
				t.Fatalf("claude-code: %+v, want proxy_unavailable", res)
			}
			if readBytes(t, filepath.Join(home, ".claude", "settings.json")) != claudeSettingsFixture {
				t.Fatal("wrote a route toward a proxy that is not serving")
			}
		})
	}
}

// TestMaintainRoutesLeavesAWrongHostAsDrift: a route at a third-party host
// is redirection evidence. Maintenance never overwrites it, and it is drift
// wherever routes are maintained. With maintenance off, or with no posture
// and no route the organization wrote, it is the developer's own setup.
func TestMaintainRoutesLeavesAWrongHostAsDrift(t *testing.T) {
	home := maintainHome(t)
	const evil = `{"env":{"ANTHROPIC_BASE_URL":"https://llm.example.com"}}`
	writeFile(t, filepath.Join(home, ".claude"), "settings.json", evil)
	r := maintainRegistrar(t, home)
	res := resultFor(r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)}), "claude-code")
	if res.Written || res.Decision.Reason != ReasonWrongHost {
		t.Fatalf("claude-code: %+v, want wrong_host", res)
	}
	if readBytes(t, filepath.Join(home, ".claude", "settings.json")) != evil {
		t.Fatal("maintenance overwrote a wrong-host route")
	}
	if d := DriftedTools(InspectRoutes(home), maintained); len(d) != 1 || d[0] != "claude-code" {
		t.Fatalf("maintained: drift = %v, want [claude-code]", d)
	}
	for _, mode := range []DriftMode{DriftModeOff, DriftModeOrgRoutes} {
		if d := DriftedTools(InspectRoutes(home), DriftPolicy{Mode: mode}); len(d) != 0 {
			t.Fatalf("%s: drift = %v, want none", mode, d)
		}
	}
}

// TestMaintainRoutesLeavesAnotherLoopbackPortAsDrift pins T-901: a route at
// a loopback port other than this daemon's proxy listener is never
// overwritten, and it is drift on a node whose routes are maintained,
// compared against the configured listener port, not a fixed 8820.
func TestMaintainRoutesLeavesAnotherLoopbackPortAsDrift(t *testing.T) {
	home := maintainHome(t)
	const forwarder = `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`
	writeFile(t, filepath.Join(home, ".claude"), "settings.json", forwarder)
	// This daemon's proxy listens on 9100, so :8820 is someone else.
	r, err := NewRegistrar(RegisterOptions{ProxyPort: 9100, HomeDir: home, Writer: routeprov.WriterManaged})
	if err != nil {
		t.Fatal(err)
	}
	res := resultFor(r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)}), "claude-code")
	if res.Written || res.Decision.Reason != ReasonOtherPort {
		t.Fatalf("claude-code: %+v, want other_port", res)
	}
	if readBytes(t, filepath.Join(home, ".claude", "settings.json")) != forwarder {
		t.Fatal("maintenance overwrote a route at another loopback port")
	}
	st := statusFor(InspectRoutes(home), "claude-code")
	if st.State != RouteOurs || st.Port != 8820 {
		t.Fatalf("status = %+v, want ours on port 8820", st)
	}
	if d := DriftedTools(InspectRoutes(home), DriftPolicy{Mode: DriftModeMaintained, ProxyPort: 9100}); len(d) != 1 || d[0] != "claude-code" {
		t.Fatalf("listener 9100: drift = %v, want [claude-code]", d)
	}
	if d := DriftedTools(InspectRoutes(home), DriftPolicy{Mode: DriftModeMaintained, ProxyPort: 8820}); len(d) != 0 {
		t.Fatalf("listener 8820: drift = %v, want none", d)
	}
}

// TestMaintainRoutesRepairsARemovedRoute: a route maintenance (or enrolment)
// wrote, then removed by hand, is put back and reported as a repair.
func TestMaintainRoutesRepairsARemovedRoute(t *testing.T) {
	home := maintainHome(t)
	writeFile(t, filepath.Join(home, ".claude"), "settings.json", claudeSettingsFixture)
	r := maintainRegistrar(t, home)
	r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)})

	// The developer removes the route.
	writeFile(t, filepath.Join(home, ".claude"), "settings.json", claudeSettingsFixture)
	st := statusFor(InspectRoutes(home), "claude-code")
	if !st.WasRouted || st.State != RouteAbsent {
		t.Fatalf("after removal: %+v, want absent and WasRouted", st)
	}
	if d := DriftedTools(InspectRoutes(home), maintained); len(d) != 1 || d[0] != "claude-code" {
		t.Fatalf("drift after removal = %v, want [claude-code]", d)
	}

	// The repair stamp comes from the injected clock, but the writer stamps
	// the rewritten record's WrittenAt with the real clock, and
	// RecentRouteActs falls back to WrittenAt once RepairedAt is outside the
	// window. In production both stamps come from time.Now, so the injected
	// clock is anchored to the real one: a fixed date here put the real-clock
	// WrittenAt inside the at+25h window from 2026-10-18 13:00 UTC onward.
	at := time.Now().UTC().Truncate(time.Second)
	res := resultFor(r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true), Now: func() time.Time { return at }}), "claude-code")
	if !res.Written || !res.Repaired || res.Error != nil {
		t.Fatalf("claude-code: %+v, want a repair", res)
	}
	acts := RecentRouteActs(home, at.Add(time.Hour), 24*time.Hour)
	if len(acts) != 1 || acts[0].Kind != RouteActRepaired || !acts[0].At.Equal(at) || acts[0].Tool != "claude-code" {
		t.Fatalf("RecentRouteActs = %+v, want one repair at %v", acts, at)
	}
	if acts := RecentRouteActs(home, at.Add(25*time.Hour), 24*time.Hour); len(acts) != 0 {
		t.Fatalf("a repair older than the window is still reported: %+v", acts)
	}
}

// TestOrgRoutesModeReadsOnlyOrganizationRoutes pins the no-posture reading
// (unset, no proxy enforcement point; D-738 leaves the organization's routes
// in place): a removed route the organization wrote is drift, the same
// removal of a route the developer wrote with `observer init` is not.
func TestOrgRoutesModeReadsOnlyOrganizationRoutes(t *testing.T) {
	cases := []struct {
		writer routeprov.Writer
		drift  bool
	}{
		{routeprov.WriterManaged, true},
		{routeprov.WriterEnrolment, true},
		{routeprov.WriterInit, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.writer), func(t *testing.T) {
			home := maintainHome(t)
			writeFile(t, filepath.Join(home, ".claude"), "settings.json", claudeSettingsFixture)
			r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, Writer: tc.writer})
			if err != nil {
				t.Fatal(err)
			}
			if res := r.RegisterClaudeCode(); res.Error != nil || !res.Added {
				t.Fatalf("write: %+v", res)
			}
			policy := DriftPolicy{Mode: DriftModeOrgRoutes, ProxyPort: 8820}
			if d := DriftedTools(InspectRoutes(home), policy); len(d) != 0 {
				t.Fatalf("route in place: drift = %v, want none", d)
			}
			writeFile(t, filepath.Join(home, ".claude"), "settings.json", claudeSettingsFixture)
			d := DriftedTools(InspectRoutes(home), policy)
			if got := len(d) == 1 && d[0] == "claude-code"; got != tc.drift {
				t.Fatalf("after removal: drift = %v, want drift=%v", d, tc.drift)
			}
		})
	}
}

// TestUnroutableConfigIsCoverageNotDrift: kimi-code with no
// [providers.openai] table (its active provider is another entry) cannot be
// routed by the writer. On a managed node it is reported as unroutable, never
// drift, and maintenance leaves it alone, unless Observer routed it before.
func TestUnroutableConfigIsCoverageNotDrift(t *testing.T) {
	home := maintainHome(t)
	const kimi = "[providers.mine]\ntype = \"openai\"\nbase_url = \"https://llm.example.com/v1\"\napi_key = \"redacted\"\n"
	writeFile(t, filepath.Join(home, ".kimi-code"), "config.toml", kimi)
	st := statusFor(InspectRoutes(home), "kimi-code")
	if st.State != RouteAbsent || st.Routability != RoutabilityConfigNotCovered {
		t.Fatalf("kimi-code: %+v, want absent + config_not_covered", st)
	}
	if d := DriftedTools(InspectRoutes(home), maintained); len(d) != 0 {
		t.Fatalf("drift = %v, want none", d)
	}
	if u := UnroutableTools(InspectRoutes(home), maintained); len(u) != 1 || u[0] != "kimi-code" {
		t.Fatalf("UnroutableTools = %v, want [kimi-code]", u)
	}
	r := maintainRegistrar(t, home)
	if res := resultFor(r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)}), "kimi-code"); res.Written || res.Decision.Reason != ReasonConfigNotCovered {
		t.Fatalf("kimi-code: %+v, want config_not_covered", res)
	}
	if readBytes(t, filepath.Join(home, ".kimi-code", "config.toml")) != kimi {
		t.Fatal("maintenance changed a config it cannot route")
	}

	// Observer routed it before (a provenance record): the table that carried
	// the route is gone, which is a removal, not a setup choice.
	f := routeprov.File{}
	f.Note(routeprov.Record{
		Tool: "kimi-code", ConfigPath: filepath.Join(home, ".kimi-code", "config.toml"),
		Value: "http://127.0.0.1:8820/v1", Writer: routeprov.WriterEnrolment, WrittenAt: "2026-10-01T00:00:00Z",
	}, routeprov.OutcomeWrote)
	if err := saveProvenance(filepath.Join(home, ".observer", ProvenanceFileName), f); err != nil {
		t.Fatal(err)
	}
	if d := DriftedTools(InspectRoutes(home), maintained); len(d) != 1 || d[0] != "kimi-code" {
		t.Fatalf("drift with a provenance record = %v, want [kimi-code]", d)
	}
	if u := UnroutableTools(InspectRoutes(home), maintained); len(u) != 0 {
		t.Fatalf("UnroutableTools with a provenance record = %v, want none", u)
	}
}

// TestUnreadableProvenanceReadsAsRouted: a damaged provenance file must not
// turn a removed route into "never routable" (the loud side).
func TestUnreadableProvenanceReadsAsRouted(t *testing.T) {
	home := maintainHome(t)
	writeFile(t, filepath.Join(home, ".kimi-code"), "config.toml", "[providers.mine]\ntype = \"openai\"\n")
	writeFile(t, filepath.Join(home, ".observer"), ProvenanceFileName, "{not json")
	if d := DriftedTools(InspectRoutes(home), maintained); len(d) != 1 || d[0] != "kimi-code" {
		t.Fatalf("drift with an unreadable provenance file = %v, want [kimi-code]", d)
	}
}

// TestMaintainRoutesHonoursTheAllowFilter: an inactive adapter component is
// never written.
func TestMaintainRoutesHonoursTheAllowFilter(t *testing.T) {
	home := maintainHome(t)
	writeFile(t, filepath.Join(home, ".claude"), "settings.json", claudeSettingsFixture)
	r := maintainRegistrar(t, home)
	got := r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true), Allow: func(tool string) bool { return tool != "claude-code" }})
	if res := resultFor(got, "claude-code"); res.Tool != "" {
		t.Fatalf("filtered tool was visited: %+v", res)
	}
	if readBytes(t, filepath.Join(home, ".claude", "settings.json")) != claudeSettingsFixture {
		t.Fatal("a filtered tool was written")
	}
}

// TestRoutableDefaultsAreWritable pins the coverage dry run against the stock
// configs the writers accept: each one reads as writable, and a qwen-code
// file on its default host is "not routed yet", never a wrong host.
func TestRoutableDefaultsAreWritable(t *testing.T) {
	home := maintainHome(t)
	writeFile(t, filepath.Join(home, ".claude"), "settings.json", `{}`)
	writeFile(t, filepath.Join(home, ".codex"), "config.toml", "model = \"gpt-5\"\n")
	writeFile(t, filepath.Join(home, ".kimi-code"), "config.toml", "[providers.openai]\napi_key = \"redacted\"\n")
	writeFile(t, filepath.Join(home, ".qwen"), "settings.json", `{"model":{"name":"gpt-4o","baseUrl":"https://api.openai.com/v1"}}`)
	writeFile(t, filepath.Join(home, ".config", "crush"), "crush.json", `{"providers":{"openai":{"api_key":"redacted"}}}`)
	for _, st := range InspectRoutes(home) {
		if st.State != RouteAbsent || st.Routability != RoutabilityWritable {
			t.Errorf("%s: state %q routability %q, want absent + writable", st.Tool, st.State, st.Routability)
		}
	}
	r := maintainRegistrar(t, home)
	r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)})
	for _, st := range InspectRoutes(home) {
		if st.State != RouteOurs {
			t.Errorf("%s after maintenance: %q, want ours", st.Tool, st.State)
		}
	}
}

// TestClientAuthFormChangeLeavesOtherRoutes pins what the client token form
// rule never touches: a developer's own route, a writer without the token
// form, and a route already in the daemon's form, in either direction.
func TestClientAuthFormChangeLeavesOtherRoutes(t *testing.T) {
	t.Parallel()
	base := RouteStatus{State: RouteOurs, ClientAuthWritable: true, OrgRouted: true}
	for _, c := range []struct {
		name string
		in   MaintainInput
		want MaintainDecision
	}{
		{"developer's own plain route", MaintainInput{Required: true, ProxyHealthy: true, WantClientAuth: true, Status: RouteStatus{State: RouteOurs, ClientAuthWritable: true}}, MaintainDecision{MaintainSkip, ReasonRouted}},
		{"writer has no token form", MaintainInput{Required: true, ProxyHealthy: true, WantClientAuth: true, Status: RouteStatus{State: RouteOurs, OrgRouted: true}}, MaintainDecision{MaintainSkip, ReasonRouted}},
		{"already in the token form", MaintainInput{Required: true, ProxyHealthy: true, WantClientAuth: true, Status: func() RouteStatus { s := base; s.ClientAuth = true; return s }()}, MaintainDecision{MaintainSkip, ReasonRouted}},
		{"plain form wanted, plain route", MaintainInput{Required: true, ProxyHealthy: true, Status: base}, MaintainDecision{MaintainSkip, ReasonRouted}},
		{"plain form wanted, token route is rewritten back", MaintainInput{Required: true, ProxyHealthy: true, Status: func() RouteStatus { s := base; s.ClientAuth = true; return s }()}, MaintainDecision{MaintainWrite, ReasonClientAuthForm}},
	} {
		if got := DecideMaintenance(c.in); got != c.want {
			t.Errorf("%s: DecideMaintenance = %+v, want %+v", c.name, got, c.want)
		}
	}
}
