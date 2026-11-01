package securityscanning

import (
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/postureop"
)

func mustCompile(t *testing.T, body string) PolicySpec {
	t.Helper()
	s, _, err := CompileBody([]byte(body), 0)
	if err != nil {
		t.Fatalf("compile %s: %v", body, err)
	}
	return s
}

// allActive is every child active.
func allActive() map[string]bool {
	m := map[string]bool{}
	for _, c := range Children {
		m[c.Component] = true
	}
	return m
}

// TestRaisePerAxis is one row per axis and boundary: the merged value keeps
// the stronger of the node's own value and the floor.
func TestRaisePerAxis(t *testing.T) {
	v := func(s string) postureop.Value { return postureop.Value{S: s} }
	n := func(x int64) postureop.Value { return postureop.Value{N: x} }
	set := func(x ...string) postureop.Value { return postureop.Value{Set: x} }
	cases := []struct {
		axis         string
		local, floor postureop.Value
		want         string
		wantErr      error
	}{
		{AxisComponents, set("security.trust"), set("security.deps"), "[security.deps security.trust]", nil},
		{AxisPrelaunchTrust, v("warn"), v("ask"), "ask", nil},
		{AxisPrelaunchTrust, v("refuse"), v("ask"), "refuse", nil},
		{AxisCommitGate, v("ask"), v("quick_scan"), "quick_scan", nil},
		{AxisQuickScanBudget, n(5), n(10), "10", nil},
		{AxisQuickScanBudget, n(30), n(10), "30", nil},
		{AxisMaxScanStaleness, n(60), n(30), "30", nil},
		{AxisMaxScanStaleness, n(15), n(30), "15", nil},
		{AxisMaxAdvisoryDBAge, n(168), n(72), "72", nil},
		{AxisMinBlockingSeverity, v("critical"), v("high"), "high", nil},
		{AxisMinBlockingSeverity, v("low"), v("high"), "low", nil},
		{AxisInstallUnknown, v("flag"), v("ask"), "ask", nil},
		{AxisOnlineChecks, v("leave"), v("required"), "required", nil},
		{AxisInstallOnlineUnknown, v("ask"), v("deny"), "deny", nil},
		{AxisHistoryScanOnEnrol, v("false"), v("true"), "true", nil},
		{AxisFindingRetention, n(90), n(365), "365", nil},
		{AxisFindingRetention, n(730), n(365), "730", nil},
		// Retention 0 is forever, the maximum: it beats any finite floor and
		// any finite local value.
		{AxisFindingRetention, n(365), n(0), "forever", nil},
		{AxisFindingRetention, n(0), n(730), "forever", nil},
		{AxisAllowDrivers, set("osv", "scalibr"), set("scalibr"), "[scalibr]", nil},
		// An empty intersection refuses (allows nothing, never "any").
		{AxisAllowDrivers, set("osv"), set("scalibr"), "", postureop.ErrEmptyIntersection},
		// Nothing enabled locally: nothing to narrow.
		{AxisAllowDrivers, set(), set("scalibr"), "[]", nil},
		{AxisAllowCustomManifests, set("sha256:a", "sha256:b"), set("sha256:a"), "[sha256:a]", nil},
		{AxisAllowScannerSources, set("vendor_release", "org_mirror"), set("org_mirror"), "[org_mirror]", nil},
		{AxisAllowOnlineChecks, v("allowed"), v("forbidden"), "forbidden", nil},
		{AxisRulePackMinVersion, v("2026.10.1"), v("2026.11.1"), "2026.11.1", nil},
		{AxisRulePackMinVersion, v("2026.12"), v("2026.11.1"), "2026.12", nil},
	}
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.axis] = true
		t.Run(c.axis+"/"+c.want, func(t *testing.T) {
			ax, ok := LookupAxis(c.axis)
			if !ok {
				t.Fatalf("no axis %s", c.axis)
			}
			got, err := raise(ax, c.local, c.floor)
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("err = %v, want %v", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s := show(ax, got); s != c.want {
				t.Fatalf("raise = %s, want %s", s, c.want)
			}
		})
	}
	for _, a := range Axes {
		if !covered[a.Name] {
			t.Errorf("axis %s has no test row", a.Name)
		}
	}
}

// TestEvaluateApplicability: every key is applied or reported with a
// named reason, never dropped.
func TestEvaluateApplicability(t *testing.T) {
	s := mustCompile(t, `{"require":{"components":["security.deps"],"commit_gate":"quick_scan","online_checks":"required","finding_retention_days":730,"prelaunch_trust":"ask"},"allow":{"custom_manifests":["sha256:`+strings.Repeat("c", 64)+`"]},"sections":{"deps":{"capability":"security.deps.v1"}}}`)
	local := postureop.Posture{AxisFindingRetention: {N: 365}, AxisOnlineChecks: {S: "leave"}}
	cases := []struct {
		name  string
		facts NodeFacts
		want  []string
	}{
		{
			name:  "individual, deps absent",
			facts: NodeFacts{Active: map[string]bool{"security.trust": true}, Local: local},
			want: []string{
				"require.components:security.deps: not_applicable: component_absent",
				"require.prelaunch_trust: not_applicable: individual_node",
				"require.commit_gate: not_applicable: individual_node",
				"require.online_checks: not_applicable: individual_node",
				"require.finding_retention_days: applied",
				"allow.custom_manifests: not_applicable: individual_node",
				"sections.deps: not_applicable: component_absent",
			},
		},
		{
			name:  "managed, deps absent",
			facts: NodeFacts{Managed: true, Active: map[string]bool{"security.trust": true}, Local: local},
			want: []string{
				"require.components:security.deps: refused: component_absent",
				"require.prelaunch_trust: not_applicable: not_built",
				"require.commit_gate: not_applicable: not_built",
				"require.online_checks: not_applicable: component_absent",
				"require.finding_retention_days: applied",
				"allow.custom_manifests: not_applicable: component_absent",
				"sections.deps: refused: component_absent",
			},
		},
		{
			name:  "managed, all active",
			facts: NodeFacts{Managed: true, Active: allActive(), Local: local},
			want: []string{
				"require.components:security.deps: applied",
				"require.prelaunch_trust: not_applicable: not_built",
				"require.commit_gate: not_applicable: not_built",
				"require.online_checks: applied",
				"require.finding_retention_days: applied",
				"allow.custom_manifests: not_applicable: not_built",
				"sections.deps: applied",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(s, c.facts)
			var lines []string
			for _, k := range got {
				lines = append(lines, k.String())
			}
			if strings.Join(lines, "\n") != strings.Join(c.want, "\n") {
				t.Fatalf("Evaluate:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(c.want, "\n"))
			}
		})
	}
}

// TestPrelaunchTrustFloorIsManagedOnly (orchestrator ruling P-125, audit
// SEC-P4 F4): an individual node running security.trust with its own trust
// setting reads the floor not_applicable: individual_node and keeps its own
// value; a managed node takes the floor.
func TestPrelaunchTrustFloorIsManagedOnly(t *testing.T) {
	s := mustCompile(t, `{"require":{"prelaunch_trust":"refuse"}}`)
	local := postureop.Posture{AxisPrelaunchTrust: {S: "warn"}}
	f := NodeFacts{Active: map[string]bool{"security": true, "security.trust": true}, Local: local}
	var line string
	for _, k := range Evaluate(s, f) {
		if strings.HasPrefix(k.String(), "require.prelaunch_trust") {
			line = k.String()
		}
	}
	if line != "require.prelaunch_trust: not_applicable: individual_node" {
		t.Fatalf("individual node: %q, want not_applicable: individual_node", line)
	}
	eff, err := Effective(&s, f)
	if err != nil {
		t.Fatal(err)
	}
	if eff[AxisPrelaunchTrust].S != "warn" {
		t.Fatalf("individual node's trust step = %q, want its own warn", eff[AxisPrelaunchTrust].S)
	}
	f.Managed = true
	if eff, _ = Effective(&s, f); eff[AxisPrelaunchTrust].S != "refuse" {
		t.Fatalf("managed node's trust step = %q, want the floor's refuse", eff[AxisPrelaunchTrust].S)
	}
}

func TestEffectiveSkipsNotApplicable(t *testing.T) {
	s := mustCompile(t, `{"require":{"online_checks":"required","finding_retention_days":0}}`)
	f := NodeFacts{Active: allActive(), Local: postureop.Posture{AxisFindingRetention: {N: 365}, AxisOnlineChecks: {S: "leave"}}}
	eff, err := Effective(&s, f)
	if err != nil {
		t.Fatal(err)
	}
	if eff[AxisOnlineChecks].S != "leave" {
		t.Errorf("online on an individual node = %q, want the developer's own leave", eff[AxisOnlineChecks].S)
	}
	if eff[AxisFindingRetention].N != 0 {
		t.Errorf("retention = %d, want 0 (forever)", eff[AxisFindingRetention].N)
	}
	f.Managed = true
	eff, _ = Effective(&s, f)
	if eff[AxisOnlineChecks].S != "required" {
		t.Errorf("online on a managed node = %q, want required", eff[AxisOnlineChecks].S)
	}
}

func TestCheckPosture(t *testing.T) {
	held := mustCompile(t, `{"require":{"finding_retention_days":730}}`)
	lower := mustCompile(t, `{"require":{"finding_retention_days":180}}`)
	higher := mustCompile(t, `{"require":{"finding_retention_days":0}}`)
	narrow := mustCompile(t, `{"allow":{"drivers":["scalibr"]}}`)
	local := postureop.Posture{AxisFindingRetention: {N: 365}, AxisAllowDrivers: {Set: []string{"osv"}}}
	cases := []struct {
		name     string
		spec     PolicySpec
		facts    NodeFacts
		wantAxis string
	}{
		{"individual, raise over held", higher, NodeFacts{Local: local, Held: &held, Active: allActive()}, ""},
		{"individual, lower than held", lower, NodeFacts{Local: local, Held: &held, Active: allActive()}, AxisFindingRetention},
		{"individual, lower but nothing held", lower, NodeFacts{Local: local, Active: allActive()}, ""},
		{"managed may lower its own floor", lower, NodeFacts{Managed: true, Local: local, Held: &held, Active: allActive()}, ""},
		{"empty intersection refuses", narrow, NodeFacts{Local: local, Active: allActive()}, AxisAllowDrivers},
		{"empty intersection refuses on managed too", narrow, NodeFacts{Managed: true, Local: local, Active: allActive()}, AxisAllowDrivers},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			axis, err := checkPosture(c.spec, c.facts)
			if axis != c.wantAxis {
				t.Fatalf("axis = %q (%v), want %q", axis, err, c.wantAxis)
			}
			if (err != nil) != (c.wantAxis != "") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestCheckPostureWithoutProviderRefuses(t *testing.T) {
	defer SetNodeFactsProvider(nil)()
	if _, err := CheckPosture(PolicySpec{}); !errors.Is(err, ErrNoNodeFacts) {
		t.Fatalf("err = %v, want ErrNoNodeFacts", err)
	}
	if caps := LiveCapabilities(); caps != nil {
		t.Fatalf("caps = %v, want none with no provider", caps)
	}
}

func TestLiveCapabilities(t *testing.T) {
	defer SetNodeFactsProvider(func() NodeFacts { return NodeFacts{Active: map[string]bool{}} })()
	if got := len(LiveCapabilities()); got != len(Children) {
		t.Fatalf("individual node advertises %d tokens, want every section (%d)", got, len(Children))
	}
	SetNodeFactsProvider(func() NodeFacts {
		return NodeFacts{Managed: true, Active: map[string]bool{"security.trust": true}}
	})
	if got := strings.Join(LiveCapabilities(), ","); got != "security.trust.v1" {
		t.Fatalf("managed node advertises %s, want only its active child", got)
	}
}
