package orgcontract

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestConfigLayerRiskLabelVocabulary: only a closed tool and a closed
// finding code make a label; a path, a key, a value or an informational code
// never does.
func TestConfigLayerRiskLabelVocabulary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		label string
		want  bool
	}{
		{"claude-code/project_route_override", true},
		{"opencode/route_shadowed", true},
		{"copilot/ide_route_override", true},
		{"qwen-code/project_hooks_disabled", true},
		{"gemini-cli/hooks_disabled", true},
		{"vtcode/hook_array_replaced", true},
		{"vtcode/layers_dropped", true},
		{"gemini-cli/auth_pins_vendor_host", true},
		{"crush/inactive_provider", true},
		{"ibm-bob/user_policy_override", true},
		{"ibm-bob/user_policy_override/GatewayUrl", false},
		{"ibm-bob/GatewayUrl", false},
		{"claude-code/hooks_off_overridden", false},
		{"stakpak/mcp_first_file_only", false},
		{"qwen-code/provider_unverified", false},
		{"unknown-tool/hooks_disabled", false},
		{"claude-code", false},
		{"/hooks_disabled", false},
		{"claude-code/", false},
		{"claude-code/hooks_disabled/extra", false},
		{"claude-code/env.ANTHROPIC_BASE_URL", false},
		{"claude-code/C:\\Users\\dev\\.claude\\settings.local.json", false},
		{"claude-code/https://api.anthropic.com", false},
	}
	for _, tc := range cases {
		if got := validConfigLayerRiskLabel(tc.label); got != tc.want {
			t.Errorf("validConfigLayerRiskLabel(%q) = %v, want %v", tc.label, got, tc.want)
		}
	}
	if label, ok := ConfigLayerRiskLabel("crush", "inactive_provider"); !ok || label != "crush/inactive_provider" {
		t.Fatalf("ConfigLayerRiskLabel(crush, inactive_provider) = %q, %v", label, ok)
	}
	for _, tool := range []string{"", "Claude-Code", "claude code", "/home/dev", "~/.claude"} {
		if ValidConfigLayerTool(tool) {
			t.Errorf("ValidConfigLayerTool(%q) = true, want false", tool)
		}
	}
}

// TestNormalizeConfigLayers: the version gates both lists, each list keeps
// closed labels only, and the derived capture-risk labels follow the lists.
func TestNormalizeConfigLayers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		in          ManagedIntegrityReport
		wantVersion int
		wantHooks   []string
		wantLayers  []string
		wantRisks   []string
	}{
		{
			name:        "older node sends no version",
			in:          ManagedIntegrityReport{CaptureCheckVersion: ManagedCaptureCheckVersion},
			wantVersion: 0,
		},
		{
			name: "no version drops the lists and their labels",
			in: ManagedIntegrityReport{
				CaptureCheckVersion: ManagedCaptureCheckVersion,
				HookDisabledTools:   []string{"gemini-cli"},
				ConfigLayerRisks:    []string{"claude-code/project_route_override"},
				CaptureRisks:        []string{CaptureRiskHookSwitchedOff, CaptureRiskConfigLayerOverride},
			},
			wantVersion: 0,
		},
		{
			name: "future version is not reported",
			in: ManagedIntegrityReport{
				CaptureCheckVersion: ManagedCaptureCheckVersion,
				ConfigLayerVersion:  ManagedConfigLayerVersion + 1,
				HookDisabledTools:   []string{"gemini-cli"},
			},
			wantVersion: 0,
		},
		{
			name:        "reported clean",
			in:          ManagedIntegrityReport{CaptureCheckVersion: ManagedCaptureCheckVersion, ConfigLayerVersion: ManagedConfigLayerVersion},
			wantVersion: ManagedConfigLayerVersion,
		},
		{
			name: "closed labels kept, sorted, deduplicated, labels derived",
			in: ManagedIntegrityReport{
				CaptureCheckVersion: ManagedCaptureCheckVersion,
				ConfigLayerVersion:  ManagedConfigLayerVersion,
				HookDisabledTools:   []string{"qwen-code", "gemini-cli", "qwen-code", "/home/dev/.qwen", "not-a-tool"},
				ConfigLayerRisks:    []string{"vtcode/layers_dropped", "claude-code/project_route_override", "vtcode/layers_dropped", "stakpak/mcp_first_file_only", "claude-code/env.ANTHROPIC_BASE_URL"},
				CaptureRisks:        []string{CaptureRiskHookRepaired},
			},
			wantVersion: ManagedConfigLayerVersion,
			wantHooks:   []string{"gemini-cli", "qwen-code"},
			wantLayers:  []string{"claude-code/project_route_override", "vtcode/layers_dropped"},
			wantRisks:   []string{CaptureRiskConfigLayerOverride, CaptureRiskHookRepaired, CaptureRiskHookSwitchedOff},
		},
		{
			name: "FU-105: a user-set Bob policy key alone derives config_layer_override",
			in: ManagedIntegrityReport{
				CaptureCheckVersion: ManagedCaptureCheckVersion,
				ConfigLayerVersion:  ManagedConfigLayerVersion,
				ConfigLayerRisks:    []string{"ibm-bob/user_policy_override", "ibm-bob/user_policy_override"},
			},
			wantVersion: ManagedConfigLayerVersion,
			wantLayers:  []string{"ibm-bob/user_policy_override"},
			wantRisks:   []string{CaptureRiskConfigLayerOverride},
		},
		{
			name: "a label without its list is dropped",
			in: ManagedIntegrityReport{
				CaptureCheckVersion: ManagedCaptureCheckVersion,
				ConfigLayerVersion:  ManagedConfigLayerVersion,
				HookDisabledTools:   []string{"not-a-tool"},
				CaptureRisks:        []string{CaptureRiskHookSwitchedOff, CaptureRiskConfigLayerOverride},
			},
			wantVersion: ManagedConfigLayerVersion,
		},
		{
			name: "no capture checks keeps the lists, carries no label",
			in: ManagedIntegrityReport{
				ConfigLayerVersion: ManagedConfigLayerVersion,
				HookDisabledTools:  []string{"droid"},
			},
			wantVersion: ManagedConfigLayerVersion,
			wantHooks:   []string{"droid"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.NormalizeLabels()
			if got.ConfigLayerVersion != tc.wantVersion {
				t.Fatalf("version = %d, want %d", got.ConfigLayerVersion, tc.wantVersion)
			}
			if !reflect.DeepEqual(got.HookDisabledTools, tc.wantHooks) {
				t.Fatalf("hook_disabled_tools = %#v, want %#v", got.HookDisabledTools, tc.wantHooks)
			}
			if !reflect.DeepEqual(got.ConfigLayerRisks, tc.wantLayers) {
				t.Fatalf("config_layer_risks = %#v, want %#v", got.ConfigLayerRisks, tc.wantLayers)
			}
			if !reflect.DeepEqual(got.CaptureRisks, tc.wantRisks) {
				t.Fatalf("capture risks = %#v, want %#v", got.CaptureRisks, tc.wantRisks)
			}
		})
	}
}

// TestNormalizeInactiveProviderTools: the list keeps the closed route tool
// vocabulary, needs no version of its own, and carries its derived label.
func TestNormalizeInactiveProviderTools(t *testing.T) {
	t.Parallel()
	got := ManagedIntegrityReport{
		CaptureCheckVersion:   ManagedCaptureCheckVersion,
		InactiveProviderTools: []string{"qwen-code", "crush", "crush", "gemini-cli", "/home/dev/.config/crush/crush.json"},
	}.NormalizeLabels()
	if want := []string{"crush", "qwen-code"}; !reflect.DeepEqual(got.InactiveProviderTools, want) {
		t.Fatalf("inactive_provider_tools = %#v, want %#v", got.InactiveProviderTools, want)
	}
	if want := []string{CaptureRiskRouteInactiveProvider}; !reflect.DeepEqual(got.CaptureRisks, want) {
		t.Fatalf("capture risks = %#v, want %#v", got.CaptureRisks, want)
	}
	if v := got.OverallHealth(); v.Health != ManagedHealthAtRisk || v.Reason != ManagedHealthReasonCaptureRisk {
		t.Fatalf("OverallHealth = %+v, want at_risk / capture_risk", v)
	}
	if got.State() != ManagedIntegrityOK || got.RouteDrift != 0 {
		t.Fatalf("an inactive provider must not read as route drift: state %s, drift %d", got.State(), got.RouteDrift)
	}
	spoof := ManagedIntegrityReport{
		CaptureCheckVersion: ManagedCaptureCheckVersion,
		CaptureRisks:        []string{CaptureRiskRouteInactiveProvider},
	}.NormalizeLabels()
	if len(spoof.CaptureRisks) != 0 {
		t.Fatalf("a label without its list survived: %#v", spoof.CaptureRisks)
	}
}

// TestDerivedCaptureRisks: one row per derivedCaptureRisks entry, each label
// present exactly when its list is, and every row has a test.
func TestDerivedCaptureRisks(t *testing.T) {
	t.Parallel()
	base := ManagedIntegrityReport{
		CaptureCheckVersion:     ManagedCaptureCheckVersion,
		RouteObservationVersion: ManagedRouteObservationVersion,
		ConfigLayerVersion:      ManagedConfigLayerVersion,
	}
	cases := []struct {
		label string
		set   func(r *ManagedIntegrityReport)
	}{
		{CaptureRiskRouteBypassObserved, func(r *ManagedIntegrityReport) { r.UnroutedSurfaces = []string{"codex/cli"} }},
		{CaptureRiskRouteInactiveProvider, func(r *ManagedIntegrityReport) { r.InactiveProviderTools = []string{"kimi-code"} }},
		{CaptureRiskHookSwitchedOff, func(r *ManagedIntegrityReport) { r.HookDisabledTools = []string{"claude-code"} }},
		{CaptureRiskConfigLayerOverride, func(r *ManagedIntegrityReport) { r.ConfigLayerRisks = []string{"claude-code/route_shadowed"} }},
	}
	if len(cases) != len(derivedCaptureRisks) {
		t.Fatalf("%d cases for %d derivedCaptureRisks rows: add one case per row", len(cases), len(derivedCaptureRisks))
	}
	for i, tc := range cases {
		if derivedCaptureRisks[i].label != tc.label {
			t.Fatalf("row %d is %s, case is %s", i, derivedCaptureRisks[i].label, tc.label)
		}
		with := base
		tc.set(&with)
		if got := with.NormalizeLabels().CaptureRisks; !reflect.DeepEqual(got, []string{tc.label}) {
			t.Errorf("%s: with its list, capture risks = %#v", tc.label, got)
		}
		without := base
		without.CaptureRisks = []string{tc.label}
		if got := without.NormalizeLabels().CaptureRisks; len(got) != 0 {
			t.Errorf("%s: without its list, capture risks = %#v", tc.label, got)
		}
		if !isStandingCaptureRisk(tc.label) {
			t.Errorf("%s must be a standing condition", tc.label)
		}
	}
}

// TestConfigLayerVersionOnTheWire: a current node always states its version,
// and a body without the key (an older node, or a row an older server
// stored) decodes as not reported, never as clean.
func TestConfigLayerVersionOnTheWire(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(ManagedIntegrityReport{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"config_layer_version":0`) {
		t.Fatalf("report body %s lacks an explicit config_layer_version", raw)
	}
	for _, key := range []string{"hook_disabled_tools", "config_layer_risks", "inactive_provider_tools"} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("empty %s must be omitted: %s", key, raw)
		}
	}
	raw, err = json.Marshal(ManagedIntegrityDetail{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"config_layer_version":0`) {
		t.Fatalf("stored detail %s lacks an explicit config_layer_version", raw)
	}
	// A node from Wave 1 (route observation, no settings-layer reading).
	var old ManagedIntegrityReport
	if err := json.Unmarshal([]byte(`{"machine_identity":"m","sibling_observers":0,"route_drift":0,"capture_check_version":1,"route_observation_version":1}`), &old); err != nil {
		t.Fatal(err)
	}
	if v := old.NormalizeLabels().OverallHealth(); v.Health != ManagedHealthNotReported || v.Reason != ManagedHealthReasonConfigNotReported {
		t.Fatalf("an older node's clean report = %+v, want not_reported / %s", v, ManagedHealthReasonConfigNotReported)
	}
	clean := ManagedIntegrityReport{
		CaptureCheckVersion:     ManagedCaptureCheckVersion,
		RouteObservationVersion: ManagedRouteObservationVersion,
		ConfigLayerVersion:      ManagedConfigLayerVersion,
	}.NormalizeLabels()
	if v := clean.OverallHealth(); v.Health != ManagedHealthOK {
		t.Fatalf("a current clean report = %+v, want ok", v)
	}
	off := clean
	off.HookDisabledTools = []string{"gemini-cli"}
	if v := off.NormalizeLabels().OverallHealth(); v.Health != ManagedHealthAtRisk || v.Reason != ManagedHealthReasonCaptureRisk {
		t.Fatalf("a report with hooks switched off = %+v, want at_risk / capture_risk", v)
	}
}
