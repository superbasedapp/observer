package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// TestAddConfigLayers (DEC-7, lane w4-wire): the settings-layer reading of
// the managed-integrity report, one case per decision of addConfigLayers.
// On the old code the report had no such reading, so a node whose hooks a
// settings layer switched off read clean to the organization.
func TestAddConfigLayers(t *testing.T) {
	roots := func(context.Context) ([]string, error) { return []string{"/work/repo"}, nil }
	switches := func(fs ...hookdisable.Finding) func([]string) []hookdisable.Finding {
		return func([]string) []hookdisable.Finding { return fs }
	}
	layers := func(fs ...agentconfig.LayerFinding) func(context.Context, []string) ([]agentconfig.LayerFinding, error) {
		return func(context.Context, []string) ([]agentconfig.LayerFinding, error) { return fs, nil }
	}
	finding := func(tool string, code agentconfig.FindingCode) agentconfig.LayerFinding {
		return agentconfig.LayerFinding{Tool: tool, Code: code, Project: "/work/repo", Key: agentconfig.KeyPath{"env", "ANTHROPIC_BASE_URL"}}
	}
	cases := []struct {
		name        string
		src         *configLayerSource
		wantVersion int
		wantHooks   []string
		wantLayers  []string
	}{
		{name: "no source", src: nil, wantVersion: 0},
		{name: "no roots lister", src: &configLayerSource{Switches: switches()}, wantVersion: 0},
		{
			name:        "the project roots cannot be listed",
			src:         &configLayerSource{Roots: func(context.Context) ([]string, error) { return nil, errors.New("db closed") }, Switches: switches()},
			wantVersion: 0,
		},
		{
			name: "the evaluator fails",
			src: &configLayerSource{Roots: roots, Switches: switches(), Layers: func(context.Context, []string) ([]agentconfig.LayerFinding, error) {
				return nil, context.Canceled
			}},
			wantVersion: 0,
		},
		{name: "reported clean", src: &configLayerSource{Roots: roots, Switches: switches(), Layers: layers()}, wantVersion: orgcontract.ManagedConfigLayerVersion},
		{
			name: "a project switch turns one tool's hooks off",
			src: &configLayerSource{Roots: roots, Switches: switches(hookdisable.Finding{
				SwitchID: "gemini.project", Scope: hookdisable.ScopeProject, Path: "/work/repo/.gemini/settings.json", Tools: []string{"gemini-cli"}, ProjectRoot: "/work/repo",
			}), Layers: layers()},
			wantVersion: orgcontract.ManagedConfigLayerVersion,
			wantHooks:   []string{"gemini-cli"},
		},
		{
			name: "a user switch silences every host that replays it",
			src: &configLayerSource{Roots: roots, Switches: switches(hookdisable.Finding{
				SwitchID: "claude.disableAllHooks", Scope: hookdisable.ScopeUser, Tools: []string{"claude-code", "cursor", "kimchi"},
			}), Layers: layers()},
			wantVersion: orgcontract.ManagedConfigLayerVersion,
			wantHooks:   []string{"claude-code", "cursor", "kimchi"},
		},
		{
			name: "a switch that only stops a replay is not counted",
			src: &configLayerSource{Roots: roots, Switches: switches(hookdisable.Finding{
				SwitchID: "devin.read_config_from.claude", Tools: []string{"devin"}, ReplayOnly: true,
			}), Layers: layers()},
			wantVersion: orgcontract.ManagedConfigLayerVersion,
		},
		{
			name:        "a project route override is a tool/finding label",
			src:         &configLayerSource{Roots: roots, Switches: switches(), Layers: layers(finding("claude-code", agentconfig.FindingProjectRouteOverride), finding("crush", agentconfig.FindingInactiveProvider))},
			wantVersion: orgcontract.ManagedConfigLayerVersion,
			wantLayers:  []string{"claude-code/project_route_override", "crush/inactive_provider"},
		},
		{
			name:        "an informational finding does not cross",
			src:         &configLayerSource{Roots: roots, Switches: switches(), Layers: layers(finding("stakpak", agentconfig.FindingMCPFirstFileOnly), finding("not-a-tool", agentconfig.FindingProviderUnverified))},
			wantVersion: orgcontract.ManagedConfigLayerVersion,
		},
		{
			name:        "only unlabelled findings: not reported, never clean",
			src:         &configLayerSource{Roots: roots, Switches: switches(hookdisable.Finding{Tools: []string{"not-a-tool"}}), Layers: layers(finding("not-a-tool", agentconfig.FindingHooksDisabled))},
			wantVersion: 0,
		},
		{
			name:        "an unlabelled finding beside a labelled one",
			src:         &configLayerSource{Roots: roots, Switches: switches(hookdisable.Finding{Tools: []string{"not-a-tool", "droid"}}), Layers: layers()},
			wantVersion: orgcontract.ManagedConfigLayerVersion,
			wantHooks:   []string{"droid"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := orgcontract.ManagedIntegrityReport{
				CaptureCheckVersion:     orgcontract.ManagedCaptureCheckVersion,
				RouteObservationVersion: orgcontract.ManagedRouteObservationVersion,
			}
			addConfigLayers(context.Background(), tc.src, &report)
			norm := report.NormalizeLabels()
			if norm.ConfigLayerVersion != tc.wantVersion {
				t.Fatalf("version = %d, want %d", norm.ConfigLayerVersion, tc.wantVersion)
			}
			if !reflect.DeepEqual(norm.HookDisabledTools, tc.wantHooks) {
				t.Fatalf("hook_disabled_tools = %#v, want %#v", norm.HookDisabledTools, tc.wantHooks)
			}
			if !reflect.DeepEqual(norm.ConfigLayerRisks, tc.wantLayers) {
				t.Fatalf("config_layer_risks = %#v, want %#v", norm.ConfigLayerRisks, tc.wantLayers)
			}
			has := map[string]bool{}
			for _, l := range norm.CaptureRisks {
				has[l] = true
			}
			if has[orgcontract.CaptureRiskHookSwitchedOff] != (len(tc.wantHooks) > 0) {
				t.Fatalf("capture risks = %v, want hook_switched_off exactly when a tool's hooks are off", norm.CaptureRisks)
			}
			if has[orgcontract.CaptureRiskConfigLayerOverride] != (len(tc.wantLayers) > 0) {
				t.Fatalf("capture risks = %v, want config_layer_override exactly when a layer finding crossed", norm.CaptureRisks)
			}
			wantHealth := orgcontract.ManagedHealthOK
			switch {
			case len(tc.wantHooks) > 0 || len(tc.wantLayers) > 0:
				wantHealth = orgcontract.ManagedHealthAtRisk
			case tc.wantVersion == 0:
				wantHealth = orgcontract.ManagedHealthNotReported
			}
			if got := norm.OverallHealth().Health; got != wantHealth {
				t.Fatalf("overall health = %s, want %s", got, wantHealth)
			}
			wire, err := json.Marshal(norm)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"/work/repo", "settings.json", "ANTHROPIC_BASE_URL"} {
				if strings.Contains(string(wire), forbidden) {
					t.Fatalf("the wire carries %q: %s", forbidden, wire)
				}
			}
		})
	}
}

// TestStoreConfigLayerSourceReadsTheHost runs the production source over a
// fixture home: a Gemini CLI user setting that turns hooks off and a
// project-local Claude Code settings file that outranks Observer's route
// (the CC-4 fixture shape) both reach the report, as tool ids and a
// "tool/finding" label only.
func TestStoreConfigLayerSourceReadsTheHost(t *testing.T) {
	home := pinToolHomes(t)
	project := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, ".gemini", "settings.json"), `{"hooksConfig":{"enabled":false}}`)
	write(filepath.Join(home, ".claude", "settings.json"), `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`)
	write(filepath.Join(project, ".claude", "settings.local.json"), `{"env":{"ANTHROPIC_BASE_URL":"https://api.anthropic.com"}}`)

	if storeConfigLayerSource(nil, home) != nil {
		t.Fatal("a nil store must give no source (not reported)")
	}
	report := orgcontract.ManagedIntegrityReport{CaptureCheckVersion: orgcontract.ManagedCaptureCheckVersion}
	lister := &fakeRootLister{roots: []string{project}}
	// No system or managed file and no launch environment of the host
	// running the test: GOOS "" skips the managed hook-off rows, SystemRoot
	// re-roots the evaluator's system paths, and the environment is empty.
	host := configLayerHost{Home: home, Getenv: func(string) string { return "" }, SystemRoot: filepath.Join(home, "no-system")}
	addConfigLayers(context.Background(), newConfigLayerSource(lister, host), &report)
	if lister.calls != 1 {
		t.Fatalf("project roots listed %d times, want once (bounded by hookdisable.MaxProjectRoots)", lister.calls)
	}
	norm := report.NormalizeLabels()
	if norm.ConfigLayerVersion != orgcontract.ManagedConfigLayerVersion {
		t.Fatalf("version = %d, want %d", norm.ConfigLayerVersion, orgcontract.ManagedConfigLayerVersion)
	}
	if !contains(norm.HookDisabledTools, "gemini-cli") {
		t.Fatalf("hook_disabled_tools = %v, want gemini-cli", norm.HookDisabledTools)
	}
	if !contains(norm.ConfigLayerRisks, "claude-code/project_route_override") {
		t.Fatalf("config_layer_risks = %v, want claude-code/project_route_override", norm.ConfigLayerRisks)
	}
	wire, err := json.Marshal(norm)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{home, project, filepath.ToSlash(project), "settings.local.json", "api.anthropic.com", "hooksConfig"} {
		if strings.Contains(string(wire), forbidden) {
			t.Fatalf("the wire carries %q: %s", forbidden, wire)
		}
	}
}

// TestCollectIntegritySignalsInactiveProvider pins item 3 of DEC-7: a Crush
// route that is in crush.json while the large model uses another provider is
// reported as inactive_provider_tools with its derived label, and is not
// drift. On the old code the probe never applied the active-provider pass.
func TestCollectIntegritySignalsInactiveProvider(t *testing.T) {
	home := pinToolHomes(t)
	db := filepath.Join(home, ".observer", "observer.db")
	if err := os.MkdirAll(filepath.Dir(db), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	crush := filepath.Join(home, ".config", "crush", "crush.json")
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		crush = filepath.Join(v, "crush", "crush.json")
	}
	if err := os.MkdirAll(filepath.Dir(crush), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crush, []byte(`{"providers":{"openai":{"base_url":"http://127.0.0.1:8820/v1"}},"models":{"large":{"provider":"anthropic"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	homes := []crossmount.HomeRoot{{Path: home, OS: "linux", Origin: "native"}}
	report := collectIntegritySignalsFrom(db, home, "/current/observer", homes, maintainedRoutes)
	if !reflect.DeepEqual(report.InactiveProviderTools, []string{"crush"}) {
		t.Fatalf("inactive_provider_tools = %v, want [crush]", report.InactiveProviderTools)
	}
	if contains(report.DriftedTools, "crush") {
		t.Fatalf("an inactive provider read as drift: %v", report.DriftedTools)
	}
	norm := report.NormalizeLabels()
	if !contains(norm.CaptureRisks, orgcontract.CaptureRiskRouteInactiveProvider) {
		t.Fatalf("capture risks = %v, want route_inactive_provider", norm.CaptureRisks)
	}
	// With route maintenance off the same host reports nothing.
	off := collectIntegritySignalsFrom(db, home, "/current/observer", homes, proxyroute.DriftPolicy{Mode: proxyroute.DriftModeOff})
	if len(off.InactiveProviderTools) != 0 {
		t.Fatalf("maintenance off reported %v", off.InactiveProviderTools)
	}
}

// TestManagedIntegrityConfigLayersFollowThePinnedHomeRule (FU-140 audit
// follow-up 1): the production source reads the relocation variables
// through crossmount.HomeEnv, so under an isolated daemon (HOME=/tmp/x
// observer start with CLAUDE_CONFIG_DIR exported) it judges the files under
// HOME, the ones the settings editor and the hook registration use, not the
// variable's directory. Before, it injected os.Getenv and judged
// $CLAUDE_CONFIG_DIR/settings.json. The control shows the variable is live
// in this path when the home is not isolated.
func TestManagedIntegrityConfigLayersFollowThePinnedHomeRule(t *testing.T) {
	for _, isolate := range []bool{true, false} {
		name := "isolated: the variable is not read"
		if !isolate {
			name = "control: unisolated, the variable is read"
		}
		t.Run(name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "home")
			outside := filepath.Join(t.TempDir(), "outside")
			for _, d := range []string{filepath.Join(home, ".claude"), outside} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(outside, "settings.json"), []byte(`{"disableAllHooks": true}`+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("CLAUDE_CONFIG_DIR", outside)
			if isolate {
				r188Isolate(t)
			}
			report := orgcontract.ManagedIntegrityReport{CaptureCheckVersion: orgcontract.ManagedCaptureCheckVersion}
			addConfigLayers(context.Background(), storeConfigLayerSource(&fakeRootLister{}, home), &report)
			norm := report.NormalizeLabels()
			got := contains(norm.HookDisabledTools, "claude-code")
			for _, r := range norm.ConfigLayerRisks {
				got = got || strings.HasPrefix(r, "claude-code/")
			}
			if got == isolate {
				t.Fatalf("isolate=%v: claude-code reported from $CLAUDE_CONFIG_DIR = %v (hooks %v, risks %v)",
					isolate, got, norm.HookDisabledTools, norm.ConfigLayerRisks)
			}
		})
	}
}
