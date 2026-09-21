package proxyroute

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// inspect_kinds_test.go — Track C item 2
// (docs/plans/org-guardrail-control-wave-2026-09-21.md): the inspection table
// dispatches on the integration registry's RouteKind, one test per kind and
// one per tenancy.

// TestInspectOneRowPerRouteKind exercises EVERY inspectable RouteKind end to
// end through a real config file: the writer's own key is read back and
// classified ours / drifted / absent.
func TestInspectOneRouteKind(t *testing.T) {
	cases := []struct {
		name string
		kind integration.RouteKind
		tool string
		// write lays down the tool's config in home carrying base.
		write func(t *testing.T, home, base string)
	}{
		{
			name: "env_settings (claude-code)", kind: integration.RouteEnvSettings, tool: "claude-code",
			write: func(t *testing.T, home, base string) {
				writeFile(t, filepath.Join(home, ".claude"), "settings.json",
					`{"env":{"ANTHROPIC_BASE_URL":"`+base+`"}}`)
			},
		},
		{
			name: "config_file (codex)", kind: integration.RouteConfigFile, tool: "codex",
			write: func(t *testing.T, home, base string) {
				writeFile(t, filepath.Join(home, ".codex"), "config.toml",
					"model_provider = \"observer\"\n[model_providers.observer]\nbase_url = \""+base+"\"\n")
			},
		},
		{
			name: "config_file (kimi-code)", kind: integration.RouteConfigFile, tool: "kimi-code",
			write: func(t *testing.T, home, base string) {
				writeFile(t, filepath.Join(home, ".kimi-code"), "config.toml",
					"[providers.openai]\nbase_url = \""+base+"\"\n")
			},
		},
		{
			name: "config_file (qwen-code)", kind: integration.RouteConfigFile, tool: "qwen-code",
			write: func(t *testing.T, home, base string) {
				writeFile(t, filepath.Join(home, ".qwen"), "settings.json",
					`{"model":{"baseUrl":"`+base+`"}}`)
			},
		},
		{
			name: "provider_json (crush)", kind: integration.RouteProviderJSON, tool: "crush",
			write: func(t *testing.T, home, base string) {
				writeFile(t, filepath.Join(home, ".config", "crush"), "crush.json",
					`{"providers":{"openai":{"base_url":"`+base+`"}}}`)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, sub := range []struct {
				base string
				want RouteState
			}{
				{"http://127.0.0.1:8820/v1", RouteOurs},
				{"https://api.openai.com/v1", RouteDrifted},
			} {
				home := t.TempDir()
				t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
				t.Setenv("CRUSH_CONFIG", "")
				t.Setenv("KIMI_CODE_HOME", "")
				t.Setenv("QWEN_HOME", "")
				tc.write(t, home, sub.base)
				got := statusFor(InspectRoutes(home), tc.tool)
				if got.State != sub.want {
					t.Fatalf("base %q: state = %q, want %q", sub.base, got.State, sub.want)
				}
				if got.Kind != tc.kind {
					t.Fatalf("Kind = %q, want %q", got.Kind, tc.kind)
				}
			}
			// Nothing written at all: Absent, never Drifted.
			home := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
			if got := statusFor(InspectRoutes(home), tc.tool); got.State != RouteAbsent {
				t.Fatalf("empty home: state = %q, want absent", got.State)
			}
		})
	}
}

func statusFor(statuses []RouteStatus, tool string) RouteStatus {
	for _, s := range statuses {
		if s.Tool == tool {
			return s
		}
	}
	return RouteStatus{}
}

// TestDriftedToolsPerTenancy is the tenancy half of item 2: an ABSENT route
// is drift only when the organization is authoritative over some enforcement
// point on this node; an individual node is byte-for-byte unchanged.
func TestDriftedToolsPerTenancy(t *testing.T) {
	statuses := []RouteStatus{
		{Tool: "claude-code", State: RouteOurs, ArtifactPresent: true},
		// codex: the config file IS on the host and its route key is gone —
		// the only absent shape that can be drift.
		{Tool: "codex", State: RouteAbsent, ArtifactPresent: true},
		// kimi-code: no config file at all (the developer does not use it).
		// Never drift, under any tenancy.
		{Tool: "kimi-code", State: RouteAbsent, ArtifactPresent: false},
		{Tool: "crush", State: RouteDrifted, ArtifactPresent: true},
		{Tool: "qwen-code", State: RouteOrgGateway, ArtifactPresent: true},
	}
	cases := []struct {
		name          string
		absentIsDrift bool
		want          []string
	}{
		{"individual node: absent is not drift", false, []string{"crush"}},
		{"managed + enforce: absent with the config present IS drift", true, []string{"codex", "crush"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DriftedTools(statuses, tc.absentIsDrift)
			if len(got) != len(tc.want) {
				t.Fatalf("DriftedTools = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("DriftedTools = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestEveryPersistedRouteKindIsInspectable holds the inspection table to the
// integration registry: every kind the registry actually uses must have an
// explicit inspectable/not-inspectable verdict, and every kind marked
// inspectable must have at least one row that implements it. A new RouteKind
// in the registry fails here rather than silently going un-inspected.
func TestEveryPersistedRouteKindIsInspectable(t *testing.T) {
	covered := map[integration.RouteKind]bool{}
	for _, ri := range routeInspectors() {
		covered[ri.kind] = true
	}
	used := map[integration.RouteKind]bool{}
	for _, c := range integration.Capabilities() {
		for _, r := range []*integration.ProxyRoute{c.Proxy, c.ProxyProbe} {
			if r != nil && r.Kind != "" {
				used[r.Kind] = true
			}
		}
	}
	for kind := range used {
		verdict, classified := routeKindInspectable[kind]
		if !classified {
			t.Errorf("registry RouteKind %q has no routeKindInspectable verdict — classify it (inspectable, or why not)", kind)
			continue
		}
		if verdict && !covered[kind] {
			t.Errorf("RouteKind %q is marked inspectable but no routeInspectors() row implements it", kind)
		}
	}
	for kind := range covered {
		if !routeKindInspectable[kind] {
			t.Errorf("routeInspectors() has a row for %q, which routeKindInspectable says is not inspectable", kind)
		}
	}
}

// TestInspectedToolsAreRegistryAdaptersWithAPersistedRoute pins that every
// inspected id is a real registry adapter declaring a persisted route — the
// label the org sees is the adapter id, not a proxyroute-local nickname.
func TestInspectedToolsAreRegistryAdapters(t *testing.T) {
	for _, tool := range InspectedTools() {
		row, ok := integration.For(tool)
		if !ok {
			t.Fatalf("inspected tool %q is not an integration registry adapter", tool)
		}
		persisted := false
		for _, r := range []*integration.ProxyRoute{row.Proxy, row.ProxyProbe} {
			if r != nil && routeKindInspectable[r.Kind] {
				persisted = true
			}
		}
		if !persisted {
			t.Fatalf("inspected tool %q declares no persisted route kind in the registry", tool)
		}
	}
}

// TestInspectedToolsAreValidWireLabels closes the loop on the managed-
// integrity wire: every id this package can report must be accepted by
// orgcontract's closed drifted_tools vocabulary, or the server would silently
// drop it in NormalizeLabels and the admin would see a route drift count with
// no tools behind it.
func TestInspectedToolsAreValidWireLabels(t *testing.T) {
	report := orgcontract.ManagedIntegrityReport{DriftedTools: InspectedTools()}
	got := report.NormalizeLabels().DriftedTools
	if len(got) != len(InspectedTools()) {
		t.Fatalf("NormalizeLabels dropped inspected tools: kept %v of %v", got, InspectedTools())
	}
}
