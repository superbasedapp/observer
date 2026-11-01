package proxyroute

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyActiveProvider pins CLI-3: a RouteOurs row whose tool's active
// provider is not the routed one becomes RouteInactiveProvider; one case per
// activeProviderReaders row plus the rows the pass must leave alone. On the
// old code the row stayed "ours" (InspectRoutes has no provider read).
func TestApplyActiveProvider(t *testing.T) {
	cases := []struct {
		name, tool, file, body string
		want                   RouteState
	}{
		{
			"crush: models.large.provider is another provider", "crush", "crush.json",
			`{"providers":{"openai":{"base_url":"http://127.0.0.1:8820/v1","api_key":"x"}},"models":{"large":{"provider":"anthropic"}}}`, RouteInactiveProvider,
		},
		{
			"crush: the large model uses openai", "crush", "crush.json",
			`{"providers":{"openai":{"base_url":"http://127.0.0.1:8820/v1"}},"models":{"large":{"provider":"openai"}}}`, RouteOurs,
		},
		{
			"crush: no provider selected is left alone", "crush", "crush.json",
			`{"providers":{"openai":{"base_url":"http://127.0.0.1:8820/v1"}}}`, RouteOurs,
		},
		{
			"qwen-code: an auth type other than openai", "qwen-code", "settings.json",
			`{"model":{"baseUrl":"http://127.0.0.1:8820/v1"},"security":{"auth":{"selectedType":"gemini"}}}`, RouteInactiveProvider,
		},
		{
			"qwen-code: qwen-oauth is unverified, not inactive (live check 21)", "qwen-code", "settings.json",
			`{"model":{"baseUrl":"http://127.0.0.1:8820/v1"},"security":{"auth":{"selectedType":"qwen-oauth"}}}`, RouteOurs,
		},
		{
			"qwen-code: openai", "qwen-code", "settings.json",
			`{"security":{"auth":{"selectedType":"openai"}}}`, RouteOurs,
		},
		{
			"kimi-code: the active provider is not openai-typed", "kimi-code", "config.toml",
			"default_model = \"k2\"\n[models.k2]\nprovider = \"moonshot\"\n[providers.moonshot]\ntype = \"kimi\"\napi_key = \"x\"\n[providers.openai]\ntype = \"openai\"\nbase_url = \"http://127.0.0.1:8820/v1\"\n", RouteInactiveProvider,
		},
		{
			"kimi-code: the active provider is openai-typed", "kimi-code", "config.toml",
			"default_model = \"k2\"\n[models.k2]\nprovider = \"lane\"\n[providers.lane]\ntype = \"openai\"\nbase_url = \"http://127.0.0.1:8820/v1\"\n", RouteOurs,
		},
		{
			"kimi-code: no default model is left alone", "kimi-code", "config.toml",
			"[providers.openai]\ntype = \"openai\"\n", RouteOurs,
		},
		{"a tool with no reader is left alone", "claude-code", "settings.json", `{}`, RouteOurs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), tc.file)
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			in := []RouteStatus{{Tool: tc.tool, State: RouteOurs, ConfigPath: p}}
			got := ApplyActiveProvider(in)
			if got[0].State != tc.want {
				t.Fatalf("state = %s, want %s", got[0].State, tc.want)
			}
			if in[0].State != RouteOurs {
				t.Fatal("ApplyActiveProvider modified its input")
			}
		})
	}
	// Only RouteOurs rows are read.
	got := ApplyActiveProvider([]RouteStatus{{Tool: "crush", State: RouteDrifted, ConfigPath: filepath.Join(t.TempDir(), "missing")}})
	if got[0].State != RouteDrifted {
		t.Fatalf("a drifted row changed: %s", got[0].State)
	}
	inspected := map[string]bool{}
	for _, ri := range routeInspectors() {
		inspected[ri.tool] = true
	}
	for tool := range activeProviderReaders {
		if !inspected[tool] {
			t.Errorf("%s: activeProviderReaders row for a tool with no route inspector", tool)
		}
	}
}

// TestInactiveProviderToolsUnderEachMode pins DEC-7: an inactive provider is
// its own managed-integrity reading under each drift mode and is never drift.
// On the old code InactiveProviderTools did not exist and a row in this state
// fell through routeVerdictRules to drift.
func TestInactiveProviderToolsUnderEachMode(t *testing.T) {
	statuses := []RouteStatus{
		{Tool: "crush", State: RouteInactiveProvider, ArtifactPresent: true, OrgRouted: true, WasRouted: true},
		{Tool: "qwen-code", State: RouteInactiveProvider, ArtifactPresent: true},
		{Tool: "codex", State: RouteOurs, ArtifactPresent: true},
	}
	cases := []struct {
		name string
		p    DriftPolicy
		want []string
	}{
		{"maintained", DriftPolicy{Mode: DriftModeMaintained}, []string{"crush", "qwen-code"}},
		{"no posture: only the route the organization wrote", DriftPolicy{Mode: DriftModeOrgRoutes}, []string{"crush"}},
		{"maintenance off", DriftPolicy{Mode: DriftModeOff}, nil},
		{"routing switched off by policy", DriftPolicy{Mode: DriftModeMaintained, Selection: Selection{RoutingOff: true}}, nil},
		{"not selected by policy", DriftPolicy{Mode: DriftModeMaintained, Selection: Selection{Tool: func(tool string) bool { return tool != "crush" }}}, []string{"qwen-code"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := InactiveProviderTools(statuses, tc.p)
			if len(got) != len(tc.want) {
				t.Fatalf("InactiveProviderTools = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("InactiveProviderTools = %v, want %v", got, tc.want)
				}
			}
			if drift := DriftedTools(statuses, tc.p); len(drift) != 0 {
				t.Fatalf("an inactive provider read as drift: %v", drift)
			}
		})
	}
}
