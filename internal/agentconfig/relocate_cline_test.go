package agentconfig

import "testing"

// TestClineRelocations pins the Cline home rules (S-6) on every OS: the
// file's own variable wins, then CLINE_DATA_DIR, then CLINE_DIR. One row per
// rule and artifact; red before the rules existed (every row resolved to
// ~/.cline/...). A relative value is what Cline uses against its own
// working directory, so it stops the walk with no path (FU-31).
func TestClineRelocations(t *testing.T) {
	for _, fx := range relocFixtures {
		j := envOf(fx, nil).Join
		cases := []struct {
			name, id string
			env      map[string]string
			want     string
			by       string
		}{
			{"mcp default", "cline-cli/mcp-settings", nil, j(fx.home, ".cline", "data", "settings", "cline_mcp_settings.json"), ""},
			{"mcp file variable wins", "cline-cli/mcp-settings", map[string]string{"CLINE_MCP_SETTINGS_PATH": fx.absFile, "CLINE_DATA_DIR": fx.abs, "CLINE_DIR": fx.abs}, envOf(fx, nil).native(fx.absFile), "CLINE_MCP_SETTINGS_PATH"},
			{"mcp data dir beats the home", "cline-cli/mcp-settings", map[string]string{"CLINE_DATA_DIR": fx.abs, "CLINE_DIR": fx.absV2}, j(fx.abs, "settings", "cline_mcp_settings.json"), "CLINE_DATA_DIR"},
			{"mcp home", "cline-cli/mcp-settings", map[string]string{"CLINE_DIR": fx.abs}, j(fx.abs, "data", "settings", "cline_mcp_settings.json"), "CLINE_DIR"},
			{"mcp relative file variable refused", "cline-cli/mcp-settings", map[string]string{"CLINE_MCP_SETTINGS_PATH": "rel/mcp.json", "CLINE_DIR": fx.abs}, "", "CLINE_MCP_SETTINGS_PATH"},
			{"extension mcp row follows the same rules", "cline/mcp-settings", map[string]string{"CLINE_DATA_DIR": fx.abs}, j(fx.abs, "settings", "cline_mcp_settings.json"), "CLINE_DATA_DIR"},
			{"extension mcp row default", "cline/mcp-settings", nil, j(fx.home, ".cline", "data", "settings", "cline_mcp_settings.json"), ""},
			{"providers file variable", "cline-cli/providers", map[string]string{"CLINE_PROVIDER_SETTINGS_PATH": fx.absFile}, envOf(fx, nil).native(fx.absFile), "CLINE_PROVIDER_SETTINGS_PATH"},
			{"providers data dir", "cline-cli/providers", map[string]string{"CLINE_DATA_DIR": fx.abs}, j(fx.abs, "settings", "providers.json"), "CLINE_DATA_DIR"},
			{"providers home", "cline-cli/providers", map[string]string{"CLINE_DIR": fx.abs}, j(fx.abs, "data", "settings", "providers.json"), "CLINE_DIR"},
			{"global settings file variable", "cline-cli/global-settings", map[string]string{"CLINE_GLOBAL_SETTINGS_PATH": fx.absFile}, envOf(fx, nil).native(fx.absFile), "CLINE_GLOBAL_SETTINGS_PATH"},
			{"global state default", "cline/global-state", nil, j(fx.home, ".cline", "data", "globalState.json"), ""},
			{"global state data dir", "cline/global-state", map[string]string{"CLINE_DATA_DIR": fx.abs, "CLINE_DIR": fx.absV2}, j(fx.abs, "globalState.json"), "CLINE_DATA_DIR"},
			{"global state home", "cline/global-state", map[string]string{"CLINE_DIR": fx.abs}, j(fx.abs, "data", "globalState.json"), "CLINE_DIR"},
			{"global state ignores the MCP file variable", "cline/global-state", map[string]string{"CLINE_MCP_SETTINGS_PATH": fx.absFile}, j(fx.home, ".cline", "data", "globalState.json"), ""},
		}
		for _, tc := range cases {
			got, err := ResolveArtifact(tc.id, envOf(fx, tc.env))
			if err != nil {
				t.Fatalf("%s/%s: %v", fx.goos, tc.name, err)
			}
			if got.Path != tc.want || got.RelocatedBy != tc.by {
				t.Errorf("%s/%s: got (%q, by %q), want (%q, by %q)", fx.goos, tc.name, got.Path, got.RelocatedBy, tc.want, tc.by)
			}
		}
	}
}
