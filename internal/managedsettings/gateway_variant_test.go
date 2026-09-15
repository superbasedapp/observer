package managedsettings

import (
	"strings"
	"testing"
)

// TestManagedSettingsGatewayVariants pins Luna L19's "zero tool
// re-registration" guarantee: moving a Claude Code or Codex fleet from the
// node-proxy deployment (traffic through a local Observer proxy on :8820) to
// Gateway-Mode thin mode (traffic direct to the org's AI Gateway) is a PURE
// base-URL swap. Every other tool-facing artifact — the MCP server pin, the
// telemetry env keys, Codex's [features]/hooks block — must be
// byte-identical between the two variants; an agent already registered
// against one variant needs no re-registration to move to the other, only
// the base-URL value changes.
func TestManagedSettingsGatewayVariants(t *testing.T) {
	const thinModeGatewayHost = "https://gw.acme.example:8840"

	t.Run("claude-code", func(t *testing.T) {
		variants := []struct {
			name    string
			baseURL string
			want    string
		}{
			{
				name:    "node-proxy",
				baseURL: DefaultClaudeCodeProxyBaseURL,
				want:    `"ANTHROPIC_BASE_URL": "http://127.0.0.1:8820"`,
			},
			{
				name:    "thin-mode",
				baseURL: thinModeGatewayHost,
				want:    `"ANTHROPIC_BASE_URL": "https://gw.acme.example:8840"`,
			},
		}

		var settingsJSONs, mcpJSONs [2]string
		for i, v := range variants {
			arts, err := GenerateClaudeCode(ClaudeCodeOptions{
				AnthropicBaseURL: v.baseURL,
				IncludeMCP:       true,
			})
			if err != nil {
				t.Fatalf("%s: GenerateClaudeCode: %v", v.name, err)
			}
			if !strings.Contains(string(arts.ManagedSettingsJSON), v.want) {
				t.Errorf("%s: managed-settings.json missing %q:\n%s", v.name, v.want, arts.ManagedSettingsJSON)
			}
			// Normalize the base URL out so the remaining diff isolates
			// everything ELSE in the artifact.
			settingsJSONs[i] = strings.ReplaceAll(string(arts.ManagedSettingsJSON), v.baseURL, "BASEURL")
			mcpJSONs[i] = string(arts.ManagedMCPJSON)
		}
		if settingsJSONs[0] != settingsJSONs[1] {
			t.Errorf("zero-re-registration violated: managed-settings.json differs beyond the base URL\nnode-proxy:\n%s\nthin-mode:\n%s",
				settingsJSONs[0], settingsJSONs[1])
		}
		if mcpJSONs[0] != mcpJSONs[1] {
			t.Errorf("zero-re-registration violated: managed-mcp.json differs between variants\nnode-proxy:\n%s\nthin-mode:\n%s",
				mcpJSONs[0], mcpJSONs[1])
		}
	})

	t.Run("codex", func(t *testing.T) {
		variants := []struct {
			name    string
			baseURL string
			want    string
		}{
			{
				name:    "node-proxy",
				baseURL: DefaultCodexProxyBaseURL,
				want:    `openai_base_url = "http://127.0.0.1:8820/v1"`,
			},
			{
				name:    "thin-mode",
				baseURL: thinModeGatewayHost + "/v1",
				want:    `openai_base_url = "https://gw.acme.example:8840/v1"`,
			},
		}

		var configTOMLs, mcpBlocks [2]string
		for i, v := range variants {
			arts, err := GenerateCodex(CodexOptions{
				OpenAIBaseURL:     v.baseURL,
				IncludeMCP:        true,
				IncludeProxyRoute: true,
			})
			if err != nil {
				t.Fatalf("%s: GenerateCodex: %v", v.name, err)
			}
			mc := string(arts.ManagedConfigTOML)
			if !strings.Contains(mc, v.want) {
				t.Errorf("%s: managed_config.toml missing %q:\n%s", v.name, v.want, mc)
			}
			if !strings.Contains(mc, "[features]") || !strings.Contains(mc, "hooks = true") {
				t.Errorf("%s: managed_config.toml missing the hooks default:\n%s", v.name, mc)
			}
			configTOMLs[i] = strings.ReplaceAll(mc, v.baseURL, "BASEURL")
			mcpStart := strings.Index(mc, "[mcp_servers.")
			if mcpStart < 0 {
				t.Fatalf("%s: managed_config.toml missing the [mcp_servers.*] block:\n%s", v.name, mc)
			}
			mcpBlocks[i] = mc[mcpStart:]
		}
		if configTOMLs[0] != configTOMLs[1] {
			t.Errorf("zero-re-registration violated: managed_config.toml differs beyond the base URL\nnode-proxy:\n%s\nthin-mode:\n%s",
				configTOMLs[0], configTOMLs[1])
		}
		if mcpBlocks[0] != mcpBlocks[1] {
			t.Errorf("zero-re-registration violated: [mcp_servers.*] block differs between variants\nnode-proxy:\n%s\nthin-mode:\n%s",
				mcpBlocks[0], mcpBlocks[1])
		}
	})
}
