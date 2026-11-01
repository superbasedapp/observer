package diag

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// TestLayerAdviceCoversEveryCode keeps the doctor wording table in step
// with the evaluator's closed finding codes.
func TestLayerAdviceCoversEveryCode(t *testing.T) {
	codes := []agentconfig.FindingCode{
		agentconfig.FindingProjectRouteOverride, agentconfig.FindingRouteShadowed, agentconfig.FindingIDERouteOverride,
		agentconfig.FindingProjectHooksDisabled, agentconfig.FindingHooksDisabled, agentconfig.FindingHooksOffOverridden,
		agentconfig.FindingHookArrayReplaced, agentconfig.FindingLayersDropped, agentconfig.FindingMCPFirstFileOnly,
		agentconfig.FindingAuthPinsVendorHost, agentconfig.FindingInactiveProvider, agentconfig.FindingProviderUnverified,
		agentconfig.FindingUserPolicyOverride,
	}
	for _, c := range codes {
		if layerAdvice[c].advice == "" {
			t.Errorf("%s: no doctor advice", c)
		}
	}
	if len(layerAdvice) != len(codes) {
		t.Errorf("layerAdvice has %d rows for %d codes", len(layerAdvice), len(codes))
	}
}

// TestCheckConfigLayers pins the doctor row (OBS-9, CC-4): a clean home is
// OK, the settings.local.json override in a recent project warns and names
// the file, never the value; an informational note alone stays OK.
func TestCheckConfigLayers(t *testing.T) {
	write := func(t *testing.T, root, rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name     string
		home     map[string]string
		project  map[string]string
		want     Status
		contains string
		env      map[string]string
	}{
		{"clean", nil, nil, StatusOK, "no config layer decides against Observer", nil},
		{
			"DoctorOptions.Getenv: the launch environment shadows the settings route",
			map[string]string{".claude/settings.json": `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`},
			nil, StatusWarn, "route_shadowed",
			map[string]string{"ANTHROPIC_BASE_URL": "https://api.anthropic.com"},
		},
		{
			"CC-4: a project settings.local.json routes to the vendor",
			map[string]string{".claude/settings.json": `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`},
			map[string]string{".claude/settings.local.json": `{"env":{"ANTHROPIC_BASE_URL":"https://api.anthropic.com"}}`},
			StatusWarn, "project_route_override", nil,
		},
		{
			"CLI-5/FU-38: Factory's project-local file wins over the project file",
			nil,
			map[string]string{".factory/settings.json": `{"hooksDisabled":false}`, ".factory/settings.local.json": `{"hooksDisabled":true}`},
			StatusWarn, "project_hooks_disabled", nil,
		},
		{
			"S-22: a first-file-wins MCP search is a note, not a warning",
			map[string]string{".stakpak/mcp.json": `{"mcpServers":{}}`},
			map[string]string{"mcp.toml": "[mcp_servers]\n"},
			StatusOK, "mcp_first_file_only", nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, proj := t.TempDir(), t.TempDir()
			for rel, b := range tc.home {
				write(t, home, rel, b)
			}
			for rel, b := range tc.project {
				write(t, proj, rel, b)
			}
			c := checkConfigLayers(context.Background(), home, home, []string{proj}, func(k string) string { return tc.env[k] })
			if c.Name != "config.layers" || c.Status != tc.want {
				t.Fatalf("check = %s %s: %s %v", c.Name, c.Status, c.Message, c.Details)
			}
			all := c.Message + strings.Join(c.Details, "\n")
			if !strings.Contains(all, tc.contains) {
				t.Fatalf("check does not mention %q: %s %v", tc.contains, c.Message, c.Details)
			}
			if strings.Contains(all, "api.anthropic.com") {
				t.Fatalf("the doctor row carries a value: %v", c.Details)
			}
		})
	}
}
