package diag

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckCodexProviderRoute pins codex.proxy_route (backlog item 14): a
// selected provider that bypasses the proxy (amazon-bedrock) WARNs instead
// of reading as proxy-exact, a bypassing profile is named, and a managed
// [application.network] policy WARNs that the plain-http loopback route is
// expected to be denied.
func TestCheckCodexProviderRoute(t *testing.T) {
	const routed = "model_provider = \"openai-observer\"\n[model_providers.openai-observer]\nname = \"x\"\nbase_url = \"http://127.0.0.1:8820/v1\"\n"
	cases := []struct {
		name         string
		config       string // "" = no config.toml
		overlays     map[string]string
		requirements string // "" = no requirements file
		system       string // "" = no system config.toml beside the requirements file
		wantStatus   Status
		wantMsg      string
		wantDetail   string
	}{
		{name: "not set up", wantStatus: StatusOK, wantMsg: "not set up"},
		{name: "routed", config: routed, wantStatus: StatusOK, wantMsg: "proxy-exact"},
		{name: "default openai unrouted", config: "model = \"gpt-6\"\n", wantStatus: StatusOK, wantMsg: "no durable route"},
		{
			name:       "bedrock bypass",
			config:     "model_provider = \"amazon-bedrock\"\n[model_providers.amazon-bedrock.aws]\nprofile = \"dev\"\nregion = \"us-east-1\"\n",
			wantStatus: StatusWarn, wantMsg: "Amazon Bedrock", wantDetail: "observer init --codex",
		},
		{
			name:       "legacy profile selects bedrock",
			config:     routed + "[profiles.aws]\nmodel_provider = \"amazon-bedrock\"\n",
			wantStatus: StatusOK, wantMsg: "proxy-exact", wantDetail: `profile "aws" selects model_provider="amazon-bedrock"`,
		},
		{
			name:       "overlay profile selects bedrock",
			config:     routed,
			overlays:   map[string]string{"work.config.toml": "model_provider = \"amazon-bedrock\"\n"},
			wantStatus: StatusOK, wantMsg: "proxy-exact", wantDetail: `profile "work" selects`,
		},
		{
			name:         "application network policy denies loopback http",
			config:       routed,
			requirements: "[application.network]\n[application.network.domains]\n\"api.openai.com\" = \"allow\"\n",
			wantStatus:   StatusWarn, wantMsg: "expected to deny", wantDetail: "[application.network]",
		},
		{
			name:         "requirements force bedrock over the observer route",
			config:       routed,
			requirements: "model_provider = \"amazon-bedrock\"\n",
			wantStatus:   StatusWarn, wantMsg: "forced by managed requirements", wantDetail: `force model_provider="amazon-bedrock"`,
		},
		{
			name:         "requirements force the builtin openai over openai-observer",
			config:       routed,
			requirements: "model_provider = \"openai\"\n",
			wantStatus:   StatusWarn, wantMsg: `over config.toml's model_provider="openai-observer"`, wantDetail: `force model_provider="openai"`,
		},
		{
			name:         "requirements force builtin openai while openai_base_url routes",
			config:       "openai_base_url = \"http://127.0.0.1:8820/v1\"\n",
			requirements: "model_provider = \"openai\"\n",
			wantStatus:   StatusOK, wantMsg: "proxy-exact", wantDetail: `force model_provider="openai"`,
		},
		{
			name:         "required provider definition replaces the configured base_url",
			config:       routed,
			requirements: "model_provider = \"openai-observer\"\n[model_providers.openai-observer]\nname = \"corp\"\nbase_url = \"https://llm.corp.example/v1\"\n",
			wantStatus:   StatusWarn, wantMsg: "not the observer proxy", wantDetail: "admin-enforced",
		},
		{
			name:         "required provider that routes to the proxy",
			config:       "model = \"gpt-6\"\n",
			requirements: "model_provider = \"corp\"\n[model_providers.corp]\nname = \"corp\"\nbase_url = \"http://127.0.0.1:8820/v1\"\n",
			wantStatus:   StatusOK, wantMsg: "proxy-exact", wantDetail: "MDM",
		},
		{
			name:       "system config.toml selects bedrock under an unset user provider",
			config:     "model = \"gpt-6\"\n",
			system:     "model_provider = \"amazon-bedrock\"\n",
			wantStatus: StatusWarn, wantMsg: "Amazon Bedrock", wantDetail: "observer init --codex",
		},
		{
			name:       "user provider wins over the system config.toml",
			config:     routed,
			system:     "model_provider = \"amazon-bedrock\"\n",
			wantStatus: StatusOK, wantMsg: "proxy-exact",
		},
		{
			name:         "application network policy disabled",
			config:       routed,
			requirements: "[application.network]\nenabled = false\n",
			wantStatus:   StatusOK, wantMsg: "proxy-exact",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			codexHome := filepath.Join(home, ".codex")
			if tc.config != "" {
				if err := os.MkdirAll(codexHome, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), []byte(tc.config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for name, body := range tc.overlays {
				if err := os.WriteFile(filepath.Join(codexHome, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			reqPath := filepath.Join(home, "requirements.toml")
			if tc.requirements != "" {
				if err := os.WriteFile(reqPath, []byte(tc.requirements), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.system != "" {
				if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(tc.system), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			c := checkCodexProviderRoute(home, reqPath)
			if c.Name != codexRouteCheckName {
				t.Errorf("Name = %q", c.Name)
			}
			if c.Status != tc.wantStatus {
				t.Errorf("Status = %v, want %v (%s; %v)", c.Status, tc.wantStatus, c.Message, c.Details)
			}
			if !strings.Contains(c.Message, tc.wantMsg) {
				t.Errorf("Message = %q, want it to contain %q", c.Message, tc.wantMsg)
			}
			if tc.wantDetail != "" && !strings.Contains(strings.Join(c.Details, "\n"), tc.wantDetail) {
				t.Errorf("Details = %v, want one containing %q", c.Details, tc.wantDetail)
			}
		})
	}
}
