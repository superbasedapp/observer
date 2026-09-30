package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCodexProviderBypassNotice pins the launch notice (backlog item 14):
// the launcher's `-c openai_base_url` injection only reaches the built-in
// openai provider, so a selected amazon-bedrock provider (base or active
// profile overlay) must be named as a proxy bypass rather than implied
// proxy-exact; a routed or default-openai config stays silent.
func TestCodexProviderBypassNotice(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		overlay  string // work.config.toml
		profile  string
		wantNote string // "" = silent
	}{
		{name: "default openai silent", base: "model = \"gpt-6\"\n"},
		{name: "routed provider silent", base: "model_provider = \"openai-observer\"\n[model_providers.openai-observer]\nbase_url = \"http://127.0.0.1:8820/v1\"\n"},
		{name: "bedrock named", base: "model_provider = \"amazon-bedrock\"\n", wantNote: "Amazon Bedrock"},
		{name: "third-party provider named", base: "model_provider = \"corp\"\n[model_providers.corp]\nbase_url = \"https://llm.corp.example/v1\"\n", wantNote: `model_provider="corp"`},
		{name: "profile overlay selects bedrock", base: "model = \"gpt-6\"\n", overlay: "model_provider = \"amazon-bedrock\"\n", profile: "work", wantNote: "Amazon Bedrock"},
		{name: "overlay ignored without its profile", base: "model = \"gpt-6\"\n", overlay: "model_provider = \"amazon-bedrock\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte(tc.base), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.overlay != "" {
				if err := os.WriteFile(filepath.Join(root, "work.config.toml"), []byte(tc.overlay), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got := codexProviderBypassNotice([]string{root}, tc.profile)
			if tc.wantNote == "" {
				if got != "" {
					t.Errorf("notice = %q, want silent", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantNote) {
				t.Errorf("notice = %q, want it to contain %q", got, tc.wantNote)
			}
		})
	}
}
