package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDecideCodexMisconfig pins the ordered effective-route table, one case
// per row (backlog item 14 follow-up 4).
func TestDecideCodexMisconfig(t *testing.T) {
	route := func(openai, provider, providerURL string) codexEffectiveRoute {
		return codexEffectiveRoute{openaiURL: openai, provider: provider, providerURL: providerURL}
	}
	cases := []struct {
		name  string
		facts codexRouteFacts
		want  codexMisconfigVerdict
		rule  string
	}{
		{"file missing", codexRouteFacts{fileMissing: true}, verdictMissingFile, "file_missing"},
		{"unreadable", codexRouteFacts{unreadable: true}, verdictSkip, "unreadable"},
		{"init provider shape routes to proxy", codexRouteFacts{eff: route("", "openai-observer", "http://127.0.0.1:8820/v1")}, verdictClean, "provider_routes_to_proxy"},
		{"custom provider on localhost spelling still clean", codexRouteFacts{eff: route("", "mine", "http://localhost:8820")}, verdictClean, "provider_routes_to_proxy"},
		{"custom provider on a stale observer port", codexRouteFacts{eff: route("", "openai-observer", "http://127.0.0.1:18820/v1")}, verdictProviderMismatch, "provider_other_observer"},
		{"bedrock is a bypass, not a misconfig", codexRouteFacts{eff: route("", "amazon-bedrock", "")}, verdictSkip, "provider_bypass"},
		{"third-party provider host is a bypass", codexRouteFacts{eff: route("", "azure", "https://x.openai.azure.com/v1")}, verdictSkip, "provider_bypass"},
		{"builtin openai routed", codexRouteFacts{eff: route("http://127.0.0.1:8820/v1", "", "")}, verdictClean, "openai_routes_to_proxy"},
		{"explicit openai provider routed", codexRouteFacts{eff: route("http://127.0.0.1:8820", "openai", "")}, verdictClean, "openai_routes_to_proxy"},
		{"builtin openai no key", codexRouteFacts{eff: route("", "", "")}, verdictMissingKey, "openai_missing_key"},
		{"builtin openai elsewhere", codexRouteFacts{eff: route("https://api.openai.com/v1", "", "")}, verdictOpenAIMismatch, "openai_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.facts.proxyURL = testProxyURL
			got, rule := decideCodexMisconfig(tc.facts)
			if got != tc.want || rule != tc.rule {
				t.Fatalf("decideCodexMisconfig = (%d, %q), want (%d, %q)", got, rule, tc.want, tc.rule)
			}
		})
	}
}

// TestFindCodexConfigMisconfigs_EffectiveRoute drives real config files
// through the scan: the `observer init` provider shape is no longer a false
// "no openai_base_url" warning, a profile overlay's wrong openai_base_url is
// attributed to the PROFILE file, and a stale provider route is reported
// but never "fixed" by --write-config.
func TestFindCodexConfigMisconfigs_EffectiveRoute(t *testing.T) {
	writeProfile := func(t *testing.T, home, name, body string) string {
		t.Helper()
		p := filepath.Join(home, name+".config.toml")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("init provider shape is clean", func(t *testing.T) {
		f := newConfigCheckFixture(t)
		f.writeConfigTOML("model_provider = \"openai-observer\"\n\n[model_providers.openai-observer]\nname = \"OpenAI (via Observer)\"\nbase_url = \"http://127.0.0.1:8820/v1\"\nwire_api = \"responses\"\nrequires_openai_auth = true\n")
		if got := findCodexConfigMisconfigs([]string{f.codexHome}, testProxyURL, ""); len(got) != 0 {
			t.Fatalf("want no misconfig for the init provider shape, got %+v", got)
		}
	})

	t.Run("profile overlay mismatch names the profile file", func(t *testing.T) {
		f := newConfigCheckFixture(t)
		f.writeConfigTOML("openai_base_url = \"http://127.0.0.1:8820/v1\"\n")
		prof := writeProfile(t, f.codexHome, "work", "openai_base_url = \"https://api.openai.com/v1\"\n")
		if got := findCodexConfigMisconfigs([]string{f.codexHome}, testProxyURL, ""); len(got) != 0 {
			t.Fatalf("base alone routes: want clean, got %+v", got)
		}
		got := findCodexConfigMisconfigs([]string{f.codexHome}, testProxyURL, "work")
		if len(got) != 1 || got[0].ConfigPath != prof || got[0].Status != configTOMLOK || got[0].CurrentValue != "https://api.openai.com/v1" {
			t.Fatalf("want one openai mismatch on %s, got %+v", prof, got)
		}
	})

	t.Run("profile selecting a stale observer provider is reported, not written", func(t *testing.T) {
		f := newConfigCheckFixture(t)
		f.writeConfigTOML("openai_base_url = \"http://127.0.0.1:8820/v1\"\n\n[model_providers.old]\nbase_url = \"http://127.0.0.1:18820/v1\"\n")
		writeProfile(t, f.codexHome, "old", "model_provider = \"old\"\n")
		got := findCodexConfigMisconfigs([]string{f.codexHome}, testProxyURL, "old")
		if len(got) != 1 || got[0].Status != configTOMLProviderMismatch || got[0].Provider != "old" || got[0].CurrentValue != "http://127.0.0.1:18820/v1" {
			t.Fatalf("want one provider mismatch for %q, got %+v", "old", got)
		}
		if got[0].fixable() {
			t.Fatal("a provider-table mismatch must not be auto-fixable")
		}
		before, _ := os.ReadFile(filepath.Join(f.codexHome, "config.toml"))
		var stderr bytes.Buffer
		runWriteCodexConfig(&stderr, got)
		after, _ := os.ReadFile(filepath.Join(f.codexHome, "config.toml"))
		if !bytes.Equal(before, after) || stderr.Len() != 0 {
			t.Fatalf("--write-config touched a provider mismatch: stderr=%q", stderr.String())
		}
		warn := checkCodexConfigTOMLBaseURL([]string{f.codexHome}, testProxyURL, "old")
		for _, want := range []string{`model_provider="old"`, "http://127.0.0.1:18820/v1", "observer init --codex --force"} {
			if !strings.Contains(warn, want) {
				t.Errorf("warning missing %q: %s", want, warn)
			}
		}
	})

	t.Run("bedrock provider is left to the bypass notice", func(t *testing.T) {
		f := newConfigCheckFixture(t)
		f.writeConfigTOML("model_provider = \"amazon-bedrock\"\n")
		if got := findCodexConfigMisconfigs([]string{f.codexHome}, testProxyURL, ""); len(got) != 0 {
			t.Fatalf("bedrock: want no misconfig (bypass notice owns it), got %+v", got)
		}
	})
}
