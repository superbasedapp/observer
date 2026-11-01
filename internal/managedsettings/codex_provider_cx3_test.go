package managedsettings

import (
	"errors"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// TestCodexObserverProviderNameMatchesWriter pins the managed provider id to
// the per-node writer's, so a node routed by `observer init` and a node bound
// by requirements.toml carry one provider.
func TestCodexObserverProviderNameMatchesWriter(t *testing.T) {
	if CodexObserverProviderName != proxyroute.ProviderName {
		t.Fatalf("CodexObserverProviderName = %q, proxyroute.ProviderName = %q", CodexObserverProviderName, proxyroute.ProviderName)
	}
}

// TestGenerateCodex_EnforceProxyProvider covers CX-3 (decision D3): the opt-in
// emits an enforced model_provider and a COMPLETE provider definition, and
// stays off by default.
func TestGenerateCodex_EnforceProxyProvider(t *testing.T) {
	const url = "http://127.0.0.1:8820/v1"
	cases := []struct {
		name    string
		opts    CodexOptions
		wantErr error
		enforce bool
	}{
		{name: "off by default", opts: CodexOptions{OpenAIBaseURL: url, IncludeProxyRoute: true}},
		{name: "opt-in", opts: CodexOptions{OpenAIBaseURL: url, IncludeProxyRoute: true, EnforceProxyProvider: true}, enforce: true},
		{
			name: "opt-in with managed hooks",
			opts: CodexOptions{
				OpenAIBaseURL: url, IncludeProxyRoute: true, EnforceProxyProvider: true,
				EnforceManagedHooksOnly: true, ManagedHooks: testCodexManagedHooks(),
			},
			enforce: true,
		},
		{name: "needs the proxy route", opts: CodexOptions{IncludeMCP: true, EnforceProxyProvider: true}, wantErr: ErrCodexEnforceProviderNeedsRoute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arts, err := GenerateCodex(tc.opts)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GenerateCodex: %v", err)
			}
			var rq struct {
				ModelProvider  string                    `toml:"model_provider"`
				ModelProviders map[string]map[string]any `toml:"model_providers"`
			}
			if _, err := toml.Decode(string(arts.RequirementsTOML), &rq); err != nil {
				t.Fatalf("requirements.toml: %v\n%s", err, arts.RequirementsTOML)
			}
			if !tc.enforce {
				if rq.ModelProvider != "" || len(rq.ModelProviders) != 0 {
					t.Fatalf("provider enforced without the opt-in:\n%s", arts.RequirementsTOML)
				}
				if strings.Contains(arts.Readme, "Enforced provider") {
					t.Error("README names an enforced provider without the opt-in")
				}
				return
			}
			if rq.ModelProvider != CodexObserverProviderName {
				t.Errorf("model_provider = %q, want %q", rq.ModelProvider, CodexObserverProviderName)
			}
			def := rq.ModelProviders[CodexObserverProviderName]
			// Complete: every key the per-node writer sets, because a
			// requirements entry replaces the configured provider whole and
			// Open Interpreter reads the same file.
			want := map[string]any{"name": codexObserverProviderDisplay, "base_url": url, "wire_api": "responses", "requires_openai_auth": true}
			for k, v := range want {
				if def[k] != v {
					t.Errorf("[model_providers.%s].%s = %v, want %v", CodexObserverProviderName, k, def[k], v)
				}
			}
			if len(def) != len(want) {
				t.Errorf("provider definition has keys %v, want exactly %v", def, want)
			}
			for _, s := range []string{"Open Interpreter", "not live-verified", "model_provider=openai"} {
				if !strings.Contains(strings.ToLower(arts.Readme), strings.ToLower(s)) {
					t.Errorf("README missing %q", s)
				}
			}
		})
	}
}
