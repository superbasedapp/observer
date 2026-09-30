package proxyroute

import "testing"

// TestClassifyCodexProvider walks the ordered posture table, one case per
// row plus the precedence edges.
func TestClassifyCodexProvider(t *testing.T) {
	const obs = "http://127.0.0.1:8820/v1"
	cases := []struct {
		name string
		in   CodexProviderInput
		want CodexPosture
	}{
		{"openai_via_observer (default provider)", CodexProviderInput{OpenAIBaseURL: obs}, CodexPostureProxy},
		{"openai_via_observer (explicit openai)", CodexProviderInput{Provider: "openai", OpenAIBaseURL: obs}, CodexPostureProxy},
		{"openai_elsewhere", CodexProviderInput{OpenAIBaseURL: "https://corp-gw.example.com/v1"}, CodexPostureDirect},
		{"openai_default", CodexProviderInput{}, CodexPostureUnrouted},
		{"provider_via_observer", CodexProviderInput{Provider: ProviderName, ProviderBaseURL: obs}, CodexPostureProxy},
		{"bedrock", CodexProviderInput{Provider: CodexBuiltinBedrock}, CodexPostureBedrock},
		{"bedrock ignores openai_base_url", CodexProviderInput{Provider: CodexBuiltinBedrock, OpenAIBaseURL: obs}, CodexPostureBedrock},
		{"provider_elsewhere", CodexProviderInput{Provider: "azure", ProviderBaseURL: "https://x.openai.azure.com/openai"}, CodexPostureDirect},
		{"provider_self_resolved", CodexProviderInput{Provider: "oss"}, CodexPostureSelfResolved},
		{"whitespace trimmed", CodexProviderInput{Provider: "  " + CodexBuiltinBedrock + " "}, CodexPostureBedrock},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyCodexProvider(tc.in); got != tc.want {
				t.Errorf("ClassifyCodexProvider(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCodexPostureBypasses pins which postures never reach the proxy and
// that each bypass carries an explanation.
func TestCodexPostureBypasses(t *testing.T) {
	for p, want := range map[CodexPosture]bool{
		CodexPostureProxy:        false,
		CodexPostureUnrouted:     false,
		CodexPostureBedrock:      true,
		CodexPostureDirect:       true,
		CodexPostureSelfResolved: true,
	} {
		if got := p.Bypasses(); got != want {
			t.Errorf("%s.Bypasses() = %v, want %v", p, got, want)
		}
		if msg := CodexBypassExplanation(p, "x"); (msg != "") != want {
			t.Errorf("CodexBypassExplanation(%s) = %q, want non-empty=%v", p, msg, want)
		}
	}
}
