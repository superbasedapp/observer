package proxyroute

import (
	"strings"
	"testing"
)

// TestCodexBuiltinProviderExplanations pins CX-9: every built-in codex
// provider without a configured base_url bypasses the proxy (the verdict was
// already right), and the explanation now says where its turns go. Before,
// amazon-bedrock-runtime read as a generic "resolves its own endpoint" and
// gcp / ollama / lmstudio named no destination.
func TestCodexBuiltinProviderExplanations(t *testing.T) {
	for _, tc := range []struct {
		provider string
		posture  CodexPosture
		want     string
	}{
		{CodexBuiltinBedrock, CodexPostureBedrock, `model_provider="amazon-bedrock" sends turns SigV4-signed straight to Amazon Bedrock`},
		{CodexBuiltinBedrockRuntime, CodexPostureBedrock, `model_provider="amazon-bedrock-runtime" sends turns SigV4-signed straight to Amazon Bedrock`},
		{CodexBuiltinGCP, CodexPostureSelfResolved, "Google Cloud Vertex AI"},
		{CodexBuiltinOllama, CodexPostureSelfResolved, "local Ollama provider, which sends turns to localhost:11434"},
		{CodexBuiltinLMStudio, CodexPostureSelfResolved, "local LM Studio provider, which sends turns to localhost:1234"},
		{"my-oss", CodexPostureSelfResolved, `model_provider="my-oss" resolves its own endpoint`},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			got := ClassifyCodexProvider(CodexProviderInput{Provider: tc.provider})
			if got != tc.posture || !got.Bypasses() {
				t.Fatalf("ClassifyCodexProvider(%s) = %q (bypasses=%v), want bypassing %q", tc.provider, got, got.Bypasses(), tc.posture)
			}
			msg := CodexBypassExplanation(got, tc.provider)
			if !strings.Contains(msg, tc.want) || !strings.Contains(msg, "not proxy-exact") {
				t.Errorf("CodexBypassExplanation(%s) = %q, want it to contain %q", tc.provider, msg, tc.want)
			}
		})
	}
	// A built-in provider pointed at the proxy still routes.
	if got := ClassifyCodexProvider(CodexProviderInput{Provider: CodexBuiltinGCP, ProviderBaseURL: "http://127.0.0.1:8820/v1"}); got != CodexPostureProxy {
		t.Errorf("gcp via observer = %q, want proxy", got)
	}
}
