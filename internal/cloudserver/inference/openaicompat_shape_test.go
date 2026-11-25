package inference

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/llmwire"
)

// TestOpenAICompatibleRequestShape pins the shared request shape on this
// lane: a GPT-5 deployment gets max_completion_tokens and its family's
// reasoning effort with the route's cap left as reserved; gpt-oss-20b (the
// shipped route) keeps max_tokens. No shape sends a temperature here.
func TestOpenAICompatibleRequestShape(t *testing.T) {
	for _, tc := range []struct {
		deployment, param, effort string
	}{
		{"gpt-5-nano", llmwire.ParamMaxCompletionTokens, "minimal"},
		{"o4-mini", llmwire.ParamMaxCompletionTokens, "low"},
		{"gpt-oss-20b", llmwire.ParamMaxTokens, ""},
	} {
		r := openAICompatibleRequestFor(Request{Deployment: tc.deployment, User: "u", MaxOutputTokens: 100})
		if r.MaxTokensParam != tc.param || r.ReasoningEffort != tc.effort || r.MaxTokens != 100 || r.Temperature != nil {
			t.Errorf("%s: param %q effort %q cap %d temp %v; want %q %q 100 nil",
				tc.deployment, r.MaxTokensParam, r.ReasoningEffort, r.MaxTokens, r.Temperature, tc.param, tc.effort)
		}
	}
}
