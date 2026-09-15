package aigateway

import (
	"strings"
	"testing"
)

func TestExtractUsageAnthropicStream(t *testing.T) {
	// Cumulative counts across events; the tail carries the largest output.
	sse := `event: message_start
data: {"message":{"usage":{"input_tokens":1200,"cache_read_input_tokens":800,"output_tokens":1}}}

event: message_delta
data: {"usage":{"output_tokens":350}}

event: message_stop
data: {}
`
	u := ExtractUsage(KindAnthropic, []byte(sse))
	if u.InputTokens != 1200 || u.OutputTokens != 350 || u.CacheReadTokens != 800 {
		t.Errorf("anthropic usage = %+v", u)
	}
}

func TestExtractUsageOpenAIStream(t *testing.T) {
	sse := `data: {"choices":[{"delta":{"content":"hi"}}]}

data: {"usage":{"prompt_tokens":500,"completion_tokens":120,"total_tokens":620,"prompt_tokens_details":{"cached_tokens":64}}}

data: [DONE]
`
	u := ExtractUsage(KindOpenAICompatible, []byte(sse))
	if u.InputTokens != 500 || u.OutputTokens != 120 || u.CacheReadTokens != 64 {
		t.Errorf("openai usage = %+v", u)
	}
}

func TestParseRequestMeta(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		model  string
		maxTok int
		stream bool
	}{
		{"anthropic", `{"model":"claude-opus-4-8","max_tokens":4096,"stream":true}`, "claude-opus-4-8", 4096, true},
		{"openai completion", `{"model":"gpt-5.6","max_completion_tokens":2000}`, "gpt-5.6", 2000, false},
		{"responses", `{"model":"gpt-5.6","max_output_tokens":900,"stream":false}`, "gpt-5.6", 900, false},
		{"garbage", `not json`, "", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := ParseRequestMeta([]byte(tc.body))
			if m.Model != tc.model || m.MaxTokens != tc.maxTok || m.Stream != tc.stream {
				t.Errorf("ParseRequestMeta = %+v", m)
			}
		})
	}
}

func TestStampPseudonym(t *testing.T) {
	// Anthropic: metadata.user_id injected when absent.
	out := StampPseudonym(KindAnthropic, []byte(`{"model":"claude-opus-4-8"}`), "pseudo123")
	if !strings.Contains(string(out), `"user_id":"pseudo123"`) {
		t.Errorf("anthropic stamp missing: %s", out)
	}
	// Existing value not overwritten.
	out = StampPseudonym(KindAnthropic, []byte(`{"metadata":{"user_id":"real"}}`), "pseudo123")
	if strings.Contains(string(out), "pseudo123") {
		t.Errorf("stamp overwrote existing user_id: %s", out)
	}
	// OpenAI: safety_identifier injected.
	out = StampPseudonym(KindOpenAICompatible, []byte(`{"model":"gpt-5.6"}`), "pseudo123")
	if !strings.Contains(string(out), `"safety_identifier":"pseudo123"`) {
		t.Errorf("openai stamp missing: %s", out)
	}
	// Empty pseudonym is a no-op.
	in := []byte(`{"model":"x"}`)
	if string(StampPseudonym(KindOpenAICompatible, in, "")) != string(in) {
		t.Error("empty pseudonym must not modify body")
	}
	// Unparseable body returned unchanged.
	if string(StampPseudonym(KindAnthropic, []byte(`nope`), "p")) != "nope" {
		t.Error("unparseable body must be returned unchanged")
	}
}

func TestEstimateInputTokens(t *testing.T) {
	if EstimateInputTokens(0) != 1 || EstimateInputTokens(-5) != 1 {
		t.Error("floor of 1 for empty body")
	}
	if EstimateInputTokens(400) != 100 {
		t.Errorf("400 bytes ~= 100 tokens, got %d", EstimateInputTokens(400))
	}
}
