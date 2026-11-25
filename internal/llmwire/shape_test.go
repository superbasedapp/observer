package llmwire

import (
	"encoding/json"
	"testing"
)

// TestResolveShape pins the model-family table: one row per model the lane
// brief names, plus the override and routing rows that change the shape.
func TestResolveShape(t *testing.T) {
	reasoning := func(effort string) Shape {
		return Shape{Profile: ProfileReasoning, MaxTokensParam: ParamMaxCompletionTokens, TemperatureOff: true, MinReplyTokens: ReasoningMinReplyTokens, ReasoningEffort: effort}
	}
	chat := Shape{Profile: ProfileChat, MaxTokensParam: ParamMaxTokens}
	cases := []struct {
		name, profile, effort, model string
		want                         Shape
	}{
		{"gpt-5", "", "", "gpt-5", reasoning("minimal")},
		{"gpt-5-mini", "auto", "", "gpt-5-mini", reasoning("minimal")},
		{"gpt-5-nano", "", "", "gpt-5-nano", reasoning("minimal")},
		{"gpt-5-nano dated", "", "", "gpt-5-nano-2025-08-07", reasoning("minimal")},
		{"gpt-5 mixed case", "", "", "  GPT-5-Nano ", reasoning("minimal")},
		{"gpt-5.1", "", "", "gpt-5.1", reasoning("low")},
		{"gpt-5-chat-latest is chat", "", "", "gpt-5-chat-latest", chat},
		{"o1-mini: no effort", "", "", "o1-mini", reasoning("")},
		{"o1-preview: no effort", "", "", "o1-preview", reasoning("")},
		{"o1", "", "", "o1", reasoning("low")},
		{"o3", "", "", "o3", reasoning("low")},
		{"o3-mini", "", "", "o3-mini", reasoning("low")},
		{"o4-mini", "", "", "o4-mini", reasoning("low")},
		{"gpt-4o-mini is chat", "", "", "gpt-4o-mini", chat},
		{"gpt-oss-20b is chat", "", "", "gpt-oss-20b", chat},
		{"unknown model is chat", "", "", "acme-large-v2", chat},
		{"empty model is chat", "", "", "", chat},
		{"routed id stays chat", "", "", "openai/gpt-5-nano", chat},
		{"explicit chat wins", "chat", "", "gpt-5-nano", chat},
		{"explicit reasoning, unknown deployment", "reasoning", "", "team-summariser", reasoning("")},
		{"explicit reasoning takes no family effort", "Reasoning", "", "gpt-5-nano", reasoning("")},
		{"effort override", "", "low", "gpt-5-nano", reasoning("low")},
		{"effort override ignored on chat", "chat", "high", "gpt-5-nano", chat},
		{"unknown profile is auto", "turbo", "", "o3", reasoning("low")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveShape(tc.profile, tc.effort, tc.model); got != tc.want {
				t.Errorf("ResolveShape(%q, %q, %q) = %+v, want %+v", tc.profile, tc.effort, tc.model, got, tc.want)
			}
		})
	}
}

// TestNormalizeProfile pins the request_profile vocabulary.
func TestNormalizeProfile(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"", ProfileAuto, true},
		{" AUTO ", ProfileAuto, true},
		{"chat", ProfileChat, true},
		{"Reasoning", ProfileReasoning, true},
		{"turbo", "turbo", false},
	} {
		got, ok := NormalizeProfile(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("NormalizeProfile(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
		if ValidProfile(tc.in) != tc.ok {
			t.Errorf("ValidProfile(%q) != %v", tc.in, tc.ok)
		}
	}
	if got := Profiles(); len(got) != 3 || got[0] != ProfileAuto {
		t.Errorf("Profiles() = %v, want auto first of three", got)
	}
}

// TestShapeApplyEncodes pins what each shape puts on the wire.
func TestShapeApplyEncodes(t *testing.T) {
	zero := 0.0
	base := Request{Model: "m", Messages: []Message{{Role: RoleUser, Content: "x"}}, MaxTokens: 16, Temperature: &zero}
	for _, tc := range []struct {
		name                string
		shape               Shape
		want, absent        string
		wantTemp            bool
		wantEffort, keepEff string
	}{
		{"chat", ResolveShape("", "", "gpt-4o-mini"), ParamMaxTokens, ParamMaxCompletionTokens, true, "", ""},
		{"reasoning", ResolveShape("", "", "gpt-5-nano"), ParamMaxCompletionTokens, ParamMaxTokens, false, "minimal", ""},
		{"caller effort kept", ResolveShape("", "", "gpt-5-nano"), ParamMaxCompletionTokens, ParamMaxTokens, false, "high", "high"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			r.ReasoningEffort = tc.keepEff
			raw, err := EncodeRequest(tc.shape.Apply(r))
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatal(err)
			}
			if body[tc.want] != float64(16) {
				t.Errorf("%s = %v, want 16 (body %s)", tc.want, body[tc.want], raw)
			}
			if _, ok := body[tc.absent]; ok {
				t.Errorf("%s sent: %s", tc.absent, raw)
			}
			if _, ok := body["temperature"]; ok != tc.wantTemp {
				t.Errorf("temperature sent = %v, want %v: %s", ok, tc.wantTemp, raw)
			}
			if got, _ := body["reasoning_effort"].(string); got != tc.wantEffort {
				t.Errorf("reasoning_effort = %q, want %q", got, tc.wantEffort)
			}
		})
	}
}

// TestRaiseReplyCap pins the minimum-cap rule.
func TestRaiseReplyCap(t *testing.T) {
	r, c := ResolveShape("reasoning", "", "x"), ResolveShape("chat", "", "x")
	for _, tc := range []struct {
		s       Shape
		in, out int
	}{
		{r, 16, ReasoningMinReplyTokens}, {r, 4096, 4096}, {r, 0, 0}, {c, 16, 16},
	} {
		if got := tc.s.RaiseReplyCap(tc.in); got != tc.out {
			t.Errorf("%s RaiseReplyCap(%d) = %d, want %d", tc.s.Profile, tc.in, got, tc.out)
		}
	}
}

// The exact 400 bodies OpenAI returns (recorded from the operator's failed
// provider Test, 2026-11-24, and OpenAI's documented temperature refusal).
const (
	openAIMaxTokens400 = `{
  "error": {
    "message": "Unsupported parameter: 'max_tokens' is not supported with this model. Use 'max_completion_tokens' instead.",
    "type": "invalid_request_error",
    "param": "max_tokens",
    "code": "unsupported_parameter"
  }
}`
	openAITemperature400 = `{
  "error": {
    "message": "Unsupported value: 'temperature' does not support 0 with this model. Only the default (1) value is supported.",
    "type": "invalid_request_error",
    "param": "temperature",
    "code": "unsupported_value"
  }
}`
)

// TestCorrectedProfile pins the self-correction rule table: one case per
// row, and the refusals that must not trigger a retry.
func TestCorrectedProfile(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body, sent string
		want       string
		wantOK     bool
	}{
		{"max_tokens refused", 400, openAIMaxTokens400, ProfileChat, ProfileReasoning, true},
		{"temperature value refused", 400, openAITemperature400, ProfileChat, ProfileReasoning, true},
		{"temperature parameter refused", 400, `{"error":{"type":"invalid_request_error","param":"temperature","code":"unsupported_parameter"}}`, ProfileChat, ProfileReasoning, true},
		{"max_completion_tokens refused", 400, `{"error":{"type":"invalid_request_error","param":"max_completion_tokens","code":"unsupported_parameter"}}`, ProfileReasoning, ProfileChat, true},
		{"already the corrected shape", 400, openAIMaxTokens400, ProfileReasoning, "", false},
		{"other param", 400, `{"error":{"type":"invalid_request_error","param":"model","code":"model_not_found"}}`, ProfileChat, "", false},
		{"null param and code", 400, `{"error":{"type":"invalid_request_error","param":null,"code":null}}`, ProfileChat, "", false},
		{"not a 400", 404, openAIMaxTokens400, ProfileChat, "", false},
		{"not an error document", 400, `upstream exploded`, ProfileChat, "", false},
		{"other error type", 400, `{"error":{"type":"server_error","param":"max_tokens","code":"unsupported_parameter"}}`, ProfileChat, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := CorrectedProfile(tc.status, tc.body, tc.sent)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("CorrectedProfile = %q, %v; want %q, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
