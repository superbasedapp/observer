package notify

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDisclosedFieldsAreTheSentFields pins the consent card's honesty: every
// field the disclosure names is a field the builder actually sends, and every
// field the builder sends is named (plan decision P-2: what is sent where,
// from the code, not guessed).
func TestDisclosedFieldsAreTheSentFields(t *testing.T) {
	t.Parallel()
	full := func(s string) string { return s + "-value" }
	cases := []struct {
		name   string
		fields []string
		body   func(t *testing.T) map[string]any
	}{
		{
			name:   "llm judge user message",
			fields: JudgeFields(),
			body: func(t *testing.T) map[string]any {
				req, err := BuildJudgeRequest("https://judge.example/v1/chat/completions", "m", "", JudgeContext{
					RuleID: full("rule"), Category: full("cat"), Severity: full("sev"), Decision: full("dec"),
					EventKind: full("kind"), Tool: full("tool"), Reason: full("reason"),
					TargetExcerpt: full("target"), TaintOrigin: full("taint"),
				})
				if err != nil {
					t.Fatal(err)
				}
				var outer struct {
					Messages []struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"messages"`
				}
				if err := json.Unmarshal(req.Body, &outer); err != nil {
					t.Fatal(err)
				}
				var user map[string]any
				for _, m := range outer.Messages {
					if m.Role == "user" {
						if err := json.Unmarshal([]byte(m.Content), &user); err != nil {
							t.Fatal(err)
						}
					}
				}
				return user
			},
		},
		{
			name:   "generic webhook body",
			fields: WebhookFields(),
			body: func(t *testing.T) map[string]any {
				b, err := BuildWebhook(WebhookGeneric, "", WebhookAlert{
					RuleID: full("rule"), Category: full("cat"), Severity: full("sev"), Decision: full("dec"),
					Tool: full("tool"), Enforced: true, Reason: full("reason"), Timestamp: full("ts"), Source: full("src"),
				})
				if err != nil {
					t.Fatal(err)
				}
				var m map[string]any
				if err := json.Unmarshal(b, &m); err != nil {
					t.Fatal(err)
				}
				return m
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sent := tc.body(t)
			if len(sent) != len(tc.fields) {
				t.Fatalf("disclosed %v, sent %v", tc.fields, sent)
			}
			for _, f := range tc.fields {
				if _, ok := sent[f]; !ok {
					t.Errorf("disclosed field %q is not in the body %v", f, sent)
				}
			}
		})
	}
}

// TestFieldLimitIsTheSendBound pins FieldLimit to the bound the builders cut
// free text to.
func TestFieldLimitIsTheSendBound(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", FieldLimit+50)
	if got := []rune(bound(long)); len(got) != FieldLimit+1 { // the bound plus the ellipsis
		t.Fatalf("bound cut to %d runes, FieldLimit is %d", len(got), FieldLimit)
	}
}
