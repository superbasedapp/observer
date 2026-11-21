package promptturn

import (
	"encoding/json"
	"strings"
	"testing"
)

type m = map[string]any

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestClassify is one row per extractor shape and turn kind.
func TestClassify(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		shape        Shape
		body         any
		wantKind     Kind
		wantText     string
		wantTrailing string
		wantOpening  string
	}{
		{
			name:     "anthropic string prompt",
			shape:    ShapeAnthropicMessages,
			body:     m{"messages": []any{m{"role": "user", "content": "fix the bug"}}},
			wantKind: KindUserPrompt, wantText: "fix the bug", wantTrailing: "fix the bug",
		},
		{
			name:  "anthropic block prompt, last user wins",
			shape: ShapeAnthropicMessages,
			body: m{"messages": []any{
				m{"role": "user", "content": "first"},
				m{"role": "assistant", "content": "ok"},
				m{"role": "user", "content": []any{m{"type": "text", "text": "second"}, m{"type": "text", "text": "more"}}},
			}},
			wantKind: KindUserPrompt, wantText: "second\nmore", wantTrailing: "second\nmore",
		},
		{
			name:  "anthropic tool loop is a continuation",
			shape: ShapeAnthropicMessages,
			body: m{"messages": []any{
				m{"role": "user", "content": "run the tests"},
				m{"role": "assistant", "content": []any{m{"type": "tool_use", "id": "t1", "name": "Bash", "input": m{}}}},
				m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "t1", "content": "PASS"}}},
			}},
			wantKind: KindContinuation, wantTrailing: "PASS", wantOpening: "run the tests",
		},
		{
			name:  "anthropic long loop: opening walks back past earlier tool results",
			shape: ShapeAnthropicMessages,
			body: m{"messages": []any{
				m{"role": "user", "content": []any{m{"type": "text", "text": "fix it"}}},
				m{"role": "assistant", "content": []any{m{"type": "tool_use", "id": "t1", "name": "Bash", "input": m{}}}},
				m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "t1", "content": "one"}}},
				m{"role": "assistant", "content": []any{m{"type": "tool_use", "id": "t2", "name": "Bash", "input": m{}}}},
				m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "t2", "content": "two"}}},
			}},
			wantKind: KindContinuation, wantTrailing: "two", wantOpening: "fix it",
		},
		{
			name:  "anthropic loop with no typed prompt has no opening",
			shape: ShapeAnthropicMessages,
			body: m{"messages": []any{
				m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "t1", "content": "out"}}},
			}},
			wantKind: KindContinuation, wantTrailing: "out",
		},
		{
			name:  "anthropic tool_result plus typed text is a prompt",
			shape: ShapeAnthropicMessages,
			body: m{"messages": []any{
				m{"role": "assistant", "content": []any{m{"type": "tool_use", "id": "t1", "name": "Bash", "input": m{}}}},
				m{"role": "user", "content": []any{
					m{"type": "tool_result", "tool_use_id": "t1", "content": []any{m{"type": "text", "text": "out"}}},
					m{"type": "text", "text": "now deploy"},
				}},
			}},
			wantKind: KindUserPrompt, wantText: "now deploy", wantTrailing: "out\nnow deploy",
		},
		{
			// N2 (fix round 2): a whitespace-only text block next to a
			// tool_result is not typed input; the message is a continuation.
			name:  "anthropic tool_result plus whitespace text is a continuation",
			shape: ShapeAnthropicMessages,
			body: m{"messages": []any{
				m{"role": "user", "content": "start the build"},
				m{"role": "assistant", "content": []any{m{"type": "tool_use", "id": "t1", "name": "Bash", "input": m{}}}},
				m{"role": "user", "content": []any{
					m{"type": "tool_result", "tool_use_id": "t1", "content": "out"},
					m{"type": "text", "text": " \n\t "},
				}},
			}},
			wantKind: KindContinuation, wantTrailing: "out\n \n\t ", wantOpening: "start the build",
		},
		{
			name:  "gemini functionResponse plus whitespace text is a continuation",
			shape: ShapeGemini,
			body: m{"contents": []any{
				m{"role": "user", "parts": []any{m{"text": "list files"}}},
				m{"role": "model", "parts": []any{m{"functionCall": m{"name": "ls"}}}},
				m{"role": "user", "parts": []any{m{"functionResponse": m{"name": "ls"}}, m{"text": "  "}}},
			}},
			wantKind: KindContinuation, wantTrailing: "{\"name\":\"ls\"}\n  ", wantOpening: "list files",
		},
		{
			name:     "anthropic image-only prompt has empty text",
			shape:    ShapeAnthropicMessages,
			body:     m{"messages": []any{m{"role": "user", "content": []any{m{"type": "image", "source": m{}}}}}},
			wantKind: KindUserPrompt,
		},
		{
			name:     "anthropic no user turn",
			shape:    ShapeAnthropicMessages,
			body:     m{"messages": []any{}},
			wantKind: KindNone,
		},
		{
			name:  "openai chat prompt",
			shape: ShapeOpenAIChat,
			body: m{"messages": []any{
				m{"role": "system", "content": "be nice"},
				m{"role": "user", "content": []any{m{"type": "text", "text": "a"}, m{"type": "text", "text": "b"}}},
			}},
			wantKind: KindUserPrompt, wantText: "a\nb", wantTrailing: "a\nb",
		},
		{
			name:  "openai chat tool loop is a continuation",
			shape: ShapeOpenAIChat,
			body: m{"messages": []any{
				m{"role": "user", "content": "original"},
				m{"role": "assistant", "content": nil, "tool_calls": []any{m{"id": "c1", "function": m{"name": "Bash"}}}},
				m{"role": "tool", "tool_call_id": "c1", "content": "tool output"},
			}},
			wantKind: KindContinuation, wantTrailing: "tool output", wantOpening: "original",
		},
		{
			name:  "openai chat tool results with no user message are a continuation",
			shape: ShapeOpenAIChat,
			body: m{"messages": []any{
				m{"role": "assistant", "content": nil, "tool_calls": []any{m{"id": "c1", "function": m{"name": "Bash"}}}},
				m{"role": "tool", "tool_call_id": "c1", "content": "tool output"},
			}},
			wantKind: KindContinuation, wantTrailing: "tool output",
		},
		{
			name:  "openai chat new prompt after a finished loop",
			shape: ShapeOpenAIChat,
			body: m{"messages": []any{
				m{"role": "user", "content": "original"},
				m{"role": "tool", "tool_call_id": "c1", "content": "tool output"},
				m{"role": "assistant", "content": "done"},
				m{"role": "user", "content": "next thing"},
			}},
			wantKind: KindUserPrompt, wantText: "next thing", wantTrailing: "next thing",
		},
		{
			name:     "openai responses bare string",
			shape:    ShapeOpenAIResponses,
			body:     m{"input": "whole prompt"},
			wantKind: KindUserPrompt, wantText: "whole prompt", wantTrailing: "whole prompt",
		},
		{
			name:  "openai responses item prompt",
			shape: ShapeOpenAIResponses,
			body: m{"input": []any{
				m{"type": "message", "role": "user", "content": []any{m{"type": "input_text", "text": "hello"}}},
			}},
			wantKind: KindUserPrompt, wantText: "hello", wantTrailing: "hello",
		},
		{
			name:  "openai responses tool loop is a continuation",
			shape: ShapeOpenAIResponses,
			body: m{"input": []any{
				m{"type": "message", "role": "user", "content": []any{m{"type": "input_text", "text": "orig"}}},
				m{"type": "function_call", "call_id": "c1", "name": "shell"},
				m{"type": "function_call_output", "call_id": "c1", "output": "ls output"},
			}},
			wantKind: KindContinuation, wantTrailing: "ls output", wantOpening: "orig",
		},
		{
			name:  "openai responses structured output rendered as JSON",
			shape: ShapeOpenAIResponses,
			body: m{"input": []any{
				m{"type": "function_call", "call_id": "c1", "name": "shell"},
				m{"type": "function_call_output", "call_id": "c1", "output": m{"ok": true}},
			}},
			wantKind: KindContinuation, wantTrailing: `{"ok":true}`,
		},
		{
			name:  "gemini prompt, model turns excluded",
			shape: ShapeGemini,
			body: m{"contents": []any{
				m{"role": "user", "parts": []any{m{"text": "first"}}},
				m{"role": "model", "parts": []any{m{"text": "reply"}}},
				m{"role": "user", "parts": []any{m{"text": "second"}, m{"text": "more"}}},
			}},
			wantKind: KindUserPrompt, wantText: "second\nmore", wantTrailing: "second\nmore",
		},
		{
			name:     "gemini omitted role defaults to user",
			shape:    ShapeGemini,
			body:     m{"contents": []any{m{"parts": []any{m{"text": "solo"}}}}},
			wantKind: KindUserPrompt, wantText: "solo", wantTrailing: "solo",
		},
		{
			name:  "gemini function response is a continuation",
			shape: ShapeGemini,
			body: m{"contents": []any{
				m{"role": "user", "parts": []any{m{"text": "orig"}}},
				m{"role": "model", "parts": []any{m{"functionCall": m{"name": "ls"}}}},
				m{"role": "user", "parts": []any{m{"functionResponse": m{"name": "ls", "response": m{"r": 1}}}}},
			}},
			wantKind: KindContinuation, wantTrailing: `{"name":"ls","response":{"r":1}}`, wantOpening: "orig",
		},
		{
			name:  "gemini role function content is a continuation",
			shape: ShapeGemini,
			body: m{"contents": []any{
				m{"role": "user", "parts": []any{m{"text": "list files"}}},
				m{"role": "model", "parts": []any{m{"functionCall": m{"name": "ls"}}}},
				m{"role": "function", "parts": []any{m{"functionResponse": m{"name": "ls"}}}},
			}},
			wantKind: KindContinuation, wantTrailing: `{"name":"ls"}`, wantOpening: "list files",
		},
		{
			name:     "unknown shape",
			shape:    ShapeUnknown,
			body:     m{"messages": []any{m{"role": "user", "content": "x"}}},
			wantKind: KindNone,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Classify(tc.shape, mustJSON(t, tc.body))
			if got.Kind != tc.wantKind || got.Text != tc.wantText || got.Trailing != tc.wantTrailing || got.Opening != tc.wantOpening {
				t.Fatalf("Classify = %+v, want kind=%s text=%q trailing=%q opening=%q", got, tc.wantKind, tc.wantText, tc.wantTrailing, tc.wantOpening)
			}
		})
	}
}

// TestShapeFor is one row per provider lane.
func TestShapeFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		provider string
		body     any
		want     Shape
	}{
		{"anthropic messages", "anthropic", m{"messages": []any{m{"role": "user", "content": "x"}}}, ShapeAnthropicMessages},
		{"openai chat", "openai", m{"messages": []any{m{"role": "user", "content": "x"}}}, ShapeOpenAIChat},
		{"openai responses", "openai", m{"input": "x"}, ShapeOpenAIResponses},
		{"gemini", "google", m{"contents": []any{m{"parts": []any{m{"text": "x"}}}}}, ShapeGemini},
		{"unknown provider", "cohere", m{}, ShapeUnknown},
		// The provider decides, never a decoy key in the body.
		{"anthropic body with a decoy contents key", "anthropic", m{"contents": []any{}, "messages": []any{m{"role": "user", "content": "x"}}}, ShapeAnthropicMessages},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ShapeFor(tc.provider, mustJSON(t, tc.body)); got != tc.want {
				t.Errorf("ShapeFor = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestMalformedNeverPanics pins the tolerant contract.
func TestMalformedNeverPanics(t *testing.T) {
	t.Parallel()
	for _, s := range []Shape{ShapeUnknown, ShapeAnthropicMessages, ShapeOpenAIChat, ShapeOpenAIResponses, ShapeGemini} {
		for _, body := range [][]byte{nil, []byte("not json"), []byte(`{"messages":7,"input":[1],"contents":"x"}`)} {
			if got := Classify(s, body); got.Kind != KindNone {
				t.Errorf("shape %s body %q: kind %s, want none", s, body, got.Kind)
			}
		}
	}
}

// TestTrailingIsCapped pins MaxTrailingBytes while the prompt text is not
// capped (the guard's own oversize handling needs the whole prompt).
func TestTrailingIsCapped(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("é", MaxTrailingBytes) // 2 bytes per rune
	got := Classify(ShapeAnthropicMessages, mustJSON(t, m{"messages": []any{m{"role": "user", "content": big}}}))
	if len(got.Trailing) > MaxTrailingBytes || !strings.HasPrefix(big, got.Trailing) {
		t.Fatalf("trailing len %d not capped on a rune boundary", len(got.Trailing))
	}
	if got.Text != big {
		t.Fatal("prompt text must not be capped")
	}
}

// TestBlocksPerShape pins Turn.Blocks: each non-blank text block of the user
// turn, never a substring, and nil for a continuation (adm-2 fixes-1, H1).
func TestBlocksPerShape(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		body     string
		want     []string
	}{
		{
			"anthropic: reminder block and prompt block", "anthropic",
			`{"messages":[{"role":"user","content":[{"type":"text","text":"<system-reminder>x</system-reminder>"},{"type":"text","text":"fix the bug"},{"type":"text","text":"  "}]}]}`,
			[]string{"<system-reminder>x</system-reminder>", "fix the bug"},
		},
		{"anthropic: string content", "anthropic", `{"messages":[{"role":"user","content":"fix the bug"}]}`, []string{"fix the bug"}},
		{
			"anthropic: continuation has no blocks", "anthropic",
			`{"messages":[{"role":"user","content":"go"},{"role":"assistant","content":"x"},{"role":"user","content":[{"type":"tool_result","content":"ok"}]}]}`, nil,
		},
		{"openai chat: parts", "openai", `{"messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"fix the bug"}]}]}`, []string{"a", "fix the bug"}},
		{"openai chat: string", "openai", `{"messages":[{"role":"user","content":"fix the bug"}]}`, []string{"fix the bug"}},
		{"openai responses: bare string", "openai", `{"input":"fix the bug"}`, []string{"fix the bug"}},
		{"openai responses: items", "openai", `{"input":[{"role":"user","content":[{"type":"input_text","text":"<env>x</env>"},{"type":"input_text","text":"fix the bug"}]}]}`, []string{"<env>x</env>", "fix the bug"}},
		{"gemini: parts", "google", `{"contents":[{"role":"user","parts":[{"text":"ctx"},{"text":"fix the bug"}]}]}`, []string{"ctx", "fix the bug"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyProvider(tc.provider, []byte(tc.body)).Blocks
			if len(got) != len(tc.want) {
				t.Fatalf("Blocks = %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("Blocks = %q, want %q", got, tc.want)
				}
			}
		})
	}
}
