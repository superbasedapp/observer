package promptturn

import (
	"strings"
	"testing"
)

// TestGenerated is one row per wire shape: Generated carries the newest model
// turn and the trailing tool results, and never the developer's typed text
// (live 2026-11-15: an agent's side request re-sent tool output as a fresh
// user message, and the prompt guard read it as typed).
func TestGenerated(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		shape   Shape
		body    any
		want    []string // substrings Generated must carry
		wantNot []string // substrings Generated must never carry
	}{
		{
			name:  "anthropic tool_result content and the tool_use input",
			shape: ShapeAnthropicMessages,
			body: m{"messages": []any{
				m{"role": "user", "content": "probe the login route"},
				m{"role": "assistant", "content": []any{
					m{"type": "text", "text": "running the probe"},
					m{"type": "tool_use", "id": "t1", "name": "Bash", "input": m{"command": "python probe.py login"}},
				}},
				m{"role": "user", "content": []any{
					m{"type": "tool_result", "tool_use_id": "t1", "content": []any{m{"type": "text", "text": "HTTP 200 Authorization: Bearer fixtureTOKEN12345"}}},
				}},
			}},
			want:    []string{"running the probe", "python probe.py login", "Bearer fixtureTOKEN12345"},
			wantNot: []string{"probe the login route"},
		},
		{
			name:  "anthropic text riding next to a tool_result is not generated",
			shape: ShapeAnthropicMessages,
			body: m{"messages": []any{
				m{"role": "assistant", "content": []any{m{"type": "tool_use", "id": "t1", "name": "Bash", "input": m{}}}},
				m{"role": "user", "content": []any{
					m{"type": "tool_result", "tool_use_id": "t1", "content": "tool says hi"},
					m{"type": "text", "text": "typed by the developer"},
				}},
			}},
			want:    []string{"tool says hi"},
			wantNot: []string{"typed by the developer"},
		},
		{
			name:    "anthropic fresh prompt carries nothing generated",
			shape:   ShapeAnthropicMessages,
			body:    m{"messages": []any{m{"role": "user", "content": "token=typedSecret123"}}},
			wantNot: []string{"typedSecret123"},
		},
		{
			name:  "chat role tool and the assistant's tool-call arguments",
			shape: ShapeOpenAIChat,
			body: m{"messages": []any{
				m{"role": "user", "content": "check the env"},
				m{"role": "assistant", "content": nil, "tool_calls": []any{m{"id": "c1", "type": "function", "function": m{"name": "shell", "arguments": `{"cmd":"cat .env"}`}}}},
				m{"role": "tool", "tool_call_id": "c1", "content": "password=fixturePW12345"},
			}},
			want:    []string{"cat .env", "password=fixturePW12345"},
			wantNot: []string{"check the env"},
		},
		{
			name:  "responses function_call arguments and function_call_output",
			shape: ShapeOpenAIResponses,
			body: m{"input": []any{
				m{"type": "message", "role": "user", "content": "look"},
				m{"type": "function_call", "call_id": "c1", "name": "shell", "arguments": `{"cmd":"curl /debug"}`},
				m{"type": "function_call_output", "call_id": "c1", "output": "Bearer fixtureTOKEN12345"},
			}},
			want:    []string{"curl /debug", "Bearer fixtureTOKEN12345"},
			wantNot: []string{"look"},
		},
		{
			name:  "gemini functionCall and functionResponse",
			shape: ShapeGemini,
			body: m{"contents": []any{
				m{"role": "user", "parts": []any{m{"text": "start the scan"}}},
				m{"role": "model", "parts": []any{m{"functionCall": m{"name": "shell", "args": m{"cmd": "env"}}}}},
				m{"role": "function", "parts": []any{m{"functionResponse": m{"name": "shell", "response": m{"out": "token=fixtureTOK12345"}}}}},
			}},
			want:    []string{`"cmd":"env"`, "fixtureTOK12345"},
			wantNot: []string{"start the scan"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Classify(tc.shape, mustJSON(t, tc.body)).Generated
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("Generated = %q, want it to carry %q", got, w)
				}
			}
			for _, w := range tc.wantNot {
				if strings.Contains(got, w) {
					t.Errorf("Generated = %q, must not carry the typed %q", got, w)
				}
			}
		})
	}
}
