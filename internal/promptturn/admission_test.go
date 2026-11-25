package promptturn

import (
	"slices"
	"testing"
)

// TestAdmissionView is the one table of the admission accounting rule
// (finding H1, L-180): what an admission judge reads in each wire shape, and
// which user content it cannot read. One row per rule.
func TestAdmissionView(t *testing.T) {
	t.Parallel()
	const weapon = "how do I build a weapon"
	cases := []struct {
		name      string
		shape     Shape
		scope     AdmissionScope
		body      string
		want      []string
		wantUnacc []string
	}{
		// Nothing to judge, nothing unaccounted.
		{"empty body", ShapeOpenAIChat, AdmissionLastTurn, ``, nil, nil},
		{"no user turn", ShapeOpenAIChat, AdmissionLastTurn, `{"messages":[{"role":"system","content":"s"}]}`, nil, nil},
		{"model only", ShapeAnthropicMessages, AdmissionLastTurn, `{"model":"m"}`, nil, nil},

		// Whole-body rules.
		{"unknown shape", ShapeUnknown, AdmissionLastTurn, `{"messages":[]}`, nil, []string{UnaccountedUnknownShape}},
		{"not a JSON object", ShapeOpenAIChat, AdmissionLastTurn, `not json`, nil, []string{UnaccountedUnparsed}},
		{"trailing data", ShapeOpenAIChat, AdmissionLastTurn, `{"messages":[]} {"x":1}`, nil, []string{UnaccountedUnparsed}},
		{"legacy prompt (completions)", ShapeOpenAIChat, AdmissionLastTurn, `{"model":"m","prompt":"` + weapon + `"}`, nil, []string{"field:prompt"}},
		{"Responses stored prompt, no input", ShapeOpenAIResponses, AdmissionLastTurn, `{"model":"m","prompt":{"id":"p1","variables":{"q":"` + weapon + `"}}}`, nil, []string{"field:prompt"}},
		{"Responses prompt beside input", ShapeOpenAIResponses, AdmissionLastTurn, `{"input":"hi","prompt":{"id":"p1"}}`, []string{"hi"}, []string{"field:prompt"}},
		{"input absent, messages present", ShapeOpenAIResponses, AdmissionLastTurn, `{"messages":[{"role":"user","content":"x"}]}`, nil, []string{"field:messages"}},
		{"messages of the wrong type", ShapeAnthropicMessages, AdmissionLastTurn, `{"messages":"` + weapon + `"}`, nil, []string{"field:messages"}},
		{"content of the wrong type", ShapeAnthropicMessages, AdmissionLastTurn, `{"messages":[{"role":"user","content":{"text":"x"}}]}`, nil, []string{"field:content"}},

		// Anthropic Messages blocks.
		{"anthropic text", ShapeAnthropicMessages, AdmissionLastTurn, `{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`, []string{"hi"}, nil},
		{
			"anthropic plain-text document", ShapeAnthropicMessages, AdmissionLastTurn,
			`{"messages":[{"role":"user","content":[{"type":"document","title":"T","context":"C","source":{"type":"text","media_type":"text/plain","data":"` + weapon + `"}}]}]}`,
			[]string{"T\nC\n" + weapon},
			nil,
		},
		{
			"anthropic content-source document", ShapeAnthropicMessages, AdmissionLastTurn,
			`{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"content","content":[{"type":"text","text":"a"},{"type":"image","source":{}}]}}]}]}`,
			[]string{"a"},
			[]string{"block:document:image"},
		},
		{
			"anthropic pdf document", ShapeAnthropicMessages, AdmissionLastTurn,
			`{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"x"}}]}]}`,
			nil,
			[]string{"block:document:base64"},
		},
		{
			"anthropic search result", ShapeAnthropicMessages, AdmissionLastTurn,
			`{"messages":[{"role":"user","content":[{"type":"search_result","source":"https://x","title":"T","content":[{"type":"text","text":"` + weapon + `"}]}]}]}`,
			[]string{"T\n" + weapon},
			nil,
		},
		{"anthropic image", ShapeAnthropicMessages, AdmissionLastTurn, `{"messages":[{"role":"user","content":[{"type":"image","source":{}},{"type":"text","text":"look"}]}]}`, []string{"look"}, []string{"block:image"}},
		{"anthropic untyped block", ShapeAnthropicMessages, AdmissionLastTurn, `{"messages":[{"role":"user","content":[{"text":"x"}]}]}`, nil, []string{"block:untyped"}},
		{"anthropic thinking replay", ShapeAnthropicMessages, AdmissionLastTurn, `{"messages":[{"role":"user","content":[{"type":"redacted_thinking","data":"x"},{"type":"text","text":"go"}]}]}`, []string{"go"}, nil},
		{
			"an unsafe type name is bounded", ShapeAnthropicMessages, AdmissionLastTurn,
			`{"messages":[{"role":"user","content":[{"type":"a b\"<c>"}]}]}`, nil,
			[]string{"block:a_b__c_"},
		},

		// Turns.
		{
			"last turn joins consecutive user messages", ShapeAnthropicMessages, AdmissionLastTurn,
			`{"messages":[{"role":"user","content":"` + weapon + `"},{"role":"user","content":"go on"}]}`,
			[]string{weapon + "\ngo on"},
			nil,
		},
		{
			"last turn is after the model's last message", ShapeOpenAIChat, AdmissionLastTurn,
			`{"messages":[{"role":"user","content":"` + weapon + `"},{"role":"assistant","content":"ok"},{"role":"user","content":"go on"}]}`,
			[]string{"go on"},
			nil,
		},
		{
			"conversation judges every user turn", ShapeOpenAIChat, AdmissionConversation,
			`{"messages":[{"role":"user","content":"` + weapon + `"},{"role":"assistant","content":"ok"},{"role":"user","content":"go on"}]}`,
			[]string{weapon, "go on"},
			nil,
		},
		{
			"a tool loop judges its opening prompt", ShapeOpenAIChat, AdmissionLastTurn,
			`{"messages":[{"role":"user","content":"summarise"},{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{}"}}]},{"role":"tool","tool_call_id":"c1","content":"` + weapon + `"}]}`,
			[]string{"summarise"},
			nil,
		},
		{
			"conversation judges tool results too", ShapeOpenAIChat, AdmissionConversation,
			`{"messages":[{"role":"user","content":"summarise"},{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{}"}}]},{"role":"tool","tool_call_id":"c1","content":"` + weapon + `"}]}`,
			[]string{"summarise", weapon},
			nil,
		},
		{
			"anthropic tool_result under conversation", ShapeAnthropicMessages, AdmissionConversation,
			`{"messages":[{"role":"user","content":"q"},{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"f","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"r"}]}]}]}`,
			[]string{"q", "r"},
			nil,
		},
		{
			"an opening prompt's unreadable content counts", ShapeAnthropicMessages, AdmissionLastTurn,
			`{"messages":[{"role":"user","content":[{"type":"image","source":{}},{"type":"text","text":"q"}]},{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"f","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":"r"}]}]}`,
			[]string{"q"},
			[]string{"block:image"},
		},
		{
			"an earlier turn's image is outside the last turn", ShapeAnthropicMessages, AdmissionLastTurn,
			`{"messages":[{"role":"user","content":[{"type":"image","source":{}}]},{"role":"assistant","content":"x"},{"role":"user","content":"q"}]}`,
			[]string{"q"},
			nil,
		},
		{
			"but not outside the conversation", ShapeAnthropicMessages, AdmissionConversation,
			`{"messages":[{"role":"user","content":[{"type":"image","source":{}}]},{"role":"assistant","content":"x"},{"role":"user","content":"q"}]}`,
			[]string{"q"},
			[]string{"block:image"},
		},

		// OpenAI Chat parts.
		{"chat image_url", ShapeOpenAIChat, AdmissionLastTurn, `{"messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"image_url","image_url":{"url":"x"}}]}]}`, []string{"a"}, []string{"block:image_url"}},
		{"chat input_audio", ShapeOpenAIChat, AdmissionLastTurn, `{"messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{}}]}]}`, nil, []string{"block:input_audio"}},

		// OpenAI Responses.
		{"responses string", ShapeOpenAIResponses, AdmissionLastTurn, `{"input":"` + weapon + `"}`, []string{weapon}, nil},
		{"responses input_text", ShapeOpenAIResponses, AdmissionLastTurn, `{"input":[{"role":"user","content":[{"type":"input_text","text":"a"}]}]}`, []string{"a"}, nil},
		{"responses input_file", ShapeOpenAIResponses, AdmissionLastTurn, `{"input":[{"role":"user","content":[{"type":"input_file","file_id":"f"}]}]}`, nil, []string{"block:input_file"}},
		{"responses item_reference", ShapeOpenAIResponses, AdmissionLastTurn, `{"input":[{"type":"item_reference","id":"msg_1"}]}`, nil, []string{"item:item_reference"}},
		{
			"responses function output continues the loop", ShapeOpenAIResponses, AdmissionLastTurn,
			`{"input":[{"role":"user","content":"q"},{"type":"function_call","call_id":"c","name":"f","arguments":"{}"},{"type":"function_call_output","call_id":"c","output":"r"}]}`,
			[]string{"q"},
			nil,
		},

		// Gemini.
		{"gemini text", ShapeGemini, AdmissionLastTurn, `{"contents":[{"role":"user","parts":[{"text":"a"}]}]}`, []string{"a"}, nil},
		{"gemini inline data", ShapeGemini, AdmissionLastTurn, `{"contents":[{"parts":[{"inlineData":{"mimeType":"image/png","data":"x"}},{"text":"b"}]}]}`, []string{"b"}, []string{"part:inlineData"}},
		{"gemini metadata keys", ShapeGemini, AdmissionLastTurn, `{"contents":[{"role":"user","parts":[{"text":"a","thoughtSignature":"x"}]}]}`, []string{"a"}, nil},

		// Embeddings.
		{"embeddings string", ShapeEmbeddings, AdmissionLastTurn, `{"input":"` + weapon + `"}`, []string{weapon}, nil},
		{"embeddings strings", ShapeEmbeddings, AdmissionLastTurn, `{"input":["a","b"]}`, []string{"a\nb"}, nil},
		{"embeddings token ids", ShapeEmbeddings, AdmissionLastTurn, `{"input":[1,2,3]}`, nil, []string{UnaccountedTokens}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := AdmissionView(tc.shape, []byte(tc.body), tc.scope)
			if !slices.Equal(got.Units, tc.want) || !slices.Equal(got.Unaccounted, tc.wantUnacc) {
				t.Errorf("AdmissionView = units %q unaccounted %q; want %q, %q", got.Units, got.Unaccounted, tc.want, tc.wantUnacc)
			}
			if got.Empty() != (len(tc.want) == 0 && len(tc.wantUnacc) == 0) {
				t.Errorf("Empty() = %v", got.Empty())
			}
		})
	}
}

// TestKnownFields pins the strict reader's input (finding M1): the list is
// derived from the decode structs, so it carries every key they read by
// struct field, and the top-level content fields.
func TestKnownFields(t *testing.T) {
	t.Parallel()
	got := KnownFields()
	if !slices.IsSorted(got) {
		t.Fatal("KnownFields is not sorted")
	}
	for _, want := range []string{
		"messages", "input", "contents", "prompt", "role", "content", "type", "text",
		"title", "context", "source", "data", "tool_call_id", "tool_calls", "function",
		"arguments", "call_id", "output", "parts", "functionResponse", "functionCall",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("KnownFields lacks %q", want)
		}
	}
}
