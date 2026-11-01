package codebuddy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestTokenBundle(t *testing.T) {
	cases := []struct {
		name                       string
		usage, raw                 string
		in, out, cr, cw, reasoning int64
	}{
		{
			name:  "agents-core usage, array details: gross input and reasoning netted",
			usage: `{"inputTokens":12000,"outputTokens":300,"inputTokensDetails":[{"cached_tokens":8000}],"outputTokensDetails":[{"reasoning_tokens":100}]}`,
			in:    4000, out: 200, cr: 8000, reasoning: 100,
		},
		{
			name:  "object-shaped details",
			usage: `{"inputTokens":500,"outputTokens":20,"inputTokensDetails":{"cached_tokens":100},"outputTokensDetails":{"reasoningTokens":5}}`,
			in:    400, out: 15, cr: 100, reasoning: 5,
		},
		{
			name:  "rawUsage wins for cache counts; DeepSeek miss is not a write",
			usage: `{"inputTokens":1000,"outputTokens":10,"inputTokensDetails":[{"cached_tokens":100}]}`,
			raw:   `{"prompt_cache_hit_tokens":700,"prompt_cache_miss_tokens":300}`,
			in:    300, out: 10, cr: 700,
		},
		{
			name:  "anthropic-shaped raw usage cache write carried, not subtracted",
			usage: `{"inputTokens":2000,"outputTokens":40}`,
			raw:   `{"cache_read_input_tokens":1500,"cache_creation_input_tokens":200}`,
			in:    500, out: 40, cr: 1500, cw: 200,
		},
		{
			name: "raw only, openai snake case",
			raw:  `{"prompt_tokens":900,"completion_tokens":60,"prompt_tokens_details":{"cached_tokens":800},"completion_tokens_details":{"reasoning_tokens":20}}`,
			in:   100, out: 40, cr: 800, reasoning: 20,
		},
		{
			name:  "cache read above gross clamps to zero",
			usage: `{"inputTokens":10,"outputTokens":1,"inputTokensDetails":[{"cached_tokens":50}]}`,
			in:    0, out: 1, cr: 50,
		},
		{name: "nothing", in: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var u, r *rawUsage
			if tc.usage != "" {
				u = &rawUsage{}
				if err := json.Unmarshal([]byte(tc.usage), u); err != nil {
					t.Fatal(err)
				}
			}
			if tc.raw != "" {
				r = &rawUsage{}
				if err := json.Unmarshal([]byte(tc.raw), r); err != nil {
					t.Fatal(err)
				}
			}
			got := tokenBundle(u, r)
			want := tokenParts{inputNet: tc.in, output: tc.out, cacheRead: tc.cr, cacheWrit: tc.cw, reasoning: tc.reasoning}
			if got != want {
				t.Errorf("tokenBundle = %+v, want %+v", got, want)
			}
		})
	}
}

func TestMsTime(t *testing.T) {
	want := time.UnixMilli(1792556783293).UTC()
	cases := []struct {
		raw  string
		want time.Time
	}{
		{`1792556783293`, want},
		{`1792556783293.0`, want},
		{`"1792556783293"`, want},
		{`"2026-10-21T04:26:23.293Z"`, want},
		{`null`, time.Time{}},
		{`"garbage"`, time.Time{}},
		{`{}`, time.Time{}},
	}
	for _, tc := range cases {
		var m msTime
		if err := m.UnmarshalJSON([]byte(tc.raw)); err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		if !m.t.Equal(tc.want) {
			t.Errorf("%s = %v, want %v", tc.raw, m.t, tc.want)
		}
	}
}

func TestArgumentsJSON(t *testing.T) {
	cases := []struct{ raw, want string }{
		{`"{\"file_path\":\"/a\"}"`, `{"file_path":"/a"}`},
		{`{"file_path":"/a"}`, `{"file_path":"/a"}`},
		{`"not json"`, ``},
		{`""`, ``},
		{`null`, ``},
		{`42`, ``},
	}
	for _, tc := range cases {
		if got := string(argumentsJSON(json.RawMessage(tc.raw))); got != tc.want {
			t.Errorf("argumentsJSON(%s) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestMapToolName(t *testing.T) {
	cases := []struct {
		name       string
		want       string
		recognised bool
	}{
		{"Read", models.ActionReadFile, true},
		{"PowerShell", models.ActionRunCommand, true},
		{"Agent", models.ActionSpawnSubagent, true},
		{"TaskCreate", models.ActionTodoUpdate, true},
		{"mcp__github__create_issue", models.ActionMCPCall, true},
		{"ImageGen", models.ActionUnknown, false},
		{"", models.ActionUnknown, false},
		{"read", models.ActionUnknown, false}, // exact native names only
	}
	for _, tc := range cases {
		got, ok := mapToolName(tc.name)
		if got != tc.want || ok != tc.recognised {
			t.Errorf("mapToolName(%q) = %q,%v want %q,%v", tc.name, got, ok, tc.want, tc.recognised)
		}
	}
}

func TestResultFailed(t *testing.T) {
	tr := true
	cases := []struct {
		name    string
		rec     rawLine
		failed  bool
		message string
	}{
		{"completed", rawLine{Status: "completed"}, false, ""},
		{"incomplete with error", rawLine{Status: "incomplete", ProviderData: &rawProviderData{Error: json.RawMessage(`"boom"`)}}, true, "boom"},
		{"isError", rawLine{Status: "completed", IsError: &tr}, true, ""},
		{"providerData error object", rawLine{Status: "completed", ProviderData: &rawProviderData{Error: json.RawMessage(`{"message":"denied"}`)}}, true, "denied"},
		{"null error", rawLine{Status: "completed", ProviderData: &rawProviderData{Error: json.RawMessage(`null`)}}, false, ""},
	}
	for _, tc := range cases {
		failed, msg := resultFailed(&tc.rec)
		if failed != tc.failed || msg != tc.message {
			t.Errorf("%s: resultFailed = %v,%q want %v,%q", tc.name, failed, msg, tc.failed, tc.message)
		}
	}
}

func TestOutputText(t *testing.T) {
	cases := []struct{ raw, want string }{
		{`"plain"`, "plain"},
		{`{"type":"text","text":"obj"}`, "obj"},
		{`[{"type":"input_text","text":"a"},{"type":"input_image","image":"x"},{"type":"input_text","text":"b"}]`, "a\nb"},
		{`null`, ""},
	}
	for _, tc := range cases {
		if got := outputText(json.RawMessage(tc.raw)); got != tc.want {
			t.Errorf("outputText(%s) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestDataURIMediaType(t *testing.T) {
	cases := []struct{ raw, want string }{
		{`"data:image/png;base64,AAAA"`, "image/png"},
		{`"https://example.com/a.png"`, ""},
		{`{"id":"file-1"}`, ""},
	}
	for _, tc := range cases {
		if got := dataURIMediaType(json.RawMessage(tc.raw)); got != tc.want {
			t.Errorf("dataURIMediaType(%s) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestMatchesShape(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/home/u/.codebuddy/projects/home-u-p/abc.jsonl", true},
		{`C:\Users\u\.codebuddy\projects\c-Users-u-p\abc.jsonl`, true},
		{"/home/u/.codebuddy/projects/home-u-p/abc/subagents/agent-1.jsonl", false},
		{"/home/u/.codebuddy/projects/abc.jsonl", false},
		{"/home/u/.codebuddy/history.jsonl", false},
		{"/home/u/.codebuddy/projects/home-u-p/abc.json", false},
	}
	for _, tc := range cases {
		if got := matchesShape(tc.path); got != tc.want {
			t.Errorf("matchesShape(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestIsMetaUserText(t *testing.T) {
	for _, s := range []string{
		`<system-reminder data-role="command-caveat">Caveat</system-reminder>`,
		"<command-name>/model</command-name>",
		"<local-command-stdout>Switched model to Hy3.</local-command-stdout>",
	} {
		if !isMetaUserText(s) {
			t.Errorf("isMetaUserText(%q) = false", s)
		}
	}
	if isMetaUserText("hi") {
		t.Error(`isMetaUserText("hi") = true`)
	}
}
