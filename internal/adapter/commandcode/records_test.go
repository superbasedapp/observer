package commandcode

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/parseutil"
	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestTokenBundleGrossToNet(t *testing.T) {
	cases := []struct {
		name  string
		usage *rawUsage
		want  tokenParts
	}{
		{
			name:  "nil usage",
			usage: nil,
			want:  tokenParts{},
		},
		{
			name:  "cold turn — no cache read, input passes through",
			usage: &rawUsage{InputTokens: 33186, OutputTokens: 195},
			want:  tokenParts{inputNet: 33186, output: 195},
		},
		{
			name: "warm turn — gross input netted against cache read",
			usage: &rawUsage{
				InputTokens: 28194, OutputTokens: 75, CacheReadTokens: 28160,
			},
			want: tokenParts{inputNet: 34, output: 75, cacheRead: 28160},
		},
		{
			name: "cross-session warm preamble on a fresh session's first turn",
			usage: &rawUsage{
				InputTokens: 27564, OutputTokens: 12, CacheReadTokens: 7904,
			},
			want: tokenParts{inputNet: 19660, output: 12, cacheRead: 7904},
		},
		{
			name: "cache read exceeds input — clamped at zero, never negative",
			usage: &rawUsage{
				InputTokens: 100, OutputTokens: 5, CacheReadTokens: 900,
			},
			want: tokenParts{inputNet: 0, output: 5, cacheRead: 900},
		},
		{
			name: "cache write is carried through, NOT subtracted (unverified)",
			usage: &rawUsage{
				InputTokens: 5000, CacheReadTokens: 1000, CacheWriteTokens: 400,
			},
			want: tokenParts{inputNet: 4000, cacheRead: 1000, cacheWrit: 400},
		},
		{
			name: "reasoning + provider cost pass through",
			usage: &rawUsage{
				InputTokens: 200, OutputTokens: 50, ReasoningTokens: 30, CostUSD: 0.0125,
			},
			want: tokenParts{inputNet: 200, output: 50, reasoning: 30, costUSD: 0.0125},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tokenBundle(tc.usage); got != tc.want {
				t.Errorf("tokenBundle() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestUsageIsZero(t *testing.T) {
	cases := []struct {
		name  string
		usage *rawUsage
		want  bool
	}{
		{"nil", nil, true},
		{"all zero", &rawUsage{}, true},
		{"input only", &rawUsage{InputTokens: 1}, false},
		{"output only", &rawUsage{OutputTokens: 1}, false},
		{"cache read only", &rawUsage{CacheReadTokens: 1}, false},
		{"cost only", &rawUsage{CostUSD: 0.01}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.usage.isZero(); got != tc.want {
				t.Errorf("isZero() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMapToolName(t *testing.T) {
	cases := []struct {
		name           string
		raw            string
		wantAction     string
		wantRecognised bool
	}{
		// grounded — observed in live Phase-0 capture
		{"read_file (grounded)", "read_file", models.ActionReadFile, true},
		{"read_directory (grounded)", "read_directory", models.ActionSearchFiles, true},
		// grounded — WP-T6 live probe finding B1 (2026-07-31): command-code's
		// ONLY shell tool; normalizes to "shellcommand", distinct from
		// "runshellcommand" (run_shell_command), so it needs its own row.
		{"shell_command (grounded)", "shell_command", models.ActionRunCommand, true},
		// normalization is case / separator insensitive
		{"camelCase variant", "readFile", models.ActionReadFile, true},
		{"kebab variant", "read-directory", models.ActionSearchFiles, true},
		{"upper with spaces", "  READ_FILE ", models.ActionReadFile, true},
		// defensive vocabulary
		{"write", "write_file", models.ActionWriteFile, true},
		{"edit", "edit_file", models.ActionEditFile, true},
		{"shell", "run_command", models.ActionRunCommand, true},
		{"grep", "grep", models.ActionSearchText, true},
		{"web fetch", "web_fetch", models.ActionWebFetch, true},
		{"todo", "todo_write", models.ActionTodoUpdate, true},
		{"subagent", "task", models.ActionSpawnSubagent, true},
		// MCP heuristics
		{"mcp double underscore", "mcp__github__list_issues", models.ActionMCPCall, true},
		{"mcp prefix", "mcp_fetch", models.ActionMCPCall, true},
		{"double underscore without mcp prefix", "server__do_thing", models.ActionMCPCall, true},
		// unmapped names survive as unknown with recognised=false
		{"unmapped", "quantum_refactor", models.ActionUnknown, false},
		{"empty", "", models.ActionUnknown, false},
		{"whitespace only", "   ", models.ActionUnknown, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, recognised := mapToolName(tc.raw)
			if action != tc.wantAction || recognised != tc.wantRecognised {
				t.Errorf("mapToolName(%q) = (%q, %v), want (%q, %v)",
					tc.raw, action, recognised, tc.wantAction, tc.wantRecognised)
			}
		})
	}
}

func TestTargetFromInput(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"file_path (read_file)", `{"file_path":"/a/b.go"}`, "/a/b.go"},
		{"path (read_directory)", `{"path":"/a"}`, "/a"},
		{"command", `{"command":"ls -la"}`, "ls -la"},
		{"query", `{"query":"golang"}`, "golang"},
		{"precedence: file_path over path", `{"path":"/a","file_path":"/a/b.go"}`, "/a/b.go"},
		{"no known key falls back to the tool name", `{"weird":1}`, "fallback"},
		{"non-object input falls back", `["x"]`, "fallback"},
		{"empty input falls back", ``, "fallback"},
		{"non-string value falls back", `{"path":123}`, "fallback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := targetFromInput(json.RawMessage(tc.input), "fallback"); got != tc.want {
				t.Errorf("targetFromInput(%s) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestAuthoredBytes(t *testing.T) {
	cases := []struct {
		name   string
		action string
		input  string
		want   int64
	}{
		{"write content", models.ActionWriteFile, `{"content":"hello"}`, 5},
		{"edit new_string", models.ActionEditFile, `{"new_string":"abc"}`, 3},
		{"edit list", models.ActionEditFile, `{"edits":[{"new_string":"ab"},{"new_string":"cde"}]}`, 5},
		{"run command", models.ActionRunCommand, `{"command":"ls"}`, 2},
		{"read-only action", models.ActionReadFile, `{"file_path":"/a/b"}`, 0},
		{"unknown keys", models.ActionWriteFile, `{"other":"xxxx"}`, 0},
		{"malformed input", models.ActionWriteFile, `not json`, 0},
		{"empty input", models.ActionWriteFile, ``, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authoredBytes(tc.action, json.RawMessage(tc.input)); got != tc.want {
				t.Errorf("authoredBytes(%q, %s) = %d, want %d", tc.action, tc.input, got, tc.want)
			}
		})
	}
}

func TestToolResultText(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"array of text blocks (observed shape)", `[{"type":"text","text":"one"},{"type":"text","text":"two"}]`, "one\ntwo"},
		{"bare string tolerated", `"plain"`, "plain"},
		{"empty array", `[]`, ""},
		{"empty input", ``, ""},
		{"blocks without text skipped", `[{"type":"image"}]`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := toolResultText(json.RawMessage(tc.raw)); got != tc.want {
				t.Errorf("toolResultText(%s) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestContentBlocksPolymorphism(t *testing.T) {
	cases := []struct {
		name      string
		content   string
		wantLen   int
		wantFirst string
	}{
		{"array shape", `[{"type":"text","text":"hi"}]`, 1, "text"},
		{"bare string folded into a text block", `"hi"`, 1, "text"},
		{"blank string yields nothing", `"   "`, 0, ""},
		{"absent content", ``, 0, ""},
		{"unexpected object yields nothing", `{"a":1}`, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &rawMessage{Content: json.RawMessage(tc.content)}
			blocks := m.contentBlocks()
			if len(blocks) != tc.wantLen {
				t.Fatalf("blocks = %d, want %d", len(blocks), tc.wantLen)
			}
			if tc.wantLen > 0 && blocks[0].Type != tc.wantFirst {
				t.Errorf("first block type = %q, want %q", blocks[0].Type, tc.wantFirst)
			}
		})
	}
	var nilMsg *rawMessage
	if got := nilMsg.contentBlocks(); got != nil {
		t.Errorf("nil message blocks = %v, want nil", got)
	}
}

func TestParseTimestamp(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want time.Time
	}{
		{
			"ISO8601 with milliseconds (the observed shape)",
			"2026-07-28T18:29:49.718Z",
			time.Date(2026, 7, 28, 18, 29, 49, 718000000, time.UTC),
		},
		{
			"RFC3339 without fraction",
			"2026-07-29T00:49:10Z",
			time.Date(2026, 7, 29, 0, 49, 10, 0, time.UTC),
		},
		{
			"offset timezone normalized to UTC",
			"2026-07-29T05:49:10+05:00",
			time.Date(2026, 7, 29, 0, 49, 10, 0, time.UTC),
		},
		{"empty", "", time.Time{}},
		{"garbage", "not-a-time", time.Time{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseutil.ParseRFC3339UTC(tc.raw); !got.Equal(tc.want) {
				t.Errorf("parseutil.ParseRFC3339UTC(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestThinkingText(t *testing.T) {
	cases := []struct {
		name   string
		blocks []rawBlock
		want   string
	}{
		{"none", []rawBlock{{Type: "text", Text: "hi"}}, ""},
		{"thinking field", []rawBlock{{Type: "thinking", Thinking: "plan"}}, "plan"},
		{"reasoning alias via text field", []rawBlock{{Type: "reasoning", Text: "why"}}, "why"},
		{
			"multiple joined",
			[]rawBlock{{Type: "thinking", Thinking: "a"}, {Type: "thinking", Thinking: "b"}},
			"a\nb",
		},
		{"blank skipped", []rawBlock{{Type: "thinking", Thinking: "  "}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := thinkingText(tc.blocks); got != tc.want {
				t.Errorf("thinkingText() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("abcdef", 3); got != "abc" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate("ab", 5); got != "ab" {
		t.Errorf("truncate = %q", got)
	}
}

func TestToolEventKey(t *testing.T) {
	if got := toolEventKey("chatcmpl-tool-x", "m1", 0); got != "chatcmpl-tool-x" {
		t.Errorf("key = %q, want the provider call id", got)
	}
	if got := toolEventKey("", "m1", 2); got != "m1:2" {
		t.Errorf("key = %q, want the line-id + position fallback", got)
	}
}

func TestSessionIDFromPath(t *testing.T) {
	got := sessionIDFromPath("/h/.commandcode/projects/p/c2bfd6d1-cc09-4661-ab19-164580a1323e.jsonl")
	if got != "c2bfd6d1-cc09-4661-ab19-164580a1323e" {
		t.Errorf("sessionIDFromPath = %q", got)
	}
}
