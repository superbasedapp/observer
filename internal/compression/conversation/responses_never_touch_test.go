package conversation

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Fernet-shaped (urlsafe base64) encrypted_content carrying `-ak-`, a run
// the api_key_prefixed scrub row matches when the value is scrubbed out of
// its key's sight — the corruption behind lane sr-openai-n2's HTTP 400
// "encrypted content could not be verified".
const neverTouchToken = "gAAAAABpQx7Rk3Lw-ak-Zq9VvYb2aXc1Yt0uTsR8pQoNmLkJiHgFeDcBa_ZyXwVuTsRqPoNm=="

// neverTouchCases is one row per responsesNeverTouchItems row plus the
// encrypted_content capability row. Each item is compact JSON exactly as a
// client sends it; the summary carries `<b> & </b>` so an HTML-escaping
// re-encode would show up as a byte difference.
var neverTouchCases = []struct {
	name string // the row's itemType, or "capability:encrypted_content"
	item string
}{
	{"reasoning", `{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"**Plan** check <b> & </b> then edit"}],"encrypted_content":"` + neverTouchToken + `"}`},
	{"compaction", `{"type":"compaction","id":"cmp_1","encrypted_content":"` + neverTouchToken + `"}`},
	{"capability:encrypted_content", `{"type":"future_encrypted_item","id":"x_1","encrypted_content":"` + neverTouchToken + `"}`},
}

// neverTouchFollower is the output item of the same response, right after
// the protected item.
const neverTouchFollower = `{"type":"message","role":"assistant","id":"msg_1","content":[{"type":"output_text","text":"` +
	`I looked at the parser and found the issue in the tokenizer loop. ` + `"}]}`

// neverTouchBody builds a Responses request with real budget pressure:
// large droppable assistant prose, a large JSON tool output the json
// compressor shrinks, and a developer message whose LAST line is an env
// export, which pushes the forward scrub off its fast path.
func neverTouchBody(item string) []byte {
	prose := strings.Repeat("Some earlier assistant narration that is safe to drop. ", 120)
	rows := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		rows = append(rows, `{\"id\":`+string(rune('0'+i%10))+`,\"name\":\"row\",\"ok\":true}`)
	}
	jsonOut := `[` + strings.Join(rows, ",") + `]`
	input := []string{
		`{"type":"message","role":"developer","content":[{"type":"input_text","text":"` + prose + `\nexport GITHUB_TOKEN=abc0123456789secret"}]}`,
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"fix the parser"}]}`,
		item,
		neverTouchFollower,
		`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"` + prose + `"}]}`,
		`{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"cat rows.json\"}","call_id":"call_1"}`,
		`{"type":"function_call_output","call_id":"call_1","output":"` + jsonOut + `"}`,
		`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"` + prose + `"}]}`,
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}]}`,
	}
	return []byte(`{"model":"gpt-5.1-codex-mini","store":false,"include":["reasoning.encrypted_content"],"input":[` +
		strings.Join(input, ",") + `]}`)
}

func neverTouchPipeline(enabled bool) *Pipeline {
	return NewPipeline(PipelineConfig{
		Enabled:       enabled,
		Mode:          ModeToken,
		TargetRatio:   0.3,
		PreserveLastN: 1,
		CompressTypes: []string{"json", "logs", "code"},
	}, DefaultRegistry(), scrub.New())
}

// TestResponsesNeverTouchItems: with compression ON and real pressure
// (drops fire, per-type compression fires, the forward scrub falls back),
// every never-touch item reaches the upstream as the client's exact bytes,
// and a reasoning item keeps its follower right after it.
func TestResponsesNeverTouchItems(t *testing.T) {
	t.Parallel()
	covered := map[string]bool{}
	for _, tc := range neverTouchCases {
		covered[tc.name] = true
		t.Run(tc.name, func(t *testing.T) {
			body := neverTouchBody(tc.item)
			if !json.Valid(body) {
				t.Fatalf("precondition: test body not valid JSON")
			}
			res := neverTouchPipeline(true).Run("openai", body)
			if res.Skipped || res.DroppedCount == 0 || res.CompressedCount == 0 {
				t.Fatalf("precondition: want drops and compression to fire, got skipped=%v dropped=%d compressed=%d",
					res.Skipped, res.DroppedCount, res.CompressedCount)
			}
			if !json.Valid(res.Body) {
				t.Fatalf("compressed body is not valid JSON")
			}
			if !bytes.Contains(res.Body, []byte(tc.item)) {
				t.Fatalf("never-touch item not forwarded byte-exact:\nwant %s\nbody %s", tc.item, res.Body)
			}
			_, keeps := responsesNeverTouch(itemTypeOf(t, tc.item), nil)
			if keeps && !bytes.Contains(res.Body, []byte(tc.item+","+neverTouchFollower)) {
				t.Fatalf("follower not kept right after the item:\n%s", res.Body)
			}
			if bytes.Contains(res.Body, []byte("abc0123456789secret")) {
				t.Fatalf("forward scrub did not run (secret leaked):\n%s", res.Body)
			}
		})
	}
	covered["capability:encrypted_content"] = true
	for _, row := range responsesNeverTouchItems {
		if !covered[row.itemType] {
			t.Errorf("responsesNeverTouchItems row %q has no test row", row.itemType)
		}
	}
}

// TestResponsesNeverTouchCompressionOff: with compression off the pipeline
// forwards the request untouched.
func TestResponsesNeverTouchCompressionOff(t *testing.T) {
	t.Parallel()
	for _, tc := range neverTouchCases {
		body := neverTouchBody(tc.item)
		res := neverTouchPipeline(false).Run("openai", body)
		if !res.Skipped || !bytes.Equal(res.Body, body) {
			t.Fatalf("%s: compression off changed the body (skipped=%v)", tc.name, res.Skipped)
		}
	}
}

func itemTypeOf(t *testing.T, item string) string {
	t.Helper()
	var v struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(item), &v); err != nil {
		t.Fatalf("bad item: %v", err)
	}
	return v.Type
}

// TestSummarizableBoundaryKeepsReasoningWithFollower: a rolling-summary
// boundary never separates a KeepWithNext message from the one after it,
// and the tool-pair expansion re-runs on the wider tail.
func TestSummarizableBoundaryKeepsReasoningWithFollower(t *testing.T) {
	t.Parallel()
	msgs := []Message{
		{Role: RoleUser, Text: "u0"},
		{Text: "r1", KeepWithNext: true},
		{Role: RoleAssistant, Text: "m2"},
		{Role: RoleUser, Text: "u3"},
		{Text: "r4", KeepWithNext: true},
		{Role: RoleAssistant, Text: "fc5", ToolUseIDs: []string{"c9"}},
		{Role: RoleTool, Text: "fco6", ReferencedIDs: []string{"c9"}},
		{Role: RoleUser, Text: "u7"},
	}
	cases := []struct {
		initialK, want int
	}{
		{initialK: 2, want: 1}, // would split r1 | m2
		{initialK: 3, want: 3}, // m2 | u3: no glue
		{initialK: 5, want: 4}, // would split r4 | fc5
		{initialK: 6, want: 4}, // tool pair pulls fc5 in, then glue pulls r4 in
		{initialK: 7, want: 7},
	}
	for _, tc := range cases {
		if got := summarizableBoundary(msgs, tc.initialK); got != tc.want {
			t.Errorf("summarizableBoundary(initialK=%d) = %d, want %d", tc.initialK, got, tc.want)
		}
	}
}
