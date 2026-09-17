package cursor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// plantedKey is an Anthropic-shaped credential the default scrubber
// redacts (`(?:sk|pk|ak)[_-][A-Za-z0-9_-]{16,}`).
const plantedKey = "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFF"

func scrubTestTurn() transcriptTurn {
	return transcriptTurn{
		User: transcriptUserLine{
			LineNumber: 3,
			Text:       "<user_query>\ndeploy using " + plantedKey + "\n</user_query>",
		},
		Assistant: []transcriptAssistantLine{{
			LineNumber: 4,
			Parts: []transcriptPart{
				{Type: "text", Text: "I will call the API with " + plantedKey + " now"},
				{
					Type:  "tool_use",
					Name:  "Shell",
					Input: json.RawMessage(`{"command":"curl -H 'x-api-key: ` + plantedKey + `' https://api.example.com"}`),
				},
			},
		}},
	}
}

// TestTranscriptBuildersScrubEveryContentField pins P1-1: every
// content-bearing field the transcript builders emit must be redacted,
// on BOTH the live path (a real scrubber) and the
// forgot-to-pass-one path (nil), which the builders now upgrade to a
// default scrubber instead of skipping the pass.
func TestTranscriptBuildersScrubEveryContentField(t *testing.T) {
	paths := []struct {
		name string
		sc   *scrub.Scrubber
	}{
		{name: "nil_scrubber_upgraded", sc: nil},
		{name: "live_scrubber", sc: scrub.New()},
	}

	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			turn := scrubTestTurn()
			ts := time.Unix(0, 0).UTC()

			userEv, ok := BuildTranscriptUserPromptEvent(turn, "sess-1", "/repo", "gen-X", "/tmp/x.jsonl", ts, p.sc)
			if !ok {
				t.Fatal("expected a user_prompt event")
			}
			toolEvs := BuildTranscriptToolEvents(turn, "sess-1", "/repo", "gen-X", "/tmp/x.jsonl", ts, p.sc)
			if len(toolEvs) != 2 {
				t.Fatalf("tool events = %d, want 2 (assistant_text + tool_use)", len(toolEvs))
			}
			var asst, shell models.ToolEvent
			for _, ev := range toolEvs {
				switch ev.RawToolName {
				case "cursor.assistant_text":
					asst = ev
				default:
					shell = ev
				}
			}
			if shell.RawToolName == "" {
				t.Fatal("no tool_use event emitted")
			}

			fields := []struct {
				name string
				got  string
			}{
				{"user_prompt.Target", userEv.Target},
				{"user_prompt.RawToolInput", userEv.RawToolInput},
				{"user_prompt.PrecedingReasoning", userEv.PrecedingReasoning},
				{"assistant_text.Target", asst.Target},
				{"assistant_text.PrecedingReasoning", asst.PrecedingReasoning},
				{"assistant_text.ToolOutput", asst.ToolOutput},
				{"tool_use.Target", shell.Target},
				{"tool_use.RawToolInput", shell.RawToolInput},
				{"tool_use.PrecedingReasoning", shell.PrecedingReasoning},
			}
			for _, f := range fields {
				if strings.Contains(f.got, plantedKey) {
					t.Errorf("%s leaks the planted key: %q", f.name, f.got)
				}
				if f.got != "" && !strings.Contains(f.got, scrub.Redacted) {
					t.Errorf("%s = %q, want a %s marker", f.name, f.got, scrub.Redacted)
				}
			}

			// Surrounding content survives the redaction.
			if !strings.Contains(userEv.Target, "deploy using") {
				t.Errorf("user_prompt.Target lost its prose: %q", userEv.Target)
			}
			if !strings.Contains(shell.Target, "curl") {
				t.Errorf("tool_use.Target lost its command: %q", shell.Target)
			}
			if !json.Valid([]byte(shell.RawToolInput)) {
				t.Errorf("tool_use.RawToolInput is no longer valid JSON: %q", shell.RawToolInput)
			}
		})
	}
}
