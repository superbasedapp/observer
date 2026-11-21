package scrub

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCustomAPIKeyPromptSuffix pins the row for Claude Code's "Detected a
// custom API key" prompt (build tracker F-058): the 20-character key
// suffix the prompt prints is removed wherever a terminal capture of that
// screen is scrubbed, with or without colour codes, while a bare run of
// characters and prose that only names the shape are left alone. The
// suffix is assembled from pieces so no literal here is credential-shaped.
func TestCustomAPIKeyPromptSuffix(t *testing.T) {
	suffix := strings.Repeat("Q7x_", 5) // 20 characters, the prompt's length
	const (
		warn  = "\x1b[33m"
		reset = "\x1b[39m"
		bold  = "\x1b[1m"
		unb   = "\x1b[22m"
	)
	cases := []struct {
		name   string
		in     string
		gone   bool   // the suffix must be redacted; false: the text is unchanged
		intact string // a substring that must survive ("" skips the check)
	}{
		{"plain line", "Detected a custom API key in your environment\nANTHROPIC_API_KEY: sk-ant-..." + suffix + "\nDo you want to use this API key?", true, "Do you want to use this API key?"},
		{"coloured label", "Detected a custom API key in your environment\n" + warn + "ANTHROPIC_API_KEY" + reset + ": sk-ant-..." + suffix + "\n", true, "Detected a custom API key in your environment"},
		{"bold label, then colour codes before the value", bold + "ANTHROPIC_API_KEY" + unb + ":" + warn + " sk-ant-..." + suffix + reset, true, "sk-ant-..."},
		{"value alone on a wrapped line", "\r\n  sk-ant-..." + suffix + "\r\n", true, "sk-ant-..."},
		{"unicode ellipsis", "ANTHROPIC_API_KEY: sk-ant-…" + suffix, true, ""},
		{"label with bare dots", warn + "ANTHROPIC_API_KEY" + reset + ": ..." + suffix, true, ""},
		{"suffix before a colour reset", "sk-ant-..." + suffix + reset + "\n", true, reset},
		{"colour after sk-ant-", warn + "ANTHROPIC_API_KEY" + reset + ": sk-ant-" + warn + "..." + suffix + reset, true, "sk-ant-"},
		{"colour after the mark", warn + "ANTHROPIC_API_KEY" + reset + ": sk-ant-..." + warn + suffix + reset, true, "..." + warn},
		{"JSON-escaped colour codes", `ANTHROPIC_API_KEY\u001b[39m: sk-ant-\u001b[2m...\u001b[22m` + suffix, true, `\u001b[22m`},
		{"a bare 20-character run", "build id " + suffix + " done", false, "build id " + suffix + " done"},
		{"prose after a coloured label", warn + "ANTHROPIC_API_KEY" + reset + ": ...see below", false, ""},
		{"a suffix under 8 characters", "sk-ant-...abc1234 is the shape", false, "sk-ant-...abc1234 is the shape"},
		{"prose naming the shape", "keys look like sk-ant-... in the prompt", false, "keys look like sk-ant-... in the prompt"},
	}
	s := New()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := s.String(c.in)
			if !c.gone {
				if out != c.in {
					t.Fatalf("changed text the row must leave alone: %q -> %q", c.in, out)
				}
				return
			}
			if strings.Contains(out, suffix) || !HasRedaction(out) {
				t.Fatalf("the suffix was not redacted: %q", out)
			}
			if c.intact != "" && !strings.Contains(out, c.intact) {
				t.Fatalf("%q lost %q", out, c.intact)
			}
			if again := s.String(out); again != out {
				t.Fatalf("not idempotent: %q -> %q", out, again)
			}
		})
	}
}

// TestCustomAPIKeyPromptSuffixForwardJSON (audit FU12-A2): the row runs on
// proxied bodies too (ScrubForward), so a JSON body holding the prompt's
// screen, colour codes JSON-escaped, keeps valid JSON, loses the suffix and
// is stable under a second pass.
func TestCustomAPIKeyPromptSuffixForwardJSON(t *testing.T) {
	suffix := strings.Repeat("Q7x_", 5)
	screen := "Detected a custom API key in your environment\n\x1b[33mANTHROPIC_API_KEY\x1b[39m: sk-ant-\x1b[2m...\x1b[22m" + suffix + "\nDo you want to use this API key?"
	body, err := json.Marshal(map[string]any{"messages": []map[string]string{{"role": "user", "content": screen}}})
	if err != nil {
		t.Fatal(err)
	}
	s := New()
	out := s.ScrubForward(body)
	if !json.Valid(out) {
		t.Fatalf("not valid JSON: %s", out)
	}
	if strings.Contains(string(out), suffix) || !HasRedaction(string(out)) {
		t.Fatalf("the suffix was not redacted: %s", out)
	}
	if again := s.ScrubForward(out); string(again) != string(out) {
		t.Fatalf("not idempotent: %s -> %s", out, again)
	}
}
