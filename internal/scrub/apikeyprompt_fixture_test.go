package scrub

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// promptSentinelSuffix is the last 20 characters of the sentinel value the
// FU12-L1 capture ran Claude Code with (never a key): the part the prompt
// prints after "sk-ant-...".
const promptSentinelSuffix = "INELSENTINELSENTINEL"

// suffixPieces returns every 4-character window of the sentinel suffix, so
// a test can assert that no part of it, not only the whole, survives.
func suffixPieces() []string {
	var out []string
	for i := 0; i+4 <= len(promptSentinelSuffix); i++ {
		out = append(out, promptSentinelSuffix[i:i+4])
	}
	return out
}

func readPromptFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), promptSentinelSuffix) {
		t.Fatalf("%s does not hold the sentinel suffix", name)
	}
	return string(b)
}

// TestCustomAPIKeyPromptFixture (live row FU12-L1, tracker F-058) runs the
// raw bytes of Claude Code 2.1.318's "Detected a custom API key" screen,
// recorded through a pty with a sentinel value, through String and
// ScrubForward. The raw stream differs from a cleaned rendering: a CSI 22 G
// cursor move instead of a space after "ANTHROPIC_API_KEY:", three ASCII
// dots, bold SGR only around the variable name, and (TERM unset) no SGR at
// all and letters dropped from other words. No part of the suffix may
// survive, the rest of the screen must, and a JSON body carrying the screen
// must stay valid JSON.
//
// The colour stream is rewritten by the F-058 row alone: only the suffix.
// On the TERM-unset stream no SGR code sits between the label and its
// colon, so the generic "api_key: value" assignment row also fires after
// the F-058 row and takes the whole value from the cursor move on; on the
// JSON-escaped body ("\r" is two characters there) its value runs to the
// next space, so the next line's cursor moves go with it. Both rewrites are
// deterministic and the body stays valid JSON; the test pins them exactly.
func TestCustomAPIKeyPromptFixture(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		intact  []string // substrings of the screen that must survive
		// rawFrom and jsonFrom: the text the redaction replaces in the raw
		// stream and in the JSON body's decoded content, from its start up
		// to (not including) the given end marker; "" ends at the suffix.
		rawFrom, rawTo, jsonFrom, jsonTo string
	}{
		{
			name:     "TERM=xterm-256color, COLORTERM=truecolor",
			fixture:  "claude-custom-api-key-prompt.txt",
			intact:   []string{"\x1b[1mANTHROPIC_API_KEY\x1b[22m:\x1b[22Gsk-ant-..." + Redacted + "\r", "Detected a custom API key in your environment", "No (\x1b[1mrecommended\x1b[22m)", "Esc to cancel"},
			rawFrom:  promptSentinelSuffix,
			jsonFrom: promptSentinelSuffix,
		},
		{
			name:     "TERM unset",
			fixture:  "claude-custom-api-key-prompt-noterm.txt",
			intact:   []string{"\x1b[1BANTHROPIC_API_KEY:" + Redacted, "Detected a custom API key\x1b[29Gin your environment", "No (recomm\x1b[16Gnded)", "Esc to ca\x1b[32Gcel"},
			rawFrom:  "\x1b[22Gsk-ant-...",
			jsonFrom: "\x1b[22Gsk-ant-...",
			jsonTo:   " Do\x1b[6G",
		},
	}
	s := New()
	for _, c := range cases {
		screen := readPromptFixture(t, c.fixture)
		body, err := json.Marshal(map[string]any{"messages": []map[string]string{{"role": "user", "content": screen}}})
		if err != nil {
			t.Fatal(err)
		}
		runs := []struct {
			path string
			out  string
			json bool
			want string
		}{
			{"String", s.String(screen), false, redactSpan(t, screen, c.rawFrom, c.rawTo)},
			{"ScrubForward raw", string(s.ScrubForward([]byte(screen))), false, redactSpan(t, screen, c.rawFrom, c.rawTo)},
			{"ScrubForward JSON body", string(s.ScrubForward(body)), true, redactSpan(t, screen, c.jsonFrom, c.jsonTo)},
		}
		for _, r := range runs {
			t.Run(c.name+"/"+r.path, func(t *testing.T) {
				for _, p := range suffixPieces() {
					if strings.Contains(r.out, p) {
						t.Fatalf("part %q of the suffix survived: %q", p, r.out)
					}
				}
				if !HasRedaction(r.out) {
					t.Fatalf("no redaction marker: %q", r.out)
				}
				if r.json {
					if !json.Valid([]byte(r.out)) {
						t.Fatalf("not valid JSON: %s", r.out)
					}
					var got struct {
						Messages []struct{ Content string } `json:"messages"`
					}
					if err := json.Unmarshal([]byte(r.out), &got); err != nil || len(got.Messages) != 1 {
						t.Fatalf("body shape lost: %v %s", err, r.out)
					}
					r.out = got.Messages[0].Content
				}
				for _, keep := range c.intact {
					if !strings.Contains(r.out, keep) {
						t.Fatalf("lost %q: %q", keep, r.out)
					}
				}
				if again := s.String(r.out); again != r.out {
					t.Fatalf("not idempotent: %q -> %q", r.out, again)
				}
				if r.out != r.want {
					t.Fatalf("rewrite differs:\n got %q\nwant %q", r.out, r.want)
				}
			})
		}
	}
}

// redactSpan returns screen with the text from the first from (which must
// precede the suffix) through the suffix replaced by Redacted; a non-empty
// to extends the span up to, not including, the first to after the suffix.
func redactSpan(t *testing.T, screen, from, to string) string {
	t.Helper()
	i := strings.Index(screen, promptSentinelSuffix)
	start := strings.LastIndex(screen[:i+len(promptSentinelSuffix)], from)
	if i < 0 || start < 0 || start > i {
		t.Fatalf("span start %q not before the suffix", from)
	}
	end := i + len(promptSentinelSuffix)
	if to != "" {
		j := strings.Index(screen[end:], to)
		if j < 0 {
			t.Fatalf("span end %q not after the suffix", to)
		}
		end += j
	}
	return screen[:start] + Redacted + screen[end:]
}

// TestCustomAPIKeyPromptFixtureNegative: ordinary terminal output in the
// same raw shape (CSI n G cursor moves, bold SGR around a name, three ASCII
// dots, dropped letters) is left byte-identical by String and by
// ScrubForward, which returns its input slice unchanged.
func TestCustomAPIKeyPromptFixtureNegative(t *testing.T) {
	keyLine := func(name string) string {
		screen := readPromptFixture(t, name)
		i := strings.Index(screen, promptSentinelSuffix)
		start := strings.LastIndex(screen[:i], "\r")
		return screen[:start] + screen[i+len(promptSentinelSuffix):]
	}
	cases := []struct{ name, in string }{
		{"colour screen without its key line", keyLine("claude-custom-api-key-prompt.txt")},
		{"TERM-unset screen without its key line", keyLine("claude-custom-api-key-prompt-noterm.txt")},
		{"label with a cursor move and prose", "\x1b[1mANTHROPIC_API_KEY\x1b[22m:\x1b[22G(not set)\r\n"},
		{"another bold label, a cursor move and dots", "\x1b[1mMODEL\x1b[22m:\x1b[22G...claude-sonnet-loading\r\n"},
		{"progress dots after a cursor move", "\x1b[2C\x1b[1BLoading\x1b[12G...done\x1b[K\r\n"},
		{"bold name, dots and a long word", "\x1b[1mBUILD_ID\x1b[22m:\x1b[22G...ABCDEFGHIJKLMNOPQRST\r\n"},
		{"dropped letters", "Enter to\x1b[12Gc\x1b[14Gnfirm \xc2\xb7 Esc to ca\x1b[32Gcel"},
		{"prose naming the shape on a raw stream", "\x1b[3mkeys look like sk-ant-... in the prompt\x1b[23m\r\n"},
	}
	s := New()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if strings.Contains(c.in, promptSentinelSuffix) {
				t.Fatalf("negative row holds the suffix: %q", c.in)
			}
			if out := s.String(c.in); out != c.in {
				t.Fatalf("String changed ordinary output: %q -> %q", c.in, out)
			}
			in := []byte(c.in)
			if out := s.ScrubForward(in); string(out) != c.in || &out[0] != &in[0] {
				t.Fatalf("ScrubForward changed ordinary output: %q -> %q", c.in, out)
			}
		})
	}
}
