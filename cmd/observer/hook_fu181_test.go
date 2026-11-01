package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestFU181ReceiverTrimsTheStreamItself (FU-181) pins the BOM trim where the
// Claude Code hook stream is built (claudeCodeHookPayload) on its own,
// without a decoder: the later strips in each decoder (FU-161 defence in
// depth) would hide a missing receiver trim from the behaviour tests. Every
// row reads the raw stream the handlers get. The over-bound row is the case
// no decoder ever sees whole: its stream must still start at the payload,
// not at the mark, and it is never classified.
func TestFU181ReceiverTrimsTheStreamItself(t *testing.T) {
	const bom = "\xef\xbb\xbf"
	small := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	big := `{"session_id":"s1","pad":"` + strings.Repeat("x", promptSubmitBodyLimit) + `"}`
	cases := []struct {
		name, in, wantStream string
		wantBody             bool
	}{
		{"bom, in bound", bom + small, small, true},
		{"no bom, in bound", small, small, true},
		{"bom, over bound", bom + big, big, false},
		{"only the first mark is the stream's", bom + bom + small, bom + small, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdin, body, _ := claudeCodeHookPayload(strings.NewReader(c.in), "pre-tool", "")
			got, err := io.ReadAll(stdin)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, []byte(c.wantStream)) {
				t.Errorf("stream starts %q (len %d), want %q (len %d)", head(got), len(got), head([]byte(c.wantStream)), len(c.wantStream))
			}
			switch {
			case c.wantBody && string(body) != c.wantStream:
				t.Errorf("classified body starts %q, want the stream's bytes", head(body))
			case !c.wantBody && body != nil:
				t.Errorf("an over-bound payload was classified (body len %d)", len(body))
			}
		})
	}
}

// head is the first bytes of b, for a readable failure.
func head(b []byte) []byte {
	if len(b) > 24 {
		return b[:24]
	}
	return b
}
