package poolside

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCRLFAndBlankLinesAdvanceTheCursorExactly is the
// [[feedback-jsonl-parser-cursor]] pin. bufio.Scanner strips the line
// terminator, so `len(line)+1` arithmetic silently under-counts by one
// byte on every CRLF line and loops forever on a blank one. The parser
// uses bufio.Reader.ReadString('\n') and adds the FULL returned length,
// so a CRLF file's cursor must still land exactly on the file size and
// every event must still be produced.
func TestCRLFAndBlankLinesAdvanceTheCursorExactly(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "poolside", fixtureName))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	lf := string(body)
	// LF → CRLF, plus a blank CRLF line spliced into the middle.
	lines := strings.SplitAfter(lf, "\n")
	var b strings.Builder
	for i, line := range lines {
		if line == "" {
			continue
		}
		b.WriteString(strings.TrimSuffix(line, "\n"))
		b.WriteString("\r\n")
		if i == len(lines)/2 {
			b.WriteString("\r\n")
		}
	}
	crlf := b.String()

	root := filepath.Join(t.TempDir(), "poolside", "trajectories")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	trajPath := filepath.Join(root, fixtureName)
	if err := os.WriteFile(trajPath, []byte(crlf), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), trajPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if res.NewOffset != int64(len(crlf)) {
		t.Errorf("NewOffset = %d, want the CRLF file size %d — the cursor drifted by %d bytes",
			res.NewOffset, len(crlf), int64(len(crlf))-res.NewOffset)
	}

	// The CRLF parse must produce exactly the same events as the LF one.
	if err := os.WriteFile(trajPath, body, 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	lfRes, err := a.ParseSessionFile(context.Background(), trajPath, 0)
	if err != nil {
		t.Fatalf("lf parse: %v", err)
	}
	if len(lfRes.ToolEvents) != len(res.ToolEvents) || len(lfRes.TokenEvents) != len(res.TokenEvents) {
		t.Fatalf("CRLF parse produced %d/%d events, LF produced %d/%d",
			len(res.ToolEvents), len(res.TokenEvents),
			len(lfRes.ToolEvents), len(lfRes.TokenEvents))
	}
	for i := range lfRes.ToolEvents {
		if lfRes.ToolEvents[i].SourceEventID != res.ToolEvents[i].SourceEventID {
			t.Errorf("event %d id differs between LF and CRLF: %q vs %q",
				i, lfRes.ToolEvents[i].SourceEventID, res.ToolEvents[i].SourceEventID)
		}
	}
	if len(res.ToolEvents) == 0 {
		t.Error("the CRLF parse produced nothing — the comparison is vacuous")
	}
}

// TestTrailingPartialLineIsDeferred pins that a record still being
// written (no terminating newline) is NOT consumed, so the next parse
// re-reads it whole.
func TestTrailingPartialLineIsDeferred(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "poolside", "malformed.ndjson"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	partial := string(body) + `{"id":"ev-partial","step_id":"","timestamp":"2026-09-05T01:12:00.0000000+00:00","type":"tool_call.pars`

	root := filepath.Join(t.TempDir(), "poolside", "trajectories")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	trajPath := filepath.Join(root, fixtureName)
	if err := os.WriteFile(trajPath, []byte(partial), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), trajPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if res.NewOffset != int64(len(body)) {
		t.Errorf("NewOffset = %d, want %d (the offset BEFORE the partial line)", res.NewOffset, len(body))
	}
}
