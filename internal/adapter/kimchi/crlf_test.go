package kimchi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCRLFTranscript rewrites a live fixture with CRLF terminators (a
// Windows editor or git autocrlf) and requires the same rows and an offset
// that lands exactly on EOF — bufio.Reader.ReadString, not Scanner's
// len(line)+1 arithmetic ([[feedback-jsonl-parser-cursor]]).
func TestCRLFTranscript(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "kimchi", "session-windows.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lf := strings.ReplaceAll(string(src), "\r\n", "\n")
	crlf := strings.ReplaceAll(lf, "\n", "\r\n")

	aLF, pLF := writeSession(t, []byte(lf), winSessionID)
	aCR, pCR := writeSession(t, []byte(crlf), winSessionID)
	resLF, resCR := parse(t, aLF, pLF, 0), parse(t, aCR, pCR, 0)

	if resCR.NewOffset != int64(len(crlf)) {
		t.Errorf("CRLF NewOffset = %d, want %d", resCR.NewOffset, len(crlf))
	}
	if len(resCR.Warnings) != 0 {
		t.Errorf("CRLF warnings: %v", resCR.Warnings)
	}
	if len(resLF.ToolEvents) != len(resCR.ToolEvents) || len(resLF.TokenEvents) != len(resCR.TokenEvents) {
		t.Fatalf("LF rows %d/%d vs CRLF rows %d/%d", len(resLF.ToolEvents), len(resLF.TokenEvents),
			len(resCR.ToolEvents), len(resCR.TokenEvents))
	}
	for i := range resLF.ToolEvents {
		if resLF.ToolEvents[i].SourceEventID != resCR.ToolEvents[i].SourceEventID {
			t.Errorf("row %d id %s vs %s", i, resLF.ToolEvents[i].SourceEventID, resCR.ToolEvents[i].SourceEventID)
		}
	}
}
