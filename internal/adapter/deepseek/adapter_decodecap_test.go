package deepseek

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// oversizedFrame is a 16-byte zstd frame whose header declares a decoded
// size one byte past maxDecodedBytes (a single-segment frame, an 8-byte
// Frame_Content_Size, one raw block of one byte). It is small on disk; only
// a decoder that honours the declared size refuses it before decoding.
func oversizedFrame() []byte {
	b := []byte{0x28, 0xb5, 0x2f, 0xfd, 0xe0}
	b = binary.LittleEndian.AppendUint64(b, uint64(maxDecodedBytes)+1)
	// Block header: last block, raw, size 1; then the one byte.
	return append(b, 0x09, 0x00, 0x00, 'x')
}

// TestParseSessionFileSkipsAnOversizedDecode is RB1 sweep finding RBSW-6: a
// session file that decodes past maxDecodedBytes is skipped with a warning
// (and not retried), never decoded.
func TestParseSessionFileSkipsAnOversizedDecode(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".dsh", "sessions")
	dir := filepath.Join(root, "--work-project--", "session-019f1111-2222-7333-8444-555555555555")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, sessionLogName)
	if err := os.WriteFile(path, oversizedFrame(), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	want := "skipped: the session decodes to more than"
	found := false
	for _, w := range res.Warnings {
		found = found || strings.Contains(w, want)
	}
	if !found {
		t.Fatalf("warnings %q, want one starting %q", res.Warnings, want)
	}
	if res.RetrySuggested || len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 {
		t.Fatalf("an oversized session was decoded or queued for retry: %+v", res)
	}
}
