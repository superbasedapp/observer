package claudecode

import (
	"path/filepath"
	"testing"
)

// TestCursorSemanticsFor pins the two capabilities the watcher's
// oversize DoS guard reads: the cursor is a real byte offset (so the
// guard applies at all), and the parse seeks-and-streams from it (so
// the guard bounds the unread tail, not the whole file).
func TestCursorSemanticsFor(t *testing.T) {
	root := t.TempDir()
	a := NewWithOptions(nil, root)

	cases := []struct {
		name          string
		path          string
		wantStreams   bool
		wantDeltaGate bool
	}{
		{
			name:          "transcript under the watch root streams from its cursor",
			path:          filepath.Join(root, "projects", "repo", "sess.jsonl"),
			wantStreams:   true,
			wantDeltaGate: true,
		},
		{
			name:          "a path this adapter does not claim gets the zero value",
			path:          filepath.Join(root, "notes.txt"),
			wantStreams:   false,
			wantDeltaGate: false,
		},
		{
			name:          "a transcript outside the watch root gets the zero value",
			path:          filepath.Join(t.TempDir(), "sess.jsonl"),
			wantStreams:   false,
			wantDeltaGate: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sem := a.CursorSemanticsFor(tc.path)
			if sem.StreamsFromCursor != tc.wantStreams {
				t.Errorf("StreamsFromCursor = %v, want %v", sem.StreamsFromCursor, tc.wantStreams)
			}
			if sem.DeltaGateMeaningful() != tc.wantDeltaGate {
				t.Errorf("DeltaGateMeaningful() = %v, want %v", sem.DeltaGateMeaningful(), tc.wantDeltaGate)
			}
			// The cursor stays a byte offset, so the guard still applies.
			if !sem.Kind.SizeGateMeaningful() {
				t.Error("SizeGateMeaningful() = false; a JSONL transcript must stay gated")
			}
		})
	}
}
