package secpostwrite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestQueueCopyWorkspaceReadRules (lane sec-box): a copy workspace's read
// keeps every rule of the project root's: a symlink in the copy and a
// path that leaves the copy are refused, never read; the same path in two
// trees is queued once per tree; and a copy only inside a box is reported
// copy_workspace without any read.
func TestQueueCopyWorkspaceReadRules(t *testing.T) {
	ws := t.TempDir()
	out := filepath.Join(t.TempDir(), "outside.py")
	writeFile(t, out, "k = \""+fakeAWSKeyID+"\"\n")
	if err := os.Symlink(out, filepath.Join(ws, "link.py")); err != nil {
		t.Skip("no symlinks here")
	}
	reads := 0
	var got []Result
	q := &Queue{Sink: func(_ context.Context, r Result) { got = append(got, r) }}
	read := ReadFile
	q.Read = func(root, rel string, n int) ([]byte, error) { reads++; return read(root, rel, n) }
	q.Submit(Write{ProjectRoot: "/p", Path: "link.py", CopyWorkspace: true, WorkspaceRoot: ws})
	q.Submit(Write{ProjectRoot: "/p", Path: "../outside.py", CopyWorkspace: true, WorkspaceRoot: ws})
	q.Submit(Write{ProjectRoot: "/p", Path: "a.py", CopyWorkspace: true})
	if !q.Submit(Write{ProjectRoot: "/p", Path: "a.py"}) {
		t.Fatal("the same path in the live tree was deduplicated against the box's")
	}
	q.Drain(context.Background())
	if len(got) != 4 {
		t.Fatalf("results %+v", got)
	}
	for i, want := range []NotScanned{NotScannedRefused, NotScannedRefused, NotScannedCopyWorkspace} {
		if got[i].NotScanned != want {
			t.Errorf("write %d: %q, want %q", i, got[i].NotScanned, want)
		}
	}
	if reads != 3 {
		t.Errorf("reads %d: the in-box write must not be read", reads)
	}
}
