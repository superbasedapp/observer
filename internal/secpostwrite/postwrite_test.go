package secpostwrite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secdetect"
)

// fakeAWSKeyID is shaped like an AWS key id and visibly fake. It is not an
// ...EXAMPLE value on purpose: secdetect never fires on an AWS-shaped key
// ending in EXAMPLE (knownExample), and these tests need a hit.
const fakeAWSKeyID = "AKIA" + "FAKEFIXTURE0TEST" // split: GitHub push protection on the public mirror

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadFileRules(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(root, "a.py"), "x = 1\n")
	writeFile(t, filepath.Join(outside, "secret.txt"), "k\n")
	writeFile(t, filepath.Join(root, "big.txt"), strings.Repeat("x", 100))
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	symlinks := runtime.GOOS != "windows"
	if symlinks {
		if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "linkdir")); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		rel  string
		max  int
		want error
		skip bool
	}{
		{"a.py", 1024, nil, false},
		{"../" + filepath.Base(outside) + "/secret.txt", 1024, ErrOutsideRoot, false},
		{"/etc/passwd", 1024, ErrOutsideRoot, false},
		{"big.txt", 10, ErrTooLarge, false},
		{"dir", 1024, ErrNotRegular, false},
		{"link.txt", 1024, ErrSymlink, !symlinks},
		{"linkdir/secret.txt", 1024, ErrOutsideRoot, !symlinks},
	}
	for _, tc := range cases {
		if tc.skip {
			continue
		}
		_, err := ReadFile(root, tc.rel, tc.max)
		if !errors.Is(err, tc.want) && !(tc.want == nil && err == nil) {
			t.Errorf("ReadFile(%q) err = %v, want %v", tc.rel, err, tc.want)
		}
	}
}

func TestQueueScansAndNeverForwardsContent(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "cfg/prod.py"), "x = 1\nk = \""+fakeAWSKeyID+"\"\n")
	writeFile(t, filepath.Join(root, "ok.go"), "package ok\n")
	var got []Result
	q := &Queue{Sink: func(_ context.Context, r Result) { got = append(got, r) }}
	q.Submit(Write{ProjectRoot: root, Path: "cfg/prod.py", ActionID: 1})
	if q.Submit(Write{ProjectRoot: root, Path: "cfg/prod.py", ActionID: 2}) {
		t.Fatal("a queued path was queued twice")
	}
	q.Submit(Write{ProjectRoot: root, Path: "ok.go"})
	q.Submit(Write{ProjectRoot: root, Path: "missing.go"})
	q.Submit(Write{ProjectRoot: root, Path: "x.go", CopyWorkspace: true})
	if n := q.Drain(context.Background()); n != 4 {
		t.Fatalf("drained %d, want 4", n)
	}
	if got[0].Scan.Status != secdetect.StatusHits || got[0].Scan.Hits[0].Line != 2 {
		t.Fatalf("prod.py = %+v", got[0])
	}
	if got[1].Scan.Status != secdetect.StatusClean {
		t.Fatalf("ok.go = %+v", got[1])
	}
	if got[2].NotScanned != NotScannedGone || got[3].NotScanned != NotScannedCopyWorkspace {
		t.Fatalf("not scanned = %q, %q", got[2].NotScanned, got[3].NotScanned)
	}
	for _, r := range got {
		if strings.Contains(strings.ToUpper(strings.Join([]string{r.Refusal, string(r.NotScanned)}, " ")), "AKIA") {
			t.Fatal("content leaked into a result")
		}
	}
	// After a drain the path may be queued again.
	if !q.Submit(Write{ProjectRoot: root, Path: "cfg/prod.py"}) {
		t.Fatal("path not re-queueable after drain")
	}
}

func TestQueueBound(t *testing.T) {
	q := &Queue{Max: 2}
	for i := 0; i < 5; i++ {
		q.Submit(Write{ProjectRoot: "/r", Path: string(rune('a' + i))})
	}
	if q.Dropped() != 3 {
		t.Fatalf("dropped %d, want 3", q.Dropped())
	}
}

func TestQueueCopyWorkspaceVisible(t *testing.T) {
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "k.py"), "k = \""+fakeAWSKeyID+"\"\n")
	var got Result
	q := &Queue{Sink: func(_ context.Context, r Result) { got = r }}
	q.Submit(Write{ProjectRoot: "/elsewhere", Path: "k.py", CopyWorkspace: true, WorkspaceRoot: ws})
	q.Drain(context.Background())
	if got.Scan.Status != secdetect.StatusHits {
		t.Fatalf("copy workspace on the host = %+v", got)
	}
}
