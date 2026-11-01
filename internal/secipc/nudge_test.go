package secipc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/localipc"
)

// TestCommitNudge: an allowed root reaches the daemon's nudger; a refused
// root, a relative root and an old version never do; the hook's send never
// waits for an answer.
func TestCommitNudge(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no owner-only IPC transport on this platform")
	}
	dir, err := os.MkdirTemp("", "secipcnudge")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, ep, err := Listen(filepath.Join(dir, "security"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	got := make(chan string, 4)
	root := filepath.Join(dir, "repo")
	go func() {
		_ = ServeWith(ctx, ln, nil, Options{
			Nudge:     func(r string) { got <- r },
			AllowRoot: func(r string) bool { return r == root },
		})
	}()
	start := time.Now()
	if err := SendCommitNudge(ctx, ep, root); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > NudgeBudget {
		t.Fatalf("the send took %v", time.Since(start))
	}
	select {
	case r := <-got:
		if r != root {
			t.Fatalf("nudged %q", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the nudge never arrived")
	}
	for _, r := range []string{filepath.Join(dir, "other"), "relative/repo"} {
		_ = SendCommitNudge(ctx, ep, r)
	}
	if takeNudge(nudgeWireRequest{V: 99, Kind: KindCommitNudge, ProjectRoot: root}, func(string) { got <- "v99" }, nil) {
		t.Fatal("a nudge of another version was taken")
	}
	select {
	case r := <-got:
		t.Fatalf("a refused nudge arrived: %q", r)
	case <-time.After(300 * time.Millisecond):
	}
}
