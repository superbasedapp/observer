package commitscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
)

// TestBoxRefsGatedAndRetried (SEC-F2B merge audit finding 4): no box ref is
// listed while BoxActive answers false (no `git for-each-ref` on an install
// without security.provenance), and a box ref's tip is remembered only once
// OnBoxCommit decided its commits, so a seam that did not decide them gets
// them again on the next scan.
func TestBoxRefsGatedAndRetried(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x.invalid", "GIT_COMMITTER_NAME=t",
			"GIT_COMMITTER_EMAIL=t@x.invalid", "GIT_CONFIG_NOSYSTEM=1", "HOME="+root)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("symbolic-ref", "HEAD", "refs/heads/main")
	if err := os.WriteFile(filepath.Join(root, "a.go"), []byte("package a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "a.go")
	git("commit", "-q", "-m", "base")
	git("checkout", "-q", "-b", "box")
	if err := os.WriteFile(filepath.Join(root, "b.go"), []byte("package a\n\nvar b = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "b.go")
	git("commit", "-q", "-m", "box work")
	boxSHA := git("rev-parse", "HEAD")
	git("update-ref", "refs/observer/sandbox/run-1", boxSHA)
	git("checkout", "-q", "main")
	git("branch", "-q", "-D", "box")

	var mu sync.Mutex
	active, decide := false, false
	listings, offers := 0, 0
	fs := newFakeStore()
	sc := New(Options{
		Roots: func(context.Context) ([]Root, error) { return []Root{{ProjectID: 1, RootPath: root}}, nil },
		Exec: func(ctx context.Context, dir string, maxBytes int, args ...string) ([]byte, bool, error) {
			if len(args) > 0 && args[0] == "for-each-ref" {
				mu.Lock()
				listings++
				mu.Unlock()
			}
			out, err := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...).Output()
			return out, false, err
		},
		State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		OnCommit:     func(context.Context, Root, commitlog.Commit) {},
		BoxActive: func() bool {
			mu.Lock()
			defer mu.Unlock()
			return active
		},
		OnBoxCommit: func(_ context.Context, r Root, c commitlog.Commit) bool {
			mu.Lock()
			defer mu.Unlock()
			if c.SHA == boxSHA && r.BoxRef == "refs/observer/sandbox/run-1" {
				offers++
			}
			return decide
		},
	})
	scan := func() {
		t.Helper()
		if _, err := sc.ScanNow(context.Background(), Root{ProjectID: 1, RootPath: root}); err != nil {
			t.Fatal(err)
		}
	}
	check := func(step string, wantListings, wantOffers int) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if listings != wantListings || offers != wantOffers {
			t.Fatalf("%s: %d listings and %d offers, want %d and %d", step, listings, offers, wantListings, wantOffers)
		}
	}
	scan()
	check("provenance off", 0, 0)
	mu.Lock()
	active = true
	mu.Unlock()
	scan()
	check("on, the seam did not decide", 1, 1)
	scan()
	check("not decided: offered again", 2, 2)
	mu.Lock()
	decide = true
	mu.Unlock()
	scan()
	check("decided", 3, 3)
	scan()
	check("decided: the unmoved ref is not offered again", 4, 3)
}
