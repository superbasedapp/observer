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

// TestBoxRefsReachOnCommit (lane SEC-F2B, security plan 7.10 M7): a commit
// a sandbox box returned under refs/observer/sandbox/<run>, or on the
// worktree source's observer-sandbox/<run>/<label> branch, is offered to
// OnBoxCommit with its box ref, never written to the ledger, and not offered
// again while the ref has not moved; HEAD's own commits carry no box ref.
func TestBoxRefsReachOnCommit(t *testing.T) {
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
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q")
	git("symbolic-ref", "HEAD", "refs/heads/main")
	write("a.go", "package a\n")
	git("add", "a.go")
	git("commit", "-q", "-m", "base")
	git("checkout", "-q", "-b", "box")
	write("b.go", "package a\n\nvar b = 1\n")
	git("add", "b.go")
	git("commit", "-q", "-m", "box work")
	boxSHA := git("rev-parse", "HEAD")
	git("update-ref", "refs/observer/sandbox/run-1", boxSHA)
	git("checkout", "-q", "-b", "observer-sandbox/run-2/work", "main")
	write("c.go", "package a\n\nvar c = 1\n")
	git("add", "c.go")
	git("commit", "-q", "-m", "worktree work")
	wtSHA := git("rev-parse", "HEAD")
	git("checkout", "-q", "main")
	git("branch", "-q", "-D", "box")

	fs := newFakeStore()
	var mu sync.Mutex
	got := map[string]string{}
	sc := New(Options{
		Roots: func(context.Context) ([]Root, error) { return []Root{{ProjectID: 1, RootPath: root}}, nil },
		Exec: func(ctx context.Context, dir string, maxBytes int, args ...string) ([]byte, bool, error) {
			cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
			out, err := cmd.Output()
			return out, false, err
		},
		State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		OnCommit: func(_ context.Context, r Root, c commitlog.Commit) {
			mu.Lock()
			defer mu.Unlock()
			got[c.SHA] = r.BoxRef
		},
		BoxActive: func() bool { return true },
		OnBoxCommit: func(_ context.Context, r Root, c commitlog.Commit) bool {
			mu.Lock()
			defer mu.Unlock()
			got[c.SHA] = r.BoxRef
			return true
		},
	})
	if _, err := sc.ScanNow(context.Background(), Root{ProjectID: 1, RootPath: root}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if got[boxSHA] != "refs/observer/sandbox/run-1" || got[wtSHA] != "refs/heads/observer-sandbox/run-2/work" {
		t.Fatalf("box commits offered %v", got)
	}
	base := git("rev-parse", "main")
	if ref, ok := got[base]; !ok || ref != "" {
		t.Fatalf("HEAD's commit offered with box ref %q (%v)", ref, ok)
	}
	got = map[string]string{}
	mu.Unlock()
	fs.mu.Lock()
	for _, c := range fs.sunk[1] {
		if c.SHA == boxSHA || c.SHA == wtSHA {
			t.Fatalf("a box commit reached the ledger: %s", c.SHA)
		}
	}
	fs.mu.Unlock()
	if _, err := sc.ScanNow(context.Background(), Root{ProjectID: 1, RootPath: root}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, again := got[boxSHA]; again {
		t.Fatal("an unmoved box ref was offered again")
	}
	if BoxRunID("refs/observer/sandbox/run-1") != "run-1" || BoxRunID("refs/heads/observer-sandbox/run-2/work") != "run-2" || BoxRunID("refs/heads/main") != "" {
		t.Fatal("BoxRunID")
	}
}
