package secquickscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/gitview"
)

// newScanRepo is a throwaway repository with a commit helper.
func newScanRepo(t *testing.T) (string, func(name, body string) string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("config", "user.email", "t@example.invalid")
	git("config", "user.name", "t")
	return dir, func(name, body string) string {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		git("add", name)
		git("commit", "-q", "-m", name)
		return git("rev-parse", "HEAD")
	}
}

// TestCommitScanCapsAndAdvances (lane SEC-GATEFIX milestone 2b): a range
// over the commit cap walks the newest commits, counts the rest as
// skipped (an unknown run), and advances, so the same head is not walked
// again.
func TestCommitScanCapsAndAdvances(t *testing.T) {
	dir, commit := newScanRepo(t)
	cs := &CommitScan{Engine: &Engine{Git: gitview.RunReadOnlyTimeout}, MaxCommits: 2}
	ctx := context.Background()
	h1 := commit("a.go", "package a\n")
	if _, ran := cs.AfterScan(ctx, dir, h1); !ran {
		t.Fatal("first head not scanned")
	}
	for _, n := range []string{"b.go", "c.go", "d.go", "e.go"} {
		commit(n, "package a\n")
	}
	h := commit("f.go", "package a\n")
	r, ran := cs.AfterScan(ctx, dir, h)
	if !ran || len(r.Commits) != 2 || r.Skipped != 3 || r.SkipReason != ReasonCommitCap || r.Verdict() != VerdictUnknown {
		t.Fatalf("capped walk = %+v", r)
	}
	if r.Commits[1].SHA != h {
		t.Fatalf("the newest commits are walked, oldest first: %+v", r.Commits)
	}
	if _, ran := cs.AfterScan(ctx, dir, h); ran {
		t.Fatal("a capped walk did not advance")
	}
}

// TestCommitScanAdvancesPastUnknown: a commit that answers unknown (over
// its own diff cap) is reported and the walk still advances.
func TestCommitScanAdvancesPastUnknown(t *testing.T) {
	dir, commit := newScanRepo(t)
	cs := &CommitScan{Engine: &Engine{Git: gitview.RunReadOnlyTimeout}, MaxDiffBytes: 8}
	ctx := context.Background()
	h := commit("a.go", "package a\nfunc f() {}\n")
	r, ran := cs.AfterScan(ctx, dir, h)
	if !ran || r.Verdict() != VerdictUnknown || r.Commits[0].Reason != ReasonDiffOverCap {
		t.Fatalf("over-cap commit = %+v", r)
	}
	if _, ran := cs.AfterScan(ctx, dir, h); ran {
		t.Fatal("an unknown commit is walked again on the next tick")
	}
}

// TestCommitScanRangeUnread: a previous head that is gone reads the new
// head alone and says the range was not read.
func TestCommitScanRangeUnread(t *testing.T) {
	dir, commit := newScanRepo(t)
	cs := &CommitScan{Engine: &Engine{Git: gitview.RunReadOnlyTimeout}}
	cs.last = map[string]string{dir: strings.Repeat("ab", 20)}
	h := commit("a.go", "package a\n")
	r, ran := cs.AfterScan(context.Background(), dir, h)
	if !ran || !r.RangeUnread || len(r.Commits) != 1 || r.Verdict() != VerdictUnknown {
		t.Fatalf("unreadable range = %+v", r)
	}
}

// TestFixtureHitNeverBlocks (milestone 2c): a secret in a fixture or
// test-data path is reported but leaves the verdict clean.
func TestFixtureHitNeverBlocks(t *testing.T) {
	g := &fakeGit{out: diffOf("testdata/creds.py", 1, "k = \""+fakeAWSKeyID+"\"")}
	r := (&Engine{Git: g.run}).Scan(context.Background(), Request{Root: "/r"})
	if r.Verdict != VerdictClean || len(r.Findings) != 1 || !r.Findings[0].Fixture {
		t.Fatalf("fixture hit = %+v", r)
	}
	if h := SecurityHit(r.Findings[0]); h.Severity == "high" {
		t.Fatalf("a fixture hit maps to a blocking severity: %+v", h)
	}
}

// TestCommitScanReportsDeletedFiles (lane sec-gate2 milestone 1b): a commit
// that deletes a file reports it, so a finding sighted there is no longer
// seen there; a commit that deletes nothing reports none.
func TestCommitScanReportsDeletedFiles(t *testing.T) {
	dir, commit := newScanRepo(t)
	cs := &CommitScan{Engine: &Engine{Git: gitview.RunReadOnlyTimeout}}
	ctx := context.Background()
	h := commit("keys.txt", "k = 1\n")
	if r, ran := cs.AfterScan(ctx, dir, h); !ran || len(r.Commits) != 1 || len(r.Commits[0].Deleted) != 0 {
		t.Fatalf("an adding commit = %+v", r)
	}
	cmd := exec.Command("git", "-C", dir, "rm", "-q", "keys.txt")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git rm: %v\n%s", err, out)
	}
	h2 := commit("other.txt", "x\n")
	r, ran := cs.AfterScan(ctx, dir, h2)
	if !ran || len(r.Commits) != 1 || strings.Join(r.Commits[0].Deleted, ",") != "keys.txt" {
		t.Fatalf("a deleting commit = %+v", r)
	}
}

// TestCommitScanRevListHonoursMaxCommits (milestone 3): the listing reads
// only revListSpan times the walk's own cap, so a range past that reads
// the head alone and says the range was not read whole.
func TestCommitScanRevListHonoursMaxCommits(t *testing.T) {
	dir, commit := newScanRepo(t)
	cs := &CommitScan{Engine: &Engine{Git: gitview.RunReadOnlyTimeout}, MaxCommits: 1}
	ctx := context.Background()
	from := commit("a.go", "package a\n")
	var head string
	for i := 0; i < revListSpan+2; i++ {
		head = commit("f.go", "package a\n// "+strings.Repeat("x", i+1)+"\n")
	}
	shas, ok := cs.revList(ctx, dir, from, head, cs.maxCommits())
	if ok || shas != nil {
		t.Fatalf("a range past %d x the cap was listed: %d commits, ok %v", revListSpan, len(shas), ok)
	}
	if shas, ok := cs.revList(ctx, dir, from, head, 2); !ok || len(shas) != revListSpan+2 {
		t.Fatalf("a range inside the span: %d commits, ok %v", len(shas), ok)
	}
}
