package projectroi

import (
	"fmt"
	"testing"
	"time"
)

// buildLargeFixture generates a deterministic, realistically-shaped
// input at the size named in R11/F15: 5k prompts, 20k edits, 5k
// commits, drawn from a bounded pool of paths so both the supersede
// pass and the commit-matching pass do real work instead of every pair
// being a trivial miss.
func buildLargeFixture(nSessions, promptsPerSession, nCommits, nEdits, nPaths int) ([]Prompt, []Edit, []Commit) {
	base := t0

	prompts := make([]Prompt, 0, nSessions*promptsPerSession)
	sessionIDs := make([]string, nSessions)
	promptTimesBySession := make([][]time.Time, nSessions)
	var actionID int64 = 1
	for s := 0; s < nSessions; s++ {
		sid := fmt.Sprintf("session-%d", s)
		sessionIDs[s] = sid
		times := make([]time.Time, promptsPerSession)
		for p := 0; p < promptsPerSession; p++ {
			at := base.Add(time.Duration(s)*time.Hour + time.Duration(p)*time.Minute)
			times[p] = at
			prompts = append(prompts, Prompt{ActionID: actionID, SessionID: sid, At: at, Tool: "claude-code"})
			actionID++
		}
		promptTimesBySession[s] = times
	}

	edits := make([]Edit, 0, nEdits)
	var editActionID int64 = 1_000_000
	for i := 0; i < nEdits; i++ {
		s := i % nSessions
		p := (i / nSessions) % promptsPerSession
		at := promptTimesBySession[s][p].Add(time.Duration(i%50+1) * time.Second)
		path := fmt.Sprintf("path-%d", i%nPaths)
		edits = append(edits, Edit{
			ActionID: editActionID, SessionID: sessionIDs[s], At: at, PathHash: path,
			AddedCode: 1, ModifiedCode: 1,
		})
		editActionID++
	}

	commits := make([]Commit, 0, nCommits)
	for i := 0; i < nCommits; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		files := []CommitFile{
			{PathHash: fmt.Sprintf("path-%d", i%nPaths)},
			{PathHash: fmt.Sprintf("path-%d", (i+1)%nPaths)},
		}
		commits = append(commits, Commit{
			ID: int64(i + 1), SHA: fmt.Sprintf("sha-%d", i), CommittedAt: at, Reachable: true, Files: files,
		})
	}
	return prompts, edits, commits
}

// BenchmarkLink is the R11/F15 performance regression guard: Link must
// stay map-keyed, never an O(prompts x commits) nested loop.
func BenchmarkLink(b *testing.B) {
	prompts, edits, commits := buildLargeFixture(1000, 5, 5000, 20000, 2000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Link(prompts, edits, commits, Options{})
	}
}

// TestLinkScalesWithinBound asserts the same fixture BenchmarkLink uses
// completes well inside a generous bound in a plain `go test` run, so
// the guard fires under `make test` without anyone having to remember
// to run benchmarks.
func TestLinkScalesWithinBound(t *testing.T) {
	prompts, edits, commits := buildLargeFixture(1000, 5, 5000, 20000, 2000)

	start := time.Now()
	l := Link(prompts, edits, commits, Options{})
	elapsed := time.Since(start)

	const bound = 3 * time.Second
	if elapsed > bound {
		t.Fatalf("Link(5k prompts, 20k edits, 5k commits) took %s, want < %s", elapsed, bound)
	}
	if len(l.Chains) != len(prompts) {
		t.Fatalf("chains = %d, want %d", len(l.Chains), len(prompts))
	}
}
