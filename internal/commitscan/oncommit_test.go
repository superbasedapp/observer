package commitscan

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
)

// TestOnCommit pins the per-commit observer seam (lane SEC-F2A): every
// commit a successful daemon tick or ScanNow read is offered once, after
// AfterScan; a failed scan offers nothing; MaxPerTick bounds the offers;
// FullScan (the backfill) never calls it.
func TestOnCommit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 11, 0, 0, 0, time.UTC)
	commits := renderCommitLog([]fakeCommit{
		{sha: "sha1", author: "alice", subject: "fix", at: at.Add(-time.Hour), files: []fakeFile{{path: "a.go", added: 1}}},
		{sha: "sha2", author: "alice", subject: "feat", at: at, files: []fakeFile{{path: "b.go", added: 2}}},
	})
	cases := []struct {
		name string
		exec *fakeExec
		run  func(sc *Scanner)
		want []string
	}{
		{
			"daemon tick offers every commit", &fakeExec{logOut: commits, revOut: []byte("sha1\nsha2\n")},
			func(sc *Scanner) { sc.runPass(ctx) },
			[]string{"sha1", "sha2"},
		},
		{
			"ScanNow offers too", &fakeExec{logOut: commits, revOut: []byte("sha1\nsha2\n")},
			func(sc *Scanner) { _, _ = sc.ScanNow(ctx, Root{ProjectID: 7, RootPath: "/r"}) },
			[]string{"sha1", "sha2"},
		},
		{
			"failed scan offers nothing", &fakeExec{err: errors.New("boom")},
			func(sc *Scanner) { sc.runPass(ctx) }, nil,
		},
		{
			"FullScan never offers", &fakeExec{logOut: commits, revOut: []byte("sha1\nsha2\n")},
			func(sc *Scanner) { _, _ = sc.FullScan(ctx, Root{ProjectID: 7, RootPath: "/r"}, time.Time{}, 100) }, nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := newFakeStore()
			var mu sync.Mutex
			var got []string
			afterRan := false
			sc := New(Options{
				Roots:        func(context.Context) ([]Root, error) { return []Root{{ProjectID: 7, RootPath: "/r"}}, nil },
				Exec:         c.exec.Exec,
				State:        fs.State,
				SetState:     fs.SetState,
				Sink:         fs.Sink,
				Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
				Now:          func() time.Time { return at.Add(time.Minute) },
				AfterScan:    func(context.Context, Root, Result) { mu.Lock(); afterRan = true; mu.Unlock() },
				OnCommit: func(_ context.Context, root Root, cm commitlog.Commit) {
					mu.Lock()
					defer mu.Unlock()
					if !afterRan {
						t.Error("OnCommit ran before AfterScan")
					}
					if root.ProjectID != 7 {
						t.Errorf("root = %+v", root)
					}
					got = append(got, cm.SHA)
				},
			})
			c.run(sc)
			mu.Lock()
			defer mu.Unlock()
			if len(got) != len(c.want) {
				t.Fatalf("offered %v, want %v", got, c.want)
			}
			seen := map[string]bool{}
			for _, s := range got {
				seen[s] = true
			}
			for _, w := range c.want {
				if !seen[w] {
					t.Fatalf("offered %v, want %v", got, c.want)
				}
			}
		})
	}
}

// TestSeenCommitsBound pins the collector's cap: a scan offers at most
// MaxPerTick commits however many pages it read.
func TestSeenCommitsBound(t *testing.T) {
	t.Parallel()
	c := &seenCommits{max: 2}
	c.add([]commitlog.Commit{{SHA: "a"}, {SHA: "b"}})
	c.add([]commitlog.Commit{{SHA: "c"}})
	if len(c.commits) != 2 || c.commits[1].SHA != "b" {
		t.Fatalf("collected %+v", c.commits)
	}
	sc := New(Options{})
	if ctx, seen := sc.withSeen(context.Background()); seen != nil || ctx.Value(seenKey{}) != nil {
		t.Fatal("no OnCommit seam: no collector")
	}
}
