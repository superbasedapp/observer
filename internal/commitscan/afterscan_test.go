package commitscan

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestAfterScan pins the S10-SKILLS additive hook: AfterScan runs once per
// SUCCESSFUL daemon tick with the scan's pinned HEAD sha, and never for a
// root whose scan failed. A nil AfterScan is the pre-arc behaviour (every
// other test in this package runs with it nil).
func TestAfterScan(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		exec      *fakeExec
		wantCalls int
		wantHead  string
	}{
		{
			"called with the pinned HEAD after a clean scan",
			&fakeExec{logOut: renderCommitLog(nil), headSHA: "abc123"}, 1, "abc123",
		},
		{
			"not called when the scan fails",
			&fakeExec{err: errors.New("boom")}, 0, "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := newFakeStore()
			var mu sync.Mutex
			var got []Result
			sc := New(Options{
				Roots:        func(context.Context) ([]Root, error) { return []Root{{ProjectID: 7, RootPath: "/r"}}, nil },
				Exec:         c.exec.Exec,
				State:        fs.State,
				SetState:     fs.SetState,
				Sink:         fs.Sink,
				Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
				Now:          func() time.Time { return at },
				AfterScan: func(_ context.Context, root Root, res Result) {
					mu.Lock()
					defer mu.Unlock()
					if root.ProjectID != 7 {
						t.Errorf("AfterScan root = %+v", root)
					}
					got = append(got, res)
				},
			})
			sc.runPass(ctx)
			if len(got) != c.wantCalls {
				t.Fatalf("AfterScan calls = %d, want %d", len(got), c.wantCalls)
			}
			if c.wantCalls > 0 && got[0].HeadSHA != c.wantHead {
				t.Errorf("AfterScan HeadSHA = %q, want %q", got[0].HeadSHA, c.wantHead)
			}
		})
	}
}
