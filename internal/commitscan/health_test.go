package commitscan

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests for the 2026-10-15 commit-capture health work: failure
// classification, root-gone recording, range-based incremental scans, the
// resumable budgeted history walk, timeout page shrinking, and ScanNow.

// fakeGitErr is a structural git failure the test Inspect understands.
type fakeGitErr struct {
	code     int
	stderr   string
	timedOut bool
}

func (e *fakeGitErr) Error() string { return fmt.Sprintf("git exit %d: %s", e.code, e.stderr) }

func inspectFake(err error) (GitFailure, bool) {
	var fe *fakeGitErr
	if !errors.As(err, &fe) {
		return GitFailure{}, false
	}
	return GitFailure{ExitCode: fe.code, Stderr: fe.stderr, TimedOut: fe.timedOut}, true
}

var errUnavailable = errors.New("fixture: git binary unavailable")

func TestClassify_Table(t *testing.T) {
	t.Parallel()
	sc := New(Options{
		Inspect:     inspectFake,
		Unavailable: func(err error) bool { return errors.Is(err, errUnavailable) },
		NotRepo: func(err error) bool {
			g, ok := inspectFake(err)
			return ok && g.ExitCode == 128 && strings.Contains(g.Stderr, "not a git repository")
		},
	})
	cases := []struct {
		name string
		err  error
		want FailureKind
	}{
		{"nil", nil, KindNone},
		{"git missing", errUnavailable, KindGitMissing},
		{"own timeout", &fakeGitErr{code: -1, timedOut: true}, KindTimeout},
		{"page timeout sentinel", fmt.Errorf("%w: x", errPageTimeout), KindTimeout},
		{"page too large", fmt.Errorf("%w: x", errPageTooLarge), KindTooLarge},
		{"chdir failed", &fakeGitErr{code: 128, stderr: "fatal: cannot change to '/gone': No such file or directory"}, KindRootMissing},
		{"not a repo", &fakeGitErr{code: 128, stderr: "fatal: not a git repository (or any of the parent directories): .git"}, KindNotRepo},
		{"dubious ownership", &fakeGitErr{code: 128, stderr: "fatal: detected dubious ownership in repository at '/mnt/c/x'"}, KindDubiousOwnership},
		{"permission", &fakeGitErr{code: 128, stderr: "fatal: Permission denied"}, KindPermission},
		{"bad object", &fakeGitErr{code: 128, stderr: "fatal: bad object deadbeef"}, KindRepoUnreadable},
		{"bad revision", &fakeGitErr{code: 128, stderr: "fatal: bad revision '^deadbeef'"}, KindRepoUnreadable},
		{"other git", &fakeGitErr{code: 1, stderr: "something new"}, KindOther},
		{"plain error", errors.New("boom"), KindOther},
	}
	for _, tc := range cases {
		if got := sc.classify(tc.err); got != tc.want {
			t.Errorf("%s: classify = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestRootKind(t *testing.T) {
	t.Parallel()
	cases := map[string]FailureKind{
		"[cursor]":                 KindNoFolder,
		"[grokbot]":                KindNoFolder,
		"relative/dir":             KindNoFolder,
		"/home/u/gone":             KindRootMissing,
		`C:\programsx\repo`:        KindRootMissing,
		"C:/programsx/repo":        KindRootMissing,
		`\\wsl.localhost\Ubuntu\x`: KindRootMissing,
	}
	for root, want := range cases {
		if got := rootKind(root); got != want {
			t.Errorf("rootKind(%q) = %q, want %q", root, got, want)
		}
	}
}

// countingStore wraps fakeStore and counts SetState calls.
type countingStore struct {
	*fakeStore
	mu   sync.Mutex
	sets int
}

func (c *countingStore) SetState(ctx context.Context, st State) error {
	c.mu.Lock()
	c.sets++
	c.mu.Unlock()
	return c.fakeStore.SetState(ctx, st)
}

func TestRunPass_RootGoneRecordedOnceAndKeepsLedger(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	cs := &countingStore{fakeStore: newFakeStore()}
	prevSuccess := at.Add(-48 * time.Hour)
	_ = cs.fakeStore.SetState(ctx, State{
		ProjectID: 7, LastSHA: "abc", LastCommittedAt: at.Add(-50 * time.Hour), LastSuccessAt: prevSuccess,
		LastHeadSHA: "abc", LastError: "gitview.runGit [log]: exit status 128 (fatal: cannot change to '/gone')", ConsecutiveFailures: 9,
	})
	roots := []Root{{ProjectID: 7, RootPath: "/gone"}}
	sc := New(Options{
		Roots:     func(context.Context) ([]Root, error) { return roots, nil },
		Scannable: func(string) bool { return false },
		Exec: func(context.Context, string, int, ...string) ([]byte, bool, error) {
			t.Fatal("git must never run for a missing root")
			return nil, false, nil
		},
		State: cs.State, SetState: cs.SetState, Sink: cs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at },
	})
	sc.runPass(ctx)
	sc.runPass(ctx)
	sc.runPass(ctx)
	st, _, _ := cs.State(ctx, 7)
	if st.LastErrorKind != KindRootMissing || st.ConsecutiveFailures != 1 {
		t.Fatalf("state = %+v, want root_missing with count pinned at 1", st)
	}
	if st.LastSHA != "abc" || st.LastHeadSHA != "abc" || !st.LastSuccessAt.Equal(prevSuccess) {
		t.Fatalf("the stored ledger watermark was not kept: %+v", st)
	}
	if cs.sets != 1 {
		t.Fatalf("SetState called %d times over 3 passes, want 1 (no write per tick)", cs.sets)
	}
}

// pagedRepo is a fake repository whose `git log` honours -n, --skip and a
// `^<sha>` exclusion over an ordered newest-first commit list.
type pagedRepo struct {
	mu        sync.Mutex
	head      string
	commits   []fakeCommit // newest first
	logCalls  []string
	timeouts  int // the next N log calls time out
	missing   map[string]bool
	onLogCall func()
}

func (p *pagedRepo) exec(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case len(args) > 1 && args[0] == "rev-parse" && args[1] == "--show-prefix":
		return nil, false, nil
	case len(args) > 0 && args[0] == "rev-parse":
		return []byte(p.head + "\n"), false, nil
	case len(args) > 0 && args[0] == "rev-list":
		var b strings.Builder
		for _, c := range p.commits {
			b.WriteString(c.sha + "\n")
		}
		return []byte(b.String()), false, nil
	case len(args) > 0 && args[0] == "log":
		p.logCalls = append(p.logCalls, strings.Join(args, " "))
		if p.onLogCall != nil {
			p.onLogCall()
		}
		if p.timeouts > 0 {
			p.timeouts--
			return nil, false, &fakeGitErr{code: -1, timedOut: true}
		}
		n, skip, exclude := 0, 0, ""
		for i, a := range args {
			switch {
			case a == "-n":
				n, _ = strconv.Atoi(args[i+1])
			case strings.HasPrefix(a, "--skip="):
				skip, _ = strconv.Atoi(strings.TrimPrefix(a, "--skip="))
			case strings.HasPrefix(a, "^"):
				exclude = strings.TrimPrefix(a, "^")
			}
		}
		if exclude != "" && p.missing[exclude] {
			return nil, false, &fakeGitErr{code: 128, stderr: "fatal: bad object " + exclude}
		}
		var sel []fakeCommit
		started := false
		for _, c := range p.commits {
			if c.sha == args[1] {
				started = true
			}
			if !started {
				continue
			}
			if c.sha == exclude {
				break
			}
			sel = append(sel, c)
		}
		if skip >= len(sel) {
			sel = nil
		} else {
			sel = sel[skip:]
		}
		if n > 0 && len(sel) > n {
			sel = sel[:n]
		}
		return renderCommitLog(sel), false, nil
	}
	return nil, false, nil
}

func (p *pagedRepo) logs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.logCalls...)
}

func makeHistory(n int, base time.Time) []fakeCommit {
	out := make([]fakeCommit, n)
	for i := 0; i < n; i++ {
		// newest first: c<n-1> ... c0
		k := n - 1 - i
		out[i] = fakeCommit{
			sha: fmt.Sprintf("c%02d", k), author: "a", subject: "s", at: base.Add(time.Duration(k) * time.Hour),
			files: []fakeFile{{path: "f.go", added: 1}},
		}
	}
	return out
}

func newHealthScanner(repo *pagedRepo, fs *fakeStore, now func() time.Time, maxPerTick int) *Scanner {
	return New(Options{
		Exec: repo.exec, Inspect: inspectFake,
		State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability:  func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:           now,
		MaxPerTick:    maxPerTick,
		HistoryBudget: 30 * time.Second,
	})
}

func TestHistoryScan_PausesAtBudgetAndResumes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	repo := &pagedRepo{head: "c09", commits: makeHistory(10, base)}
	clock := base.Add(240 * time.Hour)
	var mu sync.Mutex
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	// every git log page "takes" 20 s of wall clock
	repo.onLogCall = func() { mu.Lock(); clock = clock.Add(20 * time.Second); mu.Unlock() }
	fs := newFakeStore()
	sc := newHealthScanner(repo, fs, now, 3)
	root := Root{ProjectID: 1, RootPath: "/r"}

	res, err := sc.ScanOnce(ctx, root)
	if err != nil || !res.Partial {
		t.Fatalf("first tick: res=%+v err=%v, want a partial (paused) walk", res, err)
	}
	st, _, _ := fs.State(ctx, 1)
	if !st.HistoryPending || st.BackfillRev != "c09" || st.BackfillSkip != 6 || st.LastSHA != "c09" || st.LastError != "" {
		t.Fatalf("paused state = %+v, want pending at c09 skip 6 with watermark c09 and no error", st)
	}
	// HEAD moves while the walk is paused: the walk keeps its pinned commit.
	repo.mu.Lock()
	repo.commits = append([]fakeCommit{{sha: "c10", author: "a", subject: "new", at: base.Add(10 * time.Hour), files: []fakeFile{{path: "g.go", added: 1}}}}, repo.commits...)
	repo.head = "c10"
	repo.mu.Unlock()

	res, err = sc.ScanOnce(ctx, root)
	if err != nil || res.Partial {
		t.Fatalf("second tick: res=%+v err=%v, want the walk to finish", res, err)
	}
	st, _, _ = fs.State(ctx, 1)
	if st.HistoryPending || st.BackfillRev != "" || st.LastHeadSHA != "c09" {
		t.Fatalf("finished state = %+v, want complete up to the pinned c09", st)
	}
	if got := len(fs.sunk[1]); got != 10 {
		t.Fatalf("sunk %d commits after the walk, want all 10", got)
	}
	// Third tick: the range scan picks up exactly what HEAD gained.
	if _, err := sc.ScanOnce(ctx, root); err != nil {
		t.Fatal(err)
	}
	logs := repo.logs()
	last := logs[len(logs)-1]
	if !strings.Contains(last, "log c10 ^c09") || strings.Contains(last, "--since") {
		t.Fatalf("third tick log = %q, want a `c10 ^c09` range with no --since", last)
	}
	st, _, _ = fs.State(ctx, 1)
	if st.LastHeadSHA != "c10" || len(fs.sunk[1]) != 11 {
		t.Fatalf("after range scan: head=%q sunk=%d, want c10 and 11", st.LastHeadSHA, len(fs.sunk[1]))
	}
}

func TestRangeScan_HeadUnchangedRunsNoLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	repo := &pagedRepo{head: "c02", commits: makeHistory(3, base)}
	fs := newFakeStore()
	_ = fs.SetState(ctx, State{
		ProjectID: 1, LastSHA: "c02", LastCommittedAt: base.Add(2 * time.Hour), LastHeadSHA: "c02",
		LastError: "old", LastErrorKind: KindTimeout, ConsecutiveFailures: 2,
	})
	sc := newHealthScanner(repo, fs, func() time.Time { return base.Add(48 * time.Hour) }, 500)
	res, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/r"})
	if err != nil || !res.Unchanged {
		t.Fatalf("res=%+v err=%v, want Unchanged", res, err)
	}
	if n := len(repo.logs()); n != 0 {
		t.Fatalf("%d git log calls, want 0 when HEAD did not move", n)
	}
	st, _, _ := fs.State(ctx, 1)
	if st.LastError != "" || st.LastErrorKind != KindNone || st.ConsecutiveFailures != 0 || st.LastSuccessAt.IsZero() {
		t.Fatalf("state = %+v, want a clean success", st)
	}
}

func TestRangeScan_MissingBaseFallsBackToSince(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	repo := &pagedRepo{head: "c02", commits: makeHistory(3, base), missing: map[string]bool{"gone1": true}}
	fs := newFakeStore()
	_ = fs.SetState(ctx, State{ProjectID: 1, LastSHA: "c01", LastCommittedAt: base.Add(time.Hour), LastHeadSHA: "gone1"})
	sc := newHealthScanner(repo, fs, func() time.Time { return base.Add(48 * time.Hour) }, 500)
	if _, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/r"}); err != nil {
		t.Fatalf("fallback scan failed: %v", err)
	}
	logs := repo.logs()
	if len(logs) != 2 || !strings.Contains(logs[0], "^gone1") || !strings.Contains(logs[1], "--since=") {
		t.Fatalf("log calls = %q, want the range attempt then a --since fallback", logs)
	}
	st, _, _ := fs.State(ctx, 1)
	if st.LastError != "" || st.LastHeadSHA != "c02" {
		t.Fatalf("state = %+v, want success with head c02", st)
	}
}

func TestScanPage_TimeoutShrinksThenSucceeds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	repo := &pagedRepo{head: "c04", commits: makeHistory(5, base), timeouts: 2}
	fs := newFakeStore()
	sc := newHealthScanner(repo, fs, func() time.Time { return base.Add(48 * time.Hour) }, 500)
	if _, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/r"}); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	logs := repo.logs()
	if len(logs) != 3 || !strings.Contains(logs[0], "-n 500") || !strings.Contains(logs[1], "-n 125") || !strings.Contains(logs[2], "-n 31") {
		t.Fatalf("log calls = %q, want 500 -> 125 -> 31", logs)
	}
	if len(fs.sunk[1]) != 5 {
		t.Fatalf("sunk %d, want 5", len(fs.sunk[1]))
	}
}

func TestScanPage_TimeoutAtRetryLimitRecordsTimeoutKind(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	repo := &pagedRepo{head: "c04", commits: makeHistory(5, base), timeouts: 99}
	fs := newFakeStore()
	sc := newHealthScanner(repo, fs, func() time.Time { return base.Add(48 * time.Hour) }, 500)
	_, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/r"})
	if err == nil {
		t.Fatal("want a failure")
	}
	if n := len(repo.logs()); n != 1+maxTimeoutRetries {
		t.Fatalf("%d log calls, want %d", n, 1+maxTimeoutRetries)
	}
	st, _, _ := fs.State(ctx, 1)
	if st.LastErrorKind != KindTimeout || !strings.Contains(st.LastError, "timed out") {
		t.Fatalf("state = %+v, want kind timeout", st)
	}
}

func TestRecordFailure_KeepsCursorAndSuccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	fs := newFakeStore()
	prev := State{
		ProjectID: 1, LastSHA: "x", LastCommittedAt: at.Add(-time.Hour), LastSuccessAt: at.Add(-2 * time.Hour),
		LastHeadSHA: "x", HistoryPending: true, BackfillRev: "x", BackfillSkip: 500,
	}
	_ = fs.SetState(ctx, prev)
	sc := New(Options{State: fs.State, SetState: fs.SetState, Inspect: inspectFake})
	sc.recordFailure(ctx, 1, at, &fakeGitErr{code: 128, stderr: "fatal: detected dubious ownership in repository"})
	st, _, _ := fs.State(ctx, 1)
	if st.LastErrorKind != KindDubiousOwnership || st.ConsecutiveFailures != 1 {
		t.Fatalf("state = %+v", st)
	}
	if st.BackfillSkip != 500 || st.BackfillRev != "x" || !st.HistoryPending || !st.LastSuccessAt.Equal(prev.LastSuccessAt) {
		t.Fatalf("failure dropped the resume cursor or last success: %+v", st)
	}
}

func TestScanNow_RootErrorAndInProgress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	fs := newFakeStore()
	sc := New(Options{
		Scannable: func(r string) bool { return r != "[cursor]" },
		Exec:      (&pagedRepo{head: "c00", commits: makeHistory(1, at)}).exec,
		State:     fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at },
	})
	_, err := sc.ScanNow(ctx, Root{ProjectID: 2, RootPath: "[cursor]"})
	var re *RootError
	if !errors.As(err, &re) || re.Kind != KindNoFolder {
		t.Fatalf("err = %v, want a no_folder RootError", err)
	}
	if !sc.acquire("/r") {
		t.Fatal("acquire failed")
	}
	if _, err := sc.ScanNow(ctx, Root{ProjectID: 1, RootPath: "/r"}); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("err = %v, want ErrScanInProgress while a tick holds the root", err)
	}
	sc.release("/r")
	if _, err := sc.ScanNow(ctx, Root{ProjectID: 1, RootPath: "/r"}); err != nil {
		t.Fatalf("ScanNow: %v", err)
	}
	if st, ok, _ := fs.State(ctx, 1); !ok || st.LastHeadSHA != "c00" {
		t.Fatalf("state after ScanNow = %+v", st)
	}
}
