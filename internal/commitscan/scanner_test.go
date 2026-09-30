package commitscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
)

// --- fixtures -----------------------------------------------------------

type fakeCommit struct {
	sha, parent, author, subject string
	at                           time.Time
	files                        []fakeFile
}

type fakeFile struct {
	path           string
	added, deleted int
}

// renderCommitLog renders commits in EXACTLY the byte shape
// internal/commitlog.ParseLog expects (see commitlog/parse.go): each
// record starts with 0x1e, a NUL-separated 6-field header line, then one
// --numstat line per file.
func renderCommitLog(commits []fakeCommit) []byte {
	var buf bytes.Buffer
	for _, c := range commits {
		buf.WriteByte(0x1e)
		buf.WriteString(c.sha)
		buf.WriteByte(0)
		buf.WriteString(c.parent)
		buf.WriteByte(0)
		buf.WriteString(c.author)
		buf.WriteByte(0)
		buf.WriteString(c.at.Format(time.RFC3339))
		buf.WriteByte(0)
		buf.WriteString(c.at.Format(time.RFC3339))
		buf.WriteByte(0)
		buf.WriteString(c.subject)
		buf.WriteByte('\n')
		for _, f := range c.files {
			fmt.Fprintf(&buf, "%d\t%d\t%s\n", f.added, f.deleted, f.path)
		}
	}
	return buf.Bytes()
}

// fakeStore is an in-memory stand-in for the store seams Options wires to
// internal/store in production.
type fakeStore struct {
	mu      sync.Mutex
	states  map[int64]State
	sunk    map[int64][]commitlog.Commit
	insertN int // next Sink call's "newly inserted" count, if >= 0; else len(commits)
}

func newFakeStore() *fakeStore {
	return &fakeStore{states: map[int64]State{}, sunk: map[int64][]commitlog.Commit{}, insertN: -1}
}

func (f *fakeStore) State(_ context.Context, projectID int64) (State, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.states[projectID]
	return st, ok, nil
}

func (f *fakeStore) SetState(_ context.Context, st State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[st.ProjectID] = st
	return nil
}

func (f *fakeStore) Sink(_ context.Context, projectID int64, commits []commitlog.Commit, _ time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sunk[projectID] = append(f.sunk[projectID], commits...)
	if f.insertN >= 0 {
		return f.insertN, nil
	}
	return len(commits), nil
}

// errFixtureNoCommits is the sentinel a test's fakeExec.headErr (or an
// inline exec closure) uses to pin the "brand-new repository, no commits
// yet" case (2026-09-22 review finding #6). fixtureNoCommits below is
// wired as Options.NoCommits by every test that exercises it, mirroring
// cmd/observer/commitscan_wire.go's production wiring of
// gitview.IsNoCommitsError.
var errFixtureNoCommits = errors.New("fixture: rev-parse --verify HEAD: no commits yet")

// errFixtureShowRefMiss is the sentinel fakeExec's "show-ref --verify
// --quiet <ref>" probe returns by default for a ref that doesn't exist
// yet — the same structural quiet-miss shape errFixtureNoCommits pins
// for the rev-parse probe (2026-09-22 review finding 11: production
// wires the ONE gitview.IsNoCommitsError predicate to classify BOTH
// probes, so the fixture must let a test tell "a real quiet miss" apart
// from "a genuine show-ref failure" — see showRefErr below).
var errFixtureShowRefMiss = errors.New("fixture: show-ref --verify --quiet: no such ref")

// fixtureNoCommits mirrors gitview.IsNoCommitsError's structural
// contract for both probes resolveHeadSHA chains: it classifies EITHER
// sentinel as "quiet miss", and nothing else.
func fixtureNoCommits(err error) bool {
	return errors.Is(err, errFixtureNoCommits) || errors.Is(err, errFixtureShowRefMiss)
}

// fakeExec records every invocation's args and dispatches on the git
// subcommand (args[0] == "log" or "rev-list") and, for "rev-parse", on
// its own argument ("--show-prefix" vs "--verify --quiet HEAD" — F14/F16
// of the 2026-09-22 review added a second rev-parse probe alongside the
// existing subtree one, so a single canned response can no longer serve
// both; the 2026-09-22 REWORK review's finding #6 switched the HEAD
// probe's own argv from "rev-parse HEAD" to "rev-parse --verify HEAD",
// and finding S8 switched it again to "rev-parse --verify --quiet HEAD"
// plus the two new "symbolic-ref -q HEAD" / "show-ref --verify --quiet
// <ref>" probes resolveHeadSHA now issues only when headErr is
// NoCommits-classified).
type fakeExec struct {
	mu     sync.Mutex
	calls  []string // one joined-args string per call, in order
	logOut []byte
	revOut []byte
	// prefixOut is "rev-parse --show-prefix"'s canned stdout. Empty
	// (the zero value) means "the project root IS the repository
	// toplevel" — matches every existing fixture's whole-repository
	// shape; TestScan_SubprojectUsesSubtreePathspec overrides it.
	prefixOut []byte
	// prefixErr, when set, makes "rev-parse --show-prefix" fail with
	// this error instead of returning prefixOut (2026-09-22 REWORK
	// review finding #6: a --show-prefix failure must be a recorded scan
	// failure, never a silent "scan the whole repository").
	prefixErr error
	// headSHA is "rev-parse --verify --quiet HEAD"'s canned resolved
	// sha. Empty (the zero value, and headErr unset) makes
	// resolveHeadSHA return a SUCCESSFUL empty string, which
	// PageArgsRev and revalidateReachability both fall back to the
	// literal ref "HEAD" for — byte-identical to this package's pre-F16
	// argv, so every existing fixture is unaffected;
	// TestFullScan_StableHeadAcrossPages sets it to pin the F16
	// behaviour itself.
	headSHA string
	// headErr, when set, makes "rev-parse --verify --quiet HEAD" fail
	// with this error instead of resolving headSHA (2026-09-22 REWORK
	// review finding #6, argv updated by finding S8). Set it to
	// errFixtureNoCommits (with NoCommits: fixtureNoCommits wired into
	// Options) to pin the "no commits yet" path — which then also
	// consults symbolicRefOut/symbolicRefErr/showRefExists below for
	// the second probe — or to any OTHER error to pin the "genuine
	// failure — record and abort" path (which never reaches the second
	// probe at all).
	headErr error
	// symbolicRefOut is "symbolic-ref -q HEAD"'s canned stdout,
	// consulted ONLY when headErr is NoCommits-classified (finding S8's
	// second probe). Defaults to "refs/heads/main" — the ordinary
	// healthy unborn-branch shape — so every existing errFixtureNoCommits
	// fixture keeps resolving "no commits yet" without setting this.
	symbolicRefOut []byte
	// symbolicRefErr, when set, makes "symbolic-ref -q HEAD" fail — the
	// "HEAD is dangling/malformed, never healthy empty" branch of
	// finding S8.
	symbolicRefErr error
	// showRefExists, when true, makes "show-ref --verify --quiet <ref>"
	// SUCCEED — the "the branch actually has a commit, contradicting
	// the rev-parse failure" branch of finding S8. Defaults to false,
	// the ordinary shape: the branch HEAD points at has no ref yet.
	showRefExists bool
	// showRefErr, when set (and showRefExists is false), makes
	// "show-ref --verify --quiet <ref>" fail with THIS error instead of
	// the default errFixtureShowRefMiss quiet-miss sentinel — used to
	// pin a GENUINE (non-quiet-miss) probe failure, e.g. a corrupt
	// repository's exit 128, which fixtureNoCommits must NOT classify as
	// "no commits yet" (2026-09-22 review finding 11).
	showRefErr error
	err        error
	callCount  int
}

func (f *fakeExec) Exec(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, strings.Join(args, " "))
	f.callCount++
	if f.err != nil {
		return nil, false, f.err
	}
	if len(args) > 0 && args[0] == "rev-list" {
		return f.revOut, false, nil
	}

	if len(args) > 1 && args[0] == "rev-parse" && args[1] == "--show-prefix" {
		if f.prefixErr != nil {
			return nil, false, f.prefixErr
		}
		return f.prefixOut, false, nil
	}
	if len(args) > 3 && args[0] == "rev-parse" && args[1] == "--verify" && args[2] == "--quiet" && args[3] == "HEAD" {
		if f.headErr != nil {
			return nil, false, f.headErr
		}
		if f.headSHA == "" {
			return nil, false, nil
		}
		return []byte(f.headSHA + "\n"), false, nil
	}
	if len(args) > 2 && args[0] == "symbolic-ref" && args[1] == "-q" && args[2] == "HEAD" {
		if f.symbolicRefErr != nil {
			return nil, false, f.symbolicRefErr
		}
		out := f.symbolicRefOut
		if out == nil {
			out = []byte("refs/heads/main\n")
		}
		return out, false, nil
	}
	if len(args) > 0 && args[0] == "show-ref" {
		if f.showRefExists {
			return []byte("deadbeefcafef00d refs/heads/main\n"), false, nil
		}
		if f.showRefErr != nil {
			return nil, false, f.showRefErr
		}
		return nil, false, errFixtureShowRefMiss
	}
	return f.logOut, false, nil
}

// firstLogCall returns the first `git log` invocation (the toplevel
// rev-parse probe precedes it since the sub-project pathspec landed).
func (f *fakeExec) firstLogCall() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, "log ") {
			return c
		}
	}
	return ""
}

func (f *fakeExec) lastCall() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return ""
	}
	return f.calls[len(f.calls)-1]
}

func (f *fakeExec) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callCount
}

// --- tests ----------------------------------------------------------------

func TestScanOnce_FirstScanFullHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at1 := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	at2 := time.Date(2026, 9, 20, 11, 0, 0, 0, time.UTC)
	exec := &fakeExec{
		logOut: renderCommitLog([]fakeCommit{
			{
				sha: "sha1", author: "alice", subject: "fix", at: at1,
				files: []fakeFile{{path: "a.go", added: 1, deleted: 0}},
			},
			{
				sha: "sha2", author: "bob", subject: "feat", at: at2,
				files: []fakeFile{{path: "b.go", added: 2, deleted: 1}},
			},
		}),
		revOut: []byte("sha1\nsha2\n"),
	}
	fs := newFakeStore()
	sc := New(Options{
		Exec:         exec.Exec,
		State:        fs.State,
		SetState:     fs.SetState,
		Sink:         fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at2.Add(time.Minute) },
	})

	res, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/repo"})
	if err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	if res.CommitsSeen != 2 || res.Inserted != 2 {
		t.Errorf("res = %+v, want CommitsSeen=2 Inserted=2", res)
	}
	if !strings.Contains(exec.lastCall(), "rev-list") {
		t.Errorf("last Exec call %q was not the reachability rev-list", exec.lastCall())
	}
	// A never-scanned project's git-log invocation must NOT carry --since.
	if strings.Contains(exec.firstLogCall(), "--since") {
		t.Errorf("first-ever scan carried --since (%q); a never-scanned project must fetch full history", exec.firstLogCall())
	}

	st, ok, err := fs.State(ctx, 1)
	if err != nil || !ok {
		t.Fatalf("State after scan: ok=%v err=%v", ok, err)
	}
	if st.LastSHA != "sha2" || !st.LastCommittedAt.Equal(at2) {
		t.Errorf("watermark = %+v, want sha2 @ %v (the newest commit)", st, at2)
	}
	if st.ConsecutiveFailures != 0 || st.LastError != "" {
		t.Errorf("a successful scan must clear failure state, got %+v", st)
	}
}

func TestScanOnce_IncrementalUsesWatermarkOverlap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	watermark := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	exec := &fakeExec{logOut: renderCommitLog(nil), revOut: []byte("")}
	fs := newFakeStore()
	fs.states[1] = State{ProjectID: 1, LastSHA: "old", LastCommittedAt: watermark, LastScanAt: watermark}
	sc := New(Options{
		Exec: exec.Exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return watermark.Add(2 * time.Hour) },
	})

	if _, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/repo"}); err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	wantSince := watermark.Add(-watermarkOverlap).UTC().Format(time.RFC3339)
	if !strings.Contains(exec.firstLogCall(), "--since="+wantSince) {
		t.Errorf("incremental scan args %q do not carry --since=%s (watermark - 1h overlap)", exec.firstLogCall(), wantSince)
	}
	// No new commits: the stored watermark must be UNCHANGED, not reset.
	st, _, _ := fs.State(ctx, 1)
	if st.LastSHA != "old" || !st.LastCommittedAt.Equal(watermark) {
		t.Errorf("watermark changed on a zero-commit scan: got %+v", st)
	}
}

func TestScanOnce_OverlapDedupIsSinkResponsibility(t *testing.T) {
	// The scanner deliberately re-sends commits inside the overlap window;
	// dedup is the store's UNIQUE(project_id, sha) contract, not the
	// scanner's. This test pins that the scanner passes the FULL parsed
	// batch through unfiltered — Inserted reflects whatever Sink reports.
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	exec := &fakeExec{
		logOut: renderCommitLog([]fakeCommit{
			{sha: "sha-seen-before", author: "a", subject: "x", at: at},
			{sha: "sha-new", author: "a", subject: "y", at: at.Add(time.Minute)},
		}),
		revOut: []byte(""),
	}
	fs := newFakeStore()
	fs.insertN = 1 // simulate the store recognizing one of the two as a duplicate
	sc := New(Options{
		Exec: exec.Exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at.Add(time.Hour) },
	})
	res, err := sc.ScanOnce(ctx, Root{ProjectID: 2, RootPath: "/repo"})
	if err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	if res.CommitsSeen != 2 {
		t.Errorf("CommitsSeen = %d, want 2 (both fetched, overlap is the store's job)", res.CommitsSeen)
	}
	if res.Inserted != 1 {
		t.Errorf("Inserted = %d, want 1 (the store-reported dedup count)", res.Inserted)
	}
}

func TestRevalidateReachability_PassesRevListShas(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	exec := &fakeExec{logOut: renderCommitLog(nil), revOut: []byte("sha1\nsha2\n\n")}
	fs := newFakeStore()
	var gotReachable map[string]bool
	var gotSince time.Time
	sc := New(Options{
		Exec: exec.Exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		LinkWindow: 14 * 24 * time.Hour,
		Reachability: func(_ context.Context, projectID int64, reachable map[string]bool, since time.Time) error {
			gotReachable, gotSince = reachable, since
			return nil
		},
		Now: func() time.Time { return at },
	})
	if _, err := sc.ScanOnce(ctx, Root{ProjectID: 3, RootPath: "/repo"}); err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	if !gotReachable["sha1"] || !gotReachable["sha2"] || len(gotReachable) != 2 {
		t.Errorf("reachable set = %v, want exactly {sha1, sha2}", gotReachable)
	}
	wantSince := at.Add(-(14*24*time.Hour + reachabilityLookback))
	if !gotSince.Equal(wantSince) {
		t.Errorf("reachability since = %v, want %v (LinkWindow + 24h lookback)", gotSince, wantSince)
	}
}

func TestRecordFailure_IncrementsConsecutiveFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	exec := &fakeExec{err: errors.New("boom")}
	fs := newFakeStore()
	sc := New(Options{
		Exec: exec.Exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at },
	})

	if _, err := sc.ScanOnce(ctx, Root{ProjectID: 4, RootPath: "/repo"}); err == nil {
		t.Fatal("ScanOnce: want error")
	}
	st, ok, _ := fs.State(ctx, 4)
	if !ok || st.ConsecutiveFailures != 1 || st.LastError == "" {
		t.Fatalf("after 1 failure: %+v", st)
	}

	if _, err := sc.ScanOnce(ctx, Root{ProjectID: 4, RootPath: "/repo"}); err == nil {
		t.Fatal("ScanOnce: want error (2nd)")
	}
	st, _, _ = fs.State(ctx, 4)
	if st.ConsecutiveFailures != 2 {
		t.Fatalf("after 2 failures: ConsecutiveFailures = %d, want 2", st.ConsecutiveFailures)
	}
}

func TestDueForScan_Backoff(t *testing.T) {
	t.Parallel()
	interval := 2 * time.Minute
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	healthy := State{ConsecutiveFailures: 0, LastScanAt: now}
	if !dueForScan(now, interval, healthy) {
		t.Error("a healthy root (0 failures) must always be due")
	}

	failing := State{ConsecutiveFailures: 3, LastScanAt: now.Add(-1 * time.Minute)}
	if dueForScan(now, interval, failing) {
		t.Error("a root with 3 consecutive failures scanned 1 minute ago should still be backed off (2^3 * 2m = 16m)")
	}
	failingLongAgo := State{ConsecutiveFailures: 3, LastScanAt: now.Add(-20 * time.Minute)}
	if !dueForScan(now, interval, failingLongAgo) {
		t.Error("a root with 3 consecutive failures scanned 20 minutes ago should be due again (backoff = 16m)")
	}

	// The backoff itself is capped at maxBackoffTicks ticks, regardless of
	// how large ConsecutiveFailures grows.
	huge := backoffDuration(1000, interval)
	if huge != time.Duration(maxBackoffTicks)*interval {
		t.Errorf("backoffDuration(1000) = %v, want the %d-tick cap (%v)", huge, maxBackoffTicks, time.Duration(maxBackoffTicks)*interval)
	}
}

func TestRunPass_GitMissingGoesIdle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	exec := &fakeExec{err: errors.New("exec: \"git\": executable file not found in $PATH")}
	fs := newFakeStore()
	sc := New(Options{
		Roots: func(context.Context) ([]Root, error) {
			return []Root{{ProjectID: 1, RootPath: "/r1"}}, nil
		},
		Exec: exec.Exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Unavailable:  func(error) bool { return true },
		Now:          time.Now,
		Interval:     time.Hour, // long enough that a 2nd tick never fires in this test
	})

	sc.runPass(ctx)
	if !sc.gitUnavailable.Load() {
		t.Fatal("scanner did not latch gitUnavailable after an Unavailable-classified failure")
	}
	st, ok, _ := fs.State(ctx, 1)
	if !ok || !strings.Contains(st.LastError, "git not found") {
		t.Errorf("state after git-missing failure = %+v, want LastError naming git-not-found", st)
	}
	callsAfterFirstPass := exec.count()

	// A second pass must be a complete no-op — no further Exec calls.
	sc.runPass(ctx)
	if exec.count() != callsAfterFirstPass {
		t.Errorf("Exec was called again after the scanner went idle: %d -> %d calls", callsAfterFirstPass, exec.count())
	}
}

func TestRunPass_ScansEveryDueRoot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	exec := &fakeExec{logOut: renderCommitLog(nil), revOut: []byte("")}
	fs := newFakeStore()
	roots := []Root{{ProjectID: 1, RootPath: "/r1"}, {ProjectID: 2, RootPath: "/r2"}}
	sc := New(Options{
		Roots:        func(context.Context) ([]Root, error) { return roots, nil },
		Exec:         exec.Exec,
		State:        fs.State,
		SetState:     fs.SetState,
		Sink:         fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at },
		Workers:      1,
	})
	sc.runPass(ctx)
	for _, r := range roots {
		if _, ok, _ := fs.State(ctx, r.ProjectID); !ok {
			t.Errorf("project %d was not scanned in the pass", r.ProjectID)
		}
	}
}

// TestRunPass_SkipsUnscannableRoot pins the Scannable seam: a root the
// predicate rejects (a synthetic placeholder such as "[cursor]") is
// skipped before any state read or git exec, so it never records a
// scan attempt and never reaches Exec; every other root scans as before.
func TestRunPass_SkipsUnscannableRoot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	exec := &fakeExec{logOut: renderCommitLog(nil), revOut: []byte("")}
	fs := newFakeStore()
	roots := []Root{{ProjectID: 1, RootPath: "/r1"}, {ProjectID: 2, RootPath: "[cursor]"}}
	sc := New(Options{
		Roots:        func(context.Context) ([]Root, error) { return roots, nil },
		Scannable:    func(root string) bool { return root == "/r1" },
		Exec:         exec.Exec,
		State:        fs.State,
		SetState:     fs.SetState,
		Sink:         fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at },
		Workers:      1,
	})
	sc.runPass(ctx)
	sc.runPass(ctx)
	if _, ok, _ := fs.State(ctx, 1); !ok {
		t.Errorf("scannable project 1 was not scanned")
	}
	if _, ok, _ := fs.State(ctx, 2); ok {
		t.Errorf("unscannable project 2 recorded a scan attempt")
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	for _, c := range exec.calls {
		if strings.Contains(c, "[cursor]") {
			t.Errorf("git was invoked for the unscannable root: %q", c)
		}
	}
}

// TestFullScan_PagesUnboundedHistory pins F3 of the 2026-09-22 arc review:
// an unbounded FullScan walks history in MaxPerTick pages (`-n N
// --skip=K`, newest first) so every git invocation stays inside the exec
// seam's timeout, sinks each page as it lands, stops on a short page, and
// takes its watermark from the newest commit of the FIRST page.
func TestFullScan_PagesUnboundedHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := func(h int) time.Time { return time.Date(2026, 9, 20, h, 0, 0, 0, time.UTC) }
	page1 := renderCommitLog([]fakeCommit{
		{sha: "sha3", author: "a", subject: "newest", at: at(12), files: []fakeFile{{path: "c.go", added: 1}}},
		{sha: "sha2", author: "a", subject: "mid", at: at(11), files: []fakeFile{{path: "b.go", added: 1}}},
	})
	page2 := renderCommitLog([]fakeCommit{
		{sha: "sha1", author: "a", subject: "oldest", at: at(10), files: []fakeFile{{path: "a.go", added: 1}}},
	})
	var mu sync.Mutex
	var calls []string
	exec := func(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		joined := strings.Join(args, " ")
		calls = append(calls, joined)
		switch {
		case args[0] == "rev-parse":
			// Both the --show-prefix (F14) and HEAD (F16) probes return
			// empty here: this test's root IS the toplevel, and it does
			// not exercise the stable-HEAD behaviour (that is
			// TestFullScan_StableHeadAcrossPages) — an empty response
			// from each falls back to this package's pre-fix argv
			// (whole-repository, literal ref "HEAD"), which is exactly
			// what the assertions below expect.
			return nil, false, nil
		case args[0] == "rev-list":
			return []byte("sha1\nsha2\nsha3\n"), false, nil
		case strings.Contains(joined, "--skip=2"):
			return page2, false, nil
		case strings.Contains(joined, "--skip="):
			t.Errorf("unexpected page request %q", joined)
			return nil, false, nil
		default:
			return page1, false, nil
		}
	}
	fs := newFakeStore()
	sc := New(Options{
		Exec: exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at(13) },
		MaxPerTick:   2,
	})
	res, err := sc.FullScan(ctx, Root{ProjectID: 1, RootPath: "/repo"}, time.Time{}, 0)
	if err != nil {
		t.Fatalf("FullScan: %v", err)
	}
	if res.CommitsSeen != 3 || res.Inserted != 3 {
		t.Errorf("res = %+v, want CommitsSeen=3 Inserted=3", res)
	}
	mu.Lock()
	defer mu.Unlock()
	var logCalls int
	for _, c := range calls {
		if strings.HasPrefix(c, "log ") {
			logCalls++
			if !strings.Contains(c, "-n 2") {
				t.Errorf("page call %q must be bounded by -n 2", c)
			}
			if strings.Contains(c, "--since") {
				t.Errorf("unbounded full scan must not carry --since: %q", c)
			}
		}
	}
	if logCalls != 2 {
		t.Errorf("git log calls = %d, want 2 (a full page, then the short last page)", logCalls)
	}
	st, ok, _ := fs.State(ctx, 1)
	if !ok || st.LastSHA != "sha3" || !st.LastCommittedAt.Equal(at(12)) {
		t.Errorf("watermark = %+v, want sha3 @ %v (newest commit of the first page)", st, at(12))
	}
}

// TestScan_SubprojectUsesSubtreePathspec pins the sub-project rule found
// on the live corpus 2026-09-22: a project rooted in a SUBDIRECTORY of a
// repository (here /repo/web under toplevel /repo) limits its git log
// AND its reachability rev-list to that subtree, and re-bases every file
// path onto the project root so PathHash matches the watcher's hashes.
func TestScan_SubprojectUsesSubtreePathspec(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	exec := &fakeExec{
		logOut: renderCommitLog([]fakeCommit{
			{
				sha: "sha1", author: "a", subject: "web fix", at: at,
				files: []fakeFile{{path: "web/src/app.tsx", added: 3}, {path: "web/index.html", added: 1}},
			},
		}),
		revOut:    []byte("sha1\n"),
		prefixOut: []byte("web/\n"),
	}
	fs := newFakeStore()
	sc := New(Options{
		Exec: exec.Exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at.Add(time.Hour) },
	})
	if _, err := sc.ScanOnce(ctx, Root{ProjectID: 7, RootPath: "/repo/web"}); err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	var sawLog, sawRevList bool
	for _, c := range exec.calls {
		switch {
		case strings.HasPrefix(c, "log "):
			sawLog = true
			if !strings.HasSuffix(c, "-- .") {
				t.Errorf("sub-project git log must end with the cwd-relative subtree pathspec \".\", got %q", c)
			}
		case strings.HasPrefix(c, "rev-list "):
			sawRevList = true
			if !strings.HasSuffix(c, "-- .") {
				t.Errorf("sub-project rev-list must carry the cwd-relative subtree pathspec \".\", got %q", c)
			}
		}
	}
	if !sawLog || !sawRevList {
		t.Fatalf("expected a log and a rev-list call, calls=%v", exec.calls)
	}
	fs.mu.Lock()
	got := fs.sunk[7]
	fs.mu.Unlock()
	if len(got) != 1 || len(got[0].Files) != 2 {
		t.Fatalf("sunk commits = %+v, want 1 commit with 2 files", got)
	}
	for _, f := range got[0].Files {
		if strings.HasPrefix(f.RelPath, "web/") {
			t.Errorf("file path %q was not re-based onto the project root", f.RelPath)
		}
	}
	if got[0].Files[0].RelPath != "src/app.tsx" || got[0].Files[0].PathHash != loc.PathHash("/repo/web", "/repo/web/src/app.tsx") {
		t.Errorf("re-based file = %+v, want src/app.tsx hashed relative to /repo/web", got[0].Files[0])
	}
}

// --- 2026-09-22 REWORK: F12 / F13 / F14 / F15 / F16 ------------------------

// TestScanOnce_NeverScannedPagesEntireHistoryInOneTick pins F12 of the
// 2026-09-22 rework review: a never-scanned project's FIRST ScanOnce call
// must not stop at the newest MaxPerTick commits — it pages through the
// WHOLE history within that one call (by delegating to FullScan), so
// nothing older than the first page is stranded behind a watermark that
// can only ever move forward on every later incremental scan.
func TestScanOnce_NeverScannedPagesEntireHistoryInOneTick(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := func(h int) time.Time { return time.Date(2026, 9, 20, h, 0, 0, 0, time.UTC) }
	page1 := renderCommitLog([]fakeCommit{
		{sha: "sha5", author: "a", subject: "5", at: at(15), files: []fakeFile{{path: "e.go", added: 1}}},
		{sha: "sha4", author: "a", subject: "4", at: at(14), files: []fakeFile{{path: "d.go", added: 1}}},
	})
	page2 := renderCommitLog([]fakeCommit{
		{sha: "sha3", author: "a", subject: "3", at: at(13), files: []fakeFile{{path: "c.go", added: 1}}},
		{sha: "sha2", author: "a", subject: "2", at: at(12), files: []fakeFile{{path: "b.go", added: 1}}},
	})
	page3 := renderCommitLog([]fakeCommit{
		{sha: "sha1", author: "a", subject: "1", at: at(11), files: []fakeFile{{path: "a.go", added: 1}}},
	})
	var mu sync.Mutex
	var logCalls []string
	exec := func(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		joined := strings.Join(args, " ")
		if args[0] == "log" {
			logCalls = append(logCalls, joined)
		}
		switch {
		case args[0] == "rev-parse":
			return nil, false, nil
		case args[0] == "rev-list":
			return []byte("sha1\nsha2\nsha3\nsha4\nsha5\n"), false, nil
		case strings.Contains(joined, "--skip=4"):
			return page3, false, nil
		case strings.Contains(joined, "--skip=2"):
			return page2, false, nil
		default:
			return page1, false, nil
		}
	}
	fs := newFakeStore() // no prior state at all: this project has never been scanned.
	sc := New(Options{
		Exec: exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at(16) },
		MaxPerTick:   2,
	})
	res, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/repo"})
	if err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	if res.CommitsSeen != 5 || res.Inserted != 5 {
		t.Errorf("res = %+v, want all 5 commits from ONE ScanOnce call, not just the newest MaxPerTick (2)", res)
	}
	mu.Lock()
	gotLogCalls := len(logCalls)
	mu.Unlock()
	if gotLogCalls != 3 {
		t.Errorf("git log calls = %d, want 3 pages (5 commits over 2-commit pages)", gotLogCalls)
	}
	st, ok, _ := fs.State(ctx, 1)
	if !ok || st.LastSHA != "sha5" || !st.LastCommittedAt.Equal(at(15)) {
		t.Errorf("watermark = %+v, want sha5 @ %v (newest commit of the first page)", st, at(15))
	}
}

// TestScanPage_OverflowRetriesAtSmallerPageSize pins the retry half of
// F13: a page whose output overflows the byte cap is retried at a
// SMALLER page size (halving down to the floor) rather than accepted as
// a truncated "success" that would silently drop the commits git could
// not fit.
func TestScanPage_OverflowRetriesAtSmallerPageSize(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	full := renderCommitLog([]fakeCommit{
		{sha: "sha1", author: "a", subject: "x", at: at, files: []fakeFile{{path: "a.go", added: 1}}},
	})
	var mu sync.Mutex
	var maxesRequested []string
	exec := func(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if args[0] == "rev-parse" {
			return nil, false, nil
		}
		if args[0] == "rev-list" {
			return []byte("sha1\n"), false, nil
		}
		joined := strings.Join(args, " ")
		for i, a := range args {
			if a == "-n" && i+1 < len(args) {
				maxesRequested = append(maxesRequested, args[i+1])
			}
		}
		if strings.Contains(joined, "-n 8") || strings.Contains(joined, "-n 4") {
			// Simulate an 8 MiB stdout cap being hit: git's real output
			// would be a byte-capped, possibly mid-record slice, not
			// this literal string — scanPage never gets far enough to
			// parse it when overflow is true.
			return []byte("would-be-truncated-git-log-output"), true, nil
		}
		return full, false, nil
	}
	fs := newFakeStore()
	sc := New(Options{
		Exec: exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at.Add(time.Hour) },
		MaxPerTick:   8,
	})
	res, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/repo"})
	if err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	if res.CommitsSeen != 1 || res.Inserted != 1 {
		t.Errorf("res = %+v, want the page to succeed once shrunk small enough (1 commit landed)", res)
	}
	if !res.Overflow {
		t.Errorf("Result.Overflow = false, want true — this page needed at least one retry")
	}
	mu.Lock()
	got := strings.Join(maxesRequested, ",")
	mu.Unlock()
	if want := "8,4,2"; got != want {
		t.Errorf("page sizes requested = %q, want %q (halving 8 -> 4 -> 2 until it fit)", got, want)
	}
	st, ok, _ := fs.State(ctx, 1)
	if !ok || st.LastSHA != "sha1" {
		t.Errorf("state after a successfully-retried scan = %+v, want the watermark set normally", st)
	}
}

// TestScanOnce_IncrementalOverflowContinuesUntilRangeExhausted pins the
// FIX for REWORK review finding #1 (F13 residue): an ordinary
// INCREMENTAL scan (a project WITH a stored watermark, routed through
// scan() rather than FullScan()) whose first page overflows and is
// shrunk must not stop at that one shrunk page — it keeps paging with
// --skip at the shrunk size until a short page proves the incremental
// range is exhausted, so every commit in the range is sunk and none is
// permanently stranded behind the newly-advanced watermark.
//
// Five commits fall inside the incremental --since window. MaxPerTick=4
// overflows and shrinks to 2 (scanPage's own retry); the round-1 defect
// would have sunk only the two newest (sha5, sha4) and advanced the
// watermark past sha3/sha2/sha1 forever. The fix must sink all five
// across three pages (2, 2, 1).
func TestScanOnce_IncrementalOverflowContinuesUntilRangeExhausted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	watermark := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	at := func(h int) time.Time { return time.Date(2026, 9, 20, h, 0, 0, 0, time.UTC) }
	page1 := renderCommitLog([]fakeCommit{
		{sha: "sha5", author: "a", subject: "5", at: at(15), files: []fakeFile{{path: "e.go", added: 1}}},
		{sha: "sha4", author: "a", subject: "4", at: at(14), files: []fakeFile{{path: "d.go", added: 1}}},
	})
	page2 := renderCommitLog([]fakeCommit{
		{sha: "sha3", author: "a", subject: "3", at: at(13), files: []fakeFile{{path: "c.go", added: 1}}},
		{sha: "sha2", author: "a", subject: "2", at: at(12), files: []fakeFile{{path: "b.go", added: 1}}},
	})
	page3 := renderCommitLog([]fakeCommit{
		{sha: "sha1", author: "a", subject: "1", at: at(11), files: []fakeFile{{path: "a.go", added: 1}}},
	})
	var mu sync.Mutex
	var logCalls []string
	exec := func(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		joined := strings.Join(args, " ")
		if args[0] == "rev-parse" {
			return nil, false, nil
		}
		if args[0] == "rev-list" {
			return []byte("sha1\nsha2\nsha3\nsha4\nsha5\n"), false, nil
		}
		logCalls = append(logCalls, joined)
		switch {
		case strings.Contains(joined, "-n 4"):
			// The nominal MaxPerTick=4 page overflows the byte cap.
			return []byte("would-be-truncated"), true, nil
		case strings.Contains(joined, "--skip=4"):
			return page3, false, nil
		case strings.Contains(joined, "--skip=2"):
			return page2, false, nil
		case strings.Contains(joined, "-n 2"):
			return page1, false, nil
		default:
			t.Errorf("unexpected log call %q", joined)
			return nil, false, nil
		}
	}
	fs := newFakeStore()
	fs.states[1] = State{ProjectID: 1, LastSHA: "old", LastCommittedAt: watermark, LastScanAt: watermark}
	sc := New(Options{
		Exec: exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return watermark.Add(6 * time.Hour) },
		MaxPerTick:   4,
	})
	res, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/repo"})
	if err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	if !res.Overflow {
		t.Errorf("Result.Overflow = false, want true — the first page needed a shrink")
	}
	if res.CommitsSeen != 5 || res.Inserted != 5 {
		t.Errorf("res = %+v, want CommitsSeen=5 Inserted=5 — the shrink must not strand sha1-sha3", res)
	}
	mu.Lock()
	gotLogCalls := len(logCalls)
	mu.Unlock()
	if gotLogCalls != 4 {
		// -n 4 (overflow), -n 2 (retry of page 1), -n 2 --skip=2, -n 2 --skip=4.
		t.Errorf("git log calls = %d, want 4 (the overflow probe + 3 successful pages)", gotLogCalls)
	}
	fs.mu.Lock()
	sunk := append([]commitlog.Commit(nil), fs.sunk[1]...)
	fs.mu.Unlock()
	gotSHAs := map[string]bool{}
	for _, c := range sunk {
		gotSHAs[c.SHA] = true
	}
	for _, want := range []string{"sha1", "sha2", "sha3", "sha4", "sha5"} {
		if !gotSHAs[want] {
			t.Errorf("sunk commits = %v, missing %q (stranded by the shrunk page)", gotSHAs, want)
		}
	}
	st, ok, _ := fs.State(ctx, 1)
	if !ok || st.LastSHA != "sha5" || !st.LastCommittedAt.Equal(at(15)) {
		t.Errorf("watermark = %+v, want sha5 @ %v (newest commit of the FIRST page)", st, at(15))
	}
	if st.ConsecutiveFailures != 0 || st.LastError != "" {
		t.Errorf("a scan that completed the whole range must clear failure state, got %+v", st)
	}
}

// genCommits renders n synthetic commits, newest (index 0) first, one
// second apart starting at base, each touching its own file — the shape
// TestScanOnce_IncrementalCleanFullPageIsNotAssumedComplete and its
// sibling below need to build a page at exactly (or one past) MaxPerTick
// without hand-writing hundreds of literals.
func genCommits(n int, base time.Time) []fakeCommit {
	out := make([]fakeCommit, n)
	for i := 0; i < n; i++ {
		out[i] = fakeCommit{
			sha:     fmt.Sprintf("sha%04d", n-i),
			author:  "a",
			subject: fmt.Sprintf("commit %d", n-i),
			at:      base.Add(-time.Duration(i) * time.Second),
			files:   []fakeFile{{path: fmt.Sprintf("f%04d.go", n-i), added: 1}},
		}
	}
	return out
}

// TestScanOnce_IncrementalCleanFullPageIsNotAssumedComplete pins the FIX
// for 2026-09-22 review finding S2: an incremental page that comes back
// CLEAN (no overflow, no shrink) and exactly MaxPerTick commits long is
// NOT proof the range is exhausted — with 501 commits inside the
// incremental --since window and MaxPerTick=500, the round-2 version
// stopped after the first (clean, full) page and advanced the watermark
// past the 501st (oldest) commit, stranding it behind the new watermark
// forever. The fix must keep paging with --skip until a SHORT page
// proves nothing older remains, regardless of whether any page ever
// needed an overflow shrink.
func TestScanOnce_IncrementalCleanFullPageIsNotAssumedComplete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	watermark := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	base := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	all := genCommits(501, base) // all[0] = sha0501 (newest) ... all[500] = sha0001 (oldest)
	page1 := renderCommitLog(all[:500])
	page2 := renderCommitLog(all[500:])

	var mu sync.Mutex
	var logCalls []string
	exec := func(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		joined := strings.Join(args, " ")
		if args[0] == "rev-parse" {
			return nil, false, nil
		}
		if args[0] == "rev-list" {
			shas := make([]string, len(all))
			for i, c := range all {
				shas[i] = c.sha
			}
			return []byte(strings.Join(shas, "\n") + "\n"), false, nil
		}
		logCalls = append(logCalls, joined)
		switch {
		case strings.Contains(joined, "--skip=500"):
			return page2, false, nil
		case strings.Contains(joined, "-n 500"):
			return page1, false, nil
		default:
			t.Errorf("unexpected log call %q", joined)
			return nil, false, nil
		}
	}
	fs := newFakeStore()
	fs.states[1] = State{ProjectID: 1, LastSHA: "old", LastCommittedAt: watermark, LastScanAt: watermark}
	sc := New(Options{
		Exec: exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return base.Add(time.Hour) },
		MaxPerTick:   500,
	})
	res, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/repo"})
	if err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	if res.CommitsSeen != 501 || res.Inserted != 501 {
		t.Errorf("res = %+v, want CommitsSeen=501 Inserted=501 — the clean full first page must not be assumed complete", res)
	}
	if res.Overflow {
		t.Errorf("Result.Overflow = true, want false — neither page ever hit the byte cap")
	}
	mu.Lock()
	gotLogCalls := len(logCalls)
	mu.Unlock()
	if gotLogCalls != 2 {
		t.Errorf("git log calls = %d, want 2 (the clean full page, then the short tail page proving completion)", gotLogCalls)
	}
	fs.mu.Lock()
	sunk := append([]commitlog.Commit(nil), fs.sunk[1]...)
	fs.mu.Unlock()
	if len(sunk) != 501 {
		t.Errorf("sunk %d commits, want 501 (nothing stranded behind the advanced watermark)", len(sunk))
	}
	st, ok, _ := fs.State(ctx, 1)
	if !ok || st.LastSHA != "sha0501" || !st.LastCommittedAt.Equal(base) {
		t.Errorf("watermark = %+v, want sha0501 @ %v (newest commit of the FIRST page, stamped once)", st, base)
	}
}

// TestScanOnce_IncrementalExactlyFullPageProbesEmptyTail is the sibling
// of the 501-commit case above at the exact boundary: precisely
// MaxPerTick (500) commits fall inside the incremental window. The fix
// cannot prove that from the first page's shape alone (a full page is
// indistinguishable from "more remain"), so it must still issue a
// second, empty --skip=500 page before concluding the range is
// exhausted — this pins that the completeness check is unconditional on
// a SHORT page, not a heuristic guess based on exact counts.
func TestScanOnce_IncrementalExactlyFullPageProbesEmptyTail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	watermark := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	base := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	all := genCommits(500, base)
	page1 := renderCommitLog(all)

	var mu sync.Mutex
	var logCalls []string
	exec := func(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		joined := strings.Join(args, " ")
		if args[0] == "rev-parse" {
			return nil, false, nil
		}
		if args[0] == "rev-list" {
			shas := make([]string, len(all))
			for i, c := range all {
				shas[i] = c.sha
			}
			return []byte(strings.Join(shas, "\n") + "\n"), false, nil
		}
		logCalls = append(logCalls, joined)
		switch {
		case strings.Contains(joined, "--skip=500"):
			return nil, false, nil // empty tail page: the range is exhausted
		case strings.Contains(joined, "-n 500"):
			return page1, false, nil
		default:
			t.Errorf("unexpected log call %q", joined)
			return nil, false, nil
		}
	}
	fs := newFakeStore()
	fs.states[1] = State{ProjectID: 1, LastSHA: "old", LastCommittedAt: watermark, LastScanAt: watermark}
	sc := New(Options{
		Exec: exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return base.Add(time.Hour) },
		MaxPerTick:   500,
	})
	res, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/repo"})
	if err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	if res.CommitsSeen != 500 || res.Inserted != 500 {
		t.Errorf("res = %+v, want CommitsSeen=500 Inserted=500", res)
	}
	mu.Lock()
	gotLogCalls := len(logCalls)
	mu.Unlock()
	if gotLogCalls != 2 {
		t.Errorf("git log calls = %d, want 2 (the exactly-full page, then the empty tail page)", gotLogCalls)
	}
	st, ok, _ := fs.State(ctx, 1)
	if !ok || st.LastSHA != "sha0500" || !st.LastCommittedAt.Equal(base) {
		t.Errorf("watermark = %+v, want sha0500 @ %v", st, base)
	}
}

// TestFullScan_BoundedMaxAcceptsSinglePageWithoutShrink pins the OTHER
// half of finding S2: FullScan's caller-bounded max>0 branch is the ONE
// place a single page IS the whole, correct answer — the caller asked
// for AT MOST max commits, not "every commit in some range", so a page
// that fits max without ever needing an overflow shrink must NOT trigger
// a second --skip page (that would silently fetch MORE than the caller
// asked for).
func TestFullScan_BoundedMaxAcceptsSinglePageWithoutShrink(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	three := renderCommitLog(genCommits(3, at))
	var mu sync.Mutex
	var logCalls int
	exec := func(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if args[0] == "rev-parse" {
			return nil, false, nil
		}
		if args[0] == "rev-list" {
			return []byte("sha0001\nsha0002\nsha0003\n"), false, nil
		}
		logCalls++
		if strings.Contains(strings.Join(args, " "), "--skip") {
			t.Fatalf("a second, --skip page must never happen for a bounded max>0 request that fit cleanly")
		}
		return three, false, nil
	}
	fs := newFakeStore()
	sc := New(Options{
		Exec: exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at.Add(time.Hour) },
		MaxPerTick:   500,
	})
	res, err := sc.FullScan(ctx, Root{ProjectID: 1, RootPath: "/repo"}, time.Time{}, 3)
	if err != nil {
		t.Fatalf("FullScan: %v", err)
	}
	if res.CommitsSeen != 3 || res.Inserted != 3 {
		t.Errorf("res = %+v, want CommitsSeen=3 Inserted=3", res)
	}
	mu.Lock()
	got := logCalls
	mu.Unlock()
	if got != 1 {
		t.Errorf("git log calls = %d, want exactly 1 — bounded max>0 accepts a single page", got)
	}
}

// TestScanPage_OverflowPersistsAtFloorRecordsFailureWithoutWatermark pins
// the other half of F13: when even the minimum page size (1 commit)
// still overflows, the scan is a hard failure and must NOT advance the
// project's watermark past the commit it could never fetch.
func TestScanPage_OverflowPersistsAtFloorRecordsFailureWithoutWatermark(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	exec := func(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
		if args[0] == "rev-parse" {
			return nil, false, nil
		}
		if args[0] == "rev-list" {
			return []byte(""), false, nil
		}
		// Every page size — even the floor of 1 commit — still overflows.
		return []byte("garbage"), true, nil
	}
	fs := newFakeStore()
	sc := New(Options{
		Exec: exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at },
		MaxPerTick:   4,
	})
	if _, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/repo"}); err == nil {
		t.Fatal("ScanOnce: want an error — overflow persisted to the page-size floor")
	}
	st, ok, _ := fs.State(ctx, 1)
	if !ok {
		t.Fatal("state was never persisted after the failure")
	}
	if !st.LastCommittedAt.IsZero() || st.LastSHA != "" {
		t.Errorf("watermark = %+v, want it left UNTOUCHED (zero) — an unresolved overflow must never advance it", st)
	}
	if st.ConsecutiveFailures == 0 || st.LastError == "" {
		t.Errorf("state = %+v, want a recorded failure", st)
	}
	fs.mu.Lock()
	sunk := fs.sunk[1]
	fs.mu.Unlock()
	if len(sunk) != 0 {
		t.Errorf("sunk = %+v, want nothing sunk from a page that never successfully parsed", sunk)
	}
}

// TestResolveSubtree_UsesGitsOwnPrefixNotLexicalComparison pins F14 of
// the 2026-09-22 rework review across its four named scenarios: the
// prefix that gates rebaseSubtree comes STRAIGHT from git
// (`rev-parse --show-prefix`), never a Go-side filepath.Rel comparison
// against RootPath — so a symlinked root (git's --show-toplevel would
// have resolved to the symlink TARGET, breaking a lexical Rel against
// the caller's own unresolved RootPath) and a case-variant repository
// (a case-insensitive filesystem's Rel used to preserve the STORED
// root's casing while git's own --numstat paths carry the repository's
// actual casing) both behave correctly: the RootPath string passed in is
// never compared against anything — only the prefix git itself reports
// for this exact `-C RootPath` invocation is used.
func TestResolveSubtree_UsesGitsOwnPrefixNotLexicalComparison(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		rootPath  string
		prefixOut string
		filePath  string
		wantRel   string
	}{
		{name: "toplevel root", rootPath: "/repo", prefixOut: "", filePath: "a.go", wantRel: "a.go"},
		{name: "nested root", rootPath: "/repo/web", prefixOut: "web/", filePath: "web/a.go", wantRel: "a.go"},
		{
			// A symlinked project root: real git's --show-toplevel would
			// resolve THROUGH the symlink to a path bearing no lexical
			// relationship to RootPath at all — exactly what broke the
			// old filepath.Rel(toplevel, RootPath) computation. Since
			// resolveSubtree no longer compares RootPath against
			// anything, an unrelated-looking RootPath has zero effect on
			// the result — only the prefix git itself reports matters.
			name: "symlinked root", rootPath: "/link/to/somewhere/else", prefixOut: "web/", filePath: "web/a.go", wantRel: "a.go",
		},
		{
			// Case-variant: git's own numstat casing ("Web/a.go") and
			// git's own prefix casing ("Web/") always agree because both
			// come from git — regardless of how RootPath itself was
			// spelled by the caller.
			name: "case-variant repo casing", rootPath: "/repo/Web", prefixOut: "Web/", filePath: "Web/a.go", wantRel: "a.go",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var prefixOut []byte
			if tc.prefixOut != "" {
				prefixOut = []byte(tc.prefixOut + "\n")
			}
			exec := &fakeExec{
				logOut: renderCommitLog([]fakeCommit{
					{sha: "sha1", author: "a", subject: "x", at: at, files: []fakeFile{{path: tc.filePath, added: 1}}},
				}),
				revOut:    []byte("sha1\n"),
				prefixOut: prefixOut,
			}
			fs := newFakeStore()
			sc := New(Options{
				Exec: exec.Exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
				Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
				Now:          func() time.Time { return at.Add(time.Hour) },
			})
			if _, err := sc.ScanOnce(ctx, Root{ProjectID: 42, RootPath: tc.rootPath}); err != nil {
				t.Fatalf("ScanOnce: %v", err)
			}
			fs.mu.Lock()
			got := fs.sunk[42]
			fs.mu.Unlock()
			if len(got) != 1 || len(got[0].Files) != 1 {
				t.Fatalf("sunk = %+v, want exactly 1 commit with 1 file", got)
			}
			if got[0].Files[0].RelPath != tc.wantRel {
				t.Errorf("RelPath = %q, want %q", got[0].Files[0].RelPath, tc.wantRel)
			}
		})
	}
}

// TestRevalidateReachability_SubprojectIsUnboundedByLookback pins F15 of
// the 2026-09-22 rework review: a sub-project's reachability revalidation
// walks its FULL pathspec-scoped history, not just the LinkWindow +
// lookback window — a legacy whole-repository row captured before the
// pathspec existed can be arbitrarily old, and bounding the revalidation
// to the lookback window would leave it stuck at reachable=1 forever.
func TestRevalidateReachability_SubprojectIsUnboundedByLookback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	exec := &fakeExec{
		logOut:    renderCommitLog(nil),
		revOut:    []byte("sha-old\nsha-new\n"),
		prefixOut: []byte("web/\n"),
	}
	fs := newFakeStore()
	var gotSince time.Time
	var gotReachable map[string]bool
	sc := New(Options{
		Exec: exec.Exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		LinkWindow: 14 * 24 * time.Hour,
		Reachability: func(_ context.Context, _ int64, reachable map[string]bool, since time.Time) error {
			gotReachable, gotSince = reachable, since
			return nil
		},
		Now: func() time.Time { return at },
	})
	if _, err := sc.ScanOnce(ctx, Root{ProjectID: 9, RootPath: "/repo/web"}); err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	if !gotSince.IsZero() {
		t.Errorf("sub-project revalidation since = %v, want the zero time (every stored row checked, F15)", gotSince)
	}
	if !gotReachable["sha-old"] || !gotReachable["sha-new"] || len(gotReachable) != 2 {
		t.Errorf("reachable set = %v, want both shas from the unbounded rev-list", gotReachable)
	}
	var sawSince bool
	for _, c := range exec.calls {
		if strings.HasPrefix(c, "rev-list ") && strings.Contains(c, "--since") {
			sawSince = true
		}
	}
	if sawSince {
		t.Errorf("sub-project rev-list must not carry --since, calls=%v", exec.calls)
	}
}

// TestFullScan_StableHeadAcrossPages pins F16 of the 2026-09-22 rework
// review: FullScan resolves HEAD to a concrete sha ONCE and uses that
// SAME sha for every page's `git log` AND the tail reachability
// rev-list — never the mutable ref "HEAD" re-resolved per invocation,
// which a rebase or reset landing between two pages of the same scan
// could see differently and lose or duplicate commits across.
func TestFullScan_StableHeadAcrossPages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := func(h int) time.Time { return time.Date(2026, 9, 20, h, 0, 0, 0, time.UTC) }
	const resolvedSHA = "deadbeefcafef00d"
	page1 := renderCommitLog([]fakeCommit{
		{sha: "sha3", author: "a", subject: "newest", at: at(12), files: []fakeFile{{path: "c.go", added: 1}}},
		{sha: "sha2", author: "a", subject: "mid", at: at(11), files: []fakeFile{{path: "b.go", added: 1}}},
	})
	page2 := renderCommitLog([]fakeCommit{
		{sha: "sha1", author: "a", subject: "oldest", at: at(10), files: []fakeFile{{path: "a.go", added: 1}}},
	})
	var mu sync.Mutex
	var calls []string
	exec := func(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		joined := strings.Join(args, " ")
		calls = append(calls, joined)
		switch {
		case len(args) > 3 && args[0] == "rev-parse" && args[1] == "--verify" && args[2] == "--quiet" && args[3] == "HEAD":
			return []byte(resolvedSHA + "\n"), false, nil
		case len(args) > 1 && args[0] == "rev-parse" && args[1] == "--show-prefix":
			return nil, false, nil
		case args[0] == "log" && args[1] != resolvedSHA:
			t.Fatalf("git log invoked against %q, want the ONE resolved sha %q (F16)", args[1], resolvedSHA)
			return nil, false, nil
		case args[0] == "rev-list" && args[1] != resolvedSHA:
			t.Fatalf("reachability rev-list invoked against %q, want the ONE resolved sha %q (F16)", args[1], resolvedSHA)
			return nil, false, nil
		case args[0] == "rev-list":
			return []byte("sha1\nsha2\nsha3\n"), false, nil
		case strings.Contains(joined, "--skip="):
			return page2, false, nil
		default:
			return page1, false, nil
		}
	}
	fs := newFakeStore()
	sc := New(Options{
		Exec: exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at(13) },
		MaxPerTick:   2,
	})
	res, err := sc.FullScan(ctx, Root{ProjectID: 1, RootPath: "/repo"}, time.Time{}, 0)
	if err != nil {
		t.Fatalf("FullScan: %v", err)
	}
	if res.CommitsSeen != 3 || res.Inserted != 3 {
		t.Errorf("res = %+v, want CommitsSeen=3 Inserted=3 — page-1 commits must not be lost", res)
	}
	mu.Lock()
	defer mu.Unlock()
	var logCalls, revListCalls int
	for _, c := range calls {
		if strings.HasPrefix(c, "log ") {
			logCalls++
			if !strings.HasPrefix(c, "log "+resolvedSHA+" ") {
				t.Errorf("log call %q does not carry the resolved sha %q", c, resolvedSHA)
			}
		}
		if strings.HasPrefix(c, "rev-list ") {
			revListCalls++
			if !strings.HasPrefix(c, "rev-list "+resolvedSHA+" ") {
				t.Errorf("rev-list call %q does not carry the resolved sha %q", c, resolvedSHA)
			}
		}
	}
	if logCalls != 2 {
		t.Errorf("git log calls = %d, want 2", logCalls)
	}
	if revListCalls != 1 {
		t.Errorf("rev-list calls = %d, want 1", revListCalls)
	}
}

// --- 2026-09-22 REWORK review: findings #1 / #6 / #7 -----------------------

// TestResolveHeadSHA_GenuineFailureRecordsFailureNotMutableHeadFallback
// pins the FIX for REWORK review finding #6: a transient/genuine
// `rev-parse --verify HEAD` failure (NOT classified by Options.NoCommits)
// must record a scan failure and ABORT the scan — never silently fall
// back to the mutable ref "HEAD", which would let a later invocation
// resolve a DIFFERENT commit than an earlier one already committed to.
// Exercised via a never-scanned project (routes through FullScan), which
// shares resolveScanTarget with the incremental scan() path.
func TestResolveHeadSHA_GenuineFailureRecordsFailureNotMutableHeadFallback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	exec := &fakeExec{headErr: errors.New("boom: rev-parse --verify HEAD failed")}
	fs := newFakeStore()
	sc := New(Options{
		Exec: exec.Exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		NoCommits:    fixtureNoCommits,
		Now:          func() time.Time { return at },
	})
	if _, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/repo"}); err == nil {
		t.Fatal("ScanOnce: want an error — a genuine rev-parse failure must abort the scan")
	}
	st, ok, _ := fs.State(ctx, 1)
	if !ok || st.ConsecutiveFailures != 1 || st.LastError == "" {
		t.Fatalf("state after a genuine HEAD-resolution failure = %+v, want a recorded failure", st)
	}
	for _, c := range exec.calls {
		if strings.HasPrefix(c, "log ") || strings.HasPrefix(c, "rev-list ") {
			t.Errorf("call %q must never have happened — the scan must abort before walking any history on an unresolved HEAD", c)
		}
	}
}

// TestScanOnce_NoCommitsYetIsCleanNotAFailure pins the OTHER half of
// REWORK review finding #6: a brand-new repository with no commits yet
// (rev-parse --verify --quiet HEAD's silent, structurally-classified
// failure — gitview.IsNoCommitsError, 2026-09-22 review finding S8 —
// confirmed by fixtureNoCommits/fakeExec's default healthy symbolic-ref
// + show-ref responses) is a clean, successful, empty scan — no
// recorded failure, no backoff, and no git log / rev-list invocation
// against a HEAD that does not exist.
func TestScanOnce_NoCommitsYetIsCleanNotAFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	exec := &fakeExec{headErr: errFixtureNoCommits}
	fs := newFakeStore()
	sc := New(Options{
		Exec: exec.Exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error {
			t.Fatal("Reachability must never be called for an unborn (commit-less) repository")
			return nil
		},
		NoCommits: fixtureNoCommits,
		Now:       func() time.Time { return at },
	})
	res, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/repo"})
	if err != nil {
		t.Fatalf("ScanOnce: %v, want a clean success for an unborn repository", err)
	}
	if res.CommitsSeen != 0 || res.Inserted != 0 {
		t.Errorf("res = %+v, want a no-op empty result", res)
	}
	st, ok, _ := fs.State(ctx, 1)
	if !ok {
		t.Fatal("state was never persisted")
	}
	if st.ConsecutiveFailures != 0 || st.LastError != "" {
		t.Errorf("state = %+v, want NO recorded failure — an unborn repo is not an error", st)
	}
	if !st.LastScanAt.Equal(at) {
		t.Errorf("LastScanAt = %v, want %v", st.LastScanAt, at)
	}
	for _, c := range exec.calls {
		if strings.HasPrefix(c, "log ") || strings.HasPrefix(c, "rev-list ") {
			t.Errorf("call %q must never have happened — there is no HEAD to walk yet", c)
		}
	}
}

// TestResolveHeadSHA_ShowRefGenuineFailureIsNotNoCommits pins the FIX
// for 2026-09-22 review finding 11: resolveHeadSHA's second probe
// (`show-ref --verify --quiet <branch>`) must record a genuine scan
// failure — never "no commits yet" — when it fails with something other
// than the exact quiet-miss shape (here, a corrupt-repository-style
// error the fixture's Options.NoCommits does NOT classify). The pre-fix
// code accepted ANY show-ref error as "the branch has no ref yet",
// which would have silently reported this repository as healthy-empty.
func TestResolveHeadSHA_ShowRefGenuineFailureIsNotNoCommits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	exec := &fakeExec{
		headErr:    errFixtureNoCommits,
		showRefErr: errors.New("fixture: show-ref: fatal: object corrupt"),
	}
	fs := newFakeStore()
	sc := New(Options{
		Exec: exec.Exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error {
			t.Fatal("Reachability must never be called after a genuine probe failure")
			return nil
		},
		NoCommits: fixtureNoCommits,
		Now:       func() time.Time { return at },
	})
	if _, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/repo"}); err == nil {
		t.Fatal("ScanOnce: want an error — a genuine show-ref failure must abort the scan, not report healthy no-commits")
	}
	st, ok, _ := fs.State(ctx, 1)
	if !ok || st.ConsecutiveFailures != 1 || st.LastError == "" {
		t.Fatalf("state after a genuine show-ref failure = %+v, want a recorded failure", st)
	}
	for _, c := range exec.calls {
		if strings.HasPrefix(c, "log ") || strings.HasPrefix(c, "rev-list ") {
			t.Errorf("call %q must never have happened — the scan must abort, not walk history on an unresolved probe", c)
		}
	}
}

// TestResolveSubtree_FailureRecordsFailureNotWholeRepoFallback pins the
// OTHER git-probe half of REWORK review finding #6: a `rev-parse
// --show-prefix` failure must record a scan failure and abort — never
// silently fall back to "" (which resolveSubtree's caller treats as
// "the project root IS the toplevel"), which would credit an unrelated
// sibling sub-project's files to this project.
func TestResolveSubtree_FailureRecordsFailureNotWholeRepoFallback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	exec := &fakeExec{prefixErr: errors.New("boom: rev-parse --show-prefix failed")}
	fs := newFakeStore()
	sc := New(Options{
		Exec: exec.Exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:          func() time.Time { return at },
	})
	if _, err := sc.ScanOnce(ctx, Root{ProjectID: 7, RootPath: "/repo/web"}); err == nil {
		t.Fatal("ScanOnce: want an error — a genuine --show-prefix failure must abort the scan")
	}
	st, ok, _ := fs.State(ctx, 7)
	if !ok || st.ConsecutiveFailures != 1 || st.LastError == "" {
		t.Fatalf("state after a genuine --show-prefix failure = %+v, want a recorded failure", st)
	}
	for _, c := range exec.calls {
		if strings.HasPrefix(c, "log ") || strings.HasPrefix(c, "rev-list ") {
			t.Errorf("call %q must never have happened — a failed subtree probe must never fall back to scanning the whole repository", c)
		}
	}
}

// TestRevalidateReachability_OverflowDoesNotMutateReachability pins the
// FIX for REWORK review finding #7: when the reachability rev-list
// overflows the byte cap even at the minimum page size, the pre-fix
// version silently handed Options.Reachability a TRUNCATED sha set —
// every stored sha git would have reported past the cut then got
// flagged reachable=0, destroying valid attribution. The fix must skip
// the revalidation pass entirely (never call Options.Reachability) when
// a page cannot be completed.
func TestRevalidateReachability_OverflowDoesNotMutateReachability(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	var reachabilityCalled bool
	exec := func(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
		if args[0] == "rev-parse" {
			return nil, false, nil
		}
		if args[0] == "log" {
			return renderCommitLog(nil), false, nil
		}
		// Every rev-list page — even at the minimum page size — overflows.
		return []byte("garbage"), true, nil
	}
	fs := newFakeStore()
	sc := New(Options{
		Exec: exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(context.Context, int64, map[string]bool, time.Time) error {
			reachabilityCalled = true
			return nil
		},
		LinkWindow: 14 * 24 * time.Hour,
		Now:        func() time.Time { return at },
	})
	res, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/repo"})
	if err != nil {
		t.Fatalf("ScanOnce: %v, want the commit scan itself to succeed (reachability is best-effort)", err)
	}
	if reachabilityCalled {
		t.Error("Options.Reachability was called with a TRUNCATED sha set — an unbounded overflow must skip the pass, never mutate reachability")
	}
	if res.Reachability != 0 {
		t.Errorf("res.Reachability = %d, want 0 (revalidation was skipped)", res.Reachability)
	}
}

// TestRevalidateReachability_PagesLargeShaSetToCompletion pins the
// "prefer paging" half of REWORK review finding #7: a reachable set
// larger than ONE page (reachabilityPageShas — this test file is in
// package commitscan, so it drives the real unexported constant rather
// than a stand-in) must be assembled across MULTIPLE --max-count/--skip
// pages, not truncated to the first page, before Options.Reachability
// ever sees the set.
func TestRevalidateReachability_PagesLargeShaSetToCompletion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)

	// Page 1 is EXACTLY a full page (reachabilityPageShas shas) — full
	// enough that, pre-fix, a caller might mistake it for "the whole
	// set". Page 2 is a short tail that ends the walk.
	shaFor := func(i int) string { return fmt.Sprintf("sha%08d", i) }
	var page1Buf bytes.Buffer
	for i := 0; i < reachabilityPageShas; i++ {
		page1Buf.WriteString(shaFor(i))
		page1Buf.WriteByte('\n')
	}
	page1 := page1Buf.Bytes()
	const tailCount = 3
	var page2Buf bytes.Buffer
	for i := reachabilityPageShas; i < reachabilityPageShas+tailCount; i++ {
		page2Buf.WriteString(shaFor(i))
		page2Buf.WriteByte('\n')
	}
	page2 := page2Buf.Bytes()

	wantMaxCount := "--max-count=" + strconv.Itoa(reachabilityPageShas)
	wantSkip := "--skip=" + strconv.Itoa(reachabilityPageShas)

	var mu sync.Mutex
	var revListCalls []string
	exec := func(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if args[0] == "rev-parse" {
			return nil, false, nil
		}
		if args[0] == "log" {
			return renderCommitLog(nil), false, nil
		}
		joined := strings.Join(args, " ")
		revListCalls = append(revListCalls, joined)
		switch {
		case strings.Contains(joined, wantMaxCount) && !strings.Contains(joined, "--skip"):
			return page1, false, nil
		case strings.Contains(joined, wantMaxCount) && strings.Contains(joined, wantSkip):
			return page2, false, nil
		default:
			t.Errorf("unexpected rev-list call %q", joined)
			return nil, false, nil
		}
	}
	fs := newFakeStore()
	var gotReachable map[string]bool
	sc := New(Options{
		Exec: exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
		Reachability: func(_ context.Context, _ int64, reachable map[string]bool, _ time.Time) error {
			gotReachable = reachable
			return nil
		},
		LinkWindow: 14 * 24 * time.Hour,
		Now:        func() time.Time { return at },
	})
	if _, err := sc.ScanOnce(ctx, Root{ProjectID: 1, RootPath: "/repo"}); err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	mu.Lock()
	gotCalls := len(revListCalls)
	mu.Unlock()
	if gotCalls != 2 {
		t.Fatalf("rev-list calls = %d, want 2 (a full page, then the short tail)", gotCalls)
	}
	if len(gotReachable) != reachabilityPageShas+tailCount {
		t.Fatalf("reachable set size = %d, want %d (BOTH pages, not just the first)", len(gotReachable), reachabilityPageShas+tailCount)
	}
	if !gotReachable[shaFor(0)] || !gotReachable[shaFor(reachabilityPageShas-1)] || !gotReachable[shaFor(reachabilityPageShas+tailCount-1)] {
		t.Error("reachable set is missing a sha from either the first or the second page")
	}
}

// TestRunPass_NotRepoRootLoggedOnceAndRecheckedPeriodically pins the
// NotRepo seam (2026-09-26): a root that exists but is not inside any
// repository is classified from the scan's own first-probe failure, logged
// ONCE at Info (never the per-tick "scan failed" WARN), skipped before any
// state read or exec until NotRepoRecheck elapses, re-probed after it with
// its failure count pinned at 1 (so the backoff never outgrows the recheck),
// and scanned normally once it becomes a repository.
func TestRunPass_NotRepoRootLoggedOnceAndRecheckedPeriodically(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	errNotRepo := errors.New("fatal: not a git repository (or any of the parent directories): .git")
	base := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	var clockMu sync.Mutex
	now := base
	clock := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	advance := func(d time.Duration) { clockMu.Lock(); now = now.Add(d); clockMu.Unlock() }

	ok := &fakeExec{logOut: renderCommitLog(nil), revOut: []byte("")}
	var mu sync.Mutex
	plainIsRepo := false
	plainCalls := 0
	exec := func(c context.Context, root string, maxBytes int, args ...string) ([]byte, bool, error) {
		if root == "/plain" {
			mu.Lock()
			plainCalls++
			isRepo := plainIsRepo
			mu.Unlock()
			if !isRepo {
				return nil, false, fmt.Errorf("gitview: %w", errNotRepo)
			}
		}
		return ok.Exec(c, root, maxBytes, args...)
	}
	calls := func() int { mu.Lock(); defer mu.Unlock(); return plainCalls }

	var logBuf bytes.Buffer
	var logMu sync.Mutex
	logger := slog.New(slog.NewTextHandler(&lockedWriter{mu: &logMu, w: &logBuf}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logText := func() string { logMu.Lock(); defer logMu.Unlock(); return logBuf.String() }

	fs := newFakeStore()
	roots := []Root{{ProjectID: 1, RootPath: "/repo"}, {ProjectID: 2, RootPath: "/plain"}}
	sc := New(Options{
		Roots:          func(context.Context) ([]Root, error) { return roots, nil },
		Exec:           exec,
		NotRepo:        func(err error) bool { return errors.Is(err, errNotRepo) },
		NotRepoRecheck: 30 * time.Minute,
		State:          fs.State,
		SetState:       fs.SetState,
		Sink:           fs.Sink,
		Reachability:   func(context.Context, int64, map[string]bool, time.Time) error { return nil },
		Now:            clock,
		Interval:       2 * time.Minute,
		Workers:        1,
		Logger:         logger,
	})

	// Pass 1: classified, logged once at Info, recorded with failures=1.
	sc.runPass(ctx)
	if calls() == 0 {
		t.Fatal("the not-a-repo root was never probed")
	}
	st, found, _ := fs.State(ctx, 2)
	if !found || st.LastError == "" || st.ConsecutiveFailures != 1 {
		t.Fatalf("plain state after pass 1 = %+v, want a recorded failure with count 1", st)
	}
	if _, found, _ := fs.State(ctx, 1); !found {
		t.Fatal("the repository root was not scanned")
	}

	// Pass 2, inside the recheck window: no exec for the plain root.
	before := calls()
	advance(2 * time.Minute)
	sc.runPass(ctx)
	if calls() != before {
		t.Fatalf("plain root probed inside the recheck window: %d -> %d calls", before, calls())
	}

	// Pass 3, past the recheck: probed again, still not a repo, count pinned.
	advance(29 * time.Minute)
	sc.runPass(ctx)
	if calls() == before {
		t.Fatal("plain root not re-probed after NotRepoRecheck")
	}
	st, _, _ = fs.State(ctx, 2)
	if st.ConsecutiveFailures != 1 {
		t.Fatalf("plain failure count after re-probe = %d, want 1 (pinned, never backing off past the recheck)", st.ConsecutiveFailures)
	}

	logs := logText()
	if n := strings.Count(logs, "root is not a git repository"); n != 1 {
		t.Fatalf("not-a-repo log lines = %d, want exactly 1 per root per process:\n%s", n, logs)
	}
	if !strings.Contains(logs, "level=INFO") || strings.Contains(logs, "scan failed") || strings.Contains(logs, "level=WARN") {
		t.Fatalf("logs must carry one Info line and no WARN / scan failed:\n%s", logs)
	}

	// The root becomes a repository: the next probe after the recheck scans it.
	mu.Lock()
	plainIsRepo = true
	mu.Unlock()
	advance(31 * time.Minute)
	sc.runPass(ctx)
	st, _, _ = fs.State(ctx, 2)
	if st.LastError != "" || st.ConsecutiveFailures != 0 {
		t.Fatalf("plain state after it became a repository = %+v, want a clean successful scan", st)
	}
	if _, skipped := sc.notRepoUntil.Load("/plain"); skipped {
		t.Fatal("a successfully scanned root is still marked not-a-repo")
	}
}

// lockedWriter serialises writes from the scanner's worker goroutines into
// one buffer.
type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
