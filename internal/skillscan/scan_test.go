package skillscan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var errMissing = errors.New("fatal: bad object")

// fakeGit answers each read-only invocation by its first argument.
type fakeGit struct {
	calls      []string
	reflog     [][]byte // one response per page
	reflogErr  error
	trees      map[string][]byte
	treeErr    map[string]error
	status     []byte
	statusErr  error
	ignorecase string
	format     string
	formatErr  error
}

func (f *fakeGit) exec(_ context.Context, _ string, _ int, args ...string) ([]byte, bool, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	switch args[0] {
	case "config":
		if f.ignorecase == "" {
			return nil, false, errors.New("exit 1")
		}
		return []byte(f.ignorecase + "\n"), false, nil
	case "rev-parse":
		if args[1] == "--show-object-format" {
			return []byte(f.format + "\n"), false, f.formatErr
		}
		return []byte("false\n"), false, nil
	case "reflog":
		if f.reflogErr != nil {
			return nil, false, f.reflogErr
		}
		page := 0
		for _, a := range args {
			if strings.HasPrefix(a, "--skip=") {
				fmt.Sscanf(a, "--skip=%d", &page)
				page /= 2 // test page size is 2
			}
		}
		if page < len(f.reflog) {
			return f.reflog[page], false, nil
		}
		return nil, false, nil
	case "ls-tree":
		sha := args[3]
		if err := f.treeErr[sha]; err != nil {
			return nil, false, err
		}
		return f.trees[sha], false, nil
	case "status":
		return f.status, false, f.statusErr
	}
	return nil, false, fmt.Errorf("unexpected git %v", args)
}

func (f *fakeGit) count(prefix string) int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

type fakeStore struct {
	signal     bool
	state      State
	hasState   bool
	moves      map[string]bool
	newest     time.Time
	batches    [][]Move
	trees      map[string]string
	treeFiles  map[string][]TreeFile
	cands      []string
	worktree   []WorktreeEntry
	replaced   int
	candsLimit int
}

func newFakeStore() *fakeStore {
	return &fakeStore{signal: true, moves: map[string]bool{}, trees: map[string]string{}, treeFiles: map[string][]TreeFile{}}
}

func (s *fakeStore) opts(g *fakeGit, now time.Time) Options {
	return Options{
		Exec:          g.exec,
		MissingObject: func(err error) bool { return errors.Is(err, errMissing) },
		HasSignal: func(context.Context, int64, string, []string) (bool, error) {
			return s.signal, nil
		},
		NewestMove: func(context.Context, int64) (time.Time, bool, error) {
			return s.newest, !s.newest.IsZero(), nil
		},
		State: func(context.Context, int64) (State, bool, error) { return s.state, s.hasState, nil },
		SetState: func(_ context.Context, st State) error {
			s.state, s.hasState = st, true
			return nil
		},
		InsertMoves: func(_ context.Context, _ int64, moves []Move) (int, bool, error) {
			s.batches = append(s.batches, moves)
			n, seen := 0, false
			for _, m := range moves {
				if m.MovedAt.After(s.newest) {
					s.newest = m.MovedAt
				}
				k := m.MovedAt.String() + m.SHA
				if s.moves[k] {
					seen = true
					continue
				}
				s.moves[k] = true
				n++
			}
			return n, seen, nil
		},
		TreeCandidates: func(_ context.Context, _ int64, _ []string, limit int) ([]string, error) {
			s.candsLimit = limit
			var out []string
			for _, c := range s.cands {
				if _, ok := s.trees[c]; !ok {
					out = append(out, c)
				}
			}
			return out, nil
		},
		TreeKnown: func(_ context.Context, _ int64, sha string) (bool, error) {
			_, ok := s.trees[sha]
			return ok, nil
		},
		SaveTree: func(_ context.Context, _ int64, sha, state string, files []TreeFile, _ time.Time) error {
			s.trees[sha], s.treeFiles[sha] = state, files
			return nil
		},
		ReplaceWorktree: func(_ context.Context, _ int64, entries []WorktreeEntry) error {
			s.worktree = entries
			s.replaced++
			return nil
		},
		Pathspecs:  []string{".claude/skills"},
		ReflogPage: 2,
		Now:        func() time.Time { return now },
	}
}

func reflogRec(sha string, unix int64, subject string) string {
	return fmt.Sprintf("\x1e%s\x00HEAD@{%d}\x00%s\n", sha, unix, subject)
}

const (
	shaA = "1111111111111111111111111111111111111111"
	shaB = "2222222222222222222222222222222222222222"
	shaC = "3333333333333333333333333333333333333333"
	blob = "aaaaaaaa11111111111111111111111111111111"
)

func TestStepFullPass(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	g := &fakeGit{
		ignorecase: "true", format: "sha1",
		reflog: [][]byte{
			[]byte(reflogRec(shaB, 200, "commit: second") + reflogRec(shaA, 100, "checkout: moving from x to y")),
			[]byte(reflogRec(shaC, 50, "clone: from somewhere")),
		},
		trees: map[string][]byte{
			shaB: []byte("100644 blob " + blob + "\t.claude/skills/deploy/SKILL.md\x00"),
		},
		treeErr: map[string]error{shaC: errMissing},
		status:  []byte("? web/.claude/skills/new/SKILL.md\x00? other/x.md\x00"),
	}
	st := newFakeStore()
	st.cands = []string{shaB, shaC}
	s := New(st.opts(g, now))
	if err := s.Step(context.Background(), Target{ProjectID: 1, RootPath: "/r/web", HeadSHA: shaB, Subtree: "web/"}); err != nil {
		t.Fatal(err)
	}
	if len(st.moves) != 3 {
		t.Errorf("moves = %d, want 3 (two pages)", len(st.moves))
	}
	// One newest-first capture in ONE insert, so the store can assign the
	// same-second sequence from the reflog's own order.
	if len(st.batches) != 1 || len(st.batches[0]) != 3 || st.batches[0][0].SHA != shaB || st.batches[0][2].SHA != shaC {
		t.Errorf("insert batches = %+v, want one newest-first batch of 3", st.batches)
	}
	if !st.state.IgnoreCase || !st.state.IgnoreCaseKnown || !st.state.ShallowKnown || st.state.ObjectFormat != "sha1" ||
		st.state.LastError != "" || st.state.HeadSHA != shaB || !st.state.ProbedAt.Equal(now) {
		t.Errorf("state = %+v", st.state)
	}
	if st.state.ReflogSince != time.Unix(50, 0).UTC() {
		t.Errorf("ReflogSince = %v, want the oldest entry", st.state.ReflogSince)
	}
	if st.trees[shaB] != "ok" || len(st.treeFiles[shaB]) != 1 || st.treeFiles[shaB][0].BlobOID != blob {
		t.Errorf("HEAD tree = %v %+v", st.trees[shaB], st.treeFiles[shaB])
	}
	if st.trees[shaC] != "missing" {
		t.Errorf("gone commit tree state = %q, want missing", st.trees[shaC])
	}
	if len(st.worktree) != 1 || st.worktree[0].RelPath != ".claude/skills/new/SKILL.md" || st.worktree[0].State != "untracked" {
		t.Errorf("worktree = %+v, want the subtree-stripped untracked skill only", st.worktree)
	}
	if n := g.count("ls-tree"); n != 2 {
		t.Errorf("ls-tree calls = %d, want 2 (HEAD once, not re-listed as a candidate)", n)
	}

	// Second tick: probes are fresh, the reflog stops at known history,
	// memoised trees are not listed again.
	g.calls = nil
	if err := s.Step(context.Background(), Target{ProjectID: 1, RootPath: "/r/web", HeadSHA: shaB, Subtree: "web/"}); err != nil {
		t.Fatal(err)
	}
	if g.count("config") != 0 || g.count("ls-tree") != 0 || g.count("reflog") != 1 {
		t.Errorf("second tick calls = %v, want one reflog page only (+status)", g.calls)
	}
}

func TestStepNoSignalDoesNoGitWork(t *testing.T) {
	g := &fakeGit{}
	st := newFakeStore()
	st.signal = false
	if err := New(st.opts(g, time.Now())).Step(context.Background(), Target{ProjectID: 1, RootPath: "/r", HeadSHA: shaA}); err != nil {
		t.Fatal(err)
	}
	if len(g.calls) != 0 || st.hasState {
		t.Errorf("calls = %v state=%v, want zero git work and no state row", g.calls, st.hasState)
	}
}

func TestStepFailuresAreRecordedNotFatal(t *testing.T) {
	g := &fakeGit{
		reflogErr: errors.New("timeout"),
		trees:     map[string][]byte{shaA: nil},
		statusErr: errors.New("status boom"),
	}
	st := newFakeStore()
	if err := New(st.opts(g, time.Now())).Step(context.Background(), Target{ProjectID: 1, RootPath: "/r", HeadSHA: shaA}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(st.state.LastError, "reflog: timeout") || !strings.Contains(st.state.LastError, "status: status boom") ||
		st.state.ConsecutiveFailures != 1 {
		t.Errorf("state = %+v, want both failures recorded, count 1", st.state)
	}
	if st.trees[shaA] != "ok" {
		t.Errorf("tree step must still run after a reflog failure: %v", st.trees)
	}
	if st.replaced != 0 {
		t.Errorf("a failed status must not replace the stored worktree rows")
	}
	// A retryable tree failure is an error, not "missing", and it does
	// not starve the other trees of the tick.
	g2 := &fakeGit{treeErr: map[string]error{shaA: errors.New("timeout")}, trees: map[string][]byte{shaB: nil}}
	st2 := newFakeStore()
	st2.cands = []string{shaB}
	_ = New(st2.opts(g2, time.Now())).Step(context.Background(), Target{ProjectID: 1, RootPath: "/r", HeadSHA: shaA})
	if _, ok := st2.trees[shaA]; ok || !strings.Contains(st2.state.LastError, "ls-tree") {
		t.Errorf("retryable tree failure memoised or unrecorded: trees=%v state=%+v", st2.trees, st2.state)
	}
	if st2.trees[shaB] != "ok" {
		t.Errorf("a failing HEAD tree starved the other candidates: %v", st2.trees)
	}
}

func TestStepEmptyRepositorySkipsHistory(t *testing.T) {
	g := &fakeGit{status: []byte("? .claude/skills/a/SKILL.md\x00")}
	st := newFakeStore()
	if err := New(st.opts(g, time.Now())).Step(context.Background(), Target{ProjectID: 1, RootPath: "/r"}); err != nil {
		t.Fatal(err)
	}
	if g.count("reflog") != 0 || g.count("ls-tree") != 0 || len(st.worktree) != 1 {
		t.Errorf("calls=%v worktree=%+v, want status only", g.calls, st.worktree)
	}
}

func TestStepCapsTreesPerTick(t *testing.T) {
	g := &fakeGit{trees: map[string][]byte{}}
	st := newFakeStore()
	for i := 0; i < 10; i++ {
		st.cands = append(st.cands, fmt.Sprintf("%040d", i))
	}
	o := st.opts(g, time.Now())
	o.TreesPerTick = 3
	_ = New(o).Step(context.Background(), Target{ProjectID: 1, RootPath: "/r", HeadSHA: shaA})
	if n := g.count("ls-tree"); n != 3 || st.candsLimit != 3 {
		t.Errorf("ls-tree calls = %d (limit %d), want 3", n, st.candsLimit)
	}
}

// TestStepProbesRefreshDaily pins that the repository probes re-run once
// ProbedAt is 24 h old (every tick sets LastScanAt, so that cannot be the
// clock), and that a failed probe keeps the earlier answer or, with none,
// stays unknown rather than false.
func TestStepProbesRefreshDaily(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	clock := now
	g := &fakeGit{format: "sha1"} // ignorecase probe fails (no answer)
	st := newFakeStore()
	o := st.opts(g, now)
	o.Now = func() time.Time { return clock }
	s := New(o)
	step := func() {
		t.Helper()
		if err := s.Step(context.Background(), Target{ProjectID: 1, RootPath: "/r", HeadSHA: shaA}); err != nil {
			t.Fatal(err)
		}
	}
	step()
	if st.state.IgnoreCaseKnown || st.state.IgnoreCase {
		t.Errorf("failed first probe = %+v, want ignorecase unknown", st.state)
	}
	g.ignorecase = "true"
	for _, c := range []struct {
		after     time.Duration
		wantProbe bool
	}{{time.Hour, false}, {23 * time.Hour, false}, {25 * time.Hour, true}} {
		clock = now.Add(c.after)
		g.calls = nil
		step()
		if got := g.count("config") == 1; got != c.wantProbe {
			t.Errorf("after %v: probed=%v, want %v (calls %v)", c.after, got, c.wantProbe, g.calls)
		}
	}
	if !st.state.IgnoreCase || !st.state.IgnoreCaseKnown {
		t.Errorf("refreshed probe = %+v, want ignorecase true", st.state)
	}
	// The next refresh fails: the earlier answer is kept.
	g.ignorecase = ""
	clock = now.Add(50 * time.Hour)
	step()
	if !st.state.IgnoreCase || !st.state.IgnoreCaseKnown {
		t.Errorf("a failed refresh overwrote the known answer: %+v", st.state)
	}
}
