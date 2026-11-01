package landingscan

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
)

const (
	shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	shaD = "dddddddddddddddddddddddddddddddddddddddd"
)

// exitErr is a fake git failure carrying an exit code.
type exitErr struct{ code int }

func (e exitErr) Error() string { return "exit" }

// fakeGit answers git argv by prefix; every call is recorded.
type fakeGit struct {
	mu      sync.Mutex
	answers []fakeAnswer
	calls   []string
}

type fakeAnswer struct {
	prefix   string
	out      string
	overflow bool
	code     int // non-zero: fail with this exit code
}

func (f *fakeGit) exec(_ context.Context, dir string, _ int, args ...string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := strings.Join(args, " ")
	f.calls = append(f.calls, dir+": "+line)
	for _, a := range f.answers {
		if strings.HasPrefix(line, a.prefix) {
			if a.code != 0 {
				return nil, false, exitErr{a.code}
			}
			return []byte(a.out), a.overflow, nil
		}
	}
	return nil, false, exitErr{128}
}

func exitCode(err error) (int, bool) {
	var e exitErr
	if errors.As(err, &e) {
		return e.code, true
	}
	return 0, false
}

// fakeStore records every write.
type fakeStore struct {
	mu       sync.Mutex
	commits  []delivery.Commit
	landings []delivery.Landing
	remotes  []delivery.Remote
	tips     []delivery.BranchTip
	fps      map[int64][2]string
	saved    []delivery.Landing
	prs      []delivery.PullRequest
	prCommit map[int64][]delivery.PRCommit
	mirrors  []delivery.Mirror
}

func (s *fakeStore) options(g *fakeGit, now time.Time) Options {
	return Options{
		Exec:     g.exec,
		ExitCode: exitCode,
		ModTime:  func(string) (time.Time, bool) { return time.Time{}, false },
		Commits: func(context.Context, int64, time.Time) ([]delivery.Commit, error) {
			return append([]delivery.Commit(nil), s.commits...), nil
		},
		Landings: func(context.Context, int64, time.Time, time.Time) ([]delivery.Landing, error) { return s.landings, nil },
		PullRequests: func(context.Context, int64, time.Time) ([]delivery.PullRequest, error) {
			return s.prs, nil
		},
		PRCommits:  func(_ context.Context, id int64) ([]delivery.PRCommit, error) { return s.prCommit[id], nil },
		BranchTips: func(context.Context, int64) ([]delivery.BranchTip, error) { return s.tips, nil },
		Mirrors:    func(context.Context) ([]delivery.Mirror, error) { return s.mirrors, nil },
		SetFingerprint: func(_ context.Context, id int64, fp, st string) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.fps == nil {
				s.fps = map[int64][2]string{}
			}
			s.fps[id] = [2]string{fp, st}
			return nil
		},
		SaveRemote: func(_ context.Context, r delivery.Remote) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.remotes = append(s.remotes, r)
			return nil
		},
		SaveBranchTips: func(_ context.Context, t []delivery.BranchTip) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.tips = append(s.tips, t...)
			return nil
		},
		SaveLandings: func(_ context.Context, ls []delivery.Landing) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.saved = append(s.saved, ls...)
			return nil
		},
		Now: func() time.Time { return now },
	}
}

func TestRunRemotesStripCredentialsAndSkipUnsafeNames(t *testing.T) {
	t.Parallel()
	g := &fakeGit{answers: []fakeAnswer{
		{prefix: "rev-parse --absolute-git-dir", out: "/r/.git\n.git\n"},
		{prefix: "config --get-regexp", out: "remote.origin.url https://u:ghp_SEEDED0123456789@github.com/o/r.git\n" +
			"remote.-evil.url https://github.com/x/y.git\nremote.local.url /srv/repo.git\n"},
		{prefix: "symbolic-ref --quiet refs/remotes/origin/HEAD", out: "refs/remotes/origin/main\n"},
		{prefix: "rev-parse --verify --quiet refs/remotes/origin/main^{commit}", out: shaD + "\n"},
	}}
	st := &fakeStore{}
	step := New(st.options(g, time.Now()))
	res, err := step.Run(context.Background(), Target{ProjectID: 1, RootPath: "/r", HeadSHA: shaA})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Remotes != 1 || len(st.remotes) != 1 {
		t.Fatalf("remotes = %+v", st.remotes)
	}
	r := st.remotes[0]
	if r.URL != "https://github.com/o/r.git" || r.DefaultBranch != "main" || r.DefaultRefSHA != shaD || strings.Contains(r.URL, "ghp_") {
		t.Fatalf("remote = %+v", r)
	}
	for _, c := range g.calls {
		if strings.Contains(c, "-evil") {
			t.Fatalf("unsafe remote name reached git: %s", c)
		}
	}
}

func TestRunThrottlesWhenNothingMoved(t *testing.T) {
	t.Parallel()
	g := &fakeGit{answers: []fakeAnswer{{prefix: "config --get-regexp", code: 1}}}
	st := &fakeStore{}
	now := time.Now()
	step := New(st.options(g, now))
	ctx := context.Background()
	if res, _ := step.Run(ctx, Target{ProjectID: 1, RootPath: "/r", HeadSHA: shaA}); res.Skipped {
		t.Fatal("first pass skipped")
	}
	if res, _ := step.Run(ctx, Target{ProjectID: 1, RootPath: "/r", HeadSHA: shaA}); !res.Skipped {
		t.Fatal("second pass with nothing moved was not skipped")
	}
	if res, _ := step.Run(ctx, Target{ProjectID: 1, RootPath: "/r", HeadSHA: shaB}); res.Skipped {
		t.Fatal("pass after HEAD moved was skipped")
	}
}

func TestRunFingerprintStates(t *testing.T) {
	t.Parallel()
	diff := "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -1 +1 @@\n-x\n+y\n"
	g := &fakeGit{answers: []fakeAnswer{
		{prefix: "config --get-regexp", code: 1},
		{prefix: "diff-tree -p --no-renames -r --no-commit-id --root " + shaA, out: diff},
		{prefix: "diff-tree -p --no-renames -r --no-commit-id --root " + shaB, overflow: true},
	}}
	now := time.Now()
	st := &fakeStore{commits: []delivery.Commit{
		{ID: 1, SHA: shaA, AIContributor: true, Reachable: true, CommittedAt: now, PatchFPState: delivery.FPPending},
		{ID: 2, SHA: shaB, AIContributor: true, Reachable: true, CommittedAt: now, PatchFPState: delivery.FPPending},
		{ID: 3, SHA: shaD, AIContributor: true, Reachable: true, CommittedAt: now, PatchFPState: delivery.FPPending},
		{ID: 4, SHA: "not-a-sha", AIContributor: true, CommittedAt: now, PatchFPState: delivery.FPPending},
	}}
	res, err := New(st.options(g, now)).Run(context.Background(), Target{ProjectID: 1, RootPath: "/r", HeadSHA: shaA})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Fingerprinted != 3 || st.fps[1][1] != delivery.FPOK || len(st.fps[1][0]) != 40 ||
		st.fps[2][1] != delivery.FPTooLarge || st.fps[3][1] != delivery.FPError {
		t.Fatalf("fingerprints = %+v (res %+v)", st.fps, res)
	}
	if _, touched := st.fps[4]; touched {
		t.Fatal("a non-sha commit id reached git")
	}
	// Every commit was evaluated (no remote: in flight).
	if len(st.saved) != 3 {
		t.Fatalf("saved landings = %+v", st.saved)
	}
	for _, l := range st.saved {
		if l.Status != delivery.StatusInFlight {
			t.Fatalf("landing = %+v", l)
		}
	}
	for _, c := range g.calls {
		for _, verb := range []string{"fetch", "merge-tree", "config --add", "config --set", "update-ref", "gc"} {
			if strings.Contains(c, ": "+verb) {
				t.Fatalf("a write verb reached git: %s", c)
			}
		}
	}
}

// TestRunUsesTheMirrorForDefaultEvidence: an ok mirror for the remote's URL
// moves default-branch evidence into the mirror directory, with the user's
// commit id passed as a plain argument.
func TestRunUsesTheMirrorForDefaultEvidence(t *testing.T) {
	t.Parallel()
	g := &fakeGit{answers: []fakeAnswer{
		{prefix: "config --get-regexp", out: "remote.origin.url https://gitlab.example.com/g/p.git\n"},
		{prefix: "symbolic-ref", code: 1},
		{prefix: "rev-parse --verify --quiet refs/remotes/origin/main^{commit}", out: shaD + "\n"},
		{prefix: "rev-parse --verify --quiet refs/heads/trunk^{commit}", out: shaD + "\n"},
		{prefix: "merge-base --is-ancestor " + shaA + " refs/heads/trunk", out: ""},
		{prefix: "log --ancestry-path", out: ""},
		{prefix: "log --format", out: ""},
	}}
	now := time.Now()
	st := &fakeStore{
		commits: []delivery.Commit{{ID: 1, SHA: shaA, AIContributor: true, Reachable: true, CommittedAt: now, PatchFPState: delivery.FPOK, PatchFP: "x"}},
		mirrors: []delivery.Mirror{{ID: 1, URL: "https://gitlab.example.com/g/p.git", Path: "/mirrors/k.git", DefaultBranch: "trunk", Status: "ok"}},
	}
	res, err := New(st.options(g, now)).Run(context.Background(), Target{ProjectID: 1, RootPath: "/r", HeadSHA: shaA})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Source != delivery.SourceMirror || len(st.saved) != 1 || st.saved[0].RuleID != "L1" || st.saved[0].Source != delivery.SourceMirror {
		t.Fatalf("res = %+v saved = %+v", res, st.saved)
	}
	sawMirror := false
	for _, c := range g.calls {
		if strings.HasPrefix(c, "/mirrors/k.git: merge-base --is-ancestor "+shaA) {
			sawMirror = true
		}
		if strings.HasPrefix(c, "/r: ") && strings.Contains(c, "/mirrors/") {
			t.Fatalf("the user repository was pointed at the mirror: %s", c)
		}
	}
	if !sawMirror {
		t.Fatalf("ancestry was not read in the mirror: %v", g.calls)
	}
}
