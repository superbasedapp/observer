package deliverysvc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/deliverynet"
	"github.com/marmutapp/superbased-observer/internal/keystore"
)

var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// fakeStore is an in-memory Store.
type fakeStore struct {
	mu        sync.Mutex
	repos     []delivery.Remote
	commits   map[int64][]delivery.Commit
	landings  map[int64][]delivery.Landing
	links     []delivery.ProviderLink
	prs       []delivery.PullRequest
	prCommits map[int64][]delivery.PRCommit
	mirrors   []delivery.Mirror
	settings  map[int64]delivery.ProjectSettings
	nextID    int64
}

func newFakeStore() *fakeStore {
	return &fakeStore{commits: map[int64][]delivery.Commit{}, landings: map[int64][]delivery.Landing{}, prCommits: map[int64][]delivery.PRCommit{}, settings: map[int64]delivery.ProjectSettings{}}
}

func (f *fakeStore) id() int64 { f.nextID++; return f.nextID }

func (f *fakeStore) ListDeliveryRepos(context.Context) ([]delivery.Remote, error) {
	return append([]delivery.Remote(nil), f.repos...), nil
}

func (f *fakeStore) LoadProjectRemotes(_ context.Context, pid int64) ([]delivery.Remote, error) {
	var out []delivery.Remote
	for _, r := range f.repos {
		if r.ProjectID == pid {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeStore) LoadDeliveryCommits(_ context.Context, pid int64, _ time.Time) ([]delivery.Commit, error) {
	return f.commits[pid], nil
}

func (f *fakeStore) LoadProjectLandings(_ context.Context, pid int64, _, _ time.Time) ([]delivery.Landing, error) {
	return f.landings[pid], nil
}

func (f *fakeStore) ListProviderLinks(context.Context) ([]delivery.ProviderLink, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]delivery.ProviderLink(nil), f.links...), nil
}

func (f *fakeStore) CreateProviderLink(_ context.Context, l delivery.ProviderLink) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l.ID = f.id()
	f.links = append(f.links, l)
	return l.ID, nil
}

func (f *fakeStore) UpdateProviderLinkStatus(_ context.Context, id int64, status, errKind, errMsg string, okAt, nextRun time.Time, failures int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.links {
		if f.links[i].ID == id {
			l := &f.links[i]
			l.Status, l.LastErrorKind, l.LastError, l.LastOKAt, l.NextRunAt, l.ConsecutiveFailures = status, errKind, errMsg, okAt, nextRun, failures
		}
	}
	return nil
}

func (f *fakeStore) DeleteProviderLink(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.links {
		if f.links[i].ID == id {
			f.links = append(f.links[:i], f.links[i+1:]...)
			return nil
		}
	}
	return nil
}

func (f *fakeStore) UpsertPullRequest(_ context.Context, pr delivery.PullRequest, cs []delivery.PRCommit) (int64, error) {
	for i := range f.prs {
		if f.prs[i].RepoSlug == pr.RepoSlug && f.prs[i].Number == pr.Number && f.prs[i].LinkID == pr.LinkID {
			pr.ID = f.prs[i].ID
			f.prs[i] = pr
			f.prCommits[pr.ID] = cs
			return pr.ID, nil
		}
	}
	pr.ID = f.id()
	f.prs = append(f.prs, pr)
	f.prCommits[pr.ID] = cs
	return pr.ID, nil
}

func (f *fakeStore) FindPullRequestsForSHA(_ context.Context, sha string) ([]delivery.PullRequest, error) {
	var out []delivery.PullRequest
	for _, p := range f.prs {
		for _, c := range f.prCommits[p.ID] {
			if c.SHA == sha {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

func (f *fakeStore) UpsertDeliveryMirror(_ context.Context, m delivery.Mirror) (int64, error) {
	for i := range f.mirrors {
		if f.mirrors[i].URLHash == m.URLHash {
			m.ID = f.mirrors[i].ID
			f.mirrors[i] = m
			return m.ID, nil
		}
	}
	m.ID = f.id()
	f.mirrors = append(f.mirrors, m)
	return m.ID, nil
}

func (f *fakeStore) ListDeliveryMirrors(context.Context) ([]delivery.Mirror, error) {
	return append([]delivery.Mirror(nil), f.mirrors...), nil
}

func (f *fakeStore) DeleteDeliveryMirror(_ context.Context, id int64) error {
	for i := range f.mirrors {
		if f.mirrors[i].ID == id {
			f.mirrors = append(f.mirrors[:i], f.mirrors[i+1:]...)
		}
	}
	return nil
}

func (f *fakeStore) GetDeliveryProjectSettings(_ context.Context, pid int64) (delivery.ProjectSettings, error) {
	return f.settings[pid], nil
}

func (f *fakeStore) ListDeliveryProjectSettings(context.Context) ([]delivery.ProjectSettings, error) {
	var out []delivery.ProjectSettings
	for _, s := range f.settings {
		out = append(out, s)
	}
	return out, nil
}

// fakeNet records every call; any call counts as egress.
type fakeNet struct {
	calls       []string
	userErr     error
	pulls       map[string][]delivery.PullRequest // sha -> PRs
	notInRepo   map[string]bool
	detail      map[int64]delivery.PullRequest
	commitsOf   map[int64][]delivery.PRCommit
	pullsErr    error
	remoteTip   string
	cloneSize   int64
	removed     []string
	lastToken   string
	cloneErr    error
	lsRemoteErr error
}

func (n *fakeNet) rec(s string) { n.calls = append(n.calls, s) }

func (n *fakeNet) User(_ context.Context, a deliverynet.Auth) (deliverynet.Account, error) {
	n.rec("user")
	n.lastToken = a.Token
	if n.userErr != nil {
		return deliverynet.Account{}, n.userErr
	}
	return deliverynet.Account{Login: "octo"}, nil
}

func (n *fakeNet) CommitPulls(_ context.Context, a deliverynet.Auth, slug, sha string) ([]delivery.PullRequest, bool, error) {
	n.rec("pulls " + slug + " " + sha)
	n.lastToken = a.Token
	if n.pullsErr != nil {
		return nil, false, n.pullsErr
	}
	if n.notInRepo[sha] {
		return nil, false, nil
	}
	return n.pulls[sha], true, nil
}

func (n *fakeNet) PullRequest(_ context.Context, _ deliverynet.Auth, _ string, num int64) (delivery.PullRequest, error) {
	n.rec("pr detail")
	return n.detail[num], nil
}

func (n *fakeNet) PullCommits(_ context.Context, _ deliverynet.Auth, _ string, num int64) ([]delivery.PRCommit, error) {
	n.rec("pr commits")
	return n.commitsOf[num], nil
}

func (n *fakeNet) MirrorDir(u string) (string, error) {
	return "/home/u/.observer/delivery/mirrors/" + deliverynet.URLHash(u) + ".git", nil
}

func (n *fakeNet) SanitizeRemoteURL(raw string) (string, error) { return raw, nil }

func (n *fakeNet) Clone(context.Context, string, string) error { n.rec("clone"); return n.cloneErr }

func (n *fakeNet) LsRemote(context.Context, string, string) (string, error) {
	n.rec("ls-remote")
	return n.remoteTip, n.lsRemoteErr
}

func (n *fakeNet) Refresh(context.Context, string, string) error { n.rec("fetch"); return nil }

func (n *fakeNet) HeadBranch(context.Context, string) (string, error) { return "main", nil }

func (n *fakeNet) LocalTip(context.Context, string, string) (string, error) {
	return n.remoteTip, nil
}

func (n *fakeNet) Size(string) (int64, error) { return n.cloneSize, nil }

func (n *fakeNet) RemoveMirror(d string) error { n.removed = append(n.removed, d); return nil }

func (n *fakeNet) count(prefix string) int {
	c := 0
	for _, s := range n.calls {
		if strings.HasPrefix(s, prefix) {
			c++
		}
	}
	return c
}

type fixture struct {
	st      *fakeStore
	net     *fakeNet
	keys    *keystore.MemStore
	opened  int
	reevals []int64
	now     time.Time
	svc     *Service
}

func newFixture(capBytes int64) *fixture {
	f := &fixture{st: newFakeStore(), net: &fakeNet{pulls: map[string][]delivery.PullRequest{}, notInRepo: map[string]bool{}, detail: map[int64]delivery.PullRequest{}, commitsOf: map[int64][]delivery.PRCommit{}}, keys: &keystore.MemStore{}, now: t0}
	f.svc = New(Options{
		Store: f.st, Net: f.net,
		OpenKeys:       func() KeyStore { f.opened++; return f.keys },
		Reevaluate:     func(_ context.Context, pid int64) error { f.reevals = append(f.reevals, pid); return nil },
		MirrorCapBytes: capBytes,
		Now:            func() time.Time { return f.now },
	})
	return f
}

func sha(n byte) string { return fmt.Sprintf("%040x", int(n)+1) }

func githubRemote(pid int64) delivery.Remote {
	return delivery.Remote{ProjectID: pid, Name: "origin", URL: "https://github.com/o/r.git", Host: "github.com", Provider: delivery.ProviderGitHub, RepoSlug: "o/r", DefaultBranch: "main"}
}

func TestZeroEgressWithNothingConnected(t *testing.T) {
	f := newFixture(0)
	f.st.repos = []delivery.Remote{githubRemote(1)}
	f.st.commits[1] = []delivery.Commit{{ID: 1, SHA: sha(0), AIContributor: true, CommittedAt: t0}}
	f.st.settings[1] = delivery.ProjectSettings{ProjectID: 1} // mirror off
	f.svc.RunOnce(context.Background())
	if len(f.net.calls) != 0 {
		t.Fatalf("egress with nothing connected: %v", f.net.calls)
	}
	if f.opened != 0 {
		t.Fatal("the keychain was opened with no token link")
	}
}

func TestConnectTokenProvesThenStoresInKeychain(t *testing.T) {
	f := newFixture(0)
	l, err := f.svc.Connect(context.Background(), ConnectRequest{Provider: delivery.ProviderGitHub, Host: "GitHub.com", AuthMode: deliverynet.AuthToken, Token: " github_pat_x "})
	if err != nil {
		t.Fatal(err)
	}
	if l.ID == 0 || l.AccountLogin != "octo" || l.Host != "github.com" || l.Status != StatusOK || l.KeyName == "" {
		t.Fatalf("link %+v", l)
	}
	if !keystore.ValidName(l.KeyName) {
		t.Fatalf("key name %q", l.KeyName)
	}
	if v, _ := f.keys.Get(l.KeyName); v != "github_pat_x" {
		t.Fatalf("keychain holds %q", v)
	}
	for _, sl := range f.st.links {
		if strings.Contains(sl.KeyName+sl.ScopesSeen+sl.AccountLogin, "github_pat_x") {
			t.Fatal("the token reached the database row")
		}
	}
}

func TestConnectFailedProbeStoresNothing(t *testing.T) {
	f := newFixture(0)
	f.net.userErr = &deliverynet.Error{Kind: deliverynet.KindAuthFailed}
	_, err := f.svc.Connect(context.Background(), ConnectRequest{Provider: delivery.ProviderGitHub, AuthMode: deliverynet.AuthToken, Token: "bad"})
	if deliverynet.KindOf(err) != deliverynet.KindAuthFailed {
		t.Fatalf("err %v", err)
	}
	if len(f.st.links) != 0 || len(f.keys.Names()) != 0 {
		t.Fatal("a failed probe stored something")
	}
}

func TestConnectFailsClosedWithoutKeychain(t *testing.T) {
	f := newFixture(0)
	f.svc.o.OpenKeys = func() KeyStore { return keystore.FailClosed() }
	_, err := f.svc.Connect(context.Background(), ConnectRequest{Provider: delivery.ProviderGitHub, AuthMode: deliverynet.AuthToken, Token: "tok"})
	if !errors.Is(err, ErrNoKeychain) {
		t.Fatalf("err %v", err)
	}
	if len(f.net.calls) != 0 || len(f.st.links) != 0 {
		t.Fatal("no keychain must mean no probe and no row")
	}
}

func TestConnectValidation(t *testing.T) {
	cases := []struct {
		name string
		req  ConnectRequest
		want error
	}{
		{"gitlab unsupported", ConnectRequest{Provider: delivery.ProviderGitLab, AuthMode: deliverynet.AuthToken, Token: "x"}, ErrUnsupported},
		{"bad mode", ConnectRequest{Provider: delivery.ProviderGitHub, AuthMode: "basic"}, ErrUnsupported},
		{"empty token", ConnectRequest{Provider: delivery.ProviderGitHub, AuthMode: deliverynet.AuthToken}, ErrInvalid},
		{"multi-line token", ConnectRequest{Provider: delivery.ProviderGitHub, AuthMode: deliverynet.AuthToken, Token: "a\nb"}, ErrInvalid},
		{"host with path", ConnectRequest{Provider: delivery.ProviderGitHub, Host: "evil.example/x", AuthMode: deliverynet.AuthGHCLI}, ErrInvalid},
		{"gh with token", ConnectRequest{Provider: delivery.ProviderGitHub, AuthMode: deliverynet.AuthGHCLI, Token: "x"}, ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(0)
			if _, err := f.svc.Connect(context.Background(), tc.req); !errors.Is(err, tc.want) {
				t.Fatalf("err %v want %v", err, tc.want)
			}
			if len(f.net.calls) != 0 {
				t.Fatal("validation failure still called out")
			}
		})
	}
}

func TestConnectGHStoresNothingInKeychain(t *testing.T) {
	f := newFixture(0)
	l, err := f.svc.Connect(context.Background(), ConnectRequest{Provider: delivery.ProviderGitHub, AuthMode: deliverynet.AuthGHCLI})
	if err != nil || l.KeyName != "" || f.opened != 0 {
		t.Fatalf("%+v %v opened=%d", l, err, f.opened)
	}
}

func TestDisconnectDeletesKeyThenLink(t *testing.T) {
	f := newFixture(0)
	l, err := f.svc.Connect(context.Background(), ConnectRequest{Provider: delivery.ProviderGitHub, AuthMode: deliverynet.AuthToken, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Disconnect(context.Background(), l.ID); err != nil {
		t.Fatal(err)
	}
	if len(f.keys.Names()) != 0 || len(f.st.links) != 0 {
		t.Fatalf("left behind keys=%v links=%v", f.keys.Names(), f.st.links)
	}
	if err := f.svc.Disconnect(context.Background(), 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err %v", err)
	}
}

// connected returns a fixture with one ok token link and one GitHub repo.
func connected(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(0)
	if _, err := f.svc.Connect(context.Background(), ConnectRequest{Provider: delivery.ProviderGitHub, AuthMode: deliverynet.AuthToken, Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	f.net.calls = nil
	f.st.repos = []delivery.Remote{githubRemote(7)}
	return f
}

func TestRunAsksAboutUnlandedAICommitsAndUpsertsPRs(t *testing.T) {
	f := connected(t)
	f.st.commits[7] = []delivery.Commit{
		{ID: 1, SHA: sha(1), AIContributor: true, CommittedAt: t0.Add(-3 * time.Hour)},
		{ID: 2, SHA: sha(2), AIContributor: true, CommittedAt: t0.Add(-1 * time.Hour)},
		{ID: 3, SHA: sha(3), AIContributor: true, CommittedAt: t0, IsMerge: true},       // G1
		{ID: 4, SHA: sha(4), AIContributor: false, CommittedAt: t0},                     // G1
		{ID: 5, SHA: sha(5), AIContributor: true, CommittedAt: t0, ForeignAuthor: true}, // G1
		{ID: 6, SHA: sha(6), AIContributor: true, CommittedAt: t0.Add(-2 * time.Hour)},  // landed
		{ID: 8, SHA: sha(8), AIContributor: true, CommittedAt: t0.Add(-4 * time.Hour)},  // not pushed
	}
	f.st.landings[7] = []delivery.Landing{{CommitID: 6, Status: delivery.StatusLanded}}
	f.net.notInRepo[sha(8)] = true
	f.net.pulls[sha(1)] = []delivery.PullRequest{{Number: 10, State: delivery.PRMerged, RepoSlug: "o/r"}}
	f.net.pulls[sha(2)] = []delivery.PullRequest{{Number: 11, State: delivery.PROpen, RepoSlug: "o/r"}}
	f.net.detail[11] = delivery.PullRequest{Number: 11, State: delivery.PROpen, Readiness: delivery.ReadyConflicts, RepoSlug: "o/r"}
	f.net.commitsOf[10] = []delivery.PRCommit{{SHA: sha(1)}}
	f.net.commitsOf[11] = []delivery.PRCommit{{SHA: sha(2)}}

	f.svc.RunOnce(context.Background())

	if got := f.net.count("pulls"); got != 3 {
		t.Fatalf("asked about %d commits, want 3 (1, 2, 8): %v", got, f.net.calls)
	}
	if f.net.calls[0] != "pulls o/r "+sha(2) {
		t.Fatalf("most recent first: %v", f.net.calls)
	}
	if f.net.count("pr detail") != 1 {
		t.Fatalf("detail fetched for non-open PRs: %v", f.net.calls)
	}
	if len(f.st.prs) != 2 || f.st.prs[0].LinkID == 0 {
		t.Fatalf("prs %+v", f.st.prs)
	}
	var open delivery.PullRequest
	for _, p := range f.st.prs {
		if p.Number == 11 {
			open = p
		}
	}
	if open.Readiness != delivery.ReadyConflicts {
		t.Fatalf("open PR not from detail: %+v", open)
	}
	if f.net.lastToken != "tok" {
		t.Fatal("token not read from the keychain")
	}
	if len(f.reevals) != 1 || f.reevals[0] != 7 {
		t.Fatalf("reevals %v", f.reevals)
	}
	l := f.st.links[0]
	if l.Status != StatusOK || !l.NextRunAt.Equal(t0.Add(DefaultPollEvery)) {
		t.Fatalf("link %+v", l)
	}

	// Second pass at the same time: not due, nothing sent.
	f.net.calls = nil
	f.svc.RunOnce(context.Background())
	if len(f.net.calls) != 0 {
		t.Fatalf("polled before the cadence: %v", f.net.calls)
	}
	// After the cadence: the merged PR's commit is terminal and skipped.
	f.now = t0.Add(DefaultPollEvery)
	f.svc.RunOnce(context.Background())
	if f.net.count("pulls o/r "+sha(1)) != 0 {
		t.Fatalf("asked again about a commit already in a merged PR: %v", f.net.calls)
	}
}

func TestCommitsPerRunBound(t *testing.T) {
	f := connected(t)
	f.svc.o.CommitsPerRun = 2
	for i := 0; i < 5; i++ {
		f.st.commits[7] = append(f.st.commits[7], delivery.Commit{ID: int64(i + 1), SHA: sha(byte(i)), AIContributor: true, CommittedAt: t0.Add(time.Duration(i) * time.Minute)})
	}
	f.svc.RunOnce(context.Background())
	if got := f.net.count("pulls"); got != 2 {
		t.Fatalf("asked %d, want 2", got)
	}
}

func TestRateLimitAndAuthFailureCadence(t *testing.T) {
	f := connected(t)
	f.st.commits[7] = []delivery.Commit{{ID: 1, SHA: sha(1), AIContributor: true, CommittedAt: t0}}
	reset := t0.Add(17 * time.Minute)
	f.net.pullsErr = &deliverynet.Error{Kind: deliverynet.KindRateLimited, ResetAt: reset}
	f.svc.RunOnce(context.Background())
	l := f.st.links[0]
	if l.Status != StatusRateLimited || !l.NextRunAt.After(reset) || l.ConsecutiveFailures != 1 {
		t.Fatalf("link %+v", l)
	}
	f.now = reset.Add(2 * time.Second)
	f.net.pullsErr = &deliverynet.Error{Kind: deliverynet.KindAuthFailed}
	f.svc.RunOnce(context.Background())
	if l = f.st.links[0]; l.Status != StatusAuthFailed {
		t.Fatalf("link %+v", l)
	}
	// Stopped: never polled again until tested.
	f.net.calls = nil
	f.now = f.now.Add(24 * time.Hour)
	f.svc.RunOnce(context.Background())
	if len(f.net.calls) != 0 {
		t.Fatalf("auth_failed link was polled: %v", f.net.calls)
	}
	// A successful TestLink restarts it, due now.
	l, err := f.svc.TestLink(context.Background(), l.ID)
	if err != nil || l.Status != StatusOK || l.ConsecutiveFailures != 0 || !l.NextRunAt.Equal(f.now) {
		t.Fatalf("after test %+v %v", l, err)
	}
}

func TestNextRunTable(t *testing.T) {
	cad := 10 * time.Minute
	cases := []struct {
		name string
		prev RunState
		o    Outcome
		want RunState
	}{
		{"ok", RunState{Failures: 3}, Outcome{}, RunState{Status: StatusOK, NextRun: t0.Add(cad)}},
		{"auth", RunState{}, Outcome{Kind: deliverynet.KindAuthFailed}, RunState{Status: StatusAuthFailed, Failures: 1, Stopped: true, NextRun: t0}},
		{"rate with reset", RunState{}, Outcome{Kind: deliverynet.KindRateLimited, ResetAt: t0.Add(time.Hour)}, RunState{Status: StatusRateLimited, Failures: 1, NextRun: t0.Add(time.Hour + time.Second)}},
		{"rate no reset", RunState{Failures: 1}, Outcome{Kind: deliverynet.KindRateLimited}, RunState{Status: StatusRateLimited, Failures: 2, NextRun: t0.Add(4 * time.Minute)}},
		{"moved keeps cadence", RunState{}, Outcome{Kind: deliverynet.KindRepoMoved}, RunState{Status: StatusRepoMoved, NextRun: t0.Add(cad)}},
		{"shape backs off", RunState{Failures: 2}, Outcome{Kind: deliverynet.KindWrongShape}, RunState{Status: StatusWrongShape, Failures: 3, NextRun: t0.Add(8 * time.Minute)}},
		{"host refused stops", RunState{}, Outcome{Kind: deliverynet.KindHostNotAllowed}, RunState{Status: StatusDisabled, Failures: 1, Stopped: true, NextRun: t0}},
		{"unreachable caps at an hour", RunState{Failures: 9}, Outcome{Kind: deliverynet.KindUnreachable}, RunState{Status: StatusUnreachable, Failures: 10, NextRun: t0.Add(time.Hour)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NextRun(tc.prev, tc.o, t0, cad); got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestScheduleClampedToMinimum(t *testing.T) {
	cases := map[int]time.Duration{0: 0, -5: 0, 5: 30 * time.Minute, 30: 30 * time.Minute, 90: 90 * time.Minute}
	for in, want := range cases {
		if got := scheduleOf(in); got != want {
			t.Errorf("scheduleOf(%d)=%v want %v", in, got, want)
		}
	}
}

func gitlabRemote(pid int64) delivery.Remote {
	return delivery.Remote{ProjectID: pid, Name: "origin", URL: "https://gitlab.com/g/p.git", Host: "gitlab.com", Provider: delivery.ProviderGitLab, RepoSlug: "g/p", DefaultBranch: "main"}
}

func TestCheckProjectMirrorCloneThenNoChangeThenRefresh(t *testing.T) {
	f := newFixture(0)
	f.st.repos = []delivery.Remote{gitlabRemote(3)}
	f.st.settings[3] = delivery.ProjectSettings{ProjectID: 3, MirrorEnabled: true}
	f.net.remoteTip, f.net.cloneSize = sha(1), 1000
	ctx := context.Background()

	res, err := f.svc.CheckProject(ctx, 3)
	if err != nil || len(res.Repos) != 1 || res.Repos[0].Status != resultCloned || !res.Reevaluated {
		t.Fatalf("%+v %v", res, err)
	}
	m := f.st.mirrors[0]
	if m.Status != MirrorOK || m.TipSHA != sha(1) || m.SizeBytes != 1000 || m.DefaultBranch != "main" {
		t.Fatalf("mirror %+v", m)
	}
	// Unchanged tip: ls-remote only, no fetch.
	f.net.calls = nil
	res, _ = f.svc.CheckProject(ctx, 3)
	if res.Repos[0].Status != resultUnchanged || f.net.count("fetch") != 0 || f.net.count("ls-remote") != 1 {
		t.Fatalf("%+v %v", res, f.net.calls)
	}
	// Moved tip: fetch.
	f.net.remoteTip = sha(2)
	res, _ = f.svc.CheckProject(ctx, 3)
	if res.Repos[0].Status != resultRefreshed || f.net.count("fetch") != 1 || f.st.mirrors[0].TipSHA != sha(2) {
		t.Fatalf("%+v %v", res, f.net.calls)
	}
	used, capB, ms, err := f.svc.MirrorUsage(ctx)
	if err != nil || used != 1000 || capB != 0 || len(ms) != 1 {
		t.Fatalf("usage %d %d %v %v", used, capB, ms, err)
	}
	if err := f.svc.DeleteMirror(ctx, ms[0].ID); err != nil || len(f.st.mirrors) != 0 || len(f.net.removed) != 1 {
		t.Fatalf("delete %v %v %v", err, f.st.mirrors, f.net.removed)
	}
}

func TestMirrorOffMeansNoClone(t *testing.T) {
	f := newFixture(0)
	f.st.repos = []delivery.Remote{gitlabRemote(3)}
	res, err := f.svc.CheckProject(context.Background(), 3)
	if err != nil || res.Repos[0].Status != "skipped" || len(f.net.calls) != 0 {
		t.Fatalf("%+v %v %v", res, err, f.net.calls)
	}
}

func TestMirrorCapRefusesNewClone(t *testing.T) {
	f := newFixture(5000)
	f.st.mirrors = []delivery.Mirror{{ID: 99, URLHash: "ffffffffffffffff", Status: MirrorOK, SizeBytes: 5000}}
	f.st.repos = []delivery.Remote{gitlabRemote(3)}
	f.st.settings[3] = delivery.ProjectSettings{ProjectID: 3, MirrorEnabled: true}
	res, _ := f.svc.CheckProject(context.Background(), 3)
	if res.Repos[0].Status != MirrorOverCap || f.net.count("clone") != 0 {
		t.Fatalf("%+v %v", res, f.net.calls)
	}
	// Under the cap, but the clone itself is too big: removed again.
	f = newFixture(5000)
	f.st.mirrors = []delivery.Mirror{{ID: 99, URLHash: "ffffffffffffffff", Status: MirrorOK, SizeBytes: 4000}}
	f.st.repos = []delivery.Remote{gitlabRemote(3)}
	f.st.settings[3] = delivery.ProjectSettings{ProjectID: 3, MirrorEnabled: true}
	f.net.cloneSize = 2000
	res, _ = f.svc.CheckProject(context.Background(), 3)
	if res.Repos[0].Status != MirrorOverCap || len(f.net.removed) != 1 {
		t.Fatalf("%+v removed %v", res, f.net.removed)
	}
}

func TestScheduledMirrorRespectsSchedule(t *testing.T) {
	f := newFixture(0)
	f.st.repos = []delivery.Remote{gitlabRemote(3)}
	f.st.settings[3] = delivery.ProjectSettings{ProjectID: 3, MirrorEnabled: true, ScheduleMinutes: 10} // clamped to 30
	f.net.remoteTip = sha(1)
	ctx := context.Background()
	f.svc.RunOnce(ctx)
	if f.net.count("clone") != 1 {
		t.Fatalf("calls %v", f.net.calls)
	}
	f.net.calls = nil
	f.now = t0.Add(20 * time.Minute)
	f.svc.RunOnce(ctx)
	if len(f.net.calls) != 0 {
		t.Fatalf("refreshed before 30 minutes: %v", f.net.calls)
	}
	f.now = t0.Add(31 * time.Minute)
	f.svc.RunOnce(ctx)
	if f.net.count("ls-remote") != 1 || f.net.count("fetch") != 0 {
		t.Fatalf("calls %v", f.net.calls)
	}
}

func TestGitHubRemoteWithLinkNeverMirrored(t *testing.T) {
	f := connected(t)
	f.st.settings[7] = delivery.ProjectSettings{ProjectID: 7, MirrorEnabled: true, ScheduleMinutes: 30}
	f.svc.RunOnce(context.Background())
	f.svc.RunOnce(context.Background())
	if f.net.count("clone") != 0 || f.net.count("ls-remote") != 0 {
		t.Fatalf("a connected GitHub remote was mirrored: %v", f.net.calls)
	}
}

// TestMirrorNeedsNonInteractiveCredentials pins the refused-prompt status: a
// clone that stopped at a credential prompt is needs_noninteractive_credentials
// (and is cloned again next time); a cloned mirror whose ls-remote stops at
// one keeps its directory, takes the same status, is refreshed (not cloned)
// next time, and returns to ok once the remote answers.
func TestMirrorNeedsNonInteractiveCredentials(t *testing.T) {
	prompt := &deliverynet.Error{Kind: deliverynet.KindNeedsNonInteractive, Msg: "prompt refused"}
	ctx := context.Background()

	f := newFixture(0)
	f.st.repos = []delivery.Remote{gitlabRemote(3)}
	f.st.settings[3] = delivery.ProjectSettings{ProjectID: 3, MirrorEnabled: true}
	f.net.remoteTip, f.net.cloneSize, f.net.cloneErr = sha(1), 1000, prompt
	res, _ := f.svc.CheckProject(ctx, 3)
	if res.Repos[0].Status != MirrorNeedsCredentials || f.st.mirrors[0].Status != MirrorNeedsCredentials {
		t.Fatalf("clone refused: %+v %+v", res.Repos, f.st.mirrors)
	}
	f.net.cloneErr, f.net.calls = nil, nil
	if res, _ = f.svc.CheckProject(ctx, 3); res.Repos[0].Status != resultCloned || f.net.count("clone") != 1 {
		t.Fatalf("retry after a refused clone: %+v %v", res.Repos, f.net.calls)
	}

	f.net.lsRemoteErr, f.net.calls = prompt, nil
	res, _ = f.svc.CheckProject(ctx, 3)
	if res.Repos[0].Status != MirrorNeedsCredentials || f.st.mirrors[0].Status != MirrorNeedsCredentials || f.net.count("clone") != 0 {
		t.Fatalf("refresh refused: %+v %+v %v", res.Repos, f.st.mirrors, f.net.calls)
	}
	f.net.lsRemoteErr, f.net.calls = nil, nil
	res, _ = f.svc.CheckProject(ctx, 3)
	if res.Repos[0].Status != resultUnchanged || f.st.mirrors[0].Status != MirrorOK || f.net.count("clone") != 0 {
		t.Fatalf("recovered: %+v %+v %v", res.Repos, f.st.mirrors, f.net.calls)
	}
}
