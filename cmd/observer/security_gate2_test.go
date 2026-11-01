//go:build !sbo_omit_security

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secciwf"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secdiffobs"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secpostwrite"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// gate2Node is a test project: a store that knows its root, and the
// post-write queue a rescan submits to, drained by the test.
type gate2Node struct {
	st   *store.Store
	root string
	q    *secpostwrite.Queue
	log  *slog.Logger
}

func newGate2Node(t *testing.T) gate2Node {
	t.Helper()
	st, _ := openTestStore(t)
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	if _, err := st.UpsertProject(context.Background(), root, ""); err != nil {
		t.Fatal(err)
	}
	n := gate2Node{st: st, root: root, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	n.q = &secpostwrite.Queue{Scanner: secdetect.Scanner{Identify: func(typ, v string) string { return "id-" + typ + "-" + v }}}
	n.q.Sink = func(ctx context.Context, r secpostwrite.Result) { recordPostWrite(ctx, st, r, n.log) }
	return n
}

func (n gate2Node) write(t *testing.T, rel, body string) {
	t.Helper()
	p := filepath.Join(n.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// postWrite feeds one agent write through the post-write queue.
func (n gate2Node) postWrite(t *testing.T, rel string) {
	t.Helper()
	n.q.Submit(secpostwrite.Write{SessionID: "s", ActionID: 1, ProjectRoot: n.root, Path: rel})
	n.q.Drain(context.Background())
}

func (n gate2Node) findings(t *testing.T) []secfinding.Finding {
	t.Helper()
	fs, err := n.st.ListSecFindings(context.Background(), store.SecFindingFilter{ProjectRootHash: secposture.ProjectRootHash(n.root)})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// only returns the one finding of rule.
func (n gate2Node) only(t *testing.T, rule string) secfinding.Finding {
	t.Helper()
	var out []secfinding.Finding
	for _, f := range n.findings(t) {
		if f.Rule.ID == rule {
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("%s findings = %+v, want one", rule, out)
	}
	return out[0]
}

const secretLine = "k = \"" + fakeSecretAWSKeyID + "\"\n"

// TestSecurityRemovedSecretClosesByPathAndIdentity (lane sec-gate2
// milestone 1b): the same secret in two files is one finding; a human edit
// that removes it from one file (seen by the rescan, no action row) keeps
// it open at the other; an `rm` of the other closes it.
func TestSecurityRemovedSecretClosesByPathAndIdentity(t *testing.T) {
	n := newGate2Node(t)
	ctx := context.Background()
	n.write(t, "a.py", secretLine)
	n.write(t, "b.py", "x = 1\n"+secretLine)
	n.postWrite(t, "a.py")
	n.postWrite(t, "b.py")
	const rule = "secret.aws_access_key"
	if f := n.only(t, rule); f.Status != policy.FindingStatusOpen {
		t.Fatalf("not open: %+v", f)
	}
	// A human edit of a.py: no action row, only the rescan sees it.
	n.write(t, "a.py", "k = os.environ['K']\n")
	rs := &securityRescan{st: n.st, q: n.q, logger: n.log}
	now := time.Now()
	rs.tick(ctx, now)
	rs.waitHistory()
	n.q.Drain(ctx)
	f := n.only(t, rule)
	if f.Status != policy.FindingStatusOpen || f.Location.RelPath != "b.py" {
		t.Fatalf("after the edit of a.py: %s at %s, want open at b.py", f.Status, f.Location.RelPath)
	}
	// An `rm` of b.py closes the last sighting.
	if err := os.Remove(filepath.Join(n.root, "b.py")); err != nil {
		t.Fatal(err)
	}
	rs.tick(ctx, now.Add(securityRescanQuiet+time.Minute))
	rs.waitHistory()
	n.q.Drain(ctx)
	if f := n.only(t, rule); f.Status != policy.FindingStatusNotReproduced {
		t.Fatalf("after rm of b.py: %s, want not_reproduced", f.Status)
	}
}

// TestSecurityCommitRemovalKeepsOtherSighting (milestone 1b): a commit
// that removes the secret from one file drops that sighting only; a commit
// that deletes the other file closes it.
func TestSecurityCommitRemovalKeepsOtherSighting(t *testing.T) {
	n := newGate2Node(t)
	ctx := context.Background()
	n.write(t, "a.py", secretLine)
	n.write(t, "b.py", secretLine)
	n.postWrite(t, "a.py")
	n.postWrite(t, "b.py")
	identity := "id-aws_access_key-" + fakeSecretAWSKeyID
	step := &securityCommitStep{st: n.st, logger: n.log}
	hash := secposture.ProjectRootHash(n.root)
	removed := secquickscan.CommitResult{SHA: "0123456789abcdef0123456789abcdef01234567", Result: secquickscan.Result{
		Verdict: secquickscan.VerdictClean, Files: 1,
		Removed: []secquickscan.Finding{{Path: "a.py", Type: "aws_access_key", Confidence: secdetect.ConfidenceHigh, Identity: identity}},
	}}
	step.recordCommit(ctx, n.root, hash, removed)
	if f := n.only(t, "secret.aws_access_key"); f.Status != policy.FindingStatusOpen || f.Location.RelPath != "b.py" {
		t.Fatalf("removed from a.py only: %s at %s, want open at b.py", f.Status, f.Location.RelPath)
	}
	deleted := secquickscan.CommitResult{SHA: "1123456789abcdef0123456789abcdef01234567", Result: secquickscan.Result{
		Verdict: secquickscan.VerdictClean, Files: 0, Deleted: []string{"b.py"},
	}}
	step.recordCommit(ctx, n.root, hash, deleted)
	if f := n.only(t, "secret.aws_access_key"); f.Status != policy.FindingStatusNotReproduced {
		t.Fatalf("b.py deleted by a commit: %s, want not_reproduced", f.Status)
	}
}

// TestSecurityCIAndObservationFindingsClose (milestone 1d): a workflow rule
// finding closes once the workflow, checked whole, no longer fires the
// rule; a disabled-verification observation closes once the file no longer
// holds the pattern; a deleted file closes both. An unrelated observation
// (removed assertions) stays open.
func TestSecurityCIAndObservationFindingsClose(t *testing.T) {
	n := newGate2Node(t)
	ctx := context.Background()
	hash := secposture.ProjectRootHash(n.root)
	const wf = ".github/workflows/ci.yml"
	bad := "on: pull_request_target\npermissions: write-all\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
	good := "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
	n.write(t, wf, bad)
	rep := secciwf.Check([]byte(bad))
	if !rep.Complete() || len(rep.Findings) == 0 {
		t.Fatalf("the fixture fires no workflow rule: %+v", rep)
	}
	var ci []secquickscan.CIFinding
	for _, h := range rep.Findings {
		ci = append(ci, secquickscan.CIFinding{Path: wf, RuleID: h.RuleID, Line: h.Line, Severity: h.Severity, FlagOnly: h.FlagOnly})
	}
	n.write(t, "client.py", "requests.get(u, verify=False)\n")
	obs := secdiffobs.Observe([]secdiffobs.FileDiff{secdiffobs.FromEdit("client.py", "", "requests.get(u, verify=False)\n")})
	asserts := secdiffobs.Observation{RuleID: "S-768", Path: "client_test.py", Line: 1, Message: "x"}
	recordSecurityCode(ctx, n.st, n.root, hash, "", policy.FindingScopeStaged, secquickscan.Result{CI: ci, CIChecked: []string{wf}, Observations: append(obs, asserts), Files: 3}, n.log)
	open := func() map[string]bool {
		m := map[string]bool{}
		for _, f := range n.findings(t) {
			if f.Status == policy.FindingStatusOpen {
				m[f.Rule.ID] = true
			}
		}
		return m
	}
	before := open()
	if !before["code.s-761"] || !before["code.s-768"] || len(before) < 3 {
		t.Fatalf("open before = %v", before)
	}
	n.write(t, wf, good)
	n.write(t, "client.py", "requests.get(u)\n")
	rs := &securityRescan{st: n.st, q: n.q, code: true, logger: n.log}
	rs.tick(ctx, time.Now())
	rs.waitHistory()
	after := open()
	for id := range before {
		want := id == "code.s-768"
		if after[id] != want {
			t.Errorf("%s open after the fix = %v, want %v (open: %v)", id, after[id], want, after)
		}
	}
	// A deleted workflow closes a workflow finding seen again since.
	n.write(t, wf, bad)
	recordSecurityCode(ctx, n.st, n.root, hash, "", policy.FindingScopeStaged, secquickscan.Result{CI: ci, CIChecked: []string{wf}, Files: 1}, n.log)
	if err := os.Remove(filepath.Join(n.root, filepath.FromSlash(wf))); err != nil {
		t.Fatal(err)
	}
	rs.tick(ctx, time.Now().Add(securityRescanQuiet+time.Minute))
	rs.waitHistory()
	for id := range open() {
		if id != "code.s-768" {
			t.Errorf("%s still open after the workflow was deleted", id)
		}
	}
}

// TestSecurityDirtyCounterCapturedOncePerLine (lane sec-gate2 milestone
// 1c): every quick-scan request of one line carries the dirty counter read
// before the line's first Fill raised it, so the push's scan cannot cover
// the commit event's own raise.
func TestSecurityDirtyCounterCapturedOncePerLine(t *testing.T) {
	n := newGatefixNode(t)
	hash := secposture.ProjectRootHash(n.root)
	for i := 0; i < 3; i++ {
		if err := secposture.RaiseDirty(n.layout, hash); err != nil {
			t.Fatal(err)
		}
	}
	var seen []uint64
	prov := hookctx.HostProviders{
		Sidecar: func(context.Context, hookctx.Request) (hookctx.Security, error) {
			return hookctx.Security{Posture: hookctx.PostureDirty, Packs: gatefixPacks}, nil
		},
		Dirty: func(_ context.Context, root string) error {
			return secposture.RaiseDirty(n.layout, secposture.ProjectRootHash(root))
		},
		QuickScan: func(_ context.Context, req hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
			seen = append(seen, req.DirtySeen)
			return hookctx.QuickScanResult{Verdict: hookctx.QuickScanClean, DirtyCovered: req.DirtySeen}, nil
		},
	}
	setInvocationHookContext(hookctx.Host(context.Background(), hookctx.Request{}, hookctx.Source{}, prov), "")
	pe := &policy.Event{Kind: policy.KindShellExec, Target: "git commit -m a && git push", ProjectRoot: n.root, Cwd: n.root}
	securityToolGateEnrich(n.cfgPath, models.ToolClaudeCode, "PreToolUse", nil)(pe)
	if len(seen) != 2 || seen[0] != 3 || seen[1] != 3 {
		t.Fatalf("DirtySeen per request = %v, want [3 3] (the counter before the line's raise)", seen)
	}
	if now, _ := secposture.ReadDirty(n.layout, hash); now != 4 {
		t.Fatalf("counter after the event = %d, want 4 (one raise)", now)
	}
}

// TestSecuritySecretPresenceRescansEverySighting (milestone 2c): the
// sweep's presence check reads every file the finding is sighted in with
// the node-keyed detector: present while one still holds the secret, gone
// once none does (edited or deleted), unknown when a file cannot be read.
func TestSecuritySecretPresenceRescansEverySighting(t *testing.T) {
	n := newGate2Node(t)
	ctx := context.Background()
	n.write(t, "a.py", secretLine)
	n.write(t, "b.py", secretLine)
	n.postWrite(t, "a.py")
	n.postWrite(t, "b.py")
	f := n.only(t, "secret.aws_access_key")
	check := securitySecretPresence(n.st, func(typ, v string) string { return "id-" + typ + "-" + v })
	if present, known := check(ctx, f); !present || !known {
		t.Fatalf("both files hold it: present %v known %v", present, known)
	}
	n.write(t, "a.py", "x = 1\n")
	if present, known := check(ctx, f); !present || !known {
		t.Fatalf("b.py still holds it: present %v known %v", present, known)
	}
	if err := os.Remove(filepath.Join(n.root, "b.py")); err != nil {
		t.Fatal(err)
	}
	if present, known := check(ctx, f); present || !known {
		t.Fatalf("edited and deleted: present %v known %v, want gone", present, known)
	}
	if err := os.Symlink(filepath.Join(n.root, "a.py"), filepath.Join(n.root, "b.py")); err == nil {
		if _, known := check(ctx, f); known {
			t.Fatal("a file the reader refuses (a symlink) gave a known answer")
		}
	}
	if securitySecretPresence(n.st, nil) != nil {
		t.Fatal("no node key must mean no presence check (the finding reopens)")
	}
}

// TestSecurityGateExplainsAStoppedDaemon (lane sec-gate2 milestone 2d):
// after `observer stop` the signed guard posture ages past its freshness
// window; the commit gate still asks (S-794 on an unknown state, S-793 on
// a dirty one whose quick scan cannot run) and now says the daemon is not
// running and how to start it. A fresh posture keeps the plain wording.
func TestSecurityGateExplainsAStoppedDaemon(t *testing.T) {
	for _, tc := range []struct {
		name    string
		age     time.Duration
		dirty   bool
		rule    string
		stopped bool
	}{
		{"fresh, unknown", 0, false, "S-794", false},
		{"stopped, unknown", 10 * time.Minute, false, "S-794", true},
		{"stopped, dirty", 10 * time.Minute, true, "S-793", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newGatefixNode(t)
			writePosture(t, n.cfgPath, guardposture.Posture{Source: "test", SecurityRecorded: true, SecurityActive: true, SecurityPacks: gatefixPacks, WrittenAt: time.Now().Add(-tc.age)})
			if tc.dirty {
				n.writeCleanPosture(t, func(f *secposture.File) { f.QuickScanAvailable = false })
				if err := secposture.RaiseDirty(n.layout, secposture.ProjectRootHash(n.root)); err != nil {
					t.Fatal(err)
				}
			}
			commit := n.commit()
			v := n.evaluate(t, commit)
			if v.RuleID != tc.rule || v.Decision != policy.DecisionAsk {
				t.Fatalf("verdict %+v (security %+v), want %s ask", v, commit.Security, tc.rule)
			}
			if got := strings.Contains(v.Reason, "observer start"); got != tc.stopped {
				t.Fatalf("reason %q: names `observer start` = %v, want %v", v.Reason, got, tc.stopped)
			}
		})
	}
}

// TestSecurityAllowRootSpellings (lane sec-gate2 milestone 3): the
// quick-scan allow-check accepts a known root in the hook's Windows
// spelling under WSL and a git working tree's root the node does not list
// yet, and still refuses a subdirectory of it or a directory outside git.
func TestSecurityAllowRootSpellings(t *testing.T) {
	var rt securityRuntime
	now := time.Now()
	// The root as a Linux or WSL node stores it (the /mnt/c spelling, a
	// literal: seeding with commitScanRoot(win) would let a translation
	// that returned its input unchanged pass), named by the hook in Windows
	// form (lane sec-gate3 milestone 2c).
	const win = `C:\Users\u\repo`
	const stored = "/mnt/c/Users/u/repo"
	roots := []string{stored}
	list := func(context.Context) ([]string, error) { return roots, nil }
	rt.projects.Store(&list)
	if runtime.GOOS != "windows" {
		if !rt.allowRoot(win, now) {
			t.Fatalf("the Windows spelling of the known root %q is refused", stored)
		}
		if rt.allowRoot(`C:\Users\u\elsewhere`, now) {
			t.Fatal("the Windows spelling of an unknown root is allowed")
		}
	}
	if !rt.allowRoot(stored, now) {
		t.Fatal("the stored spelling of the known root is refused")
	}
	repo := t.TempDir()
	if r, err := filepath.EvalSymlinks(repo); err == nil {
		repo = r
	}
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if gitRoot, ok := git.FindRoot(repo); !ok || gitRoot != repo {
		t.Skipf("git.FindRoot does not see the fixture repository (%q, %v)", gitRoot, ok)
	}
	if !rt.allowRoot(repo, now) {
		t.Fatal("a git working tree's root not yet in projects is refused")
	}
	sub := filepath.Join(repo, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if rt.allowRoot(sub, now) {
		t.Fatal("a subdirectory of a repository is allowed as a root")
	}
	if rt.allowRoot(t.TempDir(), now) {
		t.Fatal("a directory outside any repository is allowed")
	}
	var none securityRuntime
	if none.allowRoot(repo, now) {
		t.Fatal("no project list published: a root is allowed")
	}
}
