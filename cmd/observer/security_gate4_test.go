//go:build !sbo_omit_security

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// gate4Repo is a repository with a committed-then-removed secret, for the
// per-remote hold tests: the secret's commit is recorded by the daemon's
// commit step, then the secret leaves the working tree by hand.
type gate4Repo struct {
	gn  gatefixNode
	n   gate2Node
	rs  *securityRescan
	sha string
}

func newGate4Repo(t *testing.T, remotes ...string) gate4Repo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	gn := newGatefixNode(t)
	n := newGate2Node(t)
	n.root = gn.root
	if err := os.MkdirAll(n.root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := n.st.UpsertProject(ctx, n.root, ""); err != nil {
		t.Fatal(err)
	}
	gitInitMain(t, n.root)
	for _, r := range remotes {
		bare := filepath.Join(t.TempDir(), r+".git")
		gitRun(t, n.root, "init", "-q", "--bare", bare)
		gitRun(t, n.root, "remote", "add", r, bare)
	}
	n.write(t, "README", "hello\n")
	gitRun(t, n.root, "add", "README")
	gitRun(t, n.root, "commit", "-q", "-m", "first")
	for _, r := range remotes {
		gitRun(t, n.root, "push", "-q", r, "main")
	}
	n.write(t, "cfg.py", secretLine)
	gitRun(t, n.root, "add", "cfg.py")
	gitRun(t, n.root, "commit", "-q", "-m", "add config")
	sha := gitRun(t, n.root, "rev-parse", "HEAD")
	step := &securityCommitStep{st: n.st, logger: n.log}
	step.recordCommit(ctx, n.root, secposture.ProjectRootHash(n.root), secquickscan.CommitResult{SHA: sha, Result: secquickscan.Result{
		Verdict: secquickscan.VerdictBlocking, Files: 1,
		Findings: []secquickscan.Finding{{
			Path: "cfg.py", Line: 1, Type: "aws_access_key", Confidence: secdetect.ConfidenceHigh,
			Identity: "id-aws_access_key-" + fakeSecretAWSKeyID,
		}},
	}})
	n.write(t, "cfg.py", "k = os.environ['K']\n")
	return gate4Repo{gn: gn, n: n, rs: &securityRescan{st: n.st, q: n.q, logger: n.log}, sha: sha}
}

// tick runs one rescan tick and re-signs the posture as the daemon does.
func (r gate4Repo) tick(t *testing.T, at time.Time) {
	t.Helper()
	ctx := context.Background()
	r.rs.tick(ctx, at)
	r.rs.waitHistory()
	r.n.q.Drain(ctx)
	r.n.signPostureScanned(t, r.gn)
}

func (r gate4Repo) push(t *testing.T, cmd string) policy.Verdict {
	t.Helper()
	r.n.signPostureScanned(t, r.gn)
	return r.gn.evaluate(t, &policy.Event{Kind: policy.KindShellExec, Target: cmd, ProjectRoot: r.n.root, Cwd: r.n.root})
}

// TestSecurityHoldIsPerRemote (lane sec-gate4 milestone 1a): with two
// remotes, a push of the secret's commit to one does not release the hold
// for the other. The agent's push to the remote that has it is not gated,
// its push to the other one is (S-792, naming the held commit and the
// remote), and so is a push whose remote cannot be read off the command.
// The finding carries the rotate note from the first push (milestone 1b);
// once both remotes have the commit it stays open with the note and stops
// gating.
func TestSecurityHoldIsPerRemote(t *testing.T) {
	r := newGate4Repo(t, "origin", "backup")
	now := time.Now()
	r.tick(t, now)
	if v := r.push(t, "git push backup main"); v.RuleID != "S-792" || v.Decision != policy.DecisionAsk {
		t.Fatalf("before any push: %+v, want S-792 ask", v)
	}

	gitRun(t, r.n.root, "push", "-q", "origin", "main")
	r.tick(t, now.Add(time.Minute))
	f := r.n.only(t, "secret.aws_access_key")
	if f.Status != policy.FindingStatusOpen || !strings.HasPrefix(f.FixHint, store.SecPushedNote) {
		t.Fatalf("after the push to origin: %s %q, want open with the rotate note", f.Status, f.FixHint)
	}
	if v := r.push(t, "git push origin main"); strings.HasPrefix(v.RuleID, "S-79") {
		t.Fatalf("the agent's push to the remote that has the commit is gated: %+v", v)
	}
	v := r.push(t, "git push backup main")
	if v.RuleID != "S-792" || v.Decision != policy.DecisionAsk {
		t.Fatalf("the agent's push to the other remote: %+v, want S-792 ask", v)
	}
	if want := "held by commit " + r.sha[:12] + ", not on remote backup yet"; !strings.Contains(v.Reason, want) {
		t.Fatalf("S-792 reason %q does not name %q", v.Reason, want)
	}
	if v := r.push(t, "git push"); v.RuleID != "S-792" {
		t.Fatalf("a push whose remote cannot be read: %+v, want S-792", v)
	}

	gitRun(t, r.n.root, "push", "-q", "backup", "main")
	r.tick(t, now.Add(2*time.Minute))
	f = r.n.only(t, "secret.aws_access_key")
	if f.Status != policy.FindingStatusOpen || !strings.HasPrefix(f.FixHint, store.SecPushedNote) {
		t.Fatalf("after both pushes: %s %q, want open with the rotate note", f.Status, f.FixHint)
	}
	for _, cmd := range []string{"git push backup main", "git push"} {
		if v := r.push(t, cmd); strings.HasPrefix(v.RuleID, "S-79") {
			t.Fatalf("%q after both remotes have the commit is gated: %+v", cmd, v)
		}
	}
}

// TestSecurityHoldReleasedByRewrite (lane sec-gate4 live-check shapes, run
// on a real repository): an amend or a reset that drops the secret's
// commit before it reached any remote leaves it reachable through the
// reflog, where a push by its reflog name or id can still send it, so the
// hold stays (lane SEC-GATE5 milestone 2, SECP-18); once the reflog no
// longer reaches it the commit is dangling and still held (lane SEC-P4
// decision 5), and once git prunes it the hold is released and the finding
// closes as not reproduced. In a repository with no remote the hold stays.
func TestSecurityHoldReleasedByRewrite(t *testing.T) {
	for _, how := range []string{"amend", "reset"} {
		t.Run(how, func(t *testing.T) {
			r := newGate4Repo(t, "origin")
			now := time.Now()
			r.tick(t, now)
			if v := r.push(t, "git push origin main"); v.RuleID != "S-792" {
				t.Fatalf("before the rewrite: %+v, want S-792", v)
			}
			switch how {
			case "amend":
				gitRun(t, r.n.root, "rm", "-q", "--cached", "cfg.py")
				gitRun(t, r.n.root, "commit", "-q", "--amend", "--allow-empty", "-m", "no config")
			default:
				gitRun(t, r.n.root, "reset", "-q", "HEAD~1")
			}
			r.tick(t, now.Add(time.Minute))
			if f := r.n.only(t, "secret.aws_access_key"); f.Status != policy.FindingStatusOpen {
				t.Fatalf("after the %s, still in the reflog: %s, want open", how, f.Status)
			}
			if v := r.push(t, "git push origin main"); v.RuleID != "S-792" {
				t.Fatalf("after the %s, still in the reflog: %+v, want S-792", how, v)
			}
			gitRun(t, r.n.root, "reflog", "expire", "--expire-unreachable=now", "--all")
			r.tick(t, now.Add(2*time.Minute))
			// Out of the reflog, the commit still exists (dangling) and a
			// push by its id still sends it: held until git prunes it (lane
			// SEC-P4 decision 5).
			if f := r.n.only(t, "secret.aws_access_key"); f.Status != policy.FindingStatusOpen {
				t.Fatalf("after the %s and the reflog expiry, the object still there: %s, want open", how, f.Status)
			}
			gitRun(t, r.n.root, "gc", "-q", "--prune=now")
			r.tick(t, now.Add(3*time.Minute))
			if f := r.n.only(t, "secret.aws_access_key"); f.Status != policy.FindingStatusNotReproduced {
				t.Fatalf("after the %s, the reflog expiry and git gc --prune=now: %s, want not_reproduced", how, f.Status)
			}
			if v := r.push(t, "git push origin main"); strings.HasPrefix(v.RuleID, "S-79") {
				t.Fatalf("after the %s the push is gated: %+v", how, v)
			}
		})
	}
	t.Run("no remote", func(t *testing.T) {
		r := newGate4Repo(t)
		now := time.Now()
		for i := range 2 {
			r.tick(t, now.Add(time.Duration(i)*time.Minute))
			if v := r.push(t, "git push origin main"); v.RuleID != "S-792" {
				t.Fatalf("tick %d: %+v, want S-792 (a repository with no remote keeps the hold)", i, v)
			}
		}
	})
}

// TestGithooksHistoryOnlyHold (lane sec-gate4 milestone 1d): the opt-in
// local git hooks treat a history-only hold as S-791 and S-792 do. With
// the secret removed from the files and committed away, the pre-commit
// check of a clean change is not refused because of the held commit;
// the pre-push check is, for a remote that does not have the commit yet
// (here a new branch on it, whose scan reads only the tip, which no longer
// shows the secret), and is not for the remote that has it.
func TestGithooksHistoryOnlyHold(t *testing.T) {
	r := newGate4Repo(t, "origin", "backup")
	gitRun(t, r.n.root, "push", "-q", "origin", "main")
	gitRun(t, r.n.root, "commit", "-q", "-am", "drop the key")
	tip := gitRun(t, r.n.root, "rev-parse", "HEAD")
	r.tick(t, time.Now())

	r.n.write(t, "notes.txt", "todo\n")
	gitRun(t, r.n.root, "add", "notes.txt")
	if line, refuse := githookVerdictLine("commit", githookEngine().Scan(context.Background(), secquickscan.Request{Root: r.n.root})); refuse {
		t.Fatalf("pre-commit of a clean change refused: %q", line)
	}

	ctx := context.Background()
	stdin := func(remoteSHA string) *strings.Reader {
		return strings.NewReader("refs/heads/main " + tip + " refs/heads/main " + remoteSHA + "\n")
	}
	line, refuse := githookPrepushCheck(ctx, r.gn.cfgPath, r.n.root, []string{"backup", "/b.git"}, stdin(strings.Repeat("0", 40)))
	if !refuse || !strings.Contains(line, "commit "+r.sha[:12]+" adds a secret that is not on remote backup yet") {
		t.Fatalf("pre-push to backup: %v %q, want refused naming the held commit", refuse, line)
	}
	if line, refuse := githookPrepushCheck(ctx, r.gn.cfgPath, r.n.root, []string{"origin", "/o.git"}, stdin(r.sha)); refuse {
		t.Fatalf("pre-push to origin, which has the commit, refused: %q", line)
	}
}

// TestSecurityHistoryCannotStallTheLoop (lane sec-gate4 milestone 2a): a
// git that hangs (it ignores its own per-call timeout) cannot stall the
// post-write loop. The tick returns at once, a tick while the pass still
// runs does not start a second one, and the pass ends at its budget.
func TestSecurityHistoryCannotStallTheLoop(t *testing.T) {
	ctx := context.Background()
	n := newGate2Node(t)
	if err := os.MkdirAll(n.root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := n.st.UpsertProject(ctx, n.root, ""); err != nil {
		t.Fatal(err)
	}
	hash := secposture.ProjectRootHash(n.root)
	for i := range 3 {
		f := secfinding.Normalize(secfinding.Finding{
			LocalKey: "k" + string(rune('0'+i)), Rule: secfinding.Rule{ID: "secret.aws_access_key", Pack: securitySecretsPack}, Engine: secfinding.Engine{Driver: "native"},
			Category: policy.FindingSecret, Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh,
			Project: secfinding.Project{RootHash: hash}, Scope: policy.FindingScopeCommit,
			Commit: secfinding.Commit{SHA: strings.Repeat(string(rune('a'+i)), 40)},
		})
		if _, _, err := n.st.UpsertSecFinding(ctx, f, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	var calls atomic.Int32
	hang := func(ctx context.Context, _ string, _ int, _ time.Duration, _ ...string) ([]byte, bool, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, false, ctx.Err()
	}
	rs := &securityRescan{
		st: n.st, q: n.q, logger: n.log, historyBudget: 300 * time.Millisecond,
		history: func(ctx context.Context, root, sha string) secquickscan.HistoryVerdict {
			return secquickscan.HistoryChecker{Git: hang, ExitCode: func(error) (int, bool) { return 0, false }}.Inspect(ctx, root, sha)
		},
	}
	t.Cleanup(rs.waitHistory)
	start := time.Now()
	rs.tick(ctx, start)
	rs.tick(ctx, start.Add(time.Minute))
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Fatalf("two ticks with a hung git took %s; the loop waited for the history pass", d)
	}
	done := make(chan struct{})
	go func() { rs.waitHistory(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the history pass did not end at its budget")
	}
	if c := calls.Load(); c != 1 {
		t.Fatalf("git calls = %d, want 1 (one pass at a time, stopped at its budget)", c)
	}
	for _, f := range n.findings(t) {
		if f.Status != policy.FindingStatusOpen {
			t.Fatalf("an unanswered history check changed a finding: %+v", f)
		}
	}
}
