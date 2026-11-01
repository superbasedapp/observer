//go:build !sbo_omit_security

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedOpen stores one open native finding as a run would.
func seedOpen(t *testing.T, st *store.Store, rootHash, pack, rule, key, rel string) {
	t.Helper()
	f := secfinding.Normalize(secfinding.Finding{
		LocalKey: key, Rule: secfinding.Rule{ID: rule, Pack: pack}, Engine: secfinding.Engine{Driver: "native"},
		Category: policy.FindingSecret, Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh,
		Project: secfinding.Project{RootHash: rootHash}, Location: secfinding.Location{RelPath: rel, StartLine: 1},
		Scope: policy.FindingScopePostWrite,
	})
	if _, _, err := st.UpsertSecFinding(context.Background(), f, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// TestSecurityRescanCannotStarve (lane sec-gate3 milestone 1a): 200 open
// rows the rescan can never answer sit ahead of one secret sighting (rows
// the rescan has no rule for, rows of a project the node does not know,
// and 140 secrets in files it cannot read, more than one page of the
// walk); the secret's file is edited by hand and its finding still closes
// within a few ticks.
func TestSecurityRescanCannotStarve(t *testing.T) {
	n := newGate2Node(t)
	ctx := context.Background()
	hash := secposture.ProjectRootHash(n.root)
	for i := range 200 {
		rel := fmt.Sprintf("a/%03d.py", i)
		switch i % 10 {
		case 0: // a removed-test observation (S-767): closes only by triage
			seedOpen(t, n.st, hash, securityCodePack, "code.s-767", "obs-"+rel, rel)
		case 1: // an install-gate row (S-747)
			seedOpen(t, n.st, hash, "security.deps", "S-747", "dep-"+rel, rel)
		case 2: // a project this node does not know
			seedOpen(t, n.st, "unknown-root-hash", securitySecretsPack, "secret.aws_access_key", "x-"+rel, rel)
		default: // a secret in a file that cannot be read (it is a directory)
			if err := os.MkdirAll(filepath.Join(n.root, filepath.FromSlash(rel)), 0o700); err != nil {
				t.Fatal(err)
			}
			seedOpen(t, n.st, hash, securitySecretsPack, "secret.generic", "dir-"+rel, rel)
		}
	}
	n.write(t, "z.py", secretLine)
	n.postWrite(t, "z.py")
	const rule = "secret.aws_access_key"
	var target secfinding.Finding
	for _, f := range n.findings(t) {
		if f.Rule.ID == rule && f.Location.RelPath == "z.py" {
			target = f
		}
	}
	if target.ID == "" || target.Status != policy.FindingStatusOpen {
		t.Fatalf("the secret in z.py is not open: %+v", target)
	}
	// A human edit: no action row, only the rescan sees it.
	n.write(t, "z.py", "k = os.environ['K']\n")
	rs := &securityRescan{st: n.st, q: n.q, code: true, logger: n.log}
	now := time.Now()
	for i := range 12 {
		rs.tick(ctx, now.Add(time.Duration(i)*time.Minute))
		rs.waitHistory()
		n.q.Drain(ctx)
	}
	f, ok, err := n.st.SecFindingByID(ctx, target.ID)
	if err != nil || !ok || f.Status != policy.FindingStatusNotReproduced {
		t.Fatalf("after 12 ticks the edited secret is %q (%v %v), want not_reproduced", f.Status, ok, err)
	}
}

// gitRun runs git in dir for a test, failing it on an error.
func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// gitInitMain makes dir a repository whose first branch is main, on any
// git version (`git init -b` needs git 2.28).
func gitInitMain(t *testing.T, dir string) {
	t.Helper()
	gitRun(t, dir, "init", "-q")
	gitRun(t, dir, "symbolic-ref", "HEAD", "refs/heads/main")
}

// TestSecurityUnpushedSecretGatesThePush (lane sec-gate3 milestone 1b): a
// developer commits a secret, then removes it by hand from the working
// tree (and in a second round with `git rm --cached` and a commit that
// deletes the file); the agent's push is still gated (S-792), because the
// commit that adds the secret is not on the upstream yet. Once the commit
// is pushed the finding closes and the push is no longer gated.
func TestSecurityUnpushedSecretGatesThePush(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	for _, removal := range []string{"edit", "rm", "commit deletes the file"} {
		t.Run(removal, func(t *testing.T) {
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
			remote := filepath.Join(t.TempDir(), "remote.git")
			gitInitMain(t, n.root)
			gitRun(t, n.root, "init", "-q", "--bare", remote)
			gitRun(t, n.root, "remote", "add", "origin", remote)
			n.write(t, "README", "hello\n")
			gitRun(t, n.root, "add", "README")
			gitRun(t, n.root, "commit", "-q", "-m", "first")
			gitRun(t, n.root, "push", "-q", "-u", "origin", "main")

			// The developer commits a secret; the daemon's commit scan records it.
			n.write(t, "cfg.py", secretLine)
			gitRun(t, n.root, "add", "cfg.py")
			gitRun(t, n.root, "commit", "-q", "-m", "add config")
			sha := gitRun(t, n.root, "rev-parse", "HEAD")
			hash := secposture.ProjectRootHash(n.root)
			identity := "id-aws_access_key-" + fakeSecretAWSKeyID
			step := &securityCommitStep{st: n.st, logger: n.log}
			step.recordCommit(ctx, n.root, hash, secquickscan.CommitResult{SHA: sha, Result: secquickscan.Result{
				Verdict: secquickscan.VerdictBlocking, Files: 1,
				Findings: []secquickscan.Finding{{Path: "cfg.py", Line: 1, Type: "aws_access_key", Confidence: secdetect.ConfidenceHigh, Identity: identity}},
			}})

			// The secret leaves the working tree.
			rs := &securityRescan{st: n.st, q: n.q, logger: n.log}
			now := time.Now()
			switch removal {
			case "edit":
				n.write(t, "cfg.py", "k = os.environ['K']\n")
			case "rm":
				if err := os.Remove(filepath.Join(n.root, "cfg.py")); err != nil {
					t.Fatal(err)
				}
			default:
				gitRun(t, n.root, "rm", "-q", "--cached", "cfg.py")
				if err := os.Remove(filepath.Join(n.root, "cfg.py")); err != nil {
					t.Fatal(err)
				}
				gitRun(t, n.root, "commit", "-q", "-m", "drop config")
				step.recordCommit(ctx, n.root, hash, secquickscan.CommitResult{SHA: gitRun(t, n.root, "rev-parse", "HEAD"), Result: secquickscan.Result{
					Verdict: secquickscan.VerdictClean, Deleted: []string{"cfg.py"},
					Removed: []secquickscan.Finding{{Path: "cfg.py", Line: 1, Type: "aws_access_key", Confidence: secdetect.ConfidenceHigh, Identity: identity}},
				}})
			}
			rs.tick(ctx, now)
			rs.waitHistory()
			n.q.Drain(ctx)
			f := n.only(t, "secret.aws_access_key")
			if f.Status != policy.FindingStatusOpen {
				t.Fatalf("after the %s the unpushed secret is %s, want open", removal, f.Status)
			}
			push := &policy.Event{Kind: policy.KindShellExec, Target: "git push", ProjectRoot: n.root, Cwd: n.root}
			n.signPosture(t, gn)
			if v := gn.evaluate(t, push); v.RuleID != "S-792" || v.Decision != policy.DecisionAsk {
				t.Fatalf("the agent's push after the %s: %+v, want S-792 ask", removal, v)
			}

			// Pushed: the commit is on the only remote. The secret is on
			// the remote now, so the finding stays open with the rotate
			// note (lane sec-gate4 milestone 1b) and no longer gates the
			// push, which already happened.
			gitRun(t, n.root, "push", "-q", "origin", "main")
			rs.tick(ctx, now.Add(securityRescanQuiet+time.Minute))
			rs.waitHistory()
			n.q.Drain(ctx)
			if f := n.only(t, "secret.aws_access_key"); f.Status != policy.FindingStatusOpen || !strings.HasPrefix(f.FixHint, store.SecPushedNote) {
				t.Fatalf("after the push: %s %q, want open with the rotate note", f.Status, f.FixHint)
			}
			n.signPosture(t, gn)
			if v := gn.evaluate(t, &policy.Event{Kind: policy.KindShellExec, Target: "git push", ProjectRoot: n.root, Cwd: n.root}); v.RuleID == "S-792" {
				t.Fatalf("a pushed and removed secret still gates the push: %+v", v)
			}
		})
	}
}

// signPosture writes the project's posture as the daemon computes it from
// the store, signed with the node's key.
func (n gate2Node) signPosture(t *testing.T, gn gatefixNode) {
	t.Helper()
	n.signPostureEpoch(t, gn, 0)
}

// signPostureScanned is signPosture with the project's dirty counter
// covered, as after a clean quick scan of the agent's changes (the hook
// raises the counter on every agent command it fills).
func (n gate2Node) signPostureScanned(t *testing.T, gn gatefixNode) {
	t.Helper()
	dirty, err := secposture.ReadDirty(gn.layout, secposture.ProjectRootHash(n.root))
	if err != nil {
		t.Fatal(err)
	}
	n.signPostureEpoch(t, gn, dirty)
}

// signPostureEpoch is signPosture with the given clean-scan epoch.
func (n gate2Node) signPostureEpoch(t *testing.T, gn gatefixNode, epoch uint64) {
	t.Helper()
	svc, err := secsvc.New(context.Background(), secsvc.Options{
		Layout: gn.layout, Store: n.st,
		Projects:           func(context.Context, time.Time) ([]string, error) { return []string{n.root}, nil },
		Packs:              func() []string { return gatefixPacks },
		QuickScanAvailable: func() bool { return true },
		PushDefault:        securityPushDefaults.get,
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := svc.Compute(context.Background(), n.root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	gn.writeCleanPosture(t, func(c *secposture.File) {
		c.Blocking, c.HistoryOnly, c.Overflow, c.Counts = f.Blocking, f.HistoryOnly, f.Overflow, f.Counts
		c.HistoryOnlyOn, c.Held, c.HeldOverflow, c.DefaultPushRemote = f.HistoryOnlyOn, f.Held, f.HeldOverflow, f.DefaultPushRemote
		c.HistoryCapped = f.HistoryCapped
		c.DirtyCleanEpoch = epoch
	})
}

// TestSecurityHistoryCheckStates (milestone 1b): the history check's
// answers on a real repository: a local commit is unpushed, a pushed one
// is pushed, a commit a reset left reachable only through the reflog stays
// unpushed (lane SEC-GATE5 milestone 2) and is gone once the reflog no
// longer reaches it, and a commit id the repository does not have is gone;
// a directory outside git is unknown.
func TestSecurityHistoryCheckStates(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	repo := t.TempDir()
	remote := filepath.Join(t.TempDir(), "r.git")
	gitInitMain(t, repo)
	gitRun(t, repo, "init", "-q", "--bare", remote)
	gitRun(t, repo, "remote", "add", "origin", remote)
	if err := os.WriteFile(filepath.Join(repo, "a"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "a")
	gitRun(t, repo, "commit", "-q", "-m", "one")
	first := gitRun(t, repo, "rev-parse", "HEAD")
	gitRun(t, repo, "push", "-q", "-u", "origin", "main")
	if err := os.WriteFile(filepath.Join(repo, "a"), []byte("2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "commit", "-q", "-am", "two")
	second := gitRun(t, repo, "rev-parse", "HEAD")
	if got := productionHistory(ctx, repo, first).State; got != secquickscan.HistoryPushed {
		t.Errorf("pushed commit: %s", got)
	}
	if got := productionHistory(ctx, repo, second).State; got != secquickscan.HistoryUnpushed {
		t.Errorf("local commit: %s", got)
	}
	gitRun(t, repo, "checkout", "-q", "--detach")
	if got := productionHistory(ctx, repo, second).State; got != secquickscan.HistoryUnpushed {
		t.Errorf("local commit on a detached HEAD too: %s", got)
	}
	gitRun(t, repo, "checkout", "-q", "main")
	gitRun(t, repo, "reset", "-q", "--hard", first)
	if got := productionHistory(ctx, repo, second).State; got != secquickscan.HistoryUnpushed {
		t.Errorf("commit reset away, still in the reflog: %s", got)
	}
	gitRun(t, repo, "reflog", "expire", "--expire-unreachable=now", "--all")
	if v := productionHistory(ctx, repo, second); v.State != secquickscan.HistoryUnpushed || v.Reason != secquickscan.HistoryReasonDangling {
		t.Errorf("commit reset away and out of the reflog, object still there: %+v, want unpushed (dangling)", v)
	}
	gitRun(t, repo, "gc", "-q", "--prune=now")
	if got := productionHistory(ctx, repo, second).State; got != secquickscan.HistoryGone {
		t.Errorf("commit reset away, out of the reflog and pruned: %s", got)
	}
	if got := productionHistory(ctx, repo, strings.Repeat("ab", 20)).State; got != secquickscan.HistoryGone {
		t.Errorf("commit the repository does not have: %s", got)
	}
	if got := productionHistory(ctx, t.TempDir(), first).State; got != secquickscan.HistoryUnknown {
		t.Errorf("outside git: %s", got)
	}
}

// TestSecurityHistoryOnlyHoldGatesOnlyThePush (lane sec-gate3 audit
// finding 2): a developer commits a secret, and while the secret is in the
// tree the agent's commit is asked (S-791). Once it is removed by hand only
// its unpushed commit holds the finding: the agent's commit of an
// unrelated clean change is no longer asked because of it, and the agent's
// push still is (S-792). In a repository with no remote the hold never
// releases, and the agent's commits stay unasked tick after tick.
func TestSecurityHistoryOnlyHoldGatesOnlyThePush(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	for _, withRemote := range []bool{true, false} {
		name := "no remote"
		if withRemote {
			name = "remote"
		}
		t.Run(name, func(t *testing.T) {
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
			if withRemote {
				remote := filepath.Join(t.TempDir(), "remote.git")
				gitRun(t, n.root, "init", "-q", "--bare", remote)
				gitRun(t, n.root, "remote", "add", "origin", remote)
			}
			n.write(t, "README", "hello\n")
			gitRun(t, n.root, "add", "README")
			gitRun(t, n.root, "commit", "-q", "-m", "first")
			if withRemote {
				gitRun(t, n.root, "push", "-q", "-u", "origin", "main")
			}

			n.write(t, "cfg.py", secretLine)
			gitRun(t, n.root, "add", "cfg.py")
			gitRun(t, n.root, "commit", "-q", "-m", "add config")
			sha := gitRun(t, n.root, "rev-parse", "HEAD")
			hash := secposture.ProjectRootHash(n.root)
			step := &securityCommitStep{st: n.st, logger: n.log}
			step.recordCommit(ctx, n.root, hash, secquickscan.CommitResult{SHA: sha, Result: secquickscan.Result{
				Verdict: secquickscan.VerdictBlocking, Files: 1,
				Findings: []secquickscan.Finding{{
					Path: "cfg.py", Line: 1, Type: "aws_access_key", Confidence: secdetect.ConfidenceHigh,
					Identity: "id-aws_access_key-" + fakeSecretAWSKeyID,
				}},
			}})
			n.signPostureScanned(t, gn)
			if v := gn.evaluate(t, gn.commit()); v.RuleID != "S-791" || v.Decision != policy.DecisionAsk {
				t.Fatalf("the agent's commit with the secret still in the tree: %+v, want S-791 ask", v)
			}

			// The developer removes it by hand; an unrelated clean change
			// waits to be committed.
			n.write(t, "cfg.py", "k = os.environ['K']\n")
			n.write(t, "notes.txt", "todo\n")
			gitRun(t, n.root, "add", "notes.txt")
			rs := &securityRescan{st: n.st, q: n.q, logger: n.log}
			now := time.Now()
			push := &policy.Event{Kind: policy.KindShellExec, Target: "git push", ProjectRoot: n.root, Cwd: n.root}
			for i := range 3 {
				rs.tick(ctx, now.Add(time.Duration(i)*(securityRescanQuiet+time.Hour)))
				rs.waitHistory()
				n.q.Drain(ctx)
				if f := n.only(t, "secret.aws_access_key"); f.Status != policy.FindingStatusOpen {
					t.Fatalf("tick %d: the unpushed secret is %s, want open (held)", i, f.Status)
				}
				n.signPostureScanned(t, gn)
				if v := gn.evaluate(t, gn.commit()); strings.HasPrefix(v.RuleID, "S-79") {
					t.Fatalf("tick %d: the agent's commit of an unrelated change is gated by the history-only hold: %+v", i, v)
				}
				n.signPostureScanned(t, gn)
				if v := gn.evaluate(t, push); v.RuleID != "S-792" || v.Decision != policy.DecisionAsk {
					t.Fatalf("tick %d: the agent's push: %+v, want S-792 ask", i, v)
				}
			}
		})
	}
}

// TestSecurityHistoryCheckNeverFetches (lane sec-gate3 audit finding 3):
// the history check runs git through the no-lazy-fetch envelope, so
// `cat-file -e` of a commit a partial clone lacks never reaches the
// promisor remote.
func TestSecurityHistoryCheckNeverFetches(t *testing.T) {
	if reflect.ValueOf(historyGit).Pointer() != reflect.ValueOf(gitview.RunReadOnlyNoLazyFetch).Pointer() {
		t.Fatal("the history check does not use gitview.RunReadOnlyNoLazyFetch")
	}
}
