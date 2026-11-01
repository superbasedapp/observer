//go:build !sbo_omit_security

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secpostwrite"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeSecretAWSKeyID is shaped like an AWS key id and visibly fake. It is
// not an ...EXAMPLE value on purpose: secdetect never fires on an AWS-shaped
// key ending in EXAMPLE (knownExample), and these tests need a hit.
const fakeSecretAWSKeyID = "AKIA" + "FAKEFIXTURE0TEST" // split: GitHub push protection on the public mirror

// TestSecurityQuickScanPlan: one request per gating commit or push (a
// chained commit and push is two, scanned one by one), none for a
// flag-only form or a read, an opaque plan for a directory change out of
// the project or too many writes, and aliases read like the gate rows.
func TestSecurityQuickScanPlan(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	aliases := func(string) (map[string]string, bool) { return map[string]string{"ci": "commit", "p": "push"}, true }
	cases := []struct {
		cmd    string
		reqs   int
		opaque bool
	}{
		{"git commit -m wip", 1, false},
		{"git push origin main", 1, false},
		{"git merge feature", 1, false},
		{"git commit -m a && git push", 2, false},
		{"git ci -m a && git p", 2, false},
		{"git status", 0, false},
		{"git stash", 0, false},
		{"cd " + other + " && git commit -m x", 0, true},
		{"cd sub && git commit -m x", 1, false},
		{"cd $HOME/x && git commit -m x", 0, true},
		{"cd .. && git commit -m x", 0, true},
		{"git commit -m a; git commit -m b; git commit -m c; git commit -m d; git push", 0, true},
	}
	for _, tc := range cases {
		pe := &policy.Event{Kind: policy.KindShellExec, Target: tc.cmd, Cwd: repo}
		plan := securityQuickScanPlanFor(pe, repo, aliases)
		if len(plan.reqs) != tc.reqs || plan.opaque != tc.opaque {
			t.Errorf("%q: %d requests, opaque %v; want %d, %v", tc.cmd, len(plan.reqs), plan.opaque, tc.reqs, tc.opaque)
		}
		for _, r := range plan.reqs {
			if r.OnlyWhen == nil {
				t.Errorf("%q: no OnlyWhen", tc.cmd)
			}
		}
	}
	if p := securityQuickScanPlanFor(&policy.Event{Kind: policy.KindShellExec, Target: "git ci -m x && git p"}, repo, nil); len(p.reqs) != 0 {
		t.Errorf("without the alias table an alias is not a write: %+v", p)
	}
	if p := securityQuickScanPlanFor(&policy.Event{Kind: policy.KindShellExec, Target: "git commit -m x"}, "", nil); len(p.reqs) != 0 || p.opaque {
		t.Error("a request with no project root")
	}
	if p := securityQuickScanPlanFor(&policy.Event{Kind: policy.KindFileAccess, Target: "git commit -m x"}, repo, nil); len(p.reqs) != 0 {
		t.Error("a file write is never classified")
	}
}

// TestSecurityQuickScanCombinesWrites (milestone 2a): `git commit && git
// push` scans both and is clean only when both are; a non-clean first
// answer stops the walk; an opaque line is unknown with no daemon call.
func TestSecurityQuickScanCombinesWrites(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cmd     string
		answers map[bool]hookctx.QuickScanVerdict // keyed by "is a push"
		want    policy.QuickScanVerdict
		scans   int
	}{
		{"both clean", "git commit -m a && git push", map[bool]hookctx.QuickScanVerdict{false: hookctx.QuickScanClean, true: hookctx.QuickScanClean}, policy.QuickScanClean, 2},
		{"push blocking", "git commit -m a && git push", map[bool]hookctx.QuickScanVerdict{false: hookctx.QuickScanClean, true: hookctx.QuickScanBlocking}, policy.QuickScanBlocking, 2},
		{"commit unknown stops", "git commit -m a && git push", map[bool]hookctx.QuickScanVerdict{false: hookctx.QuickScanUnknown, true: hookctx.QuickScanClean}, policy.QuickScanUnknown, 1},
		// A commit in another repository reads that repository's posture
		// (none here: unknown, lane SEC-GATE5 milestone 1), which outranks
		// dirty, so no quick scan is read and S-794 asks.
		{"directory change", "cd /elsewhere && git commit -m a", nil, policy.QuickScanNone, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scans, dirty := 0, 0
			prov := hookctx.HostProviders{
				Sidecar: func(context.Context, hookctx.Request) (hookctx.Security, error) {
					return hookctx.Security{Posture: hookctx.PostureDirty, Packs: []string{"security"}}, nil
				},
				Dirty: func(context.Context, string) error { dirty++; return nil },
				QuickScan: func(_ context.Context, req hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
					scans++
					return hookctx.QuickScanResult{Verdict: tc.answers[policy.GitWriteIsPush(req.Form)]}, nil
				},
			}
			cfgPath := filepath.Join(t.TempDir(), "config.toml")
			writeGuardPosture(t, cfgPath, true)
			setInvocationHookContext(hookctx.Host(context.Background(), hookctx.Request{}, hookctx.Source{}, prov), "")
			t.Cleanup(func() { setInvocationHookContext(nil, "") })
			pe := &policy.Event{Kind: policy.KindShellExec, Target: tc.cmd, ProjectRoot: "/r", Cwd: "/r"}
			securityToolGateEnrich(cfgPath, models.ToolClaudeCode, "PreToolUse", nil)(pe)
			if pe.Security == nil || pe.Security.QuickScan != tc.want || scans != tc.scans {
				t.Fatalf("security %+v, scans %d; want %s, %d", pe.Security, scans, tc.want, tc.scans)
			}
			if dirty != 1 {
				t.Fatalf("dirty raised %d times, want once per event", dirty)
			}
		})
	}
}

// TestSecurityToolGateEnrichPhaseC drives the tool gate's enrich step over
// a fake posture and quick scan: a write carries its in-hook secret hits; a
// commit in a dirty project carries the quick scan's verdict; a commit in a
// clean project asks nothing.
func TestSecurityToolGateEnrichPhaseC(t *testing.T) {
	posture := hookctx.PostureDirty
	scans := 0
	prov := hookctx.HostProviders{
		Sidecar: func(context.Context, hookctx.Request) (hookctx.Security, error) {
			return hookctx.Security{Posture: posture, Packs: []string{"security", "security.secrets"}}, nil
		},
		QuickScan: func(_ context.Context, req hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
			scans++
			if req.Form.Form != policy.GitWriteCommit {
				t.Errorf("form %+v", req.Form)
			}
			return hookctx.QuickScanResult{Verdict: hookctx.QuickScanClean}, nil
		},
	}
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	writeGuardPosture(t, cfgPath, true)
	setInvocationHookContext(hookctx.Host(context.Background(), hookctx.Request{}, hookctx.Source{}, prov), "")
	t.Cleanup(func() { setInvocationHookContext(nil, "") })
	enrich := securityToolGateEnrich(cfgPath, models.ToolClaudeCode, "PreToolUse", nil)

	write := &policy.Event{
		Kind: policy.KindFileAccess, ActionType: models.ActionWriteFile, Target: "/r/cfg.py", ProjectRoot: "/r",
		Edits: []policy.ProposedEdit{{Kind: policy.EditWhole, New: "k = \"" + fakeSecretAWSKeyID + "\"\n"}},
	}
	enrich(write)
	if write.Security == nil || len(write.Security.Hits) != 1 || write.Security.QuickScan != policy.QuickScanNone {
		t.Fatalf("write security = %+v", write.Security)
	}

	commit := &policy.Event{Kind: policy.KindShellExec, Target: "git commit -m wip", ProjectRoot: "/r"}
	enrich(commit)
	if commit.Security == nil || commit.Security.QuickScan != policy.QuickScanClean || scans != 1 {
		t.Fatalf("dirty commit security = %+v (scans %d)", commit.Security, scans)
	}

	posture = hookctx.PostureClean
	clean := &policy.Event{Kind: policy.KindShellExec, Target: "git commit -m wip", ProjectRoot: "/r"}
	enrich(clean)
	if clean.Security == nil || clean.Security.QuickScan != policy.QuickScanNone || scans != 1 {
		t.Fatalf("clean commit security = %+v (scans %d)", clean.Security, scans)
	}
}

// TestSecurityQuickScannerCoversOnlyWhatItSaw: a clean answer covers the
// smaller of the hook's counter and the daemon's own reading, never more.
func TestSecurityQuickScannerCoversOnlyWhatItSaw(t *testing.T) {
	layout := secposture.Layout{Dir: filepath.Join(t.TempDir(), "security")}
	root := "/r"
	hash := secposture.ProjectRootHash(root)
	for i := 0; i < 3; i++ {
		if err := secposture.RaiseDirty(layout, hash); err != nil {
			t.Fatal(err)
		}
	}
	clean := func(context.Context, string, int, time.Duration, ...string) ([]byte, bool, error) {
		return nil, false, nil
	}
	qs := securityQuickScanner(layout, &secquickscan.Engine{Git: clean})
	commit := policy.GitWrite{Form: policy.GitWriteCommit}
	for _, tc := range []struct{ seen, want uint64 }{{2, 2}, {9, 3}, {0, 0}} {
		r, err := qs(context.Background(), hookctx.QuickScanRequest{ProjectRoot: root, Form: commit, DirtySeen: tc.seen})
		if err != nil || r.Verdict != policy.QuickScanClean || r.DirtyCovered != tc.want {
			t.Errorf("seen %d: %+v, %v, want covered %d", tc.seen, r, err, tc.want)
		}
	}
	r, _ := qs(context.Background(), hookctx.QuickScanRequest{ProjectRoot: root, Form: policy.GitWrite{Form: policy.GitWriteMerge}, DirtySeen: 2})
	if r.Verdict != policy.QuickScanUnknown || r.DirtyCovered != 0 {
		t.Fatalf("merge = %+v, want unknown with no coverage", r)
	}
}

// TestRecordPostWriteStoresBlockingSecret: a scanned write's blocking hit
// becomes one open secret finding with no value in it; an unscanned write
// or a clean one stores nothing.
func TestRecordPostWriteStoresBlockingSecret(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cfg.py"), []byte("x = 1\nk = \""+fakeSecretAWSKeyID+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	q := &secpostwrite.Queue{Scanner: secdetect.Scanner{Identify: func(typ, _ string) string { return "id-" + typ }}}
	var results []secpostwrite.Result
	q.Sink = func(_ context.Context, r secpostwrite.Result) { results = append(results, r) }
	q.Submit(secpostwrite.Write{SessionID: "s", ActionID: 7, ProjectRoot: dir, Path: "cfg.py"})
	q.Submit(secpostwrite.Write{SessionID: "s", ActionID: 8, ProjectRoot: dir, Path: "gone.py"})
	q.Drain(ctx)
	for _, r := range results {
		recordPostWrite(ctx, st, r, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	fs, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: secposture.ProjectRootHash(dir)})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Rule.ID != "secret.aws_access_key" || fs[0].Location.RelPath != "cfg.py" || fs[0].Location.StartLine != 2 || fs[0].Scope != policy.FindingScopePostWrite {
		t.Fatalf("findings = %+v", fs)
	}
}

// TestSecurityCommitStepIsInertUntilPublished: the commit scanner's step
// touches nothing (here: a nil store) while no postwrite loop has published
// its scanner.
func TestSecurityCommitStepIsInertUntilPublished(t *testing.T) {
	securityRT.commitScan.Store(nil)
	step := newSecurityCommitAfterScan(nil)
	step(context.Background(), commitscan.Root{RootPath: "/r"}, commitscan.Result{HeadSHA: "0123456789abcdef0123456789abcdef01234567"})
}

// TestSecurityCIFindingNeverBlocks: a landed workflow rule hit is stored
// at its rule's severity with medium confidence, so it never joins S-791's
// blocking set (high confidence only), and carries the fixed rule text.
func TestSecurityCIFindingNeverBlocks(t *testing.T) {
	f := securityCIFinding("h", "0123456789abcdef0123456789abcdef01234567", secquickscan.CIFinding{Path: ".github/workflows/pr.yml", RuleID: "S-771", Line: 7, Severity: "high"})
	if f.Category != policy.FindingCIConfig || f.Severity != policy.FindingSeverityHigh || f.Confidence != policy.FindingConfidenceMedium ||
		f.Rule.ID != "ci.s-771" || f.LocalKey == "" || f.Location.StartLine != 7 || !strings.HasPrefix(f.Message, "S-771: ") {
		t.Fatalf("finding = %+v", f)
	}
	low := securityCIFinding("h", "", secquickscan.CIFinding{Path: ".github/workflows/x.yml", RuleID: "S-776", FlagOnly: true, Severity: "low"})
	if low.Severity != policy.FindingSeverityLow {
		t.Fatalf("flag-only rule severity = %s", low.Severity)
	}
}
