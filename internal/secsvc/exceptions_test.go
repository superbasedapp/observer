//go:build !sbo_omit_security

package secsvc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secexcept"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func realStore(t *testing.T) *store.Store {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database)
}

func secretAt(root, key, rel string) secfinding.Finding {
	return secfinding.Normalize(secfinding.Finding{
		LocalKey: key, Rule: secfinding.Rule{ID: "S-721"}, Category: policy.FindingSecret,
		Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
		Project: secfinding.Project{RootHash: secposture.ProjectRootHash(root)}, Location: secfinding.Location{RelPath: rel, StartLine: 2},
		Status: policy.FindingStatusOpen,
	})
}

func TestExceptionGrantSweepUntilChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := realStore(t)
	root := "/work/proj"
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	id, _, err := st.UpsertSecFinding(ctx, secretAt(root, "k1", "conf/a.py"), t0)
	if err != nil {
		t.Fatal(err)
	}
	fileHash := "h1"
	now := t0
	d := ExceptionDeps{
		Store:    st,
		HashFile: func(r, rel string) (string, bool) { return fileHash, r == root && rel == "conf/a.py" && fileHash != "" },
		RootFor: func(_ context.Context, h string) (string, bool) {
			return root, h == secposture.ProjectRootHash(root)
		},
		Now: func() time.Time { return now },
	}
	// An agent (no origin) is refused before anything is read or written.
	if _, err := GrantException(ctx, d, secexcept.Request{FindingID: id, Reason: "test_fixture", Expiry: "until_change"}); err == nil {
		t.Fatal("a grant with no local-owner origin was accepted")
	}
	ex, err := GrantException(ctx, d, secexcept.Request{FindingID: id, Reason: "test_fixture", Expiry: "until_change", Origin: secexcept.OriginCLI})
	if err != nil {
		t.Fatal(err)
	}
	if f, _, _ := st.SecFindingByID(ctx, id); f.Status != policy.FindingStatusSuppressed || ex.FileHash != "h1" {
		t.Fatalf("after grant: %s %+v", f.Status, ex)
	}
	// Same file: the sweep keeps it.
	now = t0.Add(time.Hour)
	if r, err := SweepExceptions(ctx, d); err != nil || r != (SweepResult{}) {
		t.Fatalf("sweep, unchanged file: %+v %v", r, err)
	}
	// The file changed: it ends and the finding is open again.
	fileHash = "h2"
	if r, err := SweepExceptions(ctx, d); err != nil || r.FileChanged != 1 {
		t.Fatalf("sweep, changed file: %+v %v", r, err)
	}
	if f, _, _ := st.SecFindingByID(ctx, id); f.Status != policy.FindingStatusOpen {
		t.Fatalf("after the file changed: %s", f.Status)
	}
	// A dated exception ends at its expiry, and the rule keeps firing for
	// every other finding in the project: an exception is never rule-wide
	// (X8).
	other, _, _ := st.UpsertSecFinding(ctx, secretAt(root, "k2", "conf/b.py"), t0)
	if _, err := GrantException(ctx, d, secexcept.Request{FindingID: id, Reason: "false_positive", Expiry: "1d", Origin: secexcept.OriginDashboard}); err != nil {
		t.Fatal(err)
	}
	keys, _ := st.SecBlockingKeys(ctx, store.SecBlockingQuery{
		ProjectRootHash: secposture.ProjectRootHash(root),
		Severities:      []secfinding.Severity{policy.FindingSeverityHigh},
	}, 10)
	if len(keys) != 1 || keys[0] != "k2" {
		t.Fatalf("an exception lowered more than its own finding: blocking %v (other %s)", keys, other)
	}
	now = now.Add(25 * time.Hour)
	if r, err := SweepExceptions(ctx, d); err != nil || r.Expired != 1 {
		t.Fatalf("sweep, expired: %+v %v", r, err)
	}
	keys, _ = st.SecBlockingKeys(ctx, store.SecBlockingQuery{
		ProjectRootHash: secposture.ProjectRootHash(root),
		Severities:      []secfinding.Severity{policy.FindingSeverityHigh},
	}, 10)
	if len(keys) != 2 {
		t.Fatalf("an expired exception still matches: blocking %v", keys)
	}
	// Revoke.
	ex, err = GrantException(ctx, d, secexcept.Request{FindingID: id, Reason: "accepted_risk", Expiry: "30d", Origin: secexcept.OriginCLI})
	if err != nil {
		t.Fatal(err)
	}
	if err := RevokeException(ctx, d, ex.ID); err != nil {
		t.Fatal(err)
	}
	if f, _, _ := st.SecFindingByID(ctx, id); f.Status != policy.FindingStatusOpen {
		t.Fatalf("after revoke: %s", f.Status)
	}
}

func gitRepo(t *testing.T) (string, func(args ...string) string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q")
	run("config", "user.email", "t@example.invalid")
	run("config", "user.name", "t")
	return dir, run
}

func writeFile(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const writeAllWorkflow = "on: push\npermissions: write-all\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"

// TestBaselineApprovalMakesWorkflowFindingsPreExisting is acceptance row C
// "a baseline approval makes matching findings pre_existing and never a
// secret", end to end over a real repository: approve, then the lazy
// rescan with the native workflow driver relabels.
func TestBaselineApprovalMakesWorkflowFindingsPreExisting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir, run := gitRepo(t)
	writeFile(t, dir, ".github/workflows/old.yml", writeAllWorkflow)
	run("add", "-A")
	run("commit", "-q", "-m", "first")
	first := run("rev-parse", "HEAD")
	writeFile(t, dir, ".github/workflows/new.yml", writeAllWorkflow)
	run("add", "-A")
	run("commit", "-q", "-m", "second")

	st := realStore(t)
	hash := secposture.ProjectRootHash(dir)
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	mk := func(rel string) string {
		id, _, err := st.UpsertSecFinding(ctx, secfinding.Normalize(secfinding.Finding{
			LocalKey: WorkflowFindingKey(hash, "S-775", rel), Rule: secfinding.Rule{ID: "ci.s-775", Pack: "security.code"},
			Category: policy.FindingCIConfig, Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceMedium,
			Baseline: policy.FindingBaselineNew, Project: secfinding.Project{RootHash: hash},
			Location: secfinding.Location{RelPath: rel, StartLine: 2}, Status: policy.FindingStatusOpen,
		}), t0)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	oldID, newID := mk(".github/workflows/old.yml"), mk(".github/workflows/new.yml")
	secretID, _, _ := st.UpsertSecFinding(ctx, secretAt(dir, "sk", "a.py"), t0)

	git := GitRunner(gitview.RunReadOnlyTimeout)
	picker, err := ProposeBaseline(ctx, git, dir)
	if err != nil || len(picker) < 2 || !picker[0].MergeBase {
		t.Fatalf("picker %+v %v", picker, err)
	}
	if _, err := ApproveBaseline(ctx, git, st, dir, "--upload-pack=x", secexcept.OriginCLI, "p1", t0); err == nil {
		t.Fatal("an option-shaped ref was accepted")
	}
	if _, err := ApproveBaseline(ctx, git, st, dir, "HEAD~1", "", "p1", t0); err == nil {
		t.Fatal("a baseline with no local-owner origin was accepted")
	}
	b, err := ApproveBaseline(ctx, git, st, dir, "HEAD~1", secexcept.OriginCLI, "p1", t0)
	if err != nil || b.Ref != first {
		t.Fatalf("approve: %+v %v (want %s)", b, err, first)
	}
	r := &BaselineRescanner{Store: st, Drivers: []secscan.Driver{WorkflowBaselineDriver{Git: git}}, PackVersion: "p1"}
	res, err := r.Rescan(ctx, dir)
	if err != nil || res.Outcome != BaselineRescanned {
		t.Fatalf("rescan: %+v %v", res, err)
	}
	for id, want := range map[string]secfinding.Baseline{
		oldID: policy.FindingBaselinePreExisting, newID: policy.FindingBaselineNew, secretID: policy.FindingBaselineNew,
	} {
		f, _, _ := st.SecFindingByID(ctx, id)
		if f.Baseline != want {
			t.Errorf("finding %s at %s: baseline %s, want %s", id, f.Location.RelPath, f.Baseline, want)
		}
	}
	// A reset leaves no trusted baseline and relabels nothing.
	if err := ResetBaseline(ctx, st, dir, secexcept.OriginDashboard, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.LatestSecBaseline(ctx, hash); ok {
		t.Fatal("a reset still reads as a baseline")
	}
	if f, _, _ := st.SecFindingByID(ctx, oldID); f.Baseline != policy.FindingBaselinePreExisting {
		t.Fatalf("a reset relabelled a finding: %s", f.Baseline)
	}
}

// TestScanHistoryFindsARemovedSecret is section 5.3 (f): a secret added in
// one commit and removed in the next is still found by the history scan,
// once, as a manual-scope finding; a cap of one commit does not reach it.
func TestScanHistoryFindsARemovedSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir, run := gitRepo(t)
	writeFile(t, dir, "a.py", "x = 1\n")
	run("add", "-A")
	run("commit", "-q", "-m", "first")
	writeFile(t, dir, "conf.py", "token = \"ghp_"+strings.Repeat("a1B2", 9)+"\"\n")
	run("add", "-A")
	run("commit", "-q", "-m", "add a token")
	if err := os.Remove(filepath.Join(dir, "conf.py")); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-q", "-m", "remove it")
	st := realStore(t)
	identify := func(typ, value string) string { return "id:" + typ + ":" + value[len(value)-4:] }
	deps := HistoryDeps{
		Git:    gitview.RunReadOnlyNoLazyFetch,
		Engine: &secquickscan.Engine{Git: gitview.RunReadOnlyNoLazyFetch, Scanner: secdetect.Scanner{Identify: identify}},
		Store:  st,
	}
	short, err := ScanHistory(ctx, deps, dir, HistoryOptions{MaxCommits: 1})
	if err != nil || short.Commits != 1 || short.Hits != 0 {
		t.Fatalf("one commit: %+v %v", short, err)
	}
	res, err := ScanHistory(ctx, deps, dir, HistoryOptions{})
	if err != nil || res.Commits != 3 || res.Hits != 1 || res.NewFindings != 1 || !res.Complete() {
		t.Fatalf("history: %+v %v", res, err)
	}
	fs, _ := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: secposture.ProjectRootHash(dir)})
	if len(fs) != 1 || fs[0].Scope != policy.FindingScopeManual || fs[0].Location.RelPath != "conf.py" {
		t.Fatalf("findings %+v", fs)
	}
	again, err := ScanHistory(ctx, deps, dir, HistoryOptions{})
	if err != nil || again.NewFindings != 0 {
		t.Fatalf("a rescan made a new finding: %+v %v", again, err)
	}
}

// TestSweepClosesAnExpiredSecretThatIsGone (lane sec-gate2 milestone 2c):
// an ended exception reopens its finding only when the rescan still finds
// the secret; a secret the rescan positively no longer finds closes as not
// reproduced; an answer the rescan cannot give reopens.
func TestSweepClosesAnExpiredSecretThatIsGone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := "/work/proj"
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name           string
		present, known bool
		want           secfinding.Status
		gone           int
	}{
		{"still there", true, true, policy.FindingStatusOpen, 0},
		{"gone", false, true, policy.FindingStatusNotReproduced, 1},
		{"cannot tell", false, false, policy.FindingStatusOpen, 0},
	} {
		st := realStore(t)
		id, _, err := st.UpsertSecFinding(ctx, secretAt(root, "k1", "conf/a.py"), t0)
		if err != nil {
			t.Fatal(err)
		}
		now := t0
		asked := 0
		d := ExceptionDeps{
			Store: st, Now: func() time.Time { return now },
			StillPresent: func(_ context.Context, f secfinding.Finding) (bool, bool) {
				asked++
				return tc.present, tc.known
			},
		}
		if _, err := GrantException(ctx, d, secexcept.Request{FindingID: id, Reason: "false_positive", Expiry: "1d", Origin: secexcept.OriginCLI}); err != nil {
			t.Fatal(err)
		}
		if _, err := SweepExceptions(ctx, d); err != nil || asked != 0 {
			t.Fatalf("%s: a live exception was rescanned (%d) or failed: %v", tc.name, asked, err)
		}
		now = t0.Add(25 * time.Hour)
		r, err := SweepExceptions(ctx, d)
		if err != nil || r.Expired != 1 || r.Gone != tc.gone || asked != 1 {
			t.Fatalf("%s: sweep %+v %v (asked %d)", tc.name, r, err, asked)
		}
		if f, _, _ := st.SecFindingByID(ctx, id); f.Status != tc.want {
			t.Fatalf("%s: finding %s, want %s", tc.name, f.Status, tc.want)
		}
	}
}

// TestApproveOfferedBaselineRefusesUnofferedCommit (milestone 2c, ledger
// SECP-23): the dashboard's approval accepts only a commit the picker
// offers; an older full commit id is refused.
func TestApproveOfferedBaselineRefusesUnofferedCommit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir, run := gitRepo(t)
	var first, head string
	for i := 0; i < 23; i++ {
		writeFile(t, dir, "f.txt", strings.Repeat("x", i+1))
		run("add", "-A")
		run("commit", "-q", "-m", "c")
		head = run("rev-parse", "HEAD")
		if i == 0 {
			first = head
		}
	}
	st := realStore(t)
	git := GitRunner(gitview.RunReadOnlyTimeout)
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	if _, err := ApproveOfferedBaseline(ctx, git, st, dir, first, secexcept.OriginDashboard, "p1", t0); err == nil {
		t.Fatal("a commit the picker does not offer was approved")
	}
	b, err := ApproveOfferedBaseline(ctx, git, st, dir, head, secexcept.OriginDashboard, "p1", t0)
	if err != nil || b.Ref != head {
		t.Fatalf("HEAD (offered): %+v %v", b, err)
	}
}

// TestSweepChecksUntilChangeBeyondAThousand (lane sec-gate3 milestone 2d):
// with more than a page of timed exceptions open, an until-change
// exception still gets its file check on the first sweep, and the sweep's
// cursor walks the until-change ones page by page.
func TestSweepChecksUntilChangeBeyondAThousand(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := realStore(t)
	root := "/work/proj"
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	hash := secposture.ProjectRootHash(root)
	for i := range sweepPage + 1 {
		id, _, err := st.UpsertSecFinding(ctx, secretAt(root, "t"+strconv.Itoa(i), "t.py"), t0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.GrantSecException(ctx, store.SecException{
			FindingID: id, ProjectRootHash: hash, RuleID: "S-721", Reason: "false_positive",
			Expiry: "30d", ExpiresAt: t0.AddDate(0, 0, 30), GrantedBy: "cli", GrantedAt: t0,
		}, policy.FindingStatusSuppressed); err != nil {
			t.Fatal(err)
		}
	}
	id, _, err := st.UpsertSecFinding(ctx, secretAt(root, "u", "u.py"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.GrantSecException(ctx, store.SecException{
		FindingID: id, ProjectRootHash: hash, RuleID: "S-721", Reason: "test_fixture",
		Expiry: "until_change", ExpiresAt: t0.AddDate(0, 0, 90), FileHash: "old", GrantedBy: "cli", GrantedAt: t0, RelPath: "u.py",
	}, policy.FindingStatusSuppressed); err != nil {
		t.Fatal(err)
	}
	var cursor int64
	d := ExceptionDeps{
		Store:             st,
		HashFile:          func(string, string) (string, bool) { return "new", true },
		RootFor:           func(context.Context, string) (string, bool) { return root, true },
		Now:               func() time.Time { return t0.Add(time.Hour) },
		UntilChangeCursor: &cursor,
	}
	r, err := SweepExceptions(ctx, d)
	if err != nil || r.FileChanged != 1 || r.Expired != 0 {
		t.Fatalf("sweep: %+v %v, want the until-change exception ended", r, err)
	}
	if cursor != 0 {
		t.Fatalf("a short page must wrap the cursor, got %d", cursor)
	}
	if f, _, _ := st.SecFindingByID(ctx, id); f.Status != policy.FindingStatusOpen {
		t.Fatalf("after the file changed: %s", f.Status)
	}
}

// TestSweepPagesPastAThousandUntilChange (lane sec-gate4 milestone 2c):
// with more than a page of until-change exceptions open, the first sweep
// checks the first page and leaves the cursor on its last row; the file
// of the one past the page changed, and it is ended on the second sweep,
// which reads the short page after the cursor and wraps it to the start.
func TestSweepPagesPastAThousandUntilChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := realStore(t)
	root := "/work/proj"
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	hash := secposture.ProjectRootHash(root)
	var ids []int64
	var lastFinding string
	for i := range sweepPage + 1 {
		rel := "u" + strconv.Itoa(i) + ".py"
		fid, _, err := st.UpsertSecFinding(ctx, secretAt(root, "u"+strconv.Itoa(i), rel), t0)
		if err != nil {
			t.Fatal(err)
		}
		xid, err := st.GrantSecException(ctx, store.SecException{
			FindingID: fid, ProjectRootHash: hash, RuleID: "S-721", Reason: "test_fixture",
			Expiry: "until_change", ExpiresAt: t0.AddDate(0, 0, 90), FileHash: "old", GrantedBy: "cli", GrantedAt: t0, RelPath: rel,
		}, policy.FindingStatusSuppressed)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, xid)
		lastFinding = fid
	}
	changed := "u" + strconv.Itoa(sweepPage) + ".py"
	var checked int
	var cursor int64
	d := ExceptionDeps{
		Store: st,
		HashFile: func(_, rel string) (string, bool) {
			checked++
			if rel == changed {
				return "new", true
			}
			return "old", true
		},
		RootFor:           func(context.Context, string) (string, bool) { return root, true },
		Now:               func() time.Time { return t0.Add(time.Hour) },
		UntilChangeCursor: &cursor,
	}
	r, err := SweepExceptions(ctx, d)
	if err != nil || r.FileChanged != 0 || checked != sweepPage {
		t.Fatalf("first sweep: %+v %v after %d file checks, want one full page and nothing ended", r, err, checked)
	}
	if cursor != ids[sweepPage-1] {
		t.Fatalf("cursor after a full page = %d, want the page's last id %d", cursor, ids[sweepPage-1])
	}
	checked = 0
	r, err = SweepExceptions(ctx, d)
	if err != nil || r.FileChanged != 1 || checked != 1 {
		t.Fatalf("second sweep: %+v %v after %d file checks, want the one past the page ended", r, err, checked)
	}
	if cursor != 0 {
		t.Fatalf("a short page must wrap the cursor, got %d", cursor)
	}
	if f, _, _ := st.SecFindingByID(ctx, lastFinding); f.Status != policy.FindingStatusOpen {
		t.Fatalf("the finding past the page: %s, want reopened", f.Status)
	}
}
