//go:build !sbo_omit_security

package main

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secdiffobs"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secpostwrite"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testIdentify is a value-free identity for tests: the type and the
// value's length, enough to tell one fake secret from another.
func testIdentify(typ, v string) string { return "id-" + typ + "-" + strconv.Itoa(len(v)) }

// postWrite scans dir/rel through the post-write queue and records it.
func postWrite(t *testing.T, st *store.Store, dir, rel string) {
	t.Helper()
	q := &secpostwrite.Queue{Scanner: secdetect.Scanner{Identify: testIdentify}}
	var results []secpostwrite.Result
	q.Sink = func(_ context.Context, r secpostwrite.Result) { results = append(results, r) }
	q.Submit(secpostwrite.Write{SessionID: "s", ActionID: 1, ProjectRoot: dir, Path: rel})
	q.Drain(context.Background())
	for _, r := range results {
		recordPostWrite(context.Background(), st, r, discardLogger())
	}
}

func scanRuns(t *testing.T, database *sql.DB, root string) []string {
	t.Helper()
	rows, err := database.Query(`SELECT outcome || ':' || coverage_json FROM sec_scan_runs WHERE project_root_hash = ? ORDER BY id`, secposture.ProjectRootHash(root))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// TestPostWriteRemovalClosesTheFinding (milestone 2d): a later write that
// removes the secret records a zero-finding run and closes the finding as
// not reproduced; the clean run is on record.
func TestPostWriteRemovalClosesTheFinding(t *testing.T) {
	st, database := openTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.py")
	if err := os.WriteFile(path, []byte("k = \""+fakeSecretAWSKeyID+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	postWrite(t, st, dir, "cfg.py")
	if err := os.WriteFile(path, []byte("k = os.environ['K']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	postWrite(t, st, dir, "cfg.py")
	fs, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: secposture.ProjectRootHash(dir)})
	if err != nil || len(fs) != 1 || fs[0].Status != policy.FindingStatusNotReproduced {
		t.Fatalf("findings after the removal = %+v, %v", fs, err)
	}
	if runs := scanRuns(t, database, dir); len(runs) != 2 || !strings.HasPrefix(runs[1], "clean:") {
		t.Fatalf("runs = %v, want a findings run then a clean one", runs)
	}
}

// TestFixtureFindingsNeverBlock (milestone 2c): a post-write hit in a
// fixture path is recorded at low severity, outside the blocking set.
func TestFixtureFindingsNeverBlock(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testdata", "creds.py"), []byte("k = \""+fakeSecretAWSKeyID+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	postWrite(t, st, dir, "testdata/creds.py")
	fs, _ := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: secposture.ProjectRootHash(dir)})
	if len(fs) != 1 || fs[0].Severity != policy.FindingSeverityLow {
		t.Fatalf("fixture finding = %+v", fs)
	}
	keys, _ := st.SecBlockingKeys(ctx, store.SecBlockingQuery{ProjectRootHash: secposture.ProjectRootHash(dir), Severities: []policy.FindingSeverity{policy.FindingSeverityHigh, policy.FindingSeverityCritical}}, 10)
	if len(keys) != 0 {
		t.Fatalf("a fixture finding blocks: %v", keys)
	}
}

// TestCommitStepRecordsEveryCommit (milestones 2b, 2d, 2i): each walked
// commit is a run under its own SHA; a commit that removed a secret keeps
// its finding open while the commit that added it is unpushed; skipped commits and an unchecked workflow are unknown runs,
// never silent; diff observations are stored.
func TestCommitStepRecordsEveryCommit(t *testing.T) {
	st, database := openTestStore(t)
	ctx := context.Background()
	root := t.TempDir()
	const sha1, sha2 = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	secret := secquickscan.Finding{Path: "k.py", Line: 1, Type: "aws_access_key", Confidence: secdetect.ConfidenceHigh, Identity: "id-1"}
	step := &securityCommitStep{st: st, logger: discardLogger(), code: true}
	step.record(ctx, root, secquickscan.CommitScanResult{
		Commits: []secquickscan.CommitResult{
			{SHA: sha1, Result: secquickscan.Result{
				Verdict: secquickscan.VerdictBlocking, Findings: []secquickscan.Finding{secret}, Files: 1,
				Observations: []secdiffobs.Observation{{RuleID: "S-767", Path: "a_test.go", Line: 3, Message: "skip"}},
			}},
			{SHA: sha2, Result: secquickscan.Result{Verdict: secquickscan.VerdictClean, Removed: []secquickscan.Finding{secret}, Files: 1, CIUnchecked: 1}},
		},
		Skipped: 3, SkipReason: secquickscan.ReasonCommitCap,
	})
	fs, _ := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: secposture.ProjectRootHash(root)})
	byRule := map[string]policy.FindingStatus{}
	for _, f := range fs {
		byRule[f.Rule.ID] = f.Status
	}
	var commitSHA string
	if err := database.QueryRow(`SELECT commit_sha FROM sec_findings WHERE rule_id = 'secret.aws_access_key'`).Scan(&commitSHA); err != nil || commitSHA != sha1 {
		t.Errorf("the secret carries commit %q (%v), want %q", commitSHA, err, sha1)
	}
	// The second commit removed it, but the first one is history a push
	// still sends: it stays open until that commit is pushed (lane
	// sec-gate3 milestone 1b).
	if byRule["secret.aws_access_key"] != policy.FindingStatusOpen {
		t.Errorf("removed but unpushed secret status = %q, want open", byRule["secret.aws_access_key"])
	}
	if byRule["code.s-767"] != policy.FindingStatusOpen {
		t.Errorf("observation not stored: %v", byRule)
	}
	runs := scanRuns(t, database, root)
	joined := strings.Join(runs, "\n")
	if !strings.Contains(joined, "workflow_unchecked") || !strings.Contains(joined, "commit_cap") {
		t.Fatalf("runs = %v, want the unchecked workflow and the skipped commits on record", runs)
	}
}

// TestQuickScanRecordsCodeWhenPublished: the quick scan's workflow and
// observation results reach the store while security.code is active (the
// postwrite loop published its step with code on), and nothing is stored
// while no step is published or the step records no code rows (lane
// sec-gate2: the test now asserts what it claims).
func TestQuickScanRecordsCodeWhenPublished(t *testing.T) {
	t.Cleanup(func() { securityRT.commitScan.Store(nil) })
	res := secquickscan.Result{Verdict: secquickscan.VerdictClean, Files: 1, Observations: []secdiffobs.Observation{{RuleID: "S-767", Path: "a_test.go", Line: 3, Message: "x"}}}
	count := func(st *store.Store, root string) int {
		fs, err := st.ListSecFindings(context.Background(), store.SecFindingFilter{ProjectRootHash: secposture.ProjectRootHash(root)})
		if err != nil {
			t.Fatal(err)
		}
		return len(fs)
	}
	// Recorded off the hook's reply path (a goroutine): wait for it.
	settle := func(st *store.Store, root string, want int) int {
		deadline := time.Now().Add(5 * time.Second)
		for {
			n := count(st, root)
			if n >= want || time.Now().After(deadline) {
				return n
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	for _, tc := range []struct {
		name string
		step *securityCommitStep
		want int
	}{
		{"no step published", nil, 0},
		{"code rows off", &securityCommitStep{code: false, logger: discardLogger()}, 0},
		{"code rows on", &securityCommitStep{code: true, logger: discardLogger()}, 1},
	} {
		st, _ := openTestStore(t)
		root := t.TempDir()
		if tc.step != nil {
			tc.step.st = st
		}
		securityRT.commitScan.Store(tc.step)
		recordQuickScanCode(root, res)
		if tc.want == 0 {
			// Give a wrongly started recorder the time it would need.
			time.Sleep(100 * time.Millisecond)
		}
		if got := settle(st, root, tc.want); got != tc.want {
			t.Fatalf("%s: %d findings, want %d", tc.name, got, tc.want)
		}
	}
}

// TestSecurityAllowRoot (milestone 2h): the endpoint answers only for a
// known project, refuses everything while no list is published, and sees
// a new project without waiting for the cache to expire.
func TestSecurityAllowRoot(t *testing.T) {
	var rt securityRuntime
	now := time.Now()
	if rt.allowRoot("/a", now) {
		t.Fatal("no list published: a root is allowed")
	}
	roots := []string{"/a"}
	list := func(context.Context) ([]string, error) { return roots, nil }
	rt.projects.Store(&list)
	if !rt.allowRoot("/a", now) || rt.allowRoot("/b", now) {
		t.Fatal("known and unknown roots")
	}
	roots = append(roots, "/b")
	if !rt.allowRoot("/b", now.Add(2*time.Second)) {
		t.Fatal("a new project is not seen")
	}
}
