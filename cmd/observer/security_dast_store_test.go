//go:build !sbo_omit_security && !sbo_omit_security_dast

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdast"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestRecordDASTRunClosesPerOrigin (security coverage gaps plan item 1):
// a complete run records its findings against the project and closes only
// the keys the same origin reported before and not now; a partial run and
// an unreachable page close nothing; another origin's findings stay open.
func TestRecordDASTRunClosesPerOrigin(t *testing.T) {
	ctx := context.Background()
	st, _ := openTestStore(t)
	root := t.TempDir()
	secDir := t.TempDir()
	hash := secposture.ProjectRootHash(root)
	a, _ := secdast.ParseTarget("http://localhost:5173/")
	b, _ := secdast.ParseTarget("http://localhost:3000/")
	csp := secdast.Hit{Check: "dast.headers.csp-missing", Path: "/", Evidence: "no Content-Security-Policy"}
	git := secdast.Hit{Check: "dast.exposed.git", Path: "/.git/HEAD", Evidence: "status 200, a git ref"}
	now := time.Now().UTC()
	run := func(t0 secdast.Target, outcome string, hits ...secdast.Hit) {
		t.Helper()
		fs := secdast.Findings(t0, hits, now, nil)
		if _, err := recordDASTRun(ctx, st, secDir, root, t0, secdast.Report{Outcome: outcome}, fs, now, time.Second); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	open := func() map[string]int {
		t.Helper()
		got, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: hash, Status: policy.FindingStatusOpen, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]int{}
		for _, f := range got {
			if f.Engine.Driver != secdast.Driver || f.Category != policy.FindingCodeVuln || f.Baseline != policy.FindingBaselineUnknown {
				t.Errorf("finding shape %+v", f)
			}
			out[f.Rule.ID]++
		}
		return out
	}
	run(a, secdast.OutcomeComplete, csp, git)
	run(b, secdast.OutcomeComplete, csp)
	if got := open(); got["dast.headers.csp-missing"] != 2 || got["dast.exposed.git"] != 1 {
		t.Fatalf("after two origins: %v", got)
	}
	run(a, secdast.OutcomeUnreachable)
	run(a, secdast.OutcomePartial, csp)
	if got := open(); got["dast.exposed.git"] != 1 {
		t.Fatalf("an unreachable or partial run closed a finding: %v", got)
	}
	run(a, secdast.OutcomeComplete, csp)
	if got := open(); got["dast.exposed.git"] != 0 || got["dast.headers.csp-missing"] != 2 {
		t.Fatalf("a complete run closed the wrong findings: %v", got)
	}
	run(a, secdast.OutcomeComplete)
	if got := open(); got["dast.headers.csp-missing"] != 1 {
		t.Fatalf("origin b's finding must stay open, a's close: %v", got)
	}
	info, err := os.Stat(filepath.Join(secDir, "dast", hash+".json"))
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("record file: %v %v", info, err)
	}
	sev := []secfinding.Severity{policy.FindingSeverityInfo, policy.FindingSeverityLow, policy.FindingSeverityMedium, policy.FindingSeverityHigh, policy.FindingSeverityCritical}
	if blocking, err := st.SecBlockingKeys(ctx, store.SecBlockingQuery{ProjectRootHash: hash, Severities: sev, IncludeUntrusted: true}, 100); err != nil || len(blocking) != 0 {
		t.Errorf("a DAST finding is in the commit gate's blocking set: %v", blocking)
	}
}
