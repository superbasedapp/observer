//go:build !sbo_omit_security

package secsvc

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// TestRecordRunBoxCommit: under a box context every finding carries the
// run, the run row names the commit, ref and run, and a completed run
// closes nothing; without one the run is recorded as before (no target).
func TestRecordRunBoxCommit(t *testing.T) {
	t.Parallel()
	gone := Gone{Pack: "security.secrets", Paths: []string{"a.go"}}
	target := secscan.Target{ProjectRoot: "/p", Scope: policy.FindingScopeCommit}
	res := secscan.Result{
		Findings: []secfinding.Finding{{LocalKey: "k", Rule: secfinding.Rule{ID: "R"}, Category: policy.FindingSecret}},
		Coverage: secscan.Coverage{Outcome: secscan.OutcomeFindings}, Engine: secscan.EngineIdentity{Name: "native"},
	}
	for _, tc := range []struct {
		name       string
		ctx        context.Context
		wantRun    string
		wantTarget any
		wantClose  bool
	}{
		{"not a box commit", context.Background(), "", nil, true},
		{
			"box commit", WithBoxCommit(context.Background(), BoxCommit{RunID: "RUN1", Ref: "refs/observer/sandbox/RUN1", Commit: "abc1234"}),
			"RUN1",
			BoxCommitTarget{Box: true, Commit: "abc1234", Ref: "refs/observer/sandbox/RUN1", RunID: "RUN1"},
			false,
		},
	} {
		st := &fakeRunStore{}
		if _, err := RecordRun(tc.ctx, st, target, res, time.Now(), 0, gone, nil); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if st.findings[0].Lineage.RunID != tc.wantRun {
			t.Errorf("%s: lineage run %q", tc.name, st.findings[0].Lineage.RunID)
		}
		if st.runs[0].Target != tc.wantTarget {
			t.Errorf("%s: target %+v", tc.name, st.runs[0].Target)
		}
		if (len(st.gone) > 0) != tc.wantClose {
			t.Errorf("%s: closes %+v", tc.name, st.gone)
		}
	}
}
