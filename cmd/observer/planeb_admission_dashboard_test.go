package main

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// TestBuildPromptJudgeView is one row per posture of the node Security
// page's organization prompt judge card (lane adm-p2): the same facts as
// `observer guard status`, an individual node shows off with no disclosure,
// and the card never claims an enforcement the node does not apply.
func TestBuildPromptJudgeView(t *testing.T) {
	det := mustSpec(t, `{"admission":{"mode":"enforce","prefilter":{"deny":["x"]}},"node_lane":true}`)
	strict := mustSpec(t, `{"admission":{"mode":"enforce","strict":true,"prefilter":{"deny":["x"]}},"node_lane":true,"latency_budget_ms":800}`)
	gwOnly := mustSpec(t, `{"admission":{"mode":"enforce","prefilter":{"deny":["x"]}}}`)
	on := planeBStatusFacts{Managed: true, HoldsEnforce: true, Accepted: true, HavePolicy: true, Version: 7, Spec: det, EngineLinked: true}
	with := func(mut func(*planeBStatusFacts)) planeBStatusFacts { f := on; mut(&f); return f }
	cases := []struct {
		name         string
		f            planeBStatusFacts
		active       bool
		failClosed   bool
		enforced     bool
		offSub       string
		disclosure   bool
		unreachSub   string
		wantBudgetMS int64
	}{
		{name: "individual node", f: planeBStatusFacts{}, offSub: "not a managed node"},
		{name: "managed, no grant", f: with(func(f *planeBStatusFacts) { f.HoldsEnforce = false }), offSub: "enforce.admission", disclosure: true, wantBudgetMS: 10000},
		{name: "gateway only", f: with(func(f *planeBStatusFacts) { f.Spec = gwOnly }), offSub: "AI gateway only", disclosure: true, wantBudgetMS: 10000},
		{name: "on, not preauthorized: flags", f: on, active: true, disclosure: true, unreachSub: "goes through", wantBudgetMS: 10000},
		{name: "on, preauthorized, not strict: enforced, fails open", f: with(func(f *planeBStatusFacts) { f.Preauthorized = true }), active: true, enforced: true, disclosure: true, unreachSub: "goes through", wantBudgetMS: 10000},
		{name: "on, strict enforced: fails closed", f: with(func(f *planeBStatusFacts) { f.Spec = strict; f.Preauthorized = true }), active: true, enforced: true, failClosed: true, disclosure: true, unreachSub: "refused", wantBudgetMS: 800},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := buildPromptJudgeView(tc.f)
			if !v.Available || v.Active != tc.active || v.FailClosed != tc.failClosed || v.Enforced != tc.enforced {
				t.Fatalf("view = %+v", v)
			}
			if tc.offSub == "" && v.OffReason != "" || !strings.Contains(v.OffReason, tc.offSub) {
				t.Fatalf("off reason = %q, want %q", v.OffReason, tc.offSub)
			}
			if (v.Disclosure != "") != tc.disclosure {
				t.Fatalf("disclosure = %q, want present %v", v.Disclosure, tc.disclosure)
			}
			if tc.disclosure && !strings.Contains(v.Disclosure, "read the prompts you type into coding agents") {
				t.Fatalf("disclosure = %q", v.Disclosure)
			}
			if !strings.Contains(v.Unreachable, tc.unreachSub) || (tc.unreachSub == "" && v.Unreachable != "") {
				t.Fatalf("unreachable = %q, want %q", v.Unreachable, tc.unreachSub)
			}
			if v.BudgetMS != tc.wantBudgetMS {
				t.Fatalf("budget = %d, want %d", v.BudgetMS, tc.wantBudgetMS)
			}
			if len(v.Lines) == 0 || len(v.Residuals) == 0 || v.Counts == nil {
				t.Fatalf("lines %v residuals %v counts %v", v.Lines, v.Residuals, v.Counts)
			}
		})
	}
}

func TestPromptJudgeStatusSeamNeedsADatabase(t *testing.T) {
	var db *sql.DB
	if _, err := promptJudgeStatusSeam("", db)(context.Background()); err == nil {
		t.Fatal("a nil database must be an error, not an empty card")
	}
}
