package dashboard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestAPIGuardSummaryCountsOrgEnforcement pins FU-235 on the wire: an
// enforced verdict the ORG policy layer produced is counted in enforced and
// split out as enforced_by_org, so the Security page can say "N enforced,
// M by your organization" on an observe node.
func TestAPIGuardSummaryCountsOrgEnforcement(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	s.opts.GuardEnabled = true
	s.opts.GuardMode = "observe"
	seedGuardEvents(t, s)
	now := time.Now().UTC()
	if _, err := store.New(s.opts.DB).InsertGuardEvents(context.Background(), []store.GuardEventRow{{
		TS: now.Add(-time.Minute), SessionID: "sC", Tool: "claude-code",
		EventKind: "shell_exec", RuleID: "R-101", Category: "destructive",
		Severity: "critical", Decision: "deny", Enforced: true, Source: "org",
		Reason: "org-locked rm -rf", TargetHash: "h4", TargetExcerpt: "rm -rf ~",
	}}); err != nil {
		t.Fatalf("seed org row: %v", err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/summary", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Counts24h struct {
			Enforced      int `json:"enforced"`
			EnforcedByOrg int `json:"enforced_by_org"`
		} `json:"counts_24h"`
		Org *guardOrgJSON `json:"org"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Counts24h.Enforced != 2 || resp.Counts24h.EnforcedByOrg != 1 {
		t.Fatalf("24h = %+v, want 2 enforced / 1 by org", resp.Counts24h)
	}
	if resp.Org != nil {
		t.Fatalf("org = %+v, want absent on a node with no org layer", resp.Org)
	}
}

// TestOrgSummary pins the posture -> wire mapping, one row per shape.
func TestOrgSummary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		p          guard.OrgOverridePosture
		wantNil    bool
		wantLocks  bool
		wantRules  int
		wantSubstr string
	}{
		{"no org layer", guard.OrgOverridePosture{}, true, false, 0, ""},
		{
			"managed node enforcing R-101",
			guard.OrgOverridePosture{OrgApplies: true, LocksEveryRule: true, Enforced: []string{"R-101"}},
			false, true, 1, "1 rule enforced by your organization (R-101)",
		},
		{
			"org layer enforcing nothing still reports an empty list",
			guard.OrgOverridePosture{OrgApplies: true},
			false, false, 0, "enforces no rule here",
		},
		{
			"unverifiable bundle locks every rule",
			guard.OrgOverridePosture{Unverifiable: true},
			false, true, 0, "does not verify",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := orgSummary(tc.p, "observe")
			if (got == nil) != tc.wantNil {
				t.Fatalf("orgSummary = %+v, want nil=%v", got, tc.wantNil)
			}
			if got == nil {
				return
			}
			if got.LocksEveryRule != tc.wantLocks || len(got.EnforcedRules) != tc.wantRules || got.EnforcedRules == nil {
				t.Fatalf("orgSummary = %+v, want locks=%v rules=%d (never a null list)", got, tc.wantLocks, tc.wantRules)
			}
			if !strings.Contains(got.Line, tc.wantSubstr) {
				t.Fatalf("line = %q, want it to contain %q", got.Line, tc.wantSubstr)
			}
		})
	}
}
