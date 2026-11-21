package settingsgate

import (
	"testing"
	"time"
)

// TestCheckApproval pins review E-50: one case per row of the approval
// table, plus the approvable cases.
func TestCheckApproval(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		f    ProposalFacts
		want string
	}{
		{"fresh and unchanged", ProposalFacts{CreatedAt: now.Add(-time.Hour), PrevValue: "local", Current: "local"}, ""},
		{"unknown before and after", ProposalFacts{CreatedAt: now.Add(-time.Hour)}, ""},
		{"exactly at the limit", ProposalFacts{CreatedAt: now.Add(-ProposalMaxAge), PrevValue: "a", Current: "a"}, ""},
		{"expired", ProposalFacts{CreatedAt: now.Add(-ProposalMaxAge - time.Minute), PrevValue: "a", Current: "a"}, ApprovalCodeExpired},
		{"expired wins over changed", ProposalFacts{CreatedAt: now.Add(-30 * 24 * time.Hour), PrevValue: "a", Current: "b"}, ApprovalCodeExpired},
		{"changed by hand", ProposalFacts{CreatedAt: now.Add(-time.Hour), PrevValue: "local", Current: "both"}, ApprovalCodeChanged},
		{"set after an unknown baseline", ProposalFacts{CreatedAt: now.Add(-time.Hour), PrevValue: "", Current: "both"}, ApprovalCodeChanged},
	} {
		got := CheckApproval(tc.f, now)
		if got.Code != tc.want || got.OK() != (tc.want == "") {
			t.Errorf("%s: CheckApproval = %+v, want code %q", tc.name, got, tc.want)
		}
		if tc.want != "" && got.Message == "" {
			t.Errorf("%s: refusal has no message", tc.name)
		}
	}
}
