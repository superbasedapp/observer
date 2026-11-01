package accessgrant

import (
	"testing"
	"time"
)

// TestFindingExceptionRules is the finding_exception row (lane SEC-E3), one
// case per rule: the request must state an expiry; the grant names a finding
// the org holds; a perpetual or a critical-finding exception needs the super
// admin; the requester never approves their own; a perpetual one falls due
// for re-review after 90 days.
func TestFindingExceptionRules(t *testing.T) {
	s := DefaultSettings()
	now := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	req := Request{Type: TypeFindingException, Justification: "test fixture key", Machine: "laptop-1"}
	req.Payload.RuleID, req.Payload.Target = "S-721.aws", "0123456789abcdef0123456789abcdef"
	if _, probs := Validate(req, s); !hasCode(probs, CodeRequired) {
		t.Fatalf("a finding exception request with no duration must be refused: %+v", probs)
	}
	req.DurationS = int64((7 * 24 * time.Hour) / time.Second)
	if n, probs := Validate(req, s); len(probs) != 0 || n.Duration != 7*24*time.Hour {
		t.Fatalf("a stated duration is accepted: %+v %+v", n, probs)
	}

	base := func() (Proposal, Facts) {
		p := Proposal{
			Type: TypeFindingException, SubjectKind: "member", UserID: "dev-1", RuleID: "S-721.aws",
			Target: "0123456789abcdef0123456789abcdef", ExpiresAt: now.Add(7 * 24 * time.Hour),
		}
		f := Facts{
			Now: now, RequesterID: "dev-1", Rule: RuleFacts{Known: true, Severity: "high"},
			Target: TargetFacts{FindingRef: true}, Approver: Approver{UserID: "sec-1", HasKey: true},
		}
		return p, f
	}
	cases := []struct {
		name     string
		mutate   func(*Proposal, *Facts)
		wantTier Tier
		wantCode string
	}{
		{name: "a dated high-severity exception needs write:security only", wantTier: TierKey},
		{name: "no write:security is refused", mutate: func(_ *Proposal, f *Facts) { f.Approver.HasKey = false }, wantTier: TierKey, wantCode: CodeForbidden},
		{name: "a finding the org does not hold is refused", mutate: func(_ *Proposal, f *Facts) { f.Target.FindingRef = false }, wantTier: TierKey, wantCode: CodeBadValue},
		{name: "a critical finding needs the super admin", mutate: func(_ *Proposal, f *Facts) { f.Rule.Severity = "critical" }, wantTier: TierSuperAdmin, wantCode: CodeTier},
		{name: "an unknown severity reads as critical", mutate: func(_ *Proposal, f *Facts) { f.Rule = RuleFacts{} }, wantTier: TierSuperAdmin, wantCode: CodeTier},
		{name: "a perpetual exception needs the super admin", mutate: func(p *Proposal, _ *Facts) { p.ExpiresAt = time.Time{} }, wantTier: TierSuperAdmin, wantCode: CodeTier},
		{name: "a super admin may approve a critical one", mutate: func(_ *Proposal, f *Facts) { f.Rule.Severity = "critical"; f.Approver.SuperAdmin = true }, wantTier: TierSuperAdmin},
		{name: "the requester never approves their own", mutate: func(_ *Proposal, f *Facts) { f.Approver.UserID = "dev-1" }, wantTier: TierKey, wantCode: CodeSelf},
		{
			// SEC-E3 merge audit finding 3: the D-086 solo-super-admin
			// carve-out does not reach a finding exception.
			name: "a sole super admin never approves their own",
			mutate: func(_ *Proposal, f *Facts) {
				f.Approver = Approver{UserID: "dev-1", HasKey: true, SuperAdmin: true, OnlyKeyHolder: true}
			},
			wantTier: TierKey, wantCode: CodeSelf,
		},
		{name: "uses are refused", mutate: func(p *Proposal, _ *Facts) { p.MaxUses = 3 }, wantTier: TierKey, wantCode: CodeBadValue},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, f := base()
			if c.mutate != nil {
				c.mutate(&p, &f)
			}
			d := Decide(p, f, s)
			if d.Tier != c.wantTier {
				t.Errorf("tier %s, want %s (%v)", d.Tier, c.wantTier, d.TierReasons)
			}
			if c.wantCode == "" && len(d.Problems) != 0 {
				t.Errorf("unexpected problems: %+v", d.Problems)
			}
			if c.wantCode != "" && !hasCode(d.Problems, c.wantCode) {
				t.Errorf("want %s, got %+v", c.wantCode, d.Problems)
			}
		})
	}
	issued := now.UnixNano()
	if due, ok := ReviewDue(issued, 0, now.Add(91*24*time.Hour)); !ok || due != issued+int64(PerpetualReviewEvery) {
		t.Errorf("a perpetual exception is due its 90-day re-review: %d %v", due, ok)
	}
}
