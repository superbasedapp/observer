package accessgrant

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func TestRequestTypeTable(t *testing.T) {
	seen := map[string]bool{}
	for _, rt := range RequestTypes {
		if seen[rt.ID] {
			t.Fatalf("duplicate type %s", rt.ID)
		}
		seen[rt.ID] = true
		if rt.ApproverKey == "" || rt.Label == "" {
			t.Fatalf("%s: incomplete row", rt.ID)
		}
		if rt.Grantable() && rt.Max == MaxFixed && rt.MaxDuration <= 0 {
			t.Fatalf("%s: grantable fixed-max type with no maximum", rt.ID)
		}
	}
	// D-081 maxima and D-088's approver.
	cases := []struct {
		id  string
		key string
		max time.Duration
	}{
		{TypeGuardExemption, KeyWritePolicy, 30 * day},
		{TypeToolAllow, KeyWritePolicy, 90 * day},
		{TypeModelAccess, KeyWritePolicy, 90 * day},
		{TypeFeatureEnable, KeyAdminDeployment, 90 * day},
		{TypeBudgetIncrease, KeyWriteBudgets, 0},
		{TypeFindingException, KeyWriteSecurity, 90 * day},
	}
	for _, c := range cases {
		rt, ok := TypeByID(c.id)
		if !ok || rt.ApproverKey != c.key || rt.MaxDuration != c.max {
			t.Errorf("%s: got %+v", c.id, rt)
		}
	}
	if TypeForLegacyKind("raise_budget").ID != TypeBudgetIncrease || TypeForLegacyKind("nonsense").ID != TypeOther ||
		TypeForLegacyKind("").ID != TypeOther || LegacyKindFor(TypeModelAccess) != "other" {
		t.Fatal("legacy kind mapping drifted")
	}
}

func TestValidate(t *testing.T) {
	s := DefaultSettings()
	guard := func(mut func(*Request)) Request {
		r := Request{
			Type: TypeGuardExemption, Justification: "need it", Machine: "laptop-7",
			Payload: orgcontract.AccessRequestPayload{RuleID: "R-171"},
		}
		if mut != nil {
			mut(&r)
		}
		return r
	}
	cases := []struct {
		name     string
		req      Request
		settings func(*Settings)
		wantCode string
		check    func(t *testing.T, n Normalized)
	}{
		{name: "minimal guard request defaults to 24h on this machine", req: guard(nil), check: func(t *testing.T, n Normalized) {
			if n.Duration != 24*time.Hour || n.SubjectKind != orgcontract.AccessGrantSubjectMachine {
				t.Fatalf("got %v %s", n.Duration, n.SubjectKind)
			}
		}},
		{name: "unknown type", req: Request{Type: "nope", Justification: "x"}, wantCode: CodeUnknown},
		{name: "justification required", req: guard(func(r *Request) { r.Justification = " " }), wantCode: CodeRequired},
		{name: "justification too long", req: guard(func(r *Request) { r.Justification = strings.Repeat("a", 2049) }), wantCode: CodeTooLong},
		{name: "rule id required", req: guard(func(r *Request) { r.Payload.RuleID = "" }), wantCode: CodeRequired},
		{name: "exact needs operand", req: guard(func(r *Request) { r.Payload.Breadth = BreadthExact }), wantCode: CodeRequired},
		{name: "bad lane", req: guard(func(r *Request) { r.Payload.Lane = "everywhere" }), wantCode: CodeBadValue},
		{name: "member-wide is approver-only", req: guard(func(r *Request) { r.SubjectKind = orgcontract.AccessGrantSubjectMember }), wantCode: CodeForbidden},
		{name: "no machine identity falls back to member", req: guard(func(r *Request) { r.Machine = "" }), check: func(t *testing.T, n Normalized) {
			if n.SubjectKind != orgcontract.AccessGrantSubjectMember || len(n.Warnings) == 0 {
				t.Fatalf("got %s %v", n.SubjectKind, n.Warnings)
			}
		}},
		{name: "duration clamped to 30d", req: guard(func(r *Request) { r.DurationS = 90 * 86400 }), check: func(t *testing.T, n Normalized) {
			if n.Duration != 30*day || len(n.Warnings) == 0 {
				t.Fatalf("got %v", n.Duration)
			}
		}},
		{
			name: "org lowered maximum", req: guard(func(r *Request) { r.DurationS = 86400 * 3 }),
			settings: func(s *Settings) { s.MaxDurationS = map[string]int64{TypeGuardExemption: 86400} },
			check: func(t *testing.T, n Normalized) {
				if n.Duration != day {
					t.Fatalf("got %v", n.Duration)
				}
			},
		},
		{name: "disabled type", req: guard(nil), settings: func(s *Settings) { s.DisabledTypes = []string{TypeGuardExemption} }, wantCode: CodeDisabled},
		{name: "negative duration", req: guard(func(r *Request) { r.DurationS = -1 }), wantCode: CodeOutOfRange},
		// D-334 (T-523): a developer on an org-managed node cannot know a
		// budget id, and in a token-usage org cannot name a dollar amount,
		// so the request goes without them; the server or the approver
		// fills them in, and Decide still needs both
		// (TestBudgetGrantStillNeedsIDAndAmount).
		{name: "budget may leave the id and the amount for later", req: Request{Type: TypeBudgetIncrease, Justification: "x", Machine: "m"}},
		{name: "budget amount cannot be negative", req: Request{
			Type: TypeBudgetIncrease, Justification: "x", Machine: "m",
			Payload: orgcontract.AccessRequestPayload{DeltaTokens: -5},
		}, wantCode: CodeOutOfRange},
		{name: "budget ok", req: Request{
			Type: TypeBudgetIncrease, Justification: "x", Machine: "m",
			Payload: orgcontract.AccessRequestPayload{BudgetID: "b-3", DeltaTokens: 200000},
		}},
		{name: "tool needs target", req: Request{Type: TypeToolAllow, Justification: "x", Machine: "m"}, wantCode: CodeRequired},
		{name: "too many uses", req: guard(func(r *Request) { r.Uses = 5000 }), wantCode: CodeOutOfRange},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ss := s
			if c.settings != nil {
				c.settings(&ss)
			}
			n, probs := Validate(c.req, ss)
			if c.wantCode == "" {
				if len(probs) > 0 {
					t.Fatalf("unexpected problems: %v", probs)
				}
			} else if !hasCode(probs, c.wantCode) {
				t.Fatalf("want %s, got %v", c.wantCode, probs)
			}
			if c.check != nil {
				c.check(t, n)
			}
		})
	}
}

func hasCode(probs []Problem, code string) bool {
	for _, p := range probs {
		if p.Code == code {
			return true
		}
	}
	return false
}

func TestDecide(t *testing.T) {
	base := func(mut func(*Proposal)) Proposal {
		p := Proposal{
			Type: TypeGuardExemption, Effect: orgcontract.AccessGrantEffectSoften,
			SubjectKind: orgcontract.AccessGrantSubjectMachine, UserID: "alice", MachineIdentity: "laptop-7",
			RuleID: "R-171", ExpiresAt: t0.Add(8 * time.Hour),
		}
		if mut != nil {
			mut(&p)
		}
		return p
	}
	approver := Approver{UserID: "bob", HasKey: true}
	super := Approver{UserID: "carol", HasKey: true, SuperAdmin: true}
	unlocked := RuleFacts{Known: true, Severity: "medium"}
	cases := []struct {
		name     string
		p        Proposal
		f        Facts
		s        func(*Settings)
		tier     Tier
		wantCode string
		check    func(t *testing.T, d Decision)
	}{
		{name: "key holder grants an unlocked rule", p: base(nil), f: Facts{Rule: unlocked, Approver: approver}, tier: TierKey},
		{name: "no key", p: base(nil), f: Facts{Rule: unlocked, Approver: Approver{UserID: "bob"}}, tier: TierKey, wantCode: CodeForbidden},
		{
			name: "perpetual needs super-admin (D-080)", p: base(func(p *Proposal) { p.ExpiresAt = time.Time{} }),
			f: Facts{Rule: unlocked, Approver: approver}, tier: TierSuperAdmin, wantCode: CodeTier,
		},
		{
			name: "perpetual by super-admin", p: base(func(p *Proposal) { p.ExpiresAt = time.Time{} }),
			f: Facts{Rule: unlocked, Approver: super}, tier: TierSuperAdmin,
		},
		{
			name: "locked rule needs super-admin by default (D-082)", p: base(nil),
			f: Facts{Rule: RuleFacts{Known: true, Locked: true}, Approver: approver}, tier: TierSuperAdmin, wantCode: CodeTier,
		},
		{
			name: "unknown rule reads as locked", p: base(nil),
			f: Facts{Rule: RuleFacts{}, Approver: approver}, tier: TierSuperAdmin, wantCode: CodeTier,
		},
		{
			name: "locked rule by policy writer when the org allows it", p: base(nil),
			f: Facts{Rule: RuleFacts{Known: true, Locked: true}, Approver: approver},
			s: func(s *Settings) { s.LockedRuleApprover = ApproverPolicyWriter }, tier: TierKey,
		},
		{
			name: "critical exempt always super-admin", p: base(func(p *Proposal) { p.Effect = orgcontract.AccessGrantEffectExempt }),
			f: Facts{Rule: RuleFacts{Known: true, Severity: "critical"}, Approver: approver},
			s: func(s *Settings) { s.LockedRuleApprover = ApproverPolicyWriter }, tier: TierSuperAdmin, wantCode: CodeTier,
		},
		{
			name: "critical soften stays at key tier", p: base(nil),
			f: Facts{Rule: RuleFacts{Known: true, Severity: "critical"}, Approver: approver}, tier: TierKey,
		},
		{
			name: "self approval refused (D-086)", p: base(nil),
			f: Facts{Rule: unlocked, Approver: approver, RequesterID: "bob"}, tier: TierKey, wantCode: CodeSelf,
		},
		{
			name: "solo super-admin may self-approve, flagged", p: base(nil),
			f:    Facts{Rule: unlocked, Approver: Approver{UserID: "carol", HasKey: true, SuperAdmin: true, OnlyKeyHolder: true}, RequesterID: "carol"},
			tier: TierKey, check: func(t *testing.T, d Decision) {
				if !d.SelfApproved {
					t.Fatal("want self_approved")
				}
			},
		},
		{
			// C156-01: a proactive grant (and an extension) has no request
			// row; the grantee is still compared with the approver.
			name: "proactive grant to oneself refused (D-086)", p: base(func(p *Proposal) { p.UserID = "bob" }),
			f: Facts{Rule: unlocked, Approver: approver}, tier: TierKey, wantCode: CodeSelf,
		},
		{
			name: "an org setting cannot switch self-approval on (D-086)", p: base(nil),
			f: Facts{Rule: unlocked, Approver: approver, RequesterID: "bob"},
			s: func(s *Settings) { s.RequireDistinctApprover = false }, tier: TierKey, wantCode: CodeSelf,
		},
		{
			name: "solo super-admin proactive grant to themselves, flagged", p: base(func(p *Proposal) { p.UserID = "carol" }),
			f:    Facts{Rule: unlocked, Approver: Approver{UserID: "carol", HasKey: true, SuperAdmin: true, OnlyKeyHolder: true}},
			tier: TierKey, check: func(t *testing.T, d Decision) {
				if !d.SelfApproved {
					t.Fatal("want self_approved")
				}
			},
		},
		{
			// C156-05: a rule the org cannot classify may be critical.
			name: "unknown rule exempt needs super-admin even for a policy writer", p: base(func(p *Proposal) { p.Effect = orgcontract.AccessGrantEffectExempt }),
			f: Facts{Rule: RuleFacts{}, Approver: approver},
			s: func(s *Settings) { s.LockedRuleApprover = ApproverPolicyWriter }, tier: TierSuperAdmin, wantCode: CodeTier,
		},
		{
			name: "longer than 30d refused", p: base(func(p *Proposal) { p.ExpiresAt = t0.Add(31 * day) }),
			f: Facts{Rule: unlocked, Approver: approver}, tier: TierKey, wantCode: CodeOutOfRange,
		},
		{
			name: "uses without expiry refused", p: base(func(p *Proposal) { p.ExpiresAt = time.Time{}; p.MaxUses = 1 }),
			f: Facts{Rule: unlocked, Approver: super}, tier: TierSuperAdmin, wantCode: CodeBadValue,
		},
		{
			name: "machine grant needs machine", p: base(func(p *Proposal) { p.MachineIdentity = "" }),
			f: Facts{Rule: unlocked, Approver: approver}, tier: TierKey, wantCode: CodeRequired,
		},
		{
			name: "guard needs effect", p: base(func(p *Proposal) { p.Effect = "" }),
			f: Facts{Rule: unlocked, Approver: approver}, tier: TierKey, wantCode: CodeRequired,
		},
		{
			name: "budget resolves delta to absolute (D-085)",
			p: Proposal{
				Type: TypeBudgetIncrease, SubjectKind: orgcontract.AccessGrantSubjectMember, UserID: "alice",
				BudgetID: "b-3", DeltaTokens: 200000, ExpiresAt: t0.Add(7 * day),
			},
			f:    Facts{Approver: Approver{UserID: "fin", HasKey: true}, BaseCapTokens: 1000000, BudgetPeriodEnd: t0.Add(20 * day)},
			tier: TierKey, check: func(t *testing.T, d Decision) {
				if d.CapTokens != 1200000 {
					t.Fatalf("cap = %d", d.CapTokens)
				}
			},
		},
		{
			name: "budget past the period end refused",
			p: Proposal{
				Type: TypeBudgetIncrease, SubjectKind: orgcontract.AccessGrantSubjectMember, UserID: "alice",
				BudgetID: "b-3", DeltaTokens: 1, ExpiresAt: t0.Add(30 * day),
			},
			f:    Facts{Approver: Approver{UserID: "fin", HasKey: true}, BaseCapTokens: 10, BudgetPeriodEnd: t0.Add(2 * day)},
			tier: TierKey, wantCode: CodeOutOfRange,
		},
		{
			name: "budget with no cap in that unit refused",
			p: Proposal{
				Type: TypeBudgetIncrease, SubjectKind: orgcontract.AccessGrantSubjectMember, UserID: "alice",
				BudgetID: "b-3", DeltaUSD: 5, ExpiresAt: t0.Add(day),
			},
			f:    Facts{Approver: Approver{UserID: "fin", HasKey: true}, BaseCapTokens: 10},
			tier: TierKey, wantCode: CodeBadValue,
		},
		// T-523: a request may leave the budget and the amount for later,
		// a grant never does.
		{
			name: "budget grant still needs the budget id",
			p: Proposal{
				Type: TypeBudgetIncrease, SubjectKind: orgcontract.AccessGrantSubjectMember, UserID: "alice",
				DeltaTokens: 1, ExpiresAt: t0.Add(day),
			},
			f:    Facts{Approver: Approver{UserID: "fin", HasKey: true}, BaseCapTokens: 10},
			tier: TierKey, wantCode: CodeRequired,
		},
		{
			name: "budget grant still needs an amount",
			p: Proposal{
				Type: TypeBudgetIncrease, SubjectKind: orgcontract.AccessGrantSubjectMember, UserID: "alice",
				BudgetID: "b-3", ExpiresAt: t0.Add(day),
			},
			f:    Facts{Approver: Approver{UserID: "fin", HasKey: true}, BaseCapTokens: 10},
			tier: TierKey, wantCode: CodeRequired,
		},
		{
			name: "an amount the request left to the approver is not a widening",
			p: Proposal{
				Type: TypeBudgetIncrease, SubjectKind: orgcontract.AccessGrantSubjectMember, UserID: "alice",
				BudgetID: "b-3", DeltaUSD: 5, ExpiresAt: t0.Add(day),
			},
			f: Facts{Approver: Approver{UserID: "fin", HasKey: true}, BaseCapUSD: 10, Requested: &Normalized{
				Request: Request{SubjectKind: orgcontract.AccessGrantSubjectMember}, Duration: day,
			}},
			tier: TierKey, check: func(t *testing.T, d Decision) {
				if d.Widened {
					t.Fatalf("widened by %v", d.WidenedBy)
				}
			},
		},
		{name: "other is not grantable", p: Proposal{Type: TypeOther}, f: Facts{Approver: approver}, tier: TierKey, wantCode: CodeUnknown},
		{name: "widening is detected", p: base(func(p *Proposal) {
			p.Effect = orgcontract.AccessGrantEffectExempt
			p.SubjectKind = orgcontract.AccessGrantSubjectMember
			p.ExpiresAt = t0.Add(48 * time.Hour)
		}), f: Facts{Rule: unlocked, Approver: approver, Requested: &Normalized{
			Request:  Request{SubjectKind: orgcontract.AccessGrantSubjectMachine, Payload: orgcontract.AccessRequestPayload{Effect: orgcontract.AccessGrantEffectSoften, OperandHash: "h"}},
			Duration: 8 * time.Hour,
		}}, tier: TierKey, check: func(t *testing.T, d Decision) {
			if !d.Widened || len(d.WidenedBy) != 4 {
				t.Fatalf("widened %v %v", d.Widened, d.WidenedBy)
			}
		}},
		{
			name: "narrowing is not widening", p: base(func(p *Proposal) { p.ExpiresAt = t0.Add(time.Hour) }),
			f: Facts{Rule: unlocked, Approver: approver, Requested: &Normalized{
				Duration: 8 * time.Hour,
				Request:  Request{SubjectKind: orgcontract.AccessGrantSubjectMachine},
			}}, tier: TierKey,
			check: func(t *testing.T, d Decision) {
				if d.Widened {
					t.Fatalf("narrowed proposal flagged widened: %v", d.WidenedBy)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := DefaultSettings()
			if c.s != nil {
				c.s(&s)
			}
			c.f.Now = t0
			d := Decide(c.p, c.f, s)
			if d.Tier != c.tier {
				t.Fatalf("tier = %s, want %s (%v)", d.Tier, c.tier, d.TierReasons)
			}
			if c.wantCode == "" && len(d.Problems) > 0 {
				t.Fatalf("unexpected problems %v", d.Problems)
			}
			if c.wantCode != "" && !hasCode(d.Problems, c.wantCode) {
				t.Fatalf("want %s got %v", c.wantCode, d.Problems)
			}
			if c.check != nil {
				c.check(t, d)
			}
		})
	}
}

func TestDefaultEffect(t *testing.T) {
	for sev, want := range map[string]string{
		"critical": orgcontract.AccessGrantEffectSoften, "High": orgcontract.AccessGrantEffectSoften,
		"medium": orgcontract.AccessGrantEffectExempt, "": orgcontract.AccessGrantEffectExempt,
	} {
		if got := DefaultEffect(sev); got != want {
			t.Errorf("%s: %s", sev, got)
		}
	}
}

func TestStatus(t *testing.T) {
	ns := func(d time.Duration) int64 { return t0.Add(d).UnixNano() }
	cases := []struct {
		name string
		w    Window
		uses int64
		want string
	}{
		{"active", Window{StartsAtNs: ns(-time.Hour), ExpiresAtNs: ns(time.Hour)}, 0, StatusActive},
		{"perpetual active", Window{StartsAtNs: ns(-time.Hour)}, 0, StatusActive},
		{"scheduled", Window{StartsAtNs: ns(time.Hour), ExpiresAtNs: ns(2 * time.Hour)}, 0, StatusScheduled},
		{"expired", Window{StartsAtNs: ns(-2 * time.Hour), ExpiresAtNs: ns(-time.Hour)}, 0, StatusExpired},
		{"exhausted beats expired", Window{StartsAtNs: ns(-2 * time.Hour), ExpiresAtNs: ns(-time.Hour), MaxUses: 1}, 1, StatusExhausted},
		{"revoked beats all", Window{StartsAtNs: ns(-2 * time.Hour), ExpiresAtNs: ns(-time.Hour), RevokedAtNs: ns(-90 * time.Minute)}, 0, StatusRevoked},
	}
	for _, c := range cases {
		if got := Status(c.w, c.uses, t0); got != c.want {
			t.Errorf("%s: %s want %s", c.name, got, c.want)
		}
	}
}

func TestHonoured(t *testing.T) {
	ns := func(d time.Duration) int64 { return t0.Add(d).UnixNano() }
	g := orgcontract.AccessGrantWire{ID: 1, Type: TypeGuardExemption, StartsAtNs: ns(-time.Hour), ExpiresAtNs: ns(8 * time.Hour)}
	rc := Receipt{ServerNowNs: ns(0), ReceivedAtNs: ns(0), LastVerifiedNs: ns(0), MaxOfflineS: 86400}
	cases := []struct {
		name   string
		g      orgcontract.AccessGrantWire
		uses   int64
		rc     Receipt
		now    time.Time
		reason string
	}{
		{"fresh", g, 0, rc, t0.Add(time.Minute), ReasonOK},
		{"absolute expiry", g, 0, rc, t0.Add(8 * time.Hour), ReasonExpired},
		{
			"node clock behind the server still expires by TTL", g, 0,
			Receipt{ServerNowNs: ns(0), ReceivedAtNs: ns(-6 * time.Hour), LastVerifiedNs: ns(-6 * time.Hour), MaxOfflineS: 86400},
			t0.Add(2*time.Hour + time.Second), ReasonExpired,
		},
		{
			"clock set back reads as the high-water mark", g, 0,
			Receipt{ServerNowNs: ns(0), ReceivedAtNs: ns(0), LastVerifiedNs: ns(0), HighWaterNs: ns(9 * time.Hour), MaxOfflineS: 86400},
			t0.Add(time.Minute), ReasonExpired,
		},
		{
			"offline past 24h is stale (D-087)",
			orgcontract.AccessGrantWire{ID: 1, StartsAtNs: ns(-time.Hour)},
			0, rc,
			t0.Add(24 * time.Hour), ReasonStale,
		},
		{
			"online only window", g, 0,
			Receipt{ServerNowNs: ns(0), ReceivedAtNs: ns(0), LastVerifiedNs: ns(0)},
			t0.Add(11 * time.Minute), ReasonStale,
		},
		{
			"not started",
			orgcontract.AccessGrantWire{ID: 1, StartsAtNs: ns(time.Hour), ExpiresAtNs: ns(2 * time.Hour)},
			0, rc,
			t0.Add(30 * time.Minute), ReasonNotStarted,
		},
		{
			"exhausted",
			orgcontract.AccessGrantWire{ID: 1, StartsAtNs: ns(-time.Hour), ExpiresAtNs: ns(time.Hour), MaxUses: 2},
			2, rc,
			t0, ReasonExhausted,
		},
		{"no receipt", g, 0, Receipt{}, t0, ReasonNoReceipt},
	}
	for _, c := range cases {
		ok, reason := Honoured(c.g, c.uses, c.rc, c.now)
		if reason != c.reason || ok != (c.reason == ReasonOK) {
			t.Errorf("%s: ok=%v reason=%q want %q", c.name, ok, reason, c.reason)
		}
	}
}

func TestMatch(t *testing.T) {
	ns := func(d time.Duration) int64 { return t0.Add(d).UnixNano() }
	rc := Receipt{ServerNowNs: ns(0), ReceivedAtNs: ns(0), LastVerifiedNs: ns(0), MaxOfflineS: 86400}
	mk := func(id int64, mut func(*orgcontract.AccessGrantWire)) Cached {
		g := orgcontract.AccessGrantWire{
			ID: id, Type: TypeGuardExemption, Effect: orgcontract.AccessGrantEffectExempt,
			SubjectKind: orgcontract.AccessGrantSubjectMember, RuleID: "R-171", StartsAtNs: ns(-time.Hour), ExpiresAtNs: ns(8 * time.Hour),
		}
		if mut != nil {
			mut(&g)
		}
		return Cached{Grant: g}
	}
	q := Query{RuleID: "R-171", Lane: LaneTool, OperandHash: "op1", ProjectRootHash: "p1", Decision: DecisionDeny}
	cases := []struct {
		name   string
		grants []Cached
		q      Query
		want   int64
	}{
		{"rule-wide matches", []Cached{mk(1, nil)}, q, 1},
		{"other rule does not", []Cached{mk(1, func(g *orgcontract.AccessGrantWire) { g.RuleID = "R-1" })}, q, 0},
		{"exact operand mismatch", []Cached{mk(1, func(g *orgcontract.AccessGrantWire) { g.OperandHash = "op2" })}, q, 0},
		{"lane all matches", []Cached{mk(1, func(g *orgcontract.AccessGrantWire) { g.Lane = LaneAll })}, q, 1},
		{"other lane does not", []Cached{mk(1, func(g *orgcontract.AccessGrantWire) { g.Lane = LanePrompt })}, q, 0},
		{"narrowest wins", []Cached{mk(1, nil), mk(2, func(g *orgcontract.AccessGrantWire) { g.OperandHash = "op1" })}, q, 2},
		{"earliest expiry breaks a tie", []Cached{mk(1, nil), mk(2, func(g *orgcontract.AccessGrantWire) { g.ExpiresAtNs = ns(time.Hour) })}, q, 2},
		{"perpetual sorts last", []Cached{mk(1, func(g *orgcontract.AccessGrantWire) { g.ExpiresAtNs = 0 }), mk(2, nil)}, q, 2},
		{"expired is no hit", []Cached{mk(1, func(g *orgcontract.AccessGrantWire) { g.ExpiresAtNs = ns(-time.Minute) })}, q, 0},
		{"budget type never matches", []Cached{mk(1, func(g *orgcontract.AccessGrantWire) { g.Type = TypeBudgetIncrease })}, q, 0},
		{"used up is no hit", []Cached{{Grant: mk(1, func(g *orgcontract.AccessGrantWire) { g.MaxUses = 1 }).Grant, UsesUsed: 1}}, q, 0},
		{"empty rule id never matches", []Cached{mk(1, nil)}, Query{}, 0},
	}
	for _, c := range cases {
		hit, ok := Match(c.q, c.grants, rc, t0)
		if (c.want == 0) == ok || (ok && hit.GrantID != c.want) {
			t.Errorf("%s: got %+v ok=%v want %d", c.name, hit, ok, c.want)
		}
	}
}

// TestMatchDecisionAndLock pins the two G3 match inputs: the verdict being
// changed (soften only acts on a DENY) and the node's org lock (a grant only
// reaches a locked rule when it was issued under the locked-rule approval
// rule, LockOverride).
func TestMatchDecisionAndLock(t *testing.T) {
	ns := func(d time.Duration) int64 { return t0.Add(d).UnixNano() }
	rc := Receipt{ServerNowNs: ns(0), ReceivedAtNs: ns(0), LastVerifiedNs: ns(0), MaxOfflineS: 86400}
	mk := func(id int64, effect string, lockOverride bool) Cached {
		return Cached{Grant: orgcontract.AccessGrantWire{
			ID: id, Type: TypeGuardExemption, Effect: effect, LockOverride: lockOverride,
			SubjectKind: orgcontract.AccessGrantSubjectMember, RuleID: "R-171",
			StartsAtNs: ns(-time.Hour), ExpiresAtNs: ns(8 * time.Hour),
		}}
	}
	exempt, soften := orgcontract.AccessGrantEffectExempt, orgcontract.AccessGrantEffectSoften
	cases := []struct {
		name       string
		grants     []Cached
		decision   string
		locked     bool
		want       int64
		lockRefuse bool
	}{
		{"exempt lifts an ask", []Cached{mk(1, exempt, false)}, DecisionAsk, false, 1, false},
		{"exempt lifts a deny", []Cached{mk(1, exempt, false)}, DecisionDeny, false, 1, false},
		{"soften acts on a deny", []Cached{mk(1, soften, false)}, DecisionDeny, false, 1, false},
		{"soften cannot change an ask", []Cached{mk(1, soften, false)}, DecisionAsk, false, 0, false},
		{"soften skipped, exempt used on an ask", []Cached{mk(1, soften, false), mk(2, exempt, false)}, DecisionAsk, false, 2, false},
		{"locked rule ignores a grant without the lock override", []Cached{mk(1, exempt, false)}, DecisionDeny, true, 0, true},
		{"locked rule honours a lock-override grant", []Cached{mk(1, exempt, true)}, DecisionDeny, true, 1, false},
		{"locked rule picks the lock-override grant", []Cached{mk(1, exempt, false), mk(2, soften, true)}, DecisionDeny, true, 2, false},
		{"unknown decision matches nothing", []Cached{mk(1, exempt, true)}, "flag", false, 0, false},
	}
	for _, c := range cases {
		q := Query{RuleID: "R-171", Lane: LaneTool, Decision: c.decision, RuleLocked: c.locked}
		res := MatchDetail(q, c.grants, rc, t0)
		if (c.want == 0) == res.OK || (res.OK && res.Hit.GrantID != c.want) {
			t.Errorf("%s: got %+v want %d", c.name, res, c.want)
		}
		if res.LockRefused != c.lockRefuse {
			t.Errorf("%s: lock refused = %v, want %v", c.name, res.LockRefused, c.lockRefuse)
		}
		if hit, ok := Match(q, c.grants, rc, t0); ok != res.OK || hit != res.Hit {
			t.Errorf("%s: Match and MatchDetail disagree", c.name)
		}
	}
}

// TestDecideLockOverride pins which grants may reach an org-locked rule on
// the node (orchestrator ruling for G3): only a guard exemption issued under
// the locked-rule approval rule - a super-admin approval, or a policy writer
// the org's own locked_rule_approver setting admits for a rule the org reads
// as locked (D-082).
func TestDecideLockOverride(t *testing.T) {
	p := Proposal{
		Type: TypeGuardExemption, Effect: orgcontract.AccessGrantEffectSoften,
		SubjectKind: orgcontract.AccessGrantSubjectMachine, UserID: "alice", MachineIdentity: "laptop-7",
		RuleID: "R-171", ExpiresAt: t0.Add(8 * time.Hour),
	}
	writer := Approver{UserID: "bob", HasKey: true}
	super := Approver{UserID: "carol", HasKey: true, SuperAdmin: true}
	locked := RuleFacts{Known: true, Locked: true, Severity: "high"}
	unlocked := RuleFacts{Known: true, Severity: "high"}
	cases := []struct {
		name     string
		p        Proposal
		rule     RuleFacts
		approver Approver
		setting  string
		want     bool
	}{
		{"super-admin on a locked rule", p, locked, super, "", true},
		// C156-05: lock_override is stamped only for a rule the org locks.
		{"super-admin on an unlocked rule carries none", p, unlocked, super, "", false},
		{"super-admin on an unknown rule", p, RuleFacts{}, super, "", true},
		{"policy writer under the org setting on a locked rule", p, locked, writer, ApproverPolicyWriter, true},
		{"policy writer under the org setting on an unknown rule", p, RuleFacts{}, writer, ApproverPolicyWriter, true},
		{"policy writer on an unlocked rule", p, unlocked, writer, ApproverPolicyWriter, false},
		{"policy writer without the setting", p, unlocked, writer, "", false},
		{"never on a non-guard grant", Proposal{
			Type: TypeToolAllow, SubjectKind: orgcontract.AccessGrantSubjectMember, UserID: "alice",
			Target: "codex", ExpiresAt: t0.Add(time.Hour),
		}, locked, super, "", false},
	}
	for _, c := range cases {
		s := DefaultSettings()
		if c.setting != "" {
			s.LockedRuleApprover = c.setting
		}
		d := Decide(c.p, Facts{Now: t0, Rule: c.rule, Approver: c.approver}, s)
		if d.LockOverride != c.want {
			t.Errorf("%s: lock_override = %v, want %v (problems %v)", c.name, d.LockOverride, c.want, d.Problems)
		}
	}
}

// TestSoftenForRule: the local-confirmation gate's question - is there an
// honoured soften grant naming this rule that may reach it given the lock?
// Narrowing fields do not matter here (the claim re-checks them per call).
func TestSoftenForRule(t *testing.T) {
	ns := func(d time.Duration) int64 { return t0.Add(d).UnixNano() }
	rc := Receipt{ServerNowNs: ns(0), ReceivedAtNs: ns(0), LastVerifiedNs: ns(0), MaxOfflineS: 86400}
	mk := func(id int64, effect string, over bool, mut func(*orgcontract.AccessGrantWire)) Cached {
		g := orgcontract.AccessGrantWire{
			ID: id, Type: TypeGuardExemption, Effect: effect, LockOverride: over, RuleID: "R-171",
			OperandHash: "op", StartsAtNs: ns(-time.Hour), ExpiresAtNs: ns(time.Hour),
		}
		if mut != nil {
			mut(&g)
		}
		return Cached{Grant: g}
	}
	soften, exempt := orgcontract.AccessGrantEffectSoften, orgcontract.AccessGrantEffectExempt
	cases := []struct {
		name   string
		grants []Cached
		locked bool
		want   int64
	}{
		{"soften with lock override on a locked rule", []Cached{mk(1, soften, true, nil)}, true, 1},
		{"soften without lock override on a locked rule", []Cached{mk(1, soften, false, nil)}, true, 0},
		{"soften on an unlocked rule", []Cached{mk(1, soften, false, nil)}, false, 1},
		{"exempt is not a confirmation grant", []Cached{mk(1, exempt, true, nil)}, true, 0},
		{"another rule", []Cached{mk(1, soften, true, func(g *orgcontract.AccessGrantWire) { g.RuleID = "R-1" })}, true, 0},
		{"expired", []Cached{mk(1, soften, true, func(g *orgcontract.AccessGrantWire) { g.ExpiresAtNs = ns(-time.Minute) })}, true, 0},
		{"spent", []Cached{{Grant: mk(1, soften, true, func(g *orgcontract.AccessGrantWire) { g.MaxUses = 1 }).Grant, UsesUsed: 1}}, true, 0},
	}
	for _, c := range cases {
		id, ok := SoftenForRule("R-171", c.locked, c.grants, rc, t0)
		if (c.want == 0) == ok || id != c.want {
			t.Errorf("%s: got %d %v, want %d", c.name, id, ok, c.want)
		}
	}
}

func TestBudgetOverlay(t *testing.T) {
	ns := func(d time.Duration) int64 { return t0.Add(d).UnixNano() }
	grants := []BudgetGrant{
		{GrantID: 1, BudgetID: "b-3", CapTokens: 1200000, StartsAtNs: ns(-time.Hour), ExpiresAtNs: ns(time.Hour)},
		{GrantID: 2, BudgetID: "b-3", CapTokens: 1500000, StartsAtNs: ns(time.Hour), ExpiresAtNs: ns(2 * time.Hour)},
	}
	o, ok := BudgetOverlay(1000000, 0, grants, t0)
	if !ok || o.GrantID != 1 || o.CapTokens != 1200000 || o.BaseCapTokens != 1000000 {
		t.Fatalf("got %+v %v", o, ok)
	}
	if _, ok := BudgetOverlay(2000000, 0, grants, t0); ok {
		t.Fatal("a grant must never lower a cap")
	}
	if o, ok := BudgetOverlay(1000000, 0, grants, t0.Add(90*time.Minute)); !ok || o.GrantID != 2 {
		t.Fatalf("scheduled grant should apply once started: %+v", o)
	}
	tok, _, reverted := RevertExpiredOverlay(1200000, 0, 1000000, 0, ns(time.Hour), t0.Add(time.Hour))
	if !reverted || tok != 1000000 {
		t.Fatal("expired overlay must revert to base")
	}
	if _, _, reverted := RevertExpiredOverlay(1200000, 0, 1000000, 0, 0, t0); reverted {
		t.Fatal("no overlay never reverts")
	}
}

func TestShapeContext(t *testing.T) {
	c := orgcontract.AccessRequestContext{RuleID: "R-1", TargetHash: "h", TargetExcerpt: "rm -rf /", ProjectRoot: "/p", GitBranch: "main"}
	got := ShapeContext(c, false, false)
	if got.TargetExcerpt != "" || got.ProjectRoot != "" || got.GitBranch != "" || got.TargetHash != "h" {
		t.Fatalf("individual default leaked content: %+v", got)
	}
	got = ShapeContext(c, false, true)
	if got.TargetExcerpt == "" || got.ProjectRoot != "" {
		t.Fatalf("opt-in should ship only the excerpt: %+v", got)
	}
	got = ShapeContext(c, true, false)
	if got.TargetExcerpt == "" || got.ProjectRoot == "" || got.GitBranch == "" {
		t.Fatalf("managed node ships content: %+v", got)
	}
	long := orgcontract.AccessRequestContext{TargetExcerpt: strings.Repeat("é", 400)}
	if n := len(ShapeContext(long, true, false).TargetExcerpt); n > MaxExcerptBytes {
		t.Fatalf("excerpt not bounded: %d", n)
	}
}

func TestSettingsNormalize(t *testing.T) {
	s, probs := DefaultSettings().Normalize()
	if len(probs) > 0 || s.LockedRuleApprover != ApproverSuperAdmin {
		t.Fatalf("defaults must normalize clean: %v", probs)
	}
	bad := DefaultSettings()
	bad.LockedRuleApprover = "anyone"
	bad.MaxDurationS = map[string]int64{TypeGuardExemption: 60 * 86400, "nope": 1, TypeBudgetIncrease: 5}
	bad.MaxOfflineS = 30 * 86400
	bad.UnansweredTTLS = 60
	bad.DisabledTypes = []string{"zzz"}
	_, probs = bad.Normalize()
	if len(probs) != 7 {
		t.Fatalf("want 7 problems, got %d: %v", len(probs), probs)
	}
}

func TestExtensionProblems(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	cur := now.Add(72 * time.Hour).UnixNano()
	cases := []struct {
		name    string
		current int64
		next    time.Time
		want    int
	}{
		{"later end extends", cur, now.Add(96 * time.Hour), 0},
		{"perpetual extension always extends", cur, time.Time{}, 0},
		{"shorter end refused", cur, now.Add(24 * time.Hour), 1},
		{"same end refused", cur, time.Unix(0, cur), 1},
		{"a perpetual grant cannot be given an end", 0, now.Add(24 * time.Hour), 1},
		{"perpetual stays perpetual", 0, time.Time{}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExtensionProblems(c.current, c.next)
			if len(got) != c.want {
				t.Fatalf("problems = %v, want %d", got, c.want)
			}
			if c.want > 0 && got[0].Code != CodeOutOfRange {
				t.Fatalf("code = %s", got[0].Code)
			}
		})
	}
}

// TestOtherIsAnsweredByNote pins T-437: "other" was LandNone (granted
// nowhere, no terminal state the developer could read). It is now answered
// with a note: never a grant, and the only answer type.
func TestOtherIsAnsweredByNote(t *testing.T) {
	for _, rt := range RequestTypes {
		if rt.AnsweredByNote() && rt.Grantable() {
			t.Fatalf("%s is both answered by note and grantable", rt.ID)
		}
		if !rt.AnsweredByNote() && !rt.Grantable() {
			t.Fatalf("%s lands nowhere: neither a grant nor an answer", rt.ID)
		}
	}
	other, _ := TypeByID(TypeOther)
	if !other.AnsweredByNote() || other.Grantable() || other.Label != "Something else" {
		t.Fatalf("other = %+v", other)
	}
	d := Decide(Proposal{Type: TypeOther}, Facts{Approver: Approver{UserID: "bob", HasKey: true}}, DefaultSettings())
	if len(d.Problems) != 1 || !strings.Contains(d.Problems[0].Message, "answered with a note") {
		t.Fatalf("decide other = %+v", d.Problems)
	}
}
