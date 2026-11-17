package accessgrant

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestCoveredBy pins the coverage table: a grant in force covers a new ask
// only when it gives everything the ask would (operator report 2026-11-13:
// S-793 granted three times on one machine, every later grant covered by the
// first).
func TestCoveredBy(t *testing.T) {
	const machine, project = "m1", "p1"
	exempt, soften := orgcontract.AccessGrantEffectExempt, orgcontract.AccessGrantEffectSoften
	end := t0.Add(30 * 24 * time.Hour).UnixNano()
	held := func(mut func(*Held)) Held {
		h := Held{
			ID: 11, Type: TypeGuardExemption, Effect: exempt, SubjectKind: orgcontract.AccessGrantSubjectMachine,
			MachineIdentity: machine, RuleID: "S-793", ProjectRootHash: project,
		}
		if mut != nil {
			mut(&h)
		}
		return h
	}
	ask := func(mut func(*Ask)) Ask {
		a := Ask{
			Type: TypeGuardExemption, SubjectKind: orgcontract.AccessGrantSubjectMachine, MachineIdentity: machine,
			RuleID: "S-793", ProjectRootHash: project, EndsAtNs: end,
		}
		if mut != nil {
			mut(&a)
		}
		return a
	}
	tool := func(h *Held) { h.Type, h.Effect, h.RuleID, h.Target = TypeToolAllow, "", "", "cursor" }
	cases := []struct {
		name string
		held Held
		ask  Ask
		want bool
	}{
		{"the live case: perpetual rule-wide exempt covers the same ask again", held(nil), ask(nil), true},
		{"covers a narrower ask (one exact command)", held(nil), ask(func(a *Ask) { a.CommandClass, a.OperandHash = "/shell_exec", "op" }), true},
		{"covers a soften ask", held(nil), ask(func(a *Ask) { a.Effect = soften }), true},
		{"covers an ask for no expiry", held(nil), ask(func(a *Ask) { a.EndsAtNs = 0 }), true},
		{"member-wide grant covers a machine ask", held(func(h *Held) { h.SubjectKind, h.MachineIdentity = orgcontract.AccessGrantSubjectMember, "" }), ask(nil), true},
		{"every-project grant covers a project ask", held(func(h *Held) { h.ProjectRootHash = "" }), ask(nil), true},
		{"lane-all grant covers a lane ask", held(func(h *Held) { h.Lane = LaneAll }), ask(func(a *Ask) { a.Lane = LaneTool }), true},
		{"a later expiry covers a shorter ask", held(func(h *Held) { h.ExpiresAtNs = end + 1 }), ask(nil), true},

		{"another rule", held(nil), ask(func(a *Ask) { a.RuleID = "S-794" }), false},
		{"another type", held(nil), ask(func(a *Ask) { a.Type, a.Target = TypeToolAllow, "S-793" }), false},
		{"another machine", held(nil), ask(func(a *Ask) { a.MachineIdentity = "m2" }), false},
		{"machine grant does not cover a member-wide proposal", held(nil), ask(func(a *Ask) { a.SubjectKind, a.MachineIdentity = orgcontract.AccessGrantSubjectMember, "" }), false},
		{"another project", held(nil), ask(func(a *Ask) { a.ProjectRootHash = "p2" }), false},
		{"project grant does not cover an every-project ask", held(nil), ask(func(a *Ask) { a.ProjectRootHash = "" }), false},
		{"exact-command grant does not cover a rule-wide ask", held(func(h *Held) { h.CommandClass, h.OperandHash = "/shell_exec", "op" }), ask(nil), false},
		{"exact-command grant does not cover another command", held(func(h *Held) { h.OperandHash = "op" }), ask(func(a *Ask) { a.OperandHash = "op2" }), false},
		{"one-lane grant does not cover an every-lane ask", held(func(h *Held) { h.Lane = LanePrompt }), ask(nil), false},
		{"soften does not cover an exempt ask", held(func(h *Held) { h.Effect = soften }), ask(func(a *Ask) { a.Effect = exempt }), false},
		{"soften does not cover an ask that leaves the effect to the approver", held(func(h *Held) { h.Effect = soften }), ask(nil), false},
		{"a use-limited grant covers nothing", held(func(h *Held) { h.MaxUses = 5 }), ask(nil), false},
		{"an earlier expiry does not cover a longer ask", held(func(h *Held) { h.ExpiresAtNs = end - 1 }), ask(nil), false},
		{"an expiring grant does not cover an ask for no expiry", held(func(h *Held) { h.ExpiresAtNs = end }), ask(func(a *Ask) { a.EndsAtNs = 0 }), false},
		{"the grant being extended does not cover its extension", held(nil), ask(func(a *Ask) { a.SupersedesID = 11 }), false},
		{"a budget increase is never already granted", held(func(h *Held) { h.Type = TypeBudgetIncrease }), ask(func(a *Ask) { a.Type = TypeBudgetIncrease }), false},
		{"tool access: same tool", held(tool), ask(func(a *Ask) { a.Type, a.RuleID, a.Target = TypeToolAllow, "", "cursor" }), true},
		{"tool access: another tool", held(tool), ask(func(a *Ask) { a.Type, a.RuleID, a.Target = TypeToolAllow, "", "codex" }), false},
		{
			"finding exception: same rule, another finding",
			held(func(h *Held) { h.Type, h.Effect, h.Target = TypeFindingException, "", "f1" }),
			ask(func(a *Ask) { a.Type, a.Target = TypeFindingException, "f2" }), false,
		},
	}
	for _, c := range cases {
		got, ok := CoveredBy(c.ask, []Held{c.held})
		if ok != c.want || (ok && got.ID != c.held.ID) {
			t.Errorf("%s: covered=%v by %d, want %v", c.name, ok, got.ID, c.want)
		}
	}
}

// TestCoveredByPicksTheLongestLived pins which grant a refusal names.
func TestCoveredByPicksTheLongestLived(t *testing.T) {
	end := t0.Add(time.Hour).UnixNano()
	mk := func(id, expires int64) Held {
		return Held{ID: id, Type: TypeGuardExemption, Effect: orgcontract.AccessGrantEffectExempt, SubjectKind: orgcontract.AccessGrantSubjectMember, RuleID: "R-1", ExpiresAtNs: expires}
	}
	a := Ask{Type: TypeGuardExemption, SubjectKind: orgcontract.AccessGrantSubjectMember, RuleID: "R-1", EndsAtNs: end}
	cases := []struct {
		name string
		held []Held
		want int64
	}{
		{"no expiry beats an expiry", []Held{mk(1, end+10), mk(2, 0)}, 2},
		{"the later expiry wins", []Held{mk(1, end+10), mk(2, end+20)}, 2},
		{"the lowest id breaks a tie", []Held{mk(3, 0), mk(2, 0)}, 2},
		{"none covers", []Held{mk(1, end-1)}, 0},
	}
	for _, c := range cases {
		got, ok := CoveredBy(a, c.held)
		if (c.want == 0) == ok || (ok && got.ID != c.want) {
			t.Errorf("%s: got G-%d ok=%v, want G-%d", c.name, got.ID, ok, c.want)
		}
	}
}

// TestAskFromRequest pins how a request's breadth becomes the scope coverage
// compares (D-092).
func TestAskFromRequest(t *testing.T) {
	payload := orgcontract.AccessRequestPayload{RuleID: "S-793", CommandClass: "/shell_exec", OperandHash: "op", ProjectRootHash: "p1"}
	cases := []struct {
		breadth        string
		class, operand string
	}{
		{BreadthRule, "", ""},
		{BreadthClass, "/shell_exec", ""},
		{BreadthExact, "/shell_exec", "op"},
		{"", "/shell_exec", "op"},
	}
	for _, c := range cases {
		p := payload
		p.Breadth = c.breadth
		a := AskFromRequest(Normalized{Request: Request{Type: TypeGuardExemption, Payload: p, SubjectKind: orgcontract.AccessGrantSubjectMachine, Machine: "m1"}, Duration: time.Hour}, t0)
		if a.CommandClass != c.class || a.OperandHash != c.operand {
			t.Errorf("breadth %q: class=%q operand=%q, want %q %q", c.breadth, a.CommandClass, a.OperandHash, c.class, c.operand)
		}
		if a.EndsAtNs != t0.Add(time.Hour).UnixNano() || a.MachineIdentity != "m1" || a.ProjectRootHash != "p1" {
			t.Errorf("breadth %q: ask = %+v", c.breadth, a)
		}
	}
}

// TestRedundant replays the machine in the operator report (2026-11-13): G-8
// exact S-793, G-9 soften S-721, G-11 and G-15 rule-wide S-793, G-14 exempt
// S-721, G-16 and G-17 S-794. Each later or narrower duplicate names the
// grant that makes it redundant; the first of an identical pair stays.
func TestRedundant(t *testing.T) {
	exempt, soften := orgcontract.AccessGrantEffectExempt, orgcontract.AccessGrantEffectSoften
	end := t0.Add(30 * 24 * time.Hour).UnixNano()
	mk := func(id int64, rule, effect string, expires int64, operand string) Held {
		return Held{
			ID: id, Type: TypeGuardExemption, Effect: effect, SubjectKind: orgcontract.AccessGrantSubjectMachine,
			MachineIdentity: "m1", RuleID: rule, ProjectRootHash: "p1", ExpiresAtNs: expires, OperandHash: operand,
		}
	}
	held := []Held{
		mk(8, "S-793", exempt, end, "op"), mk(9, "S-721", soften, end, ""), mk(10, "S-748", exempt, end, ""),
		mk(11, "S-793", exempt, 0, ""), mk(12, "R-104", exempt, 0, ""), mk(13, "R-153", exempt, 0, ""),
		mk(14, "S-721", exempt, 0, ""), mk(15, "S-793", exempt, 0, ""), mk(16, "S-794", exempt, 0, ""),
		mk(17, "S-794", exempt, 0, ""),
	}
	got := Redundant(held)
	want := map[int64]int64{8: 11, 9: 14, 15: 11, 17: 16}
	if len(got) != len(want) {
		t.Fatalf("redundant = %v, want %v", got, want)
	}
	for id, by := range want {
		if got[id] != by {
			t.Errorf("G-%d: covered by G-%d, want G-%d", id, got[id], by)
		}
	}
}

// TestDecideAlreadyGranted pins the approval-side refusal: a proposal a grant
// in force covers is refused with the grant named, an extension of that very
// grant is not, and a wider proposal is still the approver's call.
func TestDecideAlreadyGranted(t *testing.T) {
	held := []Held{{
		ID: 11, Type: TypeGuardExemption, Effect: orgcontract.AccessGrantEffectExempt,
		SubjectKind: orgcontract.AccessGrantSubjectMachine, MachineIdentity: "m1", RuleID: "S-793", ProjectRootHash: "p1",
	}}
	base := Proposal{
		Type: TypeGuardExemption, Effect: orgcontract.AccessGrantEffectExempt, SubjectKind: orgcontract.AccessGrantSubjectMachine,
		UserID: "dev", MachineIdentity: "m1", RuleID: "S-793", ProjectRootHash: "p1",
	}
	facts := func(supersedes int64) Facts {
		return Facts{
			Now: t0, Held: held, SupersedesID: supersedes,
			Rule:     RuleFacts{Known: true, Severity: "warn"},
			Approver: Approver{UserID: "admin", HasKey: true, SuperAdmin: true},
		}
	}
	cases := []struct {
		name       string
		mut        func(*Proposal)
		supersedes int64
		refused    bool
	}{
		{"the same grant again, no expiry", nil, 0, true},
		{"the same grant again, 30 days", func(p *Proposal) { p.ExpiresAt = t0.Add(30 * 24 * time.Hour) }, 0, true},
		{"one exact command under the rule-wide grant", func(p *Proposal) { p.OperandHash = "op" }, 0, true},
		{"an extension of that grant", nil, 11, false},
		{"every project is wider", func(p *Proposal) { p.ProjectRootHash = "" }, 0, false},
		{"every machine is wider", func(p *Proposal) { p.SubjectKind, p.MachineIdentity = orgcontract.AccessGrantSubjectMember, "" }, 0, false},
		{"another rule", func(p *Proposal) { p.RuleID = "S-794" }, 0, false},
	}
	for _, c := range cases {
		p := base
		if c.mut != nil {
			c.mut(&p)
		}
		d := Decide(p, facts(c.supersedes), DefaultSettings())
		got := false
		for _, pr := range d.Problems {
			if pr.Code == CodeAlreadyGranted {
				got = true
			} else {
				t.Errorf("%s: unexpected problem %+v", c.name, pr)
			}
		}
		if got != c.refused {
			t.Errorf("%s: already-granted refusal = %v, want %v (%+v)", c.name, got, c.refused, d.Problems)
		}
	}
}

// TestMatchScopeMissAndEffectOrder pins the two enforcement-side answers
// added with the coverage table: a miss that names the honoured grant pinned
// to another scope, and exempt winning over soften at equal narrowness.
func TestMatchScopeMissAndEffectOrder(t *testing.T) {
	ns := func(d time.Duration) int64 { return t0.Add(d).UnixNano() }
	rc := Receipt{ServerNowNs: ns(0), ReceivedAtNs: ns(0), LastVerifiedNs: ns(0), MaxOfflineS: 86400}
	exempt, soften := orgcontract.AccessGrantEffectExempt, orgcontract.AccessGrantEffectSoften
	mk := func(id int64, effect string, mut func(*orgcontract.AccessGrantWire)) Cached {
		g := orgcontract.AccessGrantWire{
			ID: id, Type: TypeGuardExemption, Effect: effect, SubjectKind: orgcontract.AccessGrantSubjectMachine,
			RuleID: "S-721", ProjectRootHash: "p1", StartsAtNs: ns(-time.Hour), LockOverride: true,
		}
		if mut != nil {
			mut(&g)
		}
		return Cached{Grant: g}
	}
	cases := []struct {
		name      string
		grants    []Cached
		q         Query
		want      int64
		scopeMiss int64
	}{
		{
			"the live pair: exempt (no expiry) beats soften (30 days) on a deny",
			[]Cached{mk(9, soften, func(g *orgcontract.AccessGrantWire) { g.ExpiresAtNs = ns(30 * 24 * time.Hour) }), mk(14, exempt, nil)},
			Query{RuleID: "S-721", Lane: LaneTool, ProjectRootHash: "p1", Decision: DecisionDeny, RuleLocked: true},
			14, 0,
		},
		{
			"a narrower soften still beats a rule-wide exempt",
			[]Cached{mk(9, soften, func(g *orgcontract.AccessGrantWire) { g.OperandHash = "op" }), mk(14, exempt, nil)},
			Query{RuleID: "S-721", Lane: LaneTool, OperandHash: "op", ProjectRootHash: "p1", Decision: DecisionDeny, RuleLocked: true},
			9, 0,
		},
		{
			"another project: no hit, the grant is named",
			[]Cached{mk(14, exempt, nil)},
			Query{RuleID: "S-721", Lane: LaneTool, ProjectRootHash: "p2", Decision: DecisionAsk, RuleLocked: true},
			0, 14,
		},
		{
			"another command: no hit, the lowest id is named",
			[]Cached{mk(8, exempt, func(g *orgcontract.AccessGrantWire) { g.OperandHash = "op" }), mk(7, exempt, func(g *orgcontract.AccessGrantWire) { g.OperandHash = "op0" })},
			Query{RuleID: "S-721", Lane: LaneTool, OperandHash: "op2", ProjectRootHash: "p1", Decision: DecisionAsk},
			0, 7,
		},
		{
			"an expired grant for another scope is not named",
			[]Cached{mk(14, exempt, func(g *orgcontract.AccessGrantWire) { g.ExpiresAtNs = ns(-time.Minute) })},
			Query{RuleID: "S-721", Lane: LaneTool, ProjectRootHash: "p2", Decision: DecisionAsk},
			0, 0,
		},
		{
			"a soften grant for another scope is not named on an ask it could not change",
			[]Cached{mk(9, soften, nil)},
			Query{RuleID: "S-721", Lane: LaneTool, ProjectRootHash: "p2", Decision: DecisionAsk},
			0, 0,
		},
		{
			"a grant without the lock override for another scope is not named on a locked rule",
			[]Cached{mk(14, exempt, func(g *orgcontract.AccessGrantWire) { g.LockOverride = false })},
			Query{RuleID: "S-721", Lane: LaneTool, ProjectRootHash: "p2", Decision: DecisionAsk, RuleLocked: true},
			0, 0,
		},
		{
			"a hit names no scope miss",
			[]Cached{mk(14, exempt, nil), mk(8, exempt, func(g *orgcontract.AccessGrantWire) { g.OperandHash = "op" })},
			Query{RuleID: "S-721", Lane: LaneTool, OperandHash: "other", ProjectRootHash: "p1", Decision: DecisionAsk},
			14, 0,
		},
	}
	for _, c := range cases {
		res := MatchDetail(c.q, c.grants, rc, t0)
		if (c.want == 0) == res.OK || (res.OK && res.Hit.GrantID != c.want) {
			t.Errorf("%s: hit = %+v ok=%v, want G-%d", c.name, res.Hit, res.OK, c.want)
		}
		if res.ScopeMissID != c.scopeMiss {
			t.Errorf("%s: scope miss = G-%d, want G-%d", c.name, res.ScopeMissID, c.scopeMiss)
		}
	}
}
