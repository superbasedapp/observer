package secassess

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// TestRelaxationTable pins the closed table (plan section 13.2): only the two
// confined kinds have rows, every row's key is a rule id or the tier key, no row
// names a never-relaxed rule, and every row carries its words.
func TestRelaxationTable(t *testing.T) {
	t.Parallel()
	never := map[string]bool{}
	for _, n := range NeverRelaxed() {
		if n.Why == "" {
			t.Errorf("never-relaxed %s has no reason", n.ID)
		}
		never[n.ID] = true
	}
	for _, id := range []string{"R-177", "R-178", "R-174", "R-170", "R-172", "R-168", "R-165"} {
		if !never[id] {
			t.Errorf("%s is missing from the never-relaxed list", id)
		}
	}
	seen := map[string]bool{}
	for _, r := range Relaxations() {
		k, ok := KindByID(string(r.Kind))
		if !ok || !k.Launchable || k.Sandbox != SandboxRequired {
			t.Errorf("row %+v is for a kind that is not a confined launchable kind", r)
		}
		if r.Type == RelaxRule && never[r.Key] {
			t.Errorf("row %s/%s names a never-relaxed rule", r.Kind, r.Key)
		}
		if r.Type == RelaxTier && r.Key != TierKey {
			t.Errorf("tier row key %q", r.Key)
		}
		if r.Title == "" || r.Lifts == "" || r.Why == "" || !strings.Contains(r.PromptLine, "%s") {
			t.Errorf("row %s/%s is missing its words", r.Kind, r.Key)
		}
		if id := string(r.Kind) + "/" + r.Key; seen[id] {
			t.Errorf("duplicate row %s", id)
		} else {
			seen[id] = true
		}
	}
	for _, k := range Kinds() {
		has := len(RelaxationsFor(k.ID)) > 0
		if has != (k.ID == PentestLocal || k.ID == RedTeamLocal) {
			t.Errorf("kind %s has rows = %v", k.ID, has)
		}
	}
	if got := RelaxKinds(); !slices.Equal(got, []ID{PentestLocal, RedTeamLocal}) {
		t.Errorf("relax kinds %v", got)
	}
	if RelaxConfigKey(PentestLocal) != "relax_pentest_local" {
		t.Errorf("config key %q", RelaxConfigKey(PentestLocal))
	}
}

// TestRelaxPromptLines: the lines come from the table's words, a scope names
// itself, the tier row lists its hosts, and nothing is added without a row.
func TestRelaxPromptLines(t *testing.T) {
	t.Parallel()
	if got := RelaxPromptLines(PentestLocal, nil); got != nil {
		t.Fatalf("no relaxations must add nothing: %v", got)
	}
	got := RelaxPromptLines(PentestLocal, []InForce{
		{Key: RuleScanner, Scope: ScopeSession},
		{Key: TierKey, Hosts: []string{"registry.npmjs.org", "pypi.org"}},
		{Key: "R-999"},
	})
	if len(got) != 2 {
		t.Fatalf("lines %v", got)
	}
	if !strings.Contains(got[0], "R-179") || !strings.Contains(got[0], "this terminal's session only") || strings.Contains(got[0], "%s") {
		t.Errorf("rule line %q", got[0])
	}
	if !strings.Contains(got[1], "registry.npmjs.org, pypi.org") || strings.Contains(got[1], "%s") {
		t.Errorf("tier line %q", got[1])
	}
	if lines := RelaxPromptLines(PentestLocal, []InForce{{Key: RuleScanner, Scope: ScopeProject}}); !strings.Contains(lines[0], "every session in this project") {
		t.Errorf("project scope not named: %v", lines)
	}
	if got := RelaxPromptLines(ThreatModel, []InForce{{Key: RuleScanner}}); got != nil {
		t.Errorf("a kind with no row must add nothing: %v", got)
	}
}

// TestBuildPromptRelaxation: a prompt with no relaxation is byte-identical to
// the one built before the addendum, and a relaxation adds exactly one section
// after the boundaries without editing them.
func TestBuildPromptRelaxation(t *testing.T) {
	t.Parallel()
	target, err := ParseTarget("http://localhost:3000/")
	if err != nil {
		t.Fatal(err)
	}
	base := PromptInput{Kind: PentestLocal, RunID: "0123456789abcdef", ProjectName: "demo", Target: &target}
	plain, err := BuildPrompt(base)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, "RELAXED FOR THIS RUN") {
		t.Fatal("a prompt with no relaxation names one")
	}
	base.Relax = []InForce{{Key: RuleScanner, Scope: ScopeSession}}
	relaxed, err := BuildPrompt(base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(relaxed, "RELAXED FOR THIS RUN") || !strings.Contains(relaxed, "rule R-179") {
		t.Fatalf("relaxed prompt lacks its section:\n%s", relaxed)
	}
	// Removing the one section gives back the plain prompt.
	i := strings.Index(relaxed, "\nRELAXED FOR THIS RUN")
	j := strings.Index(relaxed, "\nSETUP (")
	if k := strings.Index(relaxed, "\nSTEPS:"); j < 0 || (k >= 0 && k < j) {
		j = k
	}
	if i < 0 || j < i || relaxed[:i]+relaxed[j:] != plain {
		t.Fatal("the relaxation section is not the only difference")
	}
}

// TestRelaxStep: one case per row of the reconcile table (plan section 13.5).
func TestRelaxStep(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	base := StepInput{State: RelaxActive, Route: RouteSelf, Now: t0.Add(2 * time.Minute), LaunchedAt: t0, MaxMinutes: 60, TerminalLive: true}
	with := func(f func(*StepInput)) StepInput { in := base; f(&in); return in }
	cases := []struct {
		name   string
		in     StepInput
		row    string
		next   RelaxState
		action StepAction
		reason string
	}{
		{"S1 ended stays", with(func(in *StepInput) { in.State = RelaxEnded }), "S1", RelaxEnded, ActionNone, ""},
		{"S1 not_bound stays even when the terminal is gone", with(func(in *StepInput) { in.State, in.TerminalLive = RelaxNotBound, false }), "S1", RelaxNotBound, ActionNone, ""},
		{"S1 existing is never deleted", with(func(in *StepInput) { in.State, in.TerminalLive = RelaxExisting, false }), "S1", RelaxExisting, ActionNone, ""},
		{"S1 lost stays", with(func(in *StepInput) { in.State = RelaxLost }), "S1", RelaxLost, ActionNone, ""},
		{"S2 terminal gone deletes the row", with(func(in *StepInput) { in.TerminalLive = false }), "S2", RelaxEnded, ActionDelete, EndTerminalExit},
		{"S2 terminal gone before binding has no row", with(func(in *StepInput) { in.State, in.TerminalLive = RelaxPendingBind, false }), "S2", RelaxEnded, ActionNone, EndTerminalExit},
		{"S2 terminal gone ends an org grant without a delete", with(func(in *StepInput) { in.State, in.Route, in.TerminalLive = RelaxOrgGrant, RouteOrgRequest, false }), "S2", RelaxEnded, ActionNone, EndTerminalExit},
		{"S3 hard cap deletes the row", with(func(in *StepInput) { in.Now = t0.Add(60 * time.Minute) }), "S3", RelaxEnded, ActionDelete, EndExpired},
		{"S3 hard cap on the tier row", with(func(in *StepInput) { in.State, in.Now = RelaxTierOn, t0.Add(61*time.Minute) }), "S3", RelaxEnded, ActionNone, EndExpired},
		{"S4 bound session creates the rows", with(func(in *StepInput) { in.State, in.SessionBound = RelaxPendingBind, true }), "S4", RelaxActive, ActionCreate, ""},
		{"S5 bind deadline passed", with(func(in *StepInput) { in.State, in.Now = RelaxPendingBind, t0.Add(5*time.Minute) }), "S5", RelaxNotBound, ActionNone, ""},
		{"S6 renew an active row", base, "S6", RelaxActive, ActionRenew, ""},
		{"S7 still waiting to bind", with(func(in *StepInput) { in.State = RelaxPendingBind }), "S7", RelaxPendingBind, ActionNone, ""},
		{"S7 the tier row is only watched", with(func(in *StepInput) { in.State = RelaxTierOn }), "S7", RelaxTierOn, ActionNone, ""},
		{"S7 an org grant is only watched", with(func(in *StepInput) { in.State, in.Route = RelaxOrgGrant, RouteOrgRequest }), "S7", RelaxOrgGrant, ActionNone, ""},
	}
	rows := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RelaxStep(tc.in)
			if got.Row != tc.row || got.Next != tc.next || got.Action != tc.action || got.EndReason != tc.reason {
				t.Fatalf("got %+v", got)
			}
		})
		rows[tc.row] = true
	}
	for _, id := range StepRowIDs() {
		if !rows[id] {
			t.Errorf("row %s has no case", id)
		}
	}
}

// TestRenewExpiry: the renewed expiry is ShortTTL ahead and never past the
// hard cap.
func TestRenewExpiry(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	if got := RenewExpiry(t0.Add(time.Minute), t0, 60); !got.Equal(t0.Add(11 * time.Minute)) {
		t.Errorf("renew %v", got)
	}
	if got := RenewExpiry(t0.Add(55*time.Minute), t0, 60); !got.Equal(t0.Add(60 * time.Minute)) {
		t.Errorf("capped renew %v", got)
	}
}

// TestEffectiveMinutesAndScope: the managed caps (plan section 13.3).
func TestEffectiveMinutesAndScope(t *testing.T) {
	t.Parallel()
	cases := []struct {
		t       Tenancy
		minutes int
		want    int
	}{
		{TenancyIndividual, 240, 240},
		{TenancyIndividual, 1, MinMinutes},
		{TenancyIndividual, 1000, MaxMinutes},
		{TenancyManaged, 240, 60},
		{TenancyManaged, 15, 15},
		{TenancyUnresolved, 120, 60},
	}
	for _, c := range cases {
		if got := EffectiveMinutes(c.t, c.minutes); got != c.want {
			t.Errorf("EffectiveMinutes(%s, %d) = %d, want %d", c.t, c.minutes, got, c.want)
		}
	}
	scopes := []struct {
		t    Tenancy
		own  string
		want string
	}{
		{TenancyIndividual, "project", ScopeProject},
		{TenancyIndividual, "session", ScopeSession},
		{TenancyIndividual, "", ScopeSession},
		{TenancyManaged, "project", ScopeSession},
		{TenancyUnresolved, "project", ScopeSession},
	}
	for _, c := range scopes {
		if got := EffectiveScope(c.t, c.own); got != c.want {
			t.Errorf("EffectiveScope(%s, %q) = %q, want %q", c.t, c.own, got, c.want)
		}
	}
}

// TestFindNarrower: a grant for the rule that does not cover the ask says why.
func TestFindNarrower(t *testing.T) {
	t.Parallel()
	const hash = "abc"
	now := int64(1_000_000_000_000)
	base := GrantFact{ID: 7, Type: "guard_exemption", Effect: "exempt", RuleID: "R-179", Honoured: true}
	cases := []struct {
		name  string
		g     GrantFact
		found bool
		why   string
	}{
		{"another project", func() GrantFact { g := base; g.ProjectRootHash = "zzz"; return g }(), true, "another project"},
		{"one command", func() GrantFact { g := base; g.OperandHash = "h"; return g }(), true, "one command"},
		{"use limited", func() GrantFact { g := base; g.MaxUses = 3; return g }(), true, "3 uses"},
		{"proxy lane", func() GrantFact { g := base; g.Lane = "proxy"; return g }(), true, "proxy lane"},
		{"soften", func() GrantFact { g := base; g.Effect = "soften"; return g }(), true, "softens"},
		{"ends soon", func() GrantFact { g := base; g.ExpiresAtNs = now + 1000; return g }(), true, "ends too soon"},
		{"not honoured", func() GrantFact { g := base; g.Honoured = false; return g }(), false, ""},
		{"another rule", func() GrantFact { g := base; g.RuleID = "R-130"; return g }(), false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, found := FindNarrower("R-179", hash, now, int64(15*time.Minute), []GrantFact{c.g})
			if found != c.found || (found && (n.ID != 7 || !strings.Contains(n.Why, c.why))) {
				t.Fatalf("got %+v %v", n, found)
			}
		})
	}
	if n, ok := FindNarrower("R-179", hash, now, 0, []GrantFact{{ID: 9, Type: "guard_exemption", Effect: "exempt", RuleID: "R-179", Honoured: true, MaxUses: 1}, {ID: 4, Type: "guard_exemption", Effect: "exempt", RuleID: "R-179", Honoured: true, MaxUses: 2}}); !ok || n.ID != 4 {
		t.Errorf("the lowest id wins: %+v", n)
	}
}
