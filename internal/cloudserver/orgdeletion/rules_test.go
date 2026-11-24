package orgdeletion

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// TestPrecheckRules has one case per precheckRules row.
func TestPrecheckRules(t *testing.T) {
	t.Parallel()
	team := func(mod func(*Membership)) Membership {
		m := Membership{OrgID: "o", Kind: KindTeam, Status: "active", Role: "member", Owners: 1, Members: 3}
		mod(&m)
		return m
	}
	cases := []struct {
		name  string
		m     Membership
		fate  Fate
		block BlockerCode
	}{
		{"personal org", Membership{Kind: KindPersonal, Role: RoleOwner, BillingOwner: true, Owners: 1, Members: 1}, FateDeletePersonal, ""},
		{"team org pending deletion, even as sole billing owner", team(func(m *Membership) {
			m.Status, m.Role, m.BillingOwner = StatusPendingDeletion, RoleOwner, true
		}), FateRemove, ""},
		{"team org purging", team(func(m *Membership) { m.Status, m.Role = StatusPurging, RoleOwner }), FateRemove, ""},
		{"billing owner of a live team", team(func(m *Membership) { m.BillingOwner = true }), FateBlock, BlockerBillingOwner},
		{"sole owner with other members", team(func(m *Membership) { m.Role = RoleOwner }), FateBlock, BlockerSoleOwnerWithMembers},
		{"sole owner alone", team(func(m *Membership) { m.Role, m.Members = RoleOwner, 1 }), FateBlock, BlockerSoleOwnerAlone},
		{"one of two owners", team(func(m *Membership) { m.Role, m.Owners = RoleOwner, 2 }), FateRemove, ""},
		{"plain member", team(func(*Membership) {}), FateRemove, ""},
		{"admin", team(func(m *Membership) { m.Role = "admin" }), FateRemove, ""},
	}
	rowsHit := map[Fate]bool{}
	for _, tc := range cases {
		fate, code := Decide(tc.m)
		if fate != tc.fate || code != tc.block {
			t.Errorf("%s: got (%s, %q), want (%s, %q)", tc.name, fate, code, tc.fate, tc.block)
		}
		rowsHit[fate] = true
	}
	if len(cases) < len(precheckRules()) {
		t.Errorf("%d cases for %d rows", len(cases), len(precheckRules()))
	}
}

// TestPrecheckPlan sorts memberships into the plan.
func TestPrecheckPlan(t *testing.T) {
	t.Parallel()
	plan := Precheck([]Membership{
		{OrgID: "p", Kind: KindPersonal, Role: RoleOwner, Owners: 1, Members: 1},
		{OrgID: "t1", Slug: "acme", Kind: KindTeam, Status: "active", Role: "member", Owners: 1, Members: 4},
		{OrgID: "t2", Slug: "solo", DisplayName: "Solo", Kind: KindTeam, Status: "active", Role: RoleOwner, Owners: 1, Members: 1},
	})
	if plan.CanDelete() {
		t.Fatal("a sole-owned team must block")
	}
	if plan.PersonalOrg == nil || plan.PersonalOrg.OrgID != "p" {
		t.Errorf("personal org = %+v", plan.PersonalOrg)
	}
	if len(plan.Removed) != 1 || plan.Removed[0].OrgID != "t1" {
		t.Errorf("removed = %+v", plan.Removed)
	}
	if len(plan.Blockers) != 1 || plan.Blockers[0] != (Blocker{Code: BlockerSoleOwnerAlone, OrgID: "t2", Slug: "solo", DisplayName: "Solo"}) {
		t.Errorf("blockers = %+v", plan.Blockers)
	}
	if !Precheck(nil).CanDelete() {
		t.Error("no membership blocks nothing")
	}
}

// TestCoolingOffRules has one case per coolingRules row (and the edges of the
// inactive window).
func TestCoolingOffRules(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		f    CoolingFacts
		want time.Duration
	}{
		{"account deletion: no window, even with a live subscription", CoolingFacts{Origin: OriginAccountDeletion, LiveSubscription: true, LastSeatDay: now, Now: now}, 0},
		{"free, never active", CoolingFacts{Origin: OriginOwner, Now: now}, InactiveFreeCoolingOff},
		{"free, last seat exactly the window ago", CoolingFacts{Origin: OriginOwner, LastSeatDay: now.Add(-InactiveWindow), Now: now}, InactiveFreeCoolingOff},
		{"free, active yesterday", CoolingFacts{Origin: OriginOwner, LastSeatDay: now.Add(-24 * time.Hour), Now: now}, DefaultCoolingOff},
		{"paid, never active", CoolingFacts{Origin: OriginOwner, LiveSubscription: true, Now: now}, DefaultCoolingOff},
		{"staff", CoolingFacts{Origin: OriginStaff, LiveSubscription: true, Now: now}, DefaultCoolingOff},
	}
	for _, tc := range cases {
		if got := CoolingOff(tc.f); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if DefaultCoolingOff != 30*24*time.Hour || InactiveFreeCoolingOff != 14*24*time.Hour {
		t.Error("plan 06 5.3.10 says 30 days, or 14 for an inactive free org")
	}
}

// TestBackoff doubles from a minute to an hour.
func TestBackoff(t *testing.T) {
	t.Parallel()
	want := map[int]time.Duration{0: time.Minute, 1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute, 7: 60 * time.Minute, 50: time.Hour}
	for n, d := range want {
		if got := Backoff(n); got != d {
			t.Errorf("Backoff(%d) = %v, want %v", n, got, d)
		}
	}
}

// TestStepTables pins both tables' order and that they validate.
func TestStepTables(t *testing.T) {
	t.Parallel()
	if err := validateTables(); err != nil {
		t.Fatal(err)
	}
	var org []Step
	for _, r := range OrgSteps() {
		org = append(org, r.Step)
	}
	if want := []Step{StepAnnounce, StepCoolingOff, StepCancelBilling, StepFence, StepAwaitHost, StepFinalize, StepRestore}; !slices.Equal(org, want) {
		t.Errorf("org steps = %v", org)
	}
	var acct []Step
	for _, r := range AccountSteps() {
		acct = append(acct, r.Step)
	}
	if want := []Step{StepPersonalOrg, StepMemberships, StepDeactivate, StepAwaitDeactivate, StepDeleteIdentity, StepFinish}; !slices.Equal(acct, want) {
		t.Errorf("account steps = %v", acct)
	}
	if got := remaining(OrgSteps(), StepFence); !slices.Equal(got, []Step{StepFence, StepAwaitHost, StepFinalize}) {
		t.Errorf("remaining from fence = %v", got)
	}
	if _, err := next(OrgSteps(), "nope"); err == nil {
		t.Error("an unknown step has a next")
	}
}

// TestClassOf keeps classes inside the column's vocabulary.
func TestClassOf(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{errors.New("boom"), "internal"},
		{Classed("billing:paddle_5xx", errors.New("x")), "billing:paddle_5xx"},
		{Classed("Has Spaces", errors.New("x")), "internal"},
		{Classed("fence", Classed("inner", errors.New("x"))), "fence"},
	}
	for _, tc := range cases {
		if got := ClassOf(tc.err); got != tc.want {
			t.Errorf("ClassOf(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// TestSubscriptionLive follows the 0090 live-slot rule.
func TestSubscriptionLive(t *testing.T) {
	t.Parallel()
	for status, live := range map[string]bool{"active": true, "trialing": true, "past_due": true, "paused": true, "canceled": false, "refunded": false, "charged_back": false, "": false} {
		if got := (Subscription{ID: "sub_1", Status: status}).Live(); got != live {
			t.Errorf("status %q live = %v", status, got)
		}
	}
	if (Subscription{Status: "active"}).Live() {
		t.Error("no subscription id is not live")
	}
}

// TestSubscriptionMayBill: every stored status but canceled may still be
// billed at Paddle. A refunded or charged-back subscription is not Live (it
// holds no live slot) but Paddle still renews it (FR-7), so a deletion must
// cancel it.
func TestSubscriptionMayBill(t *testing.T) {
	t.Parallel()
	for status, may := range map[string]bool{"active": true, "trialing": true, "past_due": true, "paused": true, "refunded": true, "charged_back": true, "canceled": false, "": false} {
		if got := (Subscription{ID: "sub_1", Status: status}).MayBill(); got != may {
			t.Errorf("status %q may bill = %v", status, got)
		}
	}
	for _, status := range []string{"active", "refunded"} {
		if (Subscription{Status: status}).MayBill() {
			t.Errorf("status %q with no subscription id may bill", status)
		}
	}
}
