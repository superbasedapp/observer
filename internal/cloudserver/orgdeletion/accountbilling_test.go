package orgdeletion

import (
	"slices"
	"testing"
)

// TestBillingRules has at least one case per billingRules row (ORGDEL-7),
// and each case names the row that must decide it.
func TestBillingRules(t *testing.T) {
	t.Parallel()
	live := func(mod func(*AccountSubscription)) AccountSubscription {
		s := AccountSubscription{Subscription: Subscription{ID: "sub_1", Status: "active"}, OrgID: "org", OrgSeen: true, OrgStatus: "active"}
		mod(&s)
		return s
	}
	cases := []struct {
		name string
		s    AccountSubscription
		row  int // 1-based billingRules row that decides
		want BillingFate
	}{
		// Row 1: Paddle bills nothing more.
		{"canceled", live(func(s *AccountSubscription) { s.Status = "canceled" }), 1, BillingNothing},
		{"no status", live(func(s *AccountSubscription) { s.Status = "" }), 1, BillingNothing},
		{"no subscription id", live(func(s *AccountSubscription) { s.ID = "" }), 1, BillingNothing},
		{"refunded with no subscription id", live(func(s *AccountSubscription) { s.ID, s.Status = "", "refunded" }), 1, BillingNothing},
		{"canceled account plan", live(func(s *AccountSubscription) { s.Status, s.OrgID, s.OrgSeen = "canceled", "", false }), 1, BillingNothing},
		// Row 2: refunded or charged back: the plan is revoked but Paddle
		// still renews the subscription (FR-7), whatever it paid for.
		{"refunded account plan", live(func(s *AccountSubscription) { s.Status, s.OrgID, s.OrgSeen, s.OrgStatus = "refunded", "", false, "" }), 2, BillingCancel},
		{"charged back account plan", live(func(s *AccountSubscription) {
			s.Status, s.OrgID, s.OrgSeen, s.OrgStatus = "charged_back", "", false, ""
		}), 2, BillingCancel},
		{"refunded personal org", live(func(s *AccountSubscription) { s.Status, s.PersonalOrg = "refunded", true }), 2, BillingCancel},
		{"refunded live team org", live(func(s *AccountSubscription) { s.Status = "refunded" }), 2, BillingCancel},
		{"charged back live team org", live(func(s *AccountSubscription) { s.Status = "charged_back" }), 2, BillingCancel},
		{"refunded invisible org", live(func(s *AccountSubscription) { s.Status, s.OrgSeen, s.OrgStatus = "refunded", false, "" }), 2, BillingCancel},
		{"refunded team org pending deletion", live(func(s *AccountSubscription) { s.Status, s.OrgStatus = "refunded", StatusPendingDeletion }), 2, BillingCancel},
		// Row 3: an account-scope (personal) subscription.
		{"account plan active", live(func(s *AccountSubscription) { s.OrgID, s.OrgSeen, s.OrgStatus = "", false, "" }), 3, BillingCancel},
		{"account plan trialing", live(func(s *AccountSubscription) { s.Status, s.OrgID, s.OrgSeen = "trialing", "", false }), 3, BillingCancel},
		{"account plan past due", live(func(s *AccountSubscription) { s.Status, s.OrgID, s.OrgSeen = "past_due", "", false }), 3, BillingCancel},
		{"account plan paused", live(func(s *AccountSubscription) { s.Status, s.OrgID, s.OrgSeen = "paused", "", false }), 3, BillingCancel},
		// Row 4: the personal org's subscription (Personal Pro re-keyed).
		{"personal org active", live(func(s *AccountSubscription) { s.PersonalOrg = true }), 4, BillingCancel},
		// Row 5: an org the account cannot see.
		{"invisible org", live(func(s *AccountSubscription) { s.OrgSeen, s.OrgStatus = false, "" }), 5, BillingRefuse},
		// Row 6: a live team org.
		{"team org active", live(func(*AccountSubscription) {}), 6, BillingRefuse},
		{"team org provisioning", live(func(s *AccountSubscription) { s.OrgStatus = "provisioning" }), 6, BillingRefuse},
		{"team org suspended", live(func(s *AccountSubscription) { s.OrgStatus = "suspended" }), 6, BillingRefuse},
		// Row 7: a team org on its way out.
		{"team org pending deletion", live(func(s *AccountSubscription) { s.OrgStatus = StatusPendingDeletion }), 7, BillingCancel},
		{"team org purging", live(func(s *AccountSubscription) { s.OrgStatus = StatusPurging }), 7, BillingCancel},
		{"team org purged", live(func(s *AccountSubscription) { s.OrgStatus = StatusPurged }), 7, BillingCancel},
	}
	rows := billingRules()
	reached := map[int]bool{}
	for _, tc := range cases {
		if got := DecideBilling(tc.s); got != tc.want {
			t.Errorf("%s: DecideBilling = %s, want %s", tc.name, got, tc.want)
		}
		if got := decidingBillingRow(tc.s) + 1; got != tc.row {
			t.Errorf("%s: decided by row %d, want row %d", tc.name, got, tc.row)
		}
		if tc.row >= 1 && tc.row <= len(rows) && rows[tc.row-1].fate != tc.want {
			t.Errorf("%s: row %d's fate is %s, the case wants %s", tc.name, tc.row, rows[tc.row-1].fate, tc.want)
		}
		reached[tc.row] = true
	}
	for i := range rows {
		if !reached[i+1] {
			t.Errorf("no case for row %d (%s)", i+1, rows[i].name)
		}
	}
}

// TestPlanAccountBilling sorts an account's subscriptions by fate, keeping
// input order: personal subscriptions to cancel, a live team's to refuse, and
// nothing for an account without a live subscription.
func TestPlanAccountBilling(t *testing.T) {
	t.Parallel()
	sub := func(id, status, org string, seen, personal bool, orgStatus string) AccountSubscription {
		return AccountSubscription{Subscription: Subscription{ID: id, Status: status}, OrgID: org, OrgSeen: seen, PersonalOrg: personal, OrgStatus: orgStatus}
	}
	ids := func(ss []AccountSubscription) []string {
		var out []string
		for _, s := range ss {
			out = append(out, s.ID)
		}
		return out
	}
	cases := []struct {
		name               string
		subs               []AccountSubscription
		cancel, refuse     []string
		wantNothingToCheck bool
	}{
		{name: "none", wantNothingToCheck: true},
		{name: "only canceled rows", subs: []AccountSubscription{
			sub("sub_a", "canceled", "", false, false, ""), sub("sub_b", "canceled", "t", true, false, "active"),
		}, wantNothingToCheck: true},
		{name: "refunded and charged-back rows still renew at Paddle: canceled, never refused", subs: []AccountSubscription{
			sub("sub_ref", "refunded", "", false, false, ""), sub("sub_cb", "charged_back", "t", true, false, "active"),
		}, cancel: []string{"sub_ref", "sub_cb"}},
		{name: "personal subscriptions", subs: []AccountSubscription{
			sub("sub_acct", "active", "", false, false, ""), sub("sub_pers", "active", "p", true, true, "active"),
		}, cancel: []string{"sub_acct", "sub_pers"}},
		{name: "org subscription", subs: []AccountSubscription{
			sub("sub_team", "active", "t", true, false, "active"),
		}, refuse: []string{"sub_team"}},
		{name: "mixed", subs: []AccountSubscription{
			sub("sub_acct", "trialing", "", false, false, ""),
			sub("sub_team", "past_due", "t", true, false, "active"),
			sub("sub_gone", "active", "g", true, false, StatusPendingDeletion),
			sub("sub_old", "canceled", "", false, false, ""),
			sub("sub_refunded", "refunded", "", false, false, ""),
		}, cancel: []string{"sub_acct", "sub_gone", "sub_refunded"}, refuse: []string{"sub_team"}},
	}
	for _, tc := range cases {
		got := PlanAccountBilling(tc.subs)
		if !slices.Equal(ids(got.Cancel), tc.cancel) || !slices.Equal(ids(got.Refuse), tc.refuse) {
			t.Errorf("%s: cancel %v refuse %v, want cancel %v refuse %v", tc.name, ids(got.Cancel), ids(got.Refuse), tc.cancel, tc.refuse)
		}
		if tc.wantNothingToCheck && (len(got.Cancel) != 0 || len(got.Refuse) != 0) {
			t.Errorf("%s: %+v, want nothing", tc.name, got)
		}
	}
}

// TestAccountCancelKey is one stable key per account and subscription.
func TestAccountCancelKey(t *testing.T) {
	t.Parallel()
	if got := AccountCancelKey("a1", "sub_1"); got != "acctdel:a1:sub_1" {
		t.Fatalf("key = %q", got)
	}
	if AccountCancelKey("a1", "sub_1") == AccountCancelKey("a1", "sub_2") || AccountCancelKey("a1", "sub_1") == AccountCancelKey("a2", "sub_1") {
		t.Fatal("keys collide")
	}
}
