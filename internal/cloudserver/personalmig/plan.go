package personalmig

import (
	"fmt"
	"strings"
)

// Plan names the migration reads and writes (internal/entitlements catalog).
const (
	// AccountFloorPlan is the account kind's floor: an account on it has no
	// paid plan to carry.
	AccountFloorPlan = "free"
	// AccountPaidPlan is the account plan a re-keyed subscription carries
	// today (D-IND-6).
	AccountPaidPlan = "plus_beta"
	// OrgPlanName and OrgPlanVersion are the personal org plan a re-keyed
	// subscription is rewritten to (D-IND-6). Version 2 since L-166
	// (2026-11-24): the AI Apps allowance. A row re-keyed earlier names v1,
	// which the catalog carries forward to v2 (entitlements.Current), so
	// both are issued the same document.
	OrgPlanName    = "personal_pro"
	OrgPlanVersion = 2
	// PaddlePlanSource is the account_plans source the Paddle account path
	// writes; re-keying closes the account's row of this source.
	PaddlePlanSource = "paddle"
	// PersonalOrgDisplayName is the display name a personal org is created
	// with.
	PersonalOrgDisplayName = "Personal"
)

// Account statuses (cloud accounts.status).
const (
	AccountActive    = "active"
	AccountSuspended = "suspended"
	AccountClosed    = "closed"
	AccountDeleted   = "deleted"
)

// Subscription is one paddle_subscriptions row of the account.
type Subscription struct {
	ID          string
	PlanName    string
	PlanVersion int
	Status      string
	// OrgID is empty for an account-scoped subscription.
	OrgID string
}

// Live mirrors the 0090 trigger's "live" predicate: every status but
// canceled, refunded and charged_back.
func (s Subscription) Live() bool {
	switch s.Status {
	case "", "canceled", "refunded", "charged_back":
		return false
	}
	return true
}

// PersonalOrg is the account's personal org, when it has one.
type PersonalOrg struct {
	OrgID  string
	Slug   string
	Status string
}

// orgUsableStatuses are the org lifecycle states a migration may target:
// being created, in service, or suspended (the store's billable states).
var orgUsableStatuses = map[string]bool{"provisioning": true, "active": true, "suspended": true}

// Footprint is everything the plan needs to know about one account, read by
// the store under the account's own context.
type Footprint struct {
	AccountID     string
	AccountStatus string
	// Results is the number of analysis_results rows of the account.
	Results int
	// Devices is the number of device registrations (revoked included).
	Devices int
	// AccountSubscriptions are the account-scoped (org_id NULL) Paddle
	// subscriptions, live or not.
	AccountSubscriptions []Subscription
	// RekeyedSubscriptions are subscriptions already bound to the personal
	// org (a previous run re-keyed them).
	RekeyedSubscriptions []Subscription
	// PlanName and PlanSource are the account plan in force; PlanSource is
	// empty when no account_plans row is in force (the default free plan).
	PlanName   string
	PlanSource string
	// OwnerSubject is the account's WorkOS subject (identity_links), empty
	// when it has none.
	OwnerSubject string
	// Org is the account's personal org, nil when it has none yet.
	Org *PersonalOrg
}

// liveAccountSubscriptions returns f's live account-scoped subscriptions.
func (f Footprint) liveAccountSubscriptions() []Subscription {
	var out []Subscription
	for _, s := range f.AccountSubscriptions {
		if s.Live() {
			out = append(out, s)
		}
	}
	return out
}

// Need is one thing an account needs done.
type Need string

// The needs, in the order they are done.
const (
	NeedEnsureOrg Need = "ensure_org"
	NeedRekey     Need = "rekey_subscription"
	NeedExport    Need = "export_results"
)

// Decision is the plan for one account.
type Decision struct {
	// InScope is true when the account has any personal-plane footprint.
	InScope bool
	// ScopeReason is the first scope rule that matched.
	ScopeReason string
	// Skip is the reason an in-scope account is skipped, "" to proceed.
	Skip string
	// Needs are what the account needs, in order. Empty with InScope and no
	// Skip means it needs nothing but its ledger row.
	Needs []Need
	// Rekey is the live subscription to re-key when Needs holds NeedRekey.
	Rekey *Subscription
	// Drift is why a verified account is not done: what it holds now that
	// the ledger does not account for (see DriftReasons). Empty for any
	// account that is not verified or has not drifted.
	Drift []string
	// Notes are operator hints that change nothing (a manual plan grant the
	// migration does not carry).
	Notes []string
}

// Has reports whether d needs n.
func (d Decision) Has(n Need) bool {
	for _, x := range d.Needs {
		if x == n {
			return true
		}
	}
	return false
}

// scopeRule is one row of the scope table: the account is in scope when
// match is true.
type scopeRule struct {
	id    string
	match func(Footprint) bool
}

// scopeRules is walked top-down; the first row that matches names the reason.
var scopeRules = []scopeRule{
	{id: "analysis_results", match: func(f Footprint) bool { return f.Results > 0 }},
	{id: "account_subscription", match: func(f Footprint) bool { return len(f.AccountSubscriptions) > 0 }},
	{id: "rekeyed_subscription", match: func(f Footprint) bool { return len(f.RekeyedSubscriptions) > 0 }},
	{id: "device_registration", match: func(f Footprint) bool { return f.Devices > 0 }},
	{id: "plan_above_floor", match: func(f Footprint) bool {
		return f.PlanName != "" && f.PlanName != AccountFloorPlan
	}},
}

// skipRule is one row of the skip table: the account is skipped with the
// reason when skip returns a non-empty string.
type skipRule struct {
	id   string
	skip func(Footprint) string
}

// skipRules is walked top-down; the first row that refuses decides.
var skipRules = []skipRule{
	{id: "account_gone", skip: func(f Footprint) string {
		if f.AccountStatus == AccountDeleted || f.AccountStatus == AccountClosed {
			return "account is " + f.AccountStatus
		}
		return ""
	}},
	{id: "account_not_active", skip: func(f Footprint) string {
		if f.AccountStatus != AccountActive {
			return fmt.Sprintf("account is %q, not active", f.AccountStatus)
		}
		return ""
	}},
	{id: "no_subject", skip: func(f Footprint) string {
		if strings.TrimSpace(f.OwnerSubject) == "" {
			return "account has no WorkOS subject (identity_links)"
		}
		return ""
	}},
	{id: "org_unusable", skip: func(f Footprint) string {
		if f.Org != nil && !orgUsableStatuses[f.Org.Status] {
			return "personal org " + f.Org.OrgID + " is " + f.Org.Status
		}
		return ""
	}},
	{id: "several_live", skip: func(f Footprint) string {
		if n := len(f.liveAccountSubscriptions()); n > 1 {
			return fmt.Sprintf("%d live account subscriptions", n)
		}
		return ""
	}},
	{id: "live_not_plus", skip: func(f Footprint) string {
		for _, s := range f.liveAccountSubscriptions() {
			if s.PlanName != AccountPaidPlan {
				return fmt.Sprintf("live subscription %s is on %s, not %s", s.ID, s.PlanName, AccountPaidPlan)
			}
		}
		return ""
	}},
	{id: "org_already_paid", skip: func(f Footprint) string {
		live := f.liveAccountSubscriptions()
		if len(live) == 0 {
			return ""
		}
		for _, s := range f.RekeyedSubscriptions {
			if s.Live() && s.ID != live[0].ID {
				return "personal org already holds live subscription " + s.ID
			}
		}
		return ""
	}},
}

// needRule is one row of the need table: the account needs n when match is
// true.
type needRule struct {
	need  Need
	match func(Footprint) bool
}

// needRules is in execution order.
var needRules = []needRule{
	{need: NeedEnsureOrg, match: func(f Footprint) bool { return f.Org == nil }},
	{need: NeedRekey, match: func(f Footprint) bool { return len(f.liveAccountSubscriptions()) == 1 }},
	{need: NeedExport, match: func(f Footprint) bool { return f.Results > 0 }},
}

// noteRule is one row of the operator-hint table.
type noteRule struct {
	note func(Footprint) string
}

var noteRules = []noteRule{
	{note: func(f Footprint) string {
		if f.PlanName != "" && f.PlanName != AccountFloorPlan && f.PlanSource != PaddlePlanSource {
			return fmt.Sprintf("account plan %s comes from %q, not Paddle; the migration does not carry it (grant the org with `observer-cloud grant-plan org` if it should keep a plan)",
				f.PlanName, f.PlanSource)
		}
		return ""
	}},
}

// Decide plans one account from its footprint. An account that is out of
// scope gets a zero Decision with InScope false.
func Decide(f Footprint) Decision {
	var d Decision
	for _, r := range scopeRules {
		if r.match(f) {
			d.InScope, d.ScopeReason = true, r.id
			break
		}
	}
	if !d.InScope {
		return d
	}
	for _, r := range skipRules {
		if why := r.skip(f); why != "" {
			d.Skip = why
			return d
		}
	}
	for _, r := range needRules {
		if r.match(f) {
			d.Needs = append(d.Needs, r.need)
		}
	}
	if d.Has(NeedRekey) {
		s := f.liveAccountSubscriptions()[0]
		d.Rekey = &s
	}
	for _, r := range noteRules {
		if n := r.note(f); n != "" {
			d.Notes = append(d.Notes, n)
		}
	}
	return d
}

// Recorded is what the ledger row of a verified account says was carried.
type Recorded struct {
	// ResultsTotal is the number of analysis_results rows the last export
	// saw (exported and skipped alike).
	ResultsTotal int
}

// driftRule is one row of the drift table: the account drifted when why
// returns a non-empty reason.
type driftRule struct {
	id  string
	why func(Footprint, Recorded) string
}

// driftRules is walked top-down and every row that matches reports. The
// personal plane keeps serving after E3 (FR-13), so a verified account may
// grow results or a subscription the migration never moved.
var driftRules = []driftRule{
	{id: "new_subscription", why: func(f Footprint, _ Recorded) string {
		if live := f.liveAccountSubscriptions(); len(live) > 0 {
			return "live account subscription " + live[0].ID + " created after verification"
		}
		return ""
	}},
	{id: "new_results", why: func(f Footprint, r Recorded) string {
		if f.Results > r.ResultsTotal {
			return fmt.Sprintf("%d result(s) created after verification (%d recorded, %d now)", f.Results-r.ResultsTotal, r.ResultsTotal, f.Results)
		}
		return ""
	}},
}

// DriftReasons returns why a verified account with footprint f and ledger
// counts rec needs another pass; empty when nothing changed.
func DriftReasons(f Footprint, rec Recorded) []string {
	var out []string
	for _, r := range driftRules {
		if why := r.why(f, rec); why != "" {
			out = append(out, why)
		}
	}
	return out
}

// DecideVerified plans a verified account: Decide, plus Drift. A skip (the
// account closed since) leaves nothing to move, so it carries no drift.
func DecideVerified(f Footprint, rec Recorded) Decision {
	d := Decide(f)
	if d.InScope && d.Skip == "" {
		d.Drift = DriftReasons(f, rec)
	}
	return d
}

// Gate is the verdict of the retirement gate for one in-scope account.
type Gate string

// The gate verdicts.
const (
	// GateClear: nothing left to move.
	GateClear Gate = "clear"
	// GateDrift: verified, but it holds data created after verification.
	GateDrift Gate = "drift"
	// GateUnfinished: the account has steps or a receipt outstanding.
	GateUnfinished Gate = "unfinished"
	// GateSkipped: the migration chose not to carry the account.
	GateSkipped Gate = "skipped"
)

// RetirementGate classifies an in-scope account at stage with decision d for
// the plane-retirement drop (the 410 switch and the M9.6 table drops). Only
// GateClear lets the drop proceed; GateSkipped needs an explicit operator
// acknowledgement because the drop discards that account's data.
func RetirementGate(stage Stage, d Decision) Gate {
	switch {
	case len(d.Drift) > 0:
		return GateDrift
	case stage == StageVerified:
		return GateClear
	case stage == StageSkipped || d.Skip != "":
		return GateSkipped
	}
	return GateUnfinished
}
