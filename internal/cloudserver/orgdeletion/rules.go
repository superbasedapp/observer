package orgdeletion

import (
	"time"
)

// The org kinds and console roles, as the control-plane registry spells them
// (store.OrgKind / store.ConsoleRole; pinned by a store test).
const (
	KindPersonal = "personal"
	KindTeam     = "team"
	RoleOwner    = "owner"
)

// The org statuses the rules read (platformcontract.KnownTenantStates).
const (
	StatusPendingDeletion = "pending_deletion"
	StatusPurging         = "purging"
	StatusPurged          = "purged"
)

// Membership is what the account precheck knows about one org the account
// belongs to.
type Membership struct {
	OrgID       string
	Slug        string
	DisplayName string
	// Kind is personal or team.
	Kind string
	// Status is the org's lifecycle status.
	Status string
	// Role is the account's console role in the org.
	Role string
	// BillingOwner reports that the account is the org's billing owner.
	BillingOwner bool
	// Owners is how many members of the org hold the owner role, the
	// account included.
	Owners int
	// Members is how many members the org has, the account included.
	Members int
}

// BlockerCode names why a membership blocks an account deletion. The values
// are the console's codes (the precheck route and the 409 body).
type BlockerCode string

// The blocker codes.
const (
	// BlockerPaysForLiveOrg: the account pays for a live org's subscription
	// (the store's own billing check, C2.front-door-5 A).
	BlockerPaysForLiveOrg BlockerCode = "pays_for_live_org"
	// BlockerBillingOwner: the account is the billing owner of a team org
	// that is not being deleted.
	BlockerBillingOwner BlockerCode = "billing_owner"
	// BlockerSoleOwnerWithMembers: the account is the only owner of a team
	// org with other members; another member must become owner first.
	BlockerSoleOwnerWithMembers BlockerCode = "sole_owner_with_members"
	// BlockerSoleOwnerAlone: the account is the only member of a team org;
	// the team must be deleted first.
	BlockerSoleOwnerAlone BlockerCode = "sole_owner_alone"
)

// Fate is what an account deletion does with one membership.
type Fate string

// The fates.
const (
	// FateDeletePersonal: the personal org is deleted with the account.
	FateDeletePersonal Fate = "delete_personal_org"
	// FateRemove: the membership is removed; the org and its data stay
	// (the org is the controller of what the member contributed).
	FateRemove Fate = "remove_membership"
	// FateBlock: the deletion is refused until the blocker is cleared.
	FateBlock Fate = "block"
)

// precheckRule is one row of the account precheck.
type precheckRule struct {
	name    string
	match   func(m Membership) bool
	fate    Fate
	blocker BlockerCode
}

// beingDeleted reports a team org already on its way out: its memberships go
// with it, so it blocks nothing.
func beingDeleted(m Membership) bool {
	return m.Status == StatusPendingDeletion || m.Status == StatusPurging || m.Status == StatusPurged
}

// precheckRules is the account precheck, walked top-down per membership; the
// first match decides. One test case per row. A function, so no caller can
// change the policy.
func precheckRules() []precheckRule {
	return []precheckRule{
		{
			name: "the personal org is deleted with the account", fate: FateDeletePersonal,
			match: func(m Membership) bool { return m.Kind == KindPersonal },
		},
		{
			name: "a team org already being deleted only loses the membership", fate: FateRemove,
			match: beingDeleted,
		},
		{
			name: "the billing owner of a live team org must transfer billing or delete the team", fate: FateBlock, blocker: BlockerBillingOwner,
			match: func(m Membership) bool { return m.BillingOwner },
		},
		{
			name: "the only owner of a team org with other members must name another owner", fate: FateBlock, blocker: BlockerSoleOwnerWithMembers,
			match: func(m Membership) bool { return m.Role == RoleOwner && m.Owners <= 1 && m.Members > 1 },
		},
		{
			name: "the only member and owner of a team org must delete the team first", fate: FateBlock, blocker: BlockerSoleOwnerAlone,
			match: func(m Membership) bool { return m.Role == RoleOwner && m.Owners <= 1 },
		},
		{
			name: "any other membership is removed", fate: FateRemove,
			match: func(Membership) bool { return true },
		},
	}
}

// Blocker is one membership that blocks an account deletion.
type Blocker struct {
	Code        BlockerCode
	OrgID       string
	Slug        string
	DisplayName string
}

// AccountPlan is what an account deletion would do with the account's orgs.
type AccountPlan struct {
	// Blockers, when any, refuse the deletion.
	Blockers []Blocker
	// PersonalOrg is the account's personal org, nil when it has none.
	PersonalOrg *Membership
	// Removed are the team memberships the deletion removes.
	Removed []Membership
}

// CanDelete reports that nothing blocks the deletion.
func (p AccountPlan) CanDelete() bool { return len(p.Blockers) == 0 }

// Decide returns the deciding precheck row's fate and blocker for m.
func Decide(m Membership) (Fate, BlockerCode) {
	rules := precheckRules()
	for _, r := range rules {
		if r.match(m) {
			return r.fate, r.blocker
		}
	}
	last := rules[len(rules)-1]
	return last.fate, last.blocker
}

// Precheck plans an account deletion over the account's memberships. It is
// pure.
func Precheck(memberships []Membership) AccountPlan {
	var plan AccountPlan
	for _, m := range memberships {
		fate, code := Decide(m)
		switch fate {
		case FateDeletePersonal:
			p := m
			plan.PersonalOrg = &p
		case FateBlock:
			plan.Blockers = append(plan.Blockers, Blocker{Code: code, OrgID: m.OrgID, Slug: m.Slug, DisplayName: m.DisplayName})
		default:
			plan.Removed = append(plan.Removed, m)
		}
	}
	return plan
}

// Origin says who asked for an org deletion (the org_deletion_requests.origin
// vocabulary).
type Origin string

// The origins.
const (
	OriginOwner           Origin = "owner"
	OriginAccountDeletion Origin = "account_deletion"
	OriginStaff           Origin = "staff"
)

// The cooling-off windows (plan 06 5.3.10 "Pending deletion").
const (
	// DefaultCoolingOff is an org's window before its purge starts.
	DefaultCoolingOff = 30 * 24 * time.Hour
	// InactiveFreeCoolingOff is the window of a free org with no recent
	// activity.
	InactiveFreeCoolingOff = 14 * 24 * time.Hour
	// InactiveWindow is how long an org must have reported no seat in use to
	// count as inactive.
	InactiveWindow = 30 * 24 * time.Hour
)

// CoolingFacts is what the window depends on.
type CoolingFacts struct {
	Origin Origin
	// LiveSubscription reports a live paid subscription on the org.
	LiveSubscription bool
	// LastSeatDay is the newest usage day that reported a seat in use (zero
	// when none ever did).
	LastSeatDay time.Time
	// Now is the request time.
	Now time.Time
}

// coolingRule is one row of the window table.
type coolingRule struct {
	name   string
	match  func(f CoolingFacts) bool
	window time.Duration
}

// coolingRules is the window table, walked top-down; the last row always
// matches. One test case per row.
func coolingRules() []coolingRule {
	return []coolingRule{
		{
			name:   "a personal org deleted with its account: no window (the account deletion runs to completion now)",
			match:  func(f CoolingFacts) bool { return f.Origin == OriginAccountDeletion },
			window: 0,
		},
		{
			name: "a free org with no seat in use for the inactive window: 14 days",
			match: func(f CoolingFacts) bool {
				return !f.LiveSubscription && (f.LastSeatDay.IsZero() || f.Now.Sub(f.LastSeatDay) >= InactiveWindow)
			},
			window: InactiveFreeCoolingOff,
		},
		{name: "any other org: 30 days", match: func(CoolingFacts) bool { return true }, window: DefaultCoolingOff},
	}
}

// CoolingOff returns the window for f.
func CoolingOff(f CoolingFacts) time.Duration {
	rules := coolingRules()
	for _, r := range rules {
		if r.match(f) {
			return r.window
		}
	}
	return rules[len(rules)-1].window
}

// Backoff is the retry delay after the n-th consecutive failure of a step
// (n >= 1): one minute doubling to a one-hour cap.
func Backoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	d := time.Minute
	for i := 1; i < n && d < time.Hour; i++ {
		d *= 2
	}
	if d > time.Hour {
		d = time.Hour
	}
	return d
}

// HostPurgeGrace is how long an org request waits at await_host for the
// host's ack of purged before it blocks as host_purge_overdue (FR-23): a host
// that never answers no longer leaves the request polling for ever. Staff
// resume it (another grace period) once the host's purge is unstuck.
const HostPurgeGrace = 7 * 24 * time.Hour

// DeactivateGrace is how long an account follow-up waits for every
// members_deactivate intent to be acked before it blocks as
// deactivation_overdue (design 4.10 step 3).
const DeactivateGrace = 30 * 24 * time.Hour
