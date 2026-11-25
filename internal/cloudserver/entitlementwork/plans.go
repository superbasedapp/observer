package entitlementwork

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// OrgPlanReader reads an org's Paddle subscription: the org-scoped row of the
// one subscription store (lead decision W14-D3; internal/cloudserver/store
// paddle.go, whose webhook handler is its one writer). store.ErrNotFound (or
// an error wrapping it) means the org has no subscription. The front-door
// lane builds the store function (store.OrgSubscription); the worker wires it
// at merge (cmd/observer-cloud hostapiworker.go orgPlanReaderFor).
type OrgPlanReader interface {
	OrgSubscription(ctx context.Context, orgID string) (store.PaddleSubscription, error)
}

// OrgGrantReader reads an org's operator plan grant (lead decision W15-D13,
// cloud 0095; *store.Store: OrgPlanGrant, written only by
// `observer-cloud grant-plan org`). It returns the org's newest grant row;
// store.ErrNotFound (or an error wrapping it) means the org has none.
type OrgGrantReader interface {
	OrgPlanGrant(ctx context.Context, orgID string) (store.OrgPlanGrant, error)
}

// OwnerPlanReader reads the account-scoped subscription of a personal org's
// owner (*store.Store: PersonalOrgOwnerSubscription, cloud 0155).
// store.ErrNotFound (or an error wrapping it) means none.
type OwnerPlanReader interface {
	PersonalOrgOwnerSubscription(ctx context.Context, orgID string) (store.PaddleSubscription, error)
}

// DefaultLaunchWindow is how long a new team org runs on its launch plan
// without a subscription: plan 06 5.8.6's "Team trial of 14 days with no
// card".
const DefaultLaunchWindow = 14 * 24 * time.Hour

// LaunchPlan is the plan a new org of Kind runs on for Window after its
// tenant was created on its host (W14-D1a): a kind whose floor is a lapsed
// state (team: every cap zero, QUOTA-1) would otherwise be read-only from its
// first quota pass. The document carries the window's end as its not_after,
// so a host falls back to the floor by itself when the window closes.
type LaunchPlan struct {
	Kind entitlements.Kind
	// Plan is the catalog plan name.
	Plan string
	// Version is the catalog version (0: the highest).
	Version int
	// Window is how long the launch lasts (0: DefaultLaunchWindow).
	Window time.Duration
}

// DefaultLaunchPlans is the launch table: a team org launches on the Team
// plan. A personal org needs none (its floor, Personal Free, is a working
// tier).
func DefaultLaunchPlans() []LaunchPlan {
	return []LaunchPlan{{Kind: entitlements.KindTeam, Plan: "team"}}
}

// DefaultPastDueGrace is how long a past_due subscription still counts as
// live after it entered past_due: the 14-day dunning window of operator
// ruling L-124 (lead decision W16-D5; SBCI_PADDLE_PAST_DUE_GRACE_DAYS).
const DefaultPastDueGrace = 14 * 24 * time.Hour

// liveRules say whether a subscription's plan is carried by the org's
// document, by its Paddle status, walked top-down, first match wins; one
// test case per row (plans_test.go). Paid and trialing in Paddle are live.
// past_due (dunning) is live for the grace window from when it entered
// past_due (store.PaddleSubscription.PastDueSince, set by cloud 0098's
// trigger), then not: the org falls to its grant, launch window or floor in
// planRules order, and nothing is deleted (W16-D5). A past_due row with no
// recorded entry is a row written before 0098 that 0099 has not backfilled;
// it stays live, as every past_due row did before W16-D5. paused, canceled,
// refunded and charged_back carry nothing.
var liveRules = []struct {
	name string
	live func(s store.PaddleSubscription, now time.Time, grace time.Duration) bool
}{
	{"paid", func(s store.PaddleSubscription, _ time.Time, _ time.Duration) bool { return s.Status == "active" }},
	{"trialing", func(s store.PaddleSubscription, _ time.Time, _ time.Duration) bool { return s.Status == "trialing" }},
	{"dunning", func(s store.PaddleSubscription, now time.Time, grace time.Duration) bool {
		return s.Status == "past_due" && (s.PastDueSince == nil || now.Before(pastDueEnd(*s.PastDueSince, grace)))
	}},
}

// pastDueEnd is when a past_due subscription stops counting as live.
func pastDueEnd(since time.Time, grace time.Duration) time.Time {
	return since.Add(grace).UTC()
}

// subscriptionLive walks liveRules.
func subscriptionLive(s store.PaddleSubscription, now time.Time, grace time.Duration) bool {
	for _, r := range liveRules {
		if r.live(s, now, grace) {
			return true
		}
	}
	return false
}

// SubscriptionPlans is the production PlanSource (ENTLWORK-6 reader side,
// W14-D3): the org's live subscription, else its operator plan grant while
// in force (W15-D13), else its launch plan while the launch window is open,
// else the floor of its kind (planRules).
type SubscriptionPlans struct {
	// Subs reads the org's subscription (nil: no org has one, so every org
	// is on its grant, launch plan or floor).
	Subs OrgPlanReader
	// Grants reads the org's operator plan grant. nil: Subs is used when it
	// also implements OrgGrantReader (the production store does, so the
	// worker's composition, cmd/observer-cloud hostapiworker.go, reads grants
	// with no edit there), else no org has a grant.
	Grants OrgGrantReader
	// Owners reads a personal org owner's account subscription (L-167). nil:
	// Subs is used when it also implements OwnerPlanReader (the production
	// store does), else no org is entitled through its owner's account.
	Owners OwnerPlanReader
	// Launch is the launch table (nil: DefaultLaunchPlans).
	Launch []LaunchPlan
	// PastDueGrace is how long a past_due subscription stays live after it
	// entered past_due (0: DefaultPastDueGrace; W16-D5).
	PastDueGrace time.Duration
	// Now is the clock (nil: time.Now).
	Now func() time.Time
}

// planFacts is one org read once, before the plan rules are walked.
type planFacts struct {
	org  store.OrgEntitlementView
	kind entitlements.Kind
	now  time.Time
	// sub is the org's subscription plan when it is live and a catalog plan
	// of the org's kind; subUntil is the end of its dunning grace when it is
	// past_due (nil otherwise).
	sub      *entitlements.Body
	subUntil *time.Time
	// paired is the personal plan the catalog pairs with the org owner's
	// live account subscription (L-167), with its dunning grace end.
	paired      *entitlements.Body
	pairedUntil *time.Time
	// grant is the org's operator grant when it is in force at now and a
	// catalog plan of the org's kind (with its end, if any).
	grant      *entitlements.Body
	grantUntil *time.Time
	launch     *LaunchPlan
}

// planRule is one row of planRules.
type planRule struct {
	name  string
	match func(f planFacts) bool
	plan  func(f planFacts) (Plan, error)
}

// planRules says which plan an org's document carries, walked top-down,
// first match wins; the last row matches everything. One test case per row
// (plans_test.go).
var planRules = []planRule{
	{
		name:  "subscription",
		match: func(f planFacts) bool { return f.sub != nil },
		plan: func(f planFacts) (Plan, error) {
			pl := Plan{Name: f.sub.Plan.Name, Version: f.sub.Plan.Version}
			if f.subUntil != nil {
				// W16-D5: a past_due plan carries its grace end, so a host
				// falls back by itself if the control plane goes silent.
				pl.NotAfter = f.subUntil.UTC().Truncate(time.Second).Unix()
			}
			return pl, nil
		},
	},
	{
		// L-167: Personal Pro is what the plus_beta subscription buys. A personal
		// org whose owner holds a live account subscription to a plan the
		// catalog pairs (entitlements.PairedPersonalPlan) is issued the
		// paired personal plan, before and after migrate-personal re-keys
		// the row onto the org (then the subscription row above decides).
		// Like the org's own subscription it is paid for, so it wins over a
		// grant; a past_due one carries its grace end.
		name:  "account_subscription",
		match: func(f planFacts) bool { return f.paired != nil },
		plan: func(f planFacts) (Plan, error) {
			pl := Plan{Name: f.paired.Plan.Name, Version: f.paired.Plan.Version}
			if f.pairedUntil != nil {
				pl.NotAfter = f.pairedUntil.UTC().Truncate(time.Second).Unix()
			}
			return pl, nil
		},
	},
	{
		// W15-D13: an operator grant keeps an org (an internal one, while
		// there is no live Paddle) on its plan after the launch window. A
		// live subscription still wins: it is what the org pays for. A
		// grant with an end carries it as the document's not_after, so a
		// host falls back by itself if the control plane goes silent.
		name:  "org_grant",
		match: func(f planFacts) bool { return f.grant != nil },
		plan: func(f planFacts) (Plan, error) {
			pl := Plan{Name: f.grant.Plan.Name, Version: f.grant.Plan.Version}
			if f.grantUntil != nil {
				pl.NotAfter = f.grantUntil.UTC().Truncate(time.Second).Unix()
			}
			return pl, nil
		},
	},
	{
		name:  "launch",
		match: func(f planFacts) bool { return f.launch != nil && launchOpen(f) },
		plan: func(f planFacts) (Plan, error) {
			b, ok := entitlements.Plan(f.launch.Plan, f.launch.Version)
			if !ok || b.Kind != f.kind {
				return Plan{}, fmt.Errorf("launch plan %s v%d is not a catalog plan of kind %s", f.launch.Plan, f.launch.Version, f.kind)
			}
			return Plan{Name: b.Plan.Name, Version: b.Plan.Version, NotAfter: launchEnd(f).Unix()}, nil
		},
	},
	{
		name:  "floor",
		match: func(planFacts) bool { return true },
		plan:  func(f planFacts) (Plan, error) { return floorPlan(f.kind) },
	},
}

// launchEnd is when the org's launch window closes.
func launchEnd(f planFacts) time.Time {
	w := f.launch.Window
	if w <= 0 {
		w = DefaultLaunchWindow
	}
	return f.org.CreatedOnHostAt.Add(w).UTC().Truncate(time.Second)
}

// launchOpen reports whether the org's tenant exists on its host (its create
// was acked) and its launch window has not closed. The window starts at the
// create's ack, not at the org's creation, so a create that waited (on the
// capacity waitlist, say) does not use up the launch.
func launchOpen(f planFacts) bool {
	return !f.org.CreatedOnHostAt.IsZero() && f.now.Before(launchEnd(f))
}

// PlanFor implements PlanSource. A subscription or grant read that fails
// (other than "none") is an error, so the issuer keeps the document in force
// rather than downgrading an org on a read outage.
func (p SubscriptionPlans) PlanFor(ctx context.Context, org store.OrgEntitlementView, kind entitlements.Kind) (Plan, error) {
	pl, _, err := p.Resolve(ctx, org, kind)
	return pl, err
}

// ownerReader is Owners, else Subs when it reads owner subscriptions too.
func (p SubscriptionPlans) ownerReader() OwnerPlanReader {
	if p.Owners != nil {
		return p.Owners
	}
	if o, ok := p.Subs.(OwnerPlanReader); ok {
		return o
	}
	return nil
}

// grantReader is Grants, else Subs when it reads grants too.
func (p SubscriptionPlans) grantReader() OrgGrantReader {
	if p.Grants != nil {
		return p.Grants
	}
	if g, ok := p.Subs.(OrgGrantReader); ok {
		return g
	}
	return nil
}

// Resolve is PlanFor plus the name of the plan rule that decided
// (PlanRuleNames), so a reader (the console's plan view) can say why the
// org is on its plan without re-deriving the rules.
func (p SubscriptionPlans) Resolve(ctx context.Context, org store.OrgEntitlementView, kind entitlements.Kind) (Plan, string, error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	f := planFacts{org: org, kind: kind, now: now()}
	if p.Subs != nil {
		sub, err := p.Subs.OrgSubscription(ctx, org.OrgID)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return Plan{}, "", fmt.Errorf("entitlementwork.SubscriptionPlans: subscription: %w", err)
		default:
			f.sub, f.subUntil = subscriptionPlan(sub, kind, f.now, p.PastDueGrace)
		}
	}
	if or := p.ownerReader(); or != nil && entitlements.AccountPlansPairInto(kind) {
		sub, err := or.PersonalOrgOwnerSubscription(ctx, org.OrgID)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return Plan{}, "", fmt.Errorf("entitlementwork.SubscriptionPlans: owner subscription: %w", err)
		default:
			f.paired, f.pairedUntil = pairedPlan(sub, kind, f.now, p.PastDueGrace)
		}
	}
	if gr := p.grantReader(); gr != nil {
		g, err := gr.OrgPlanGrant(ctx, org.OrgID)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return Plan{}, "", fmt.Errorf("entitlementwork.SubscriptionPlans: org grant: %w", err)
		default:
			f.grant, f.grantUntil = grantPlan(g, kind, f.now)
		}
	}
	launch := p.Launch
	if launch == nil {
		launch = DefaultLaunchPlans()
	}
	for i := range launch {
		if launch[i].Kind == kind {
			f.launch = &launch[i]
			break
		}
	}
	for _, r := range planRules {
		if r.match(f) {
			pl, err := r.plan(f)
			if err != nil {
				return Plan{}, "", fmt.Errorf("entitlementwork.SubscriptionPlans: %s: %w", r.name, err)
			}
			return pl, r.name, nil
		}
	}
	pl, err := floorPlan(kind) // unreachable: the last row matches everything
	return pl, "floor", err
}

// grantPlan returns the catalog plan an operator grant gives at now, with its
// end, when the grant is in force and names a catalog plan of the org's
// kind; nil otherwise. A version the catalog carries forward is issued as
// its successor (entitlements.Current; L-166: a Personal Pro v1 grant is
// issued Personal Pro v2). A grant of another kind (a personal plan on a team
// org) grants nothing: the org falls through to its launch plan or floor.
func grantPlan(g store.OrgPlanGrant, kind entitlements.Kind, now time.Time) (*entitlements.Body, *time.Time) {
	if !g.InForce(now) || g.PlanVersion == 0 {
		return nil, nil
	}
	b, ok := entitlements.Current(g.PlanName, g.PlanVersion)
	if !ok || b.Kind != kind {
		return nil, nil
	}
	return &b, g.EffectiveUntil
}

// subscriptionPlan returns the catalog plan a subscription grants when the
// subscription is live at now (liveRules) and its plan is a catalog plan of
// the org's kind; nil otherwise. The row's version is resolved through
// entitlements.Current, so a version the catalog carries forward (L-166:
// Personal Pro v1, the version migrate-personal re-keyed subscriptions to)
// is issued as its successor with no write to the row; a version that moves
// only by its price (Business v1) stays as it is. A plan of another kind (a personal price
// mapped onto a team org, a misconfigured price map) grants nothing: the org
// falls through to its launch plan or floor, never to a plan it did not buy.
//
// W16-D5: a past_due subscription is live only until its grace ends
// (PastDueSince + grace, PastDueSince set by cloud 0098's trigger); the
// second result is that end while it is still live, which the document
// carries as its not_after. A past_due row with no PastDueSince (written
// before 0098 and not yet backfilled by 0099) keeps the pre-W16-D5 rule:
// live, with no end, until Paddle's own dunning cancels it. A grace of zero
// or less is DefaultPastDueGrace.
func subscriptionPlan(s store.PaddleSubscription, kind entitlements.Kind, now time.Time, grace time.Duration) (*entitlements.Body, *time.Time) {
	if grace <= 0 {
		grace = DefaultPastDueGrace
	}
	if !subscriptionLive(s, now, grace) || s.PlanName == "" {
		return nil, nil
	}
	b, ok := entitlements.Current(s.PlanName, s.PlanVersion)
	if !ok || s.PlanVersion == 0 || b.Kind != kind {
		return nil, nil
	}
	if s.Status != "past_due" || s.PastDueSince == nil {
		return &b, nil
	}
	until := pastDueEnd(*s.PastDueSince, grace)
	return &b, &until
}

// pairedPlan returns the personal plan the catalog pairs with an owner's
// account subscription when it is live at now (liveRules, the same dunning
// grace as subscriptionPlan) and the paired plan is of the org's kind; nil
// otherwise.
func pairedPlan(s store.PaddleSubscription, kind entitlements.Kind, now time.Time, grace time.Duration) (*entitlements.Body, *time.Time) {
	if grace <= 0 {
		grace = DefaultPastDueGrace
	}
	if !subscriptionLive(s, now, grace) || s.PlanName == "" {
		return nil, nil
	}
	b, ok := entitlements.PairedPersonalPlan(s.PlanName)
	if !ok || b.Kind != kind {
		return nil, nil
	}
	if s.Status != "past_due" || s.PastDueSince == nil {
		return &b, nil
	}
	until := pastDueEnd(*s.PastDueSince, grace)
	return &b, &until
}

// PlanRuleNames returns the plan rule names in table order (tests and docs).
func PlanRuleNames() []string {
	out := make([]string, 0, len(planRules))
	for _, r := range planRules {
		out = append(out, r.name)
	}
	return out
}
