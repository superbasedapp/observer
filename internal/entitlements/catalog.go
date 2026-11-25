package entitlements

import (
	"fmt"
	"slices"
	"sort"
)

// catalog.go is the plan catalog: one template body per (plan, version),
// the one authored source of what a plan entitles (plan 06 17.2: "the cloud
// plans and account_plans tables stop being an authored source"). The
// document signer issues an org's document from a template (Compose); the
// cloud service generates its plans rows from the account-kind templates
// (internal/cloudserver/store/plangen.go). A new plan, or a change to one,
// is a new (name, version) row here, never an edit of a released row and
// never a migration that writes plans.
//
// Values come from plan 06 8.3 (the price card, D-1), 5.3.9 (quotas) and
// 17.5 (retention classes, the downgrade rule). Where the plan gives no
// number the row says so and the w11 handback lists it for the operator.

// planDef is one catalog row: a template plus whether it is a floor and
// whether it carries forward the holders of earlier versions.
type planDef struct {
	body Body
	// floor marks the floor document of body.Kind (exactly one per kind).
	floor bool
	// carries marks a version that replaces the version just below it for
	// every holder, at no change of price: an org whose subscription or
	// operator grant names the earlier version is issued this one (Current).
	// A version whose holders move only by a new price (Business v2) leaves
	// it false.
	carries bool
}

// The AI Apps allowances of the personal plans (operator ruling L-166,
// 2026-11-24; the operator's proposal). The one place these numbers live:
// the catalog rows below, the tests and the docs read them from here.
const (
	// PersonalFreePlaneAEvents and PersonalFreePlaneAGB are Personal Free's
	// monthly AI Apps allowance (personal_free v2).
	PersonalFreePlaneAEvents = 100_000
	PersonalFreePlaneAGB     = 1
	// PersonalProPlaneAEvents and PersonalProPlaneAGB are Personal Pro's
	// (personal_pro v2).
	PersonalProPlaneAEvents = 2_000_000
	PersonalProPlaneAGB     = 10
)

// CapabilityPlaneAGateway is the AI Apps OTLP gateway's component id: the
// capability a plan sells AI Apps ingest by (capability.go's row).
const CapabilityPlaneAGateway = "org.planea.gateway"

// The hosted AI gateway's allowances (hosted AI gateway plan 3.13; decision
// 4 of L-174, 2026-11-25): forwarded requests per UTC month and requests in
// flight at once, included in the plan. The one place these numbers live:
// the v3 catalog rows below, the tests and the docs read them from here.
// Team (v1) includes none; dedicated and self-hosted run their own gateway
// and are not capped by plan.
const (
	// PersonalFreeAIGWRequests and PersonalFreeAIGWConcurrency are Personal
	// Free's (personal_free v3, the personal floor).
	PersonalFreeAIGWRequests    = 10_000
	PersonalFreeAIGWConcurrency = 4
	// PersonalProAIGWRequests and PersonalProAIGWConcurrency are Personal
	// Pro's (personal_pro v3, what the Plus subscription buys).
	PersonalProAIGWRequests    = 250_000
	PersonalProAIGWConcurrency = 16
	// BusinessAIGWRequests and BusinessAIGWConcurrency are Business v3's: a
	// conservative start until the window-totals ledger is measured under
	// load (plan R3); raising them is a new Business version, no code.
	BusinessAIGWRequests    = 1_000_000
	BusinessAIGWConcurrency = 64
)

// CapabilityAIGateway is the AI gateway's component id (the model call path
// that prices, budgets and polices an app's model calls): the capability a
// plan sells the hosted AI gateway by (capability.go's row).
const CapabilityAIGateway = "org.aigateway"

func template(kind Kind, name string, version int, label string, caps map[CapName]int64, capabilities []string, terms map[TermName]string) Body {
	sort.Strings(capabilities)
	return Body{
		Schema:       BodySchema,
		Kind:         kind,
		Plan:         PlanRef{Name: name, Version: version, Label: label},
		Capabilities: capabilities,
		Caps:         caps,
		Terms:        terms,
	}
}

// businessCapabilities is every plan-gated capability the price card's
// Business plan sells: SSO and SCIM, the vendor pollers, Plane A, the
// enterprise modules (defaults for the operator), and the feature rows,
// among them org.own_idp (W16-D8: Business keeps its own IdP; Team does
// not, so the team row below never lists it).
func businessCapabilities() []string { return GatedIDs(GatePlan) }

func planDefs() []planDef {
	const haiku = "session_enrichment.claude-haiku-5-5.v1"
	return []planDef{
		// ---- account: the personal plane (cloud plans rows). These two
		// reproduce cloud migration 0079's v5 rows in every entitlement
		// column; the generator checks that and inserts nothing for them.
		// The label is copy, not an entitlement (no account-kind template is
		// issued as a document): the generator keeps the row's label equal
		// to this one (cloud 0156). plus_beta's reads "Personal Pro", the
		// one name a customer sees for the paid individual plan (operator
		// ruling 2026-11-24; 0079's copy of the beta's "Plus" is replaced
		// at the next migrate). plus_beta stays the internal id.
		{floor: true, body: template(KindAccount, "free", 5, "Signed-in Free",
			map[CapName]int64{
				CapEnrichmentDaily: 100, CapEnrichmentMonthly: 3000, CapEnrichmentConcurrency: 2,
				CapEnrichmentResultsRetentionDays: 30,
			}, nil,
			map[TermName]string{TermEnrichmentTier: "free", TermEnrichmentBudgetPool: "free", TermEnrichmentRoute: haiku})},
		{body: template(KindAccount, "plus_beta", 5, "Personal Pro",
			map[CapName]int64{
				CapEnrichmentDaily: 500, CapEnrichmentMonthly: 15000, CapEnrichmentConcurrency: 4,
				CapEnrichmentResultsRetentionDays: 365,
			}, []string{"org.digest"},
			map[TermName]string{TermEnrichmentTier: "paid", TermEnrichmentBudgetPool: "plus_beta", TermEnrichmentRoute: haiku})},

		// ---- personal: pooled personal orgs (plan 06 8.3, 17.5). v1 of
		// each is history (released before AI Apps reached personal orgs).
		{body: template(KindPersonal, "personal_free", 1, "Personal Free",
			map[CapName]int64{
				CapMembersMax: 1, CapMachineIdentitiesMax: 10, CapRetentionDays: 30, CapStorageGB: 1,
				CapPushMBPerDay: 20, CapHoldsMax: 5, CapEnrichmentMonthly: 30,
				CapRequestsRPS: 10, CapRequestsBurst: 50,
				CapPlaneAEventsMonthly: 0, CapPlaneAGBMonthly: 0,
			}, nil, nil)},
		{body: template(KindPersonal, "personal_pro", 1, "Personal Pro",
			map[CapName]int64{
				CapRetentionDays: 60, CapStorageGB: 10, CapHoldsMax: 200, CapEnrichmentMonthly: 300,
			}, []string{"org.digest"}, nil)},
		// v2 of both (operator ruling L-166, 2026-11-24): v1 as released
		// plus an AI Apps allowance and the gateway capability, so a solo
		// developer sends traces from the SDKs with no Observer install.
		// personal_free v2 is the floor: a host evaluates every personal
		// org against it from the roll, and the issuer re-issues each floor
		// document at its next pass. Both carry their v1 holders forward
		// (no price changes), so a Pro subscription or grant that names v1
		// is issued v2.
		{carries: true, body: template(KindPersonal, "personal_free", 2, "Personal Free",
			map[CapName]int64{
				CapMembersMax: 1, CapMachineIdentitiesMax: 10, CapRetentionDays: 30, CapStorageGB: 1,
				CapPushMBPerDay: 20, CapHoldsMax: 5, CapEnrichmentMonthly: 30,
				CapRequestsRPS: 10, CapRequestsBurst: 50,
				CapPlaneAEventsMonthly: PersonalFreePlaneAEvents, CapPlaneAGBMonthly: PersonalFreePlaneAGB,
			}, []string{CapabilityPlaneAGateway}, nil)},
		{carries: true, body: template(KindPersonal, "personal_pro", 2, "Personal Pro",
			map[CapName]int64{
				CapRetentionDays: 60, CapStorageGB: 10, CapHoldsMax: 200, CapEnrichmentMonthly: 300,
				CapPlaneAEventsMonthly: PersonalProPlaneAEvents, CapPlaneAGBMonthly: PersonalProPlaneAGB,
			}, []string{"org.digest", CapabilityPlaneAGateway}, nil)},
		// v3 of both (hosted AI gateway, L-172; decision 4 of L-174,
		// 2026-11-25): v2 as released plus the AI gateway capability and its
		// allowance (forwarded requests a month and requests in flight).
		// personal_free v3 is the personal floor from the roll that ships it:
		// every personal org holds at least Personal Free's allowance, and a
		// v1 or v2 document composes with it until the issuer replaces it.
		// Both carry their v2 holders forward (no price change).
		{floor: true, carries: true, body: template(KindPersonal, "personal_free", 3, "Personal Free",
			map[CapName]int64{
				CapMembersMax: 1, CapMachineIdentitiesMax: 10, CapRetentionDays: 30, CapStorageGB: 1,
				CapPushMBPerDay: 20, CapHoldsMax: 5, CapEnrichmentMonthly: 30,
				CapRequestsRPS: 10, CapRequestsBurst: 50,
				CapPlaneAEventsMonthly: PersonalFreePlaneAEvents, CapPlaneAGBMonthly: PersonalFreePlaneAGB,
				CapAIGWRequestsMonthly: PersonalFreeAIGWRequests, CapAIGWConcurrency: PersonalFreeAIGWConcurrency,
			}, []string{CapabilityPlaneAGateway, CapabilityAIGateway}, nil)},
		{carries: true, body: template(KindPersonal, "personal_pro", 3, "Personal Pro",
			map[CapName]int64{
				CapRetentionDays: 60, CapStorageGB: 10, CapHoldsMax: 200, CapEnrichmentMonthly: 300,
				CapPlaneAEventsMonthly: PersonalProPlaneAEvents, CapPlaneAGBMonthly: PersonalProPlaneAGB,
				CapAIGWRequestsMonthly: PersonalProAIGWRequests, CapAIGWConcurrency: PersonalProAIGWConcurrency,
			}, []string{"org.digest", CapabilityPlaneAGateway, CapabilityAIGateway}, nil)},

		// ---- team: pooled team orgs. The floor is the lapsed state, not a
		// free tier (Team Free is deferred, D-16): over every cap means
		// read-only and nothing is deleted (17.5); sign-in and dashboards
		// keep working (18.3.4).
		{body: template(KindTeam, "team_lapsed", 1, "Team (no active subscription)",
			map[CapName]int64{
				CapMembersMax: 0, CapSeatsMin: 0, CapMachineIdentitiesMax: 0, CapRetentionDays: 30,
				CapStorageGB: 0, CapStorageGBPerSeat: 0, CapPushMBPerDay: 0, CapHoldsMax: 0, CapHoldsPerSeat: 0,
				CapEnrichmentMonthly: 0, CapEnrichmentMonthlyPerSeat: 0, CapAuditLogDays: 30,
				CapRequestsRPS: 50, CapRequestsBurst: 200,
				CapPlaneAEventsMonthly: 0, CapPlaneAGBMonthly: 0,
			}, nil, nil)},
		// v2 (hosted AI gateway, L-172; plan 3.13): v1 as released plus the AI
		// gateway caps at 0. It is the team floor from the roll that ships it,
		// so a team document that sets no AI gateway cap (Team, Business v1
		// and v2, which already list org.aigateway) holds 0, which is "not in
		// the plan", never unlimited (plan R10).
		{floor: true, carries: true, body: template(KindTeam, "team_lapsed", 2, "Team (no active subscription)",
			map[CapName]int64{
				CapMembersMax: 0, CapSeatsMin: 0, CapMachineIdentitiesMax: 0, CapRetentionDays: 30,
				CapStorageGB: 0, CapStorageGBPerSeat: 0, CapPushMBPerDay: 0, CapHoldsMax: 0, CapHoldsPerSeat: 0,
				CapEnrichmentMonthly: 0, CapEnrichmentMonthlyPerSeat: 0, CapAuditLogDays: 30,
				CapRequestsRPS: 50, CapRequestsBurst: 200,
				CapPlaneAEventsMonthly: 0, CapPlaneAGBMonthly: 0,
				CapAIGWRequestsMonthly: 0, CapAIGWConcurrency: 0,
			}, nil, nil)},
		{body: template(KindTeam, "team", 1, "Team",
			map[CapName]int64{
				CapMembersMax: Unlimited, CapSeatsMin: 3, CapMachineIdentitiesMax: 10, CapRetentionDays: 60,
				CapStorageGBPerSeat: 3, CapPushMBPerDay: 500, CapHoldsPerSeat: 50,
				CapEnrichmentMonthlyPerSeat: 150, CapAuditLogDays: 365,
			}, []string{"org.assistant", "org.digest", "org.security"}, nil)},
		{body: template(KindTeam, "business", 1, "Business",
			map[CapName]int64{
				CapMembersMax: Unlimited, CapSeatsMin: 10, CapMachineIdentitiesMax: 50, CapRetentionDays: 180,
				CapStorageGBPerSeat: 6, CapPushMBPerDay: 1000, CapHoldsPerSeat: 50,
				CapEnrichmentMonthlyPerSeat: 300, CapAuditLogDays: 365,
			}, businessCapabilities(), nil)},
		// Business v2 (Plane A packaging, D14 and D20): v1 as released plus
		// the Plane A gateway's monthly allowance (10M events and 50 GB) and
		// a request rate above the team floor's 50 rps / 200 burst, which
		// Business v1 inherits because it sets none. v1 stays as released:
		// the issuer treats a stored document as current while its (name,
		// version) matches, so an edit of v1 would never reach an org that
		// holds one. A Business price moves to v2 by its price mapping.
		{body: template(KindTeam, "business", 2, "Business",
			map[CapName]int64{
				CapMembersMax: Unlimited, CapSeatsMin: 10, CapMachineIdentitiesMax: 50, CapRetentionDays: 180,
				CapStorageGBPerSeat: 6, CapPushMBPerDay: 1000, CapHoldsPerSeat: 50,
				CapEnrichmentMonthlyPerSeat: 300, CapAuditLogDays: 365,
				CapRequestsRPS: 200, CapRequestsBurst: 800,
				CapPlaneAEventsMonthly: 10_000_000, CapPlaneAGBMonthly: 50,
			}, businessCapabilities(), nil)},
		// Business v3 (hosted AI gateway, L-172; decision 4 of L-174): v2 as
		// released plus the AI gateway's allowance. Like v2 it does not carry
		// its holders: a Business price moves to v3 by its price mapping (the
		// Paddle Business price maps to business:3 at the roll that ships it).
		{body: template(KindTeam, "business", 3, "Business",
			map[CapName]int64{
				CapMembersMax: Unlimited, CapSeatsMin: 10, CapMachineIdentitiesMax: 50, CapRetentionDays: 180,
				CapStorageGBPerSeat: 6, CapPushMBPerDay: 1000, CapHoldsPerSeat: 50,
				CapEnrichmentMonthlyPerSeat: 300, CapAuditLogDays: 365,
				CapRequestsRPS: 200, CapRequestsBurst: 800,
				CapPlaneAEventsMonthly: 10_000_000, CapPlaneAGBMonthly: 50,
				CapAIGWRequestsMonthly: BusinessAIGWRequests, CapAIGWConcurrency: BusinessAIGWConcurrency,
			}, businessCapabilities(), nil)},

		// ---- dedicated (plan 06 5.2 model B): a contract document; the
		// floor is the lapsed state.
		{floor: true, body: template(KindDedicated, "dedicated_lapsed", 1, "Dedicated (no active contract)",
			map[CapName]int64{CapMembersMax: 0, CapSeatsMin: 0, CapMachineIdentitiesMax: 0}, nil, nil)},
		{body: template(KindDedicated, "dedicated", 1, "Dedicated",
			map[CapName]int64{CapMembersMax: Unlimited, CapSeatsMin: 50, CapMachineIdentitiesMax: Unlimited},
			GatedIDs(GatePlan), nil)},

		// ---- self-hosted (plan 06 5.2 model C): the floor is the D-6
		// community tier (10 developers, every component: single mode is
		// otherwise unchanged); the licence includes 50 developers.
		{floor: true, body: template(KindSelfHosted, "community", 1, "Community",
			map[CapName]int64{CapMembersMax: 10, CapSeatsIncluded: 0, CapMachineIdentitiesMax: Unlimited},
			GatedIDs(GatePlan), nil)},
		{body: template(KindSelfHosted, "self_hosted", 1, "Self-hosted licence",
			map[CapName]int64{CapMembersMax: Unlimited, CapSeatsIncluded: 50, CapMachineIdentitiesMax: Unlimited},
			GatedIDs(GatePlan), nil)},
	}
}

// Plans returns every catalog template, in catalog order. Each call returns
// fresh copies.
func Plans() []Body {
	defs := planDefs()
	out := make([]Body, 0, len(defs))
	for _, d := range defs {
		out = append(out, d.body.Normalized())
	}
	return out
}

// PlansOfKind returns the templates of kind k, in catalog order.
func PlansOfKind(k Kind) []Body {
	var out []Body
	for _, b := range Plans() {
		if b.Kind == k {
			out = append(out, b)
		}
	}
	return out
}

// Plan returns the template (name, version); version 0 asks for the highest
// catalog version of name.
func Plan(name string, version int) (Body, bool) {
	var best Body
	found := false
	for _, b := range Plans() {
		if b.Plan.Name != name {
			continue
		}
		if version != 0 && b.Plan.Version == version {
			return b, true
		}
		if version == 0 && (!found || b.Plan.Version > best.Plan.Version) {
			best, found = b, true
		}
	}
	return best, found
}

// Current returns the template an org holding (name, version) is issued:
// the version itself, or the newest version that carries it forward (each
// version from version+1 up is marked carries; the walk stops at the first
// that is not). false when (name, version) is not a catalog plan; version 0
// is the highest catalog version, as in Plan.
func Current(name string, version int) (Body, bool) {
	cur, ok := Plan(name, version)
	if !ok {
		return Body{}, false
	}
	defs := planDefs()
	for {
		next := -1
		for i, d := range defs {
			if d.body.Plan.Name == name && d.body.Plan.Version == cur.Plan.Version+1 {
				next = i
				break
			}
		}
		if next < 0 || !defs[next].carries {
			return cur, true
		}
		cur = defs[next].body.Normalized()
	}
}

// accountPair pairs an account plan with the personal plan its holder's
// personal org is issued.
type accountPair struct {
	account, personal string
}

// accountPairs is the pairing table (operator ruling L-167, 2026-11-24:
// Personal Pro is what the plus_beta account subscription buys; there is no
// Paddle product of its own). The personal plan is issued at its newest version.
func accountPairs() []accountPair {
	return []accountPair{{account: "plus_beta", personal: "personal_pro"}}
}

// PairedPersonalPlan returns the personal plan (its newest version) that an
// account plan's holder's personal org is issued, and false when the account
// plan pairs with none.
func PairedPersonalPlan(accountPlan string) (Body, bool) {
	for _, p := range accountPairs() {
		if p.account == accountPlan {
			return Plan(p.personal, 0)
		}
	}
	return Body{}, false
}

// AccountPlansPairInto reports whether any account plan pairs with a plan of
// kind k: whether an org of kind k may be entitled by its owner's account
// subscription at all.
func AccountPlansPairInto(k Kind) bool {
	for _, p := range accountPairs() {
		if b, ok := Plan(p.personal, 0); ok && b.Kind == k {
			return true
		}
	}
	return false
}

// GrantingPlans returns the catalog templates of kind k, at their highest
// version, that list the capability id (catalog order; empty when none
// does). A refusal names the plans that would grant what it refused from
// here, never from a hard-coded name.
func GrantingPlans(k Kind, id string) []Body {
	var out []Body
	for _, b := range PlansOfKind(k) {
		latest, ok := Plan(b.Plan.Name, 0)
		if !ok || latest.Plan.Version != b.Plan.Version {
			continue
		}
		if slices.Contains(latest.Capabilities, id) {
			out = append(out, latest)
		}
	}
	return out
}

// Floor returns the floor template of kind k (false for an unknown kind).
func Floor(k Kind) (Body, bool) {
	for _, d := range planDefs() {
		if d.floor && d.body.Kind == k {
			return d.body.Normalized(), true
		}
	}
	return Body{}, false
}

// Compose issues a document body from a catalog template for org: the
// template's grants, the org, the issue time and the validity window (unix
// seconds; notAfter 0 = no end). The result passes CheckIssuable or Compose
// fails. This is the signer side's pure half; the worker that signs, stores
// and pushes it is M6's.
func Compose(planName string, version int, org string, issuedAt, notBefore, notAfter int64) (Body, error) {
	t, ok := Plan(planName, version)
	if !ok {
		return Body{}, fmt.Errorf("entitlements.Compose: no catalog plan %s v%d: %w", planName, version, ErrBody)
	}
	b := t.Normalized()
	b.Org = org
	b.IssuedAt = issuedAt
	b.NotBefore = notBefore
	b.NotAfter = notAfter
	if err := b.CheckIssuable(); err != nil {
		return Body{}, fmt.Errorf("entitlements.Compose: %w", err)
	}
	return b, nil
}
