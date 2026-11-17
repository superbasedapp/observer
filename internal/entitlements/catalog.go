package entitlements

import (
	"fmt"
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

// planDef is one catalog row: a template plus whether it is a floor.
type planDef struct {
	body Body
	// floor marks the floor document of body.Kind (exactly one per kind).
	floor bool
}

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
		// reproduce cloud migration 0079's v5 rows exactly; the generator
		// checks that and inserts nothing for them.
		{floor: true, body: template(KindAccount, "free", 5, "Signed-in Free",
			map[CapName]int64{
				CapEnrichmentDaily: 100, CapEnrichmentMonthly: 3000, CapEnrichmentConcurrency: 2,
				CapEnrichmentResultsRetentionDays: 30,
			}, nil,
			map[TermName]string{TermEnrichmentTier: "free", TermEnrichmentBudgetPool: "free", TermEnrichmentRoute: haiku})},
		{body: template(KindAccount, "plus_beta", 5, "Plus",
			map[CapName]int64{
				CapEnrichmentDaily: 500, CapEnrichmentMonthly: 15000, CapEnrichmentConcurrency: 4,
				CapEnrichmentResultsRetentionDays: 365,
			}, []string{"org.digest"},
			map[TermName]string{TermEnrichmentTier: "paid", TermEnrichmentBudgetPool: "plus_beta", TermEnrichmentRoute: haiku})},

		// ---- personal: pooled personal orgs (plan 06 8.3, 17.5).
		{floor: true, body: template(KindPersonal, "personal_free", 1, "Personal Free",
			map[CapName]int64{
				CapMembersMax: 1, CapMachineIdentitiesMax: 10, CapRetentionDays: 30, CapStorageGB: 1,
				CapPushMBPerDay: 20, CapHoldsMax: 5, CapEnrichmentMonthly: 30,
				CapRequestsRPS: 10, CapRequestsBurst: 50,
			}, nil, nil)},
		{body: template(KindPersonal, "personal_pro", 1, "Personal Pro",
			map[CapName]int64{
				CapRetentionDays: 60, CapStorageGB: 10, CapHoldsMax: 200, CapEnrichmentMonthly: 300,
			}, []string{"org.digest"}, nil)},

		// ---- team: pooled team orgs. The floor is the lapsed state, not a
		// free tier (Team Free is deferred, D-16): over every cap means
		// read-only and nothing is deleted (17.5); sign-in and dashboards
		// keep working (18.3.4).
		{floor: true, body: template(KindTeam, "team_lapsed", 1, "Team (no active subscription)",
			map[CapName]int64{
				CapMembersMax: 0, CapSeatsMin: 0, CapMachineIdentitiesMax: 0, CapRetentionDays: 30,
				CapStorageGB: 0, CapStorageGBPerSeat: 0, CapPushMBPerDay: 0, CapHoldsMax: 0, CapHoldsPerSeat: 0,
				CapEnrichmentMonthly: 0, CapEnrichmentMonthlyPerSeat: 0, CapAuditLogDays: 30,
				CapRequestsRPS: 50, CapRequestsBurst: 200,
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
