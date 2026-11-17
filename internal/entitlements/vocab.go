package entitlements

import "slices"

// Kind is the kind of org (or account) a document entitles. It selects the
// floor and binds a document to the deployment it was issued for: a
// self-hosted licence never verifies on a pooled org, nor a team document
// on a personal one. Code outside this package branches on capabilities,
// never on Kind (plan 06 17.3, "web2 branches on entitlement capabilities").
type Kind string

// The closed Kind vocabulary.
const (
	// KindAccount is a personal-plane account on the hosted cloud service
	// (the plans and account_plans tables), until plan 06 9.4 (E3) moves
	// those users to personal orgs.
	KindAccount Kind = "account"
	// KindPersonal is a pooled personal org.
	KindPersonal Kind = "personal"
	// KindTeam is a pooled team org.
	KindTeam Kind = "team"
	// KindDedicated is a dedicated managed deployment (plan 06 5.2 model B).
	KindDedicated Kind = "dedicated"
	// KindSelfHosted is a self-hosted deployment: the document is the
	// licence file (plan 06 5.2 model C).
	KindSelfHosted Kind = "self_hosted"
)

// Kinds returns every Kind, in declaration order.
func Kinds() []Kind {
	return []Kind{KindAccount, KindPersonal, KindTeam, KindDedicated, KindSelfHosted}
}

// Valid reports whether k is a known Kind.
func (k Kind) Valid() bool { return slices.Contains(Kinds(), k) }

// Unlimited is the cap value that means "not limited by the entitlement".
// It is explicit on purpose: an absent cap falls back to the floor, so a
// document that forgets a cap can never grant an unlimited one.
const Unlimited int64 = -1

// CapName names a numeric cap. The vocabulary is closed (capRules).
type CapName string

// The closed cap vocabulary. Every "max" or allowance cap reads "at most N".
const (
	// CapMembersMax is the members_max of plan 06 5.3.9.
	CapMembersMax CapName = "members.max"
	// CapSeatsMin is the plan minimum of billable seats (plan 06 8.3).
	CapSeatsMin CapName = "seats.min"
	// CapSeatsIncluded is the number of developers a self-hosted licence
	// includes before per-developer pricing (plan 06 8.3).
	CapSeatsIncluded CapName = "seats.included"
	// CapMachineIdentitiesMax bounds machine identities (plan 06 5.8.5).
	CapMachineIdentitiesMax CapName = "machine_identities.max"
	// CapRetentionDays is the org data retention class (plan 06 17.5).
	CapRetentionDays CapName = "retention.days"
	// CapStorageGB is a flat stored-bytes allowance in GB.
	CapStorageGB CapName = "storage.gb"
	// CapStorageGBPerSeat is the pooled stored-bytes allowance per seat.
	CapStorageGBPerSeat CapName = "storage.gb_per_seat"
	// CapPushMBPerDay is the daily push byte allowance (plan 06 5.3.9).
	CapPushMBPerDay CapName = "push.mb_per_day"
	// CapHoldsMax is a flat number of saved-session holds.
	CapHoldsMax CapName = "holds.max"
	// CapHoldsPerSeat is the number of holds per seat.
	CapHoldsPerSeat CapName = "holds.per_seat"
	// CapEnrichmentMonthly is the monthly enrichment allowance.
	CapEnrichmentMonthly CapName = "enrichment.monthly"
	// CapEnrichmentMonthlyPerSeat is the monthly enrichment allowance per
	// seat.
	CapEnrichmentMonthlyPerSeat CapName = "enrichment.monthly_per_seat"
	// CapEnrichmentDaily is the personal plane's daily enrichment count cap
	// (plans.daily_cap).
	CapEnrichmentDaily CapName = "enrichment.daily"
	// CapEnrichmentConcurrency is the personal plane's concurrent job cap
	// (plans.concurrency_cap).
	CapEnrichmentConcurrency CapName = "enrichment.concurrency"
	// CapEnrichmentResultsRetentionDays is how long the personal plane keeps
	// a hosted result (plans.results_retention_days).
	CapEnrichmentResultsRetentionDays CapName = "enrichment.results_retention_days"
	// CapAuditLogDays is how long the audit log is kept.
	CapAuditLogDays CapName = "audit_log.days"
	// CapRequestsRPS is the per-org request rate (plan 06 5.3.9).
	CapRequestsRPS CapName = "requests.rps"
	// CapRequestsBurst is the per-org request burst (plan 06 5.3.9).
	CapRequestsBurst CapName = "requests.burst"
)

// RetentionClasses are the only retention.days values a pooled document may
// carry (plan 06 17.5: three classes, so three purge behaviours).
func RetentionClasses() []int64 { return []int64{30, 60, 180} }

// capRule is one row of the cap vocabulary.
type capRule struct {
	name CapName
	// unit is what one unit counts, for the reader and the docs.
	unit string
	// kinds are the kinds a document may set the cap for; a floor of each
	// of these kinds sets it.
	kinds []Kind
	// value, when set, restricts the finite values (Unlimited is always
	// accepted).
	value func(int64) bool
}

func capRules() []capRule {
	pooled := []Kind{KindPersonal, KindTeam}
	orgs := []Kind{KindPersonal, KindTeam, KindDedicated, KindSelfHosted}
	return []capRule{
		{name: CapMembersMax, unit: "members", kinds: orgs},
		{name: CapSeatsMin, unit: "seats", kinds: []Kind{KindTeam, KindDedicated}},
		{name: CapSeatsIncluded, unit: "developers", kinds: []Kind{KindSelfHosted}},
		{name: CapMachineIdentitiesMax, unit: "machine identities", kinds: orgs},
		{name: CapRetentionDays, unit: "days", kinds: pooled, value: func(n int64) bool { return slices.Contains(RetentionClasses(), n) }},
		{name: CapStorageGB, unit: "GB", kinds: pooled},
		{name: CapStorageGBPerSeat, unit: "GB per seat", kinds: []Kind{KindTeam}},
		{name: CapPushMBPerDay, unit: "MB per day", kinds: pooled},
		{name: CapHoldsMax, unit: "holds", kinds: pooled},
		{name: CapHoldsPerSeat, unit: "holds per seat", kinds: []Kind{KindTeam}},
		{name: CapEnrichmentMonthly, unit: "enrichments per month", kinds: []Kind{KindAccount, KindPersonal, KindTeam}},
		{name: CapEnrichmentMonthlyPerSeat, unit: "enrichments per seat per month", kinds: []Kind{KindTeam}},
		{name: CapEnrichmentDaily, unit: "enrichments per day", kinds: []Kind{KindAccount}},
		{name: CapEnrichmentConcurrency, unit: "concurrent jobs", kinds: []Kind{KindAccount}},
		{name: CapEnrichmentResultsRetentionDays, unit: "days", kinds: []Kind{KindAccount}},
		{name: CapAuditLogDays, unit: "days", kinds: []Kind{KindTeam}},
		{name: CapRequestsRPS, unit: "requests per second", kinds: pooled},
		{name: CapRequestsBurst, unit: "requests", kinds: pooled},
	}
}

func capRuleFor(n CapName) (capRule, bool) {
	for _, r := range capRules() {
		if r.name == n {
			return r, true
		}
	}
	return capRule{}, false
}

// CapNames returns every cap name, in vocabulary order.
func CapNames() []CapName {
	var out []CapName
	for _, r := range capRules() {
		out = append(out, r.name)
	}
	return out
}

// CapsFor returns the caps a document of kind k may set, in vocabulary
// order; the floor of k sets every one of them.
func CapsFor(k Kind) []CapName {
	var out []CapName
	for _, r := range capRules() {
		if slices.Contains(r.kinds, k) {
			out = append(out, r.name)
		}
	}
	return out
}

// Unit returns what one unit of the cap counts ("" for an unknown cap).
func (n CapName) Unit() string {
	r, _ := capRuleFor(n)
	return r.unit
}

// Known reports whether n is in the vocabulary.
func (n CapName) Known() bool {
	_, ok := capRuleFor(n)
	return ok
}

// TermName names a string-valued term. The vocabulary is closed.
type TermName string

// The closed term vocabulary: the personal plane's enrichment bindings,
// which the plans row carries today (plans.enrichment_tier, budget_pool,
// route_id).
const (
	// TermEnrichmentTier names the enrichment_tiers row.
	TermEnrichmentTier TermName = "enrichment.tier"
	// TermEnrichmentBudgetPool names the budget_pools row.
	TermEnrichmentBudgetPool TermName = "enrichment.budget_pool"
	// TermEnrichmentRoute names the pinned route_registry row.
	TermEnrichmentRoute TermName = "enrichment.route"
)

// termRule is one row of the term vocabulary.
type termRule struct {
	name  TermName
	kinds []Kind
}

func termRules() []termRule {
	return []termRule{
		{name: TermEnrichmentTier, kinds: []Kind{KindAccount}},
		{name: TermEnrichmentBudgetPool, kinds: []Kind{KindAccount}},
		{name: TermEnrichmentRoute, kinds: []Kind{KindAccount}},
	}
}

func termRuleFor(n TermName) (termRule, bool) {
	for _, r := range termRules() {
		if r.name == n {
			return r, true
		}
	}
	return termRule{}, false
}

// TermNames returns every term name, in vocabulary order.
func TermNames() []TermName {
	var out []TermName
	for _, r := range termRules() {
		out = append(out, r.name)
	}
	return out
}

// Known reports whether n is in the vocabulary.
func (n TermName) Known() bool {
	_, ok := termRuleFor(n)
	return ok
}
