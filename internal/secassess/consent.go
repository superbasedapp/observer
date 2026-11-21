package secassess

import "slices"

// consent.go is where a relaxation's consent route is decided (plan section
// 13.4) and where the report route is decided (13.8): two pure, ordered
// tables, walked top-down, one test row each. No branch on a tool or a kind id
// lives anywhere else.

// Tenancy is how the node is run. An unresolved tenancy (no governance
// provider wired, or the answer cannot be read) is treated as managed, the
// guard's own stricter reading.
type Tenancy string

// The tenancies.
const (
	TenancyManaged    Tenancy = "managed"
	TenancyIndividual Tenancy = "individual"
	TenancyUnresolved Tenancy = "unresolved"
)

// Lock is the org lock on one rule on this node, as the guard answers it
// (guard.Guard.RuleRelaxation).
type Lock string

// The locks.
const (
	// LockUntouched: the org layer does not reach the rule here.
	LockUntouched Lock = "untouched"
	// LockOverridable: the org marked the rule overridable, so the guard
	// honours a local approval for it.
	LockOverridable Lock = "overridable"
	// LockLocked: the org layer locks the rule here (or the answer could not
	// be read), so a local approval is inert.
	LockLocked Lock = "locked"
)

// RuleFacts is the guard's answer for one rule in one project.
type RuleFacts struct {
	Lock Lock
	// Decision is the rule's decision in the running mode (allow, flag, ask,
	// deny); "" when it could not be read, which reads as ask.
	Decision string
}

// Route is where a relaxation's consent comes from.
type Route string

// The routes.
const (
	// RouteSelf: the developer's own tick is the consent.
	RouteSelf Route = "self"
	// RouteOrgRequest: the organization must approve; the run is held.
	RouteOrgRequest Route = "org_request"
	// RouteNotNeeded: nothing to lift.
	RouteNotNeeded Route = "not_needed"
	// RouteRefused: not offered; Code and Reason say why.
	RouteRefused Route = "refused"
)

// The refusal codes of a relaxation.
const (
	CodeRelaxDisabled     = "relax_disabled"
	CodeNeedsOrg          = "needs_org"
	CodeTierAboveMax      = "tier_above_max"
	CodeTierUnsupported   = "tier_unsupported"
	CodeNeedsAllowHosts   = "needs_allow_hosts"
	CodeNeedsOrgSetting   = "needs_org_setting"
	CodeRelaxNotAvailable = "relaxation_not_available"
)

// Policy is the [security.assessments] block as plain data.
type Policy struct {
	// Relax says, per kind, whether its rows may be asked for.
	Relax          map[ID]bool
	ScopedApproval bool
	// MaxTier is the highest live tier the tier row accepts: "proxy_only" or
	// "internet".
	MaxTier     string
	Scope       string
	MaxMinutes  int
	ReportToOrg bool
}

// TierFacts are the facts the tier row reads.
type TierFacts struct {
	// Live is the node's live network tier ("" is internet).
	Live string
	// Hosts is [terminal.sandbox] egress_allow_hosts; NoHostPinned says an org
	// pin of it left no host in common (the gateway then allows no host).
	Hosts        []string
	NoHostPinned bool
}

// LiveTier returns the live tier with the empty tier read as internet.
func (t TierFacts) LiveTier() string {
	if t.Live == "" {
		return "internet"
	}
	return t.Live
}

// Narrowed says the box's reachable hosts are limited to a list (or to none).
func (t TierFacts) Narrowed() bool { return len(t.Hosts) > 0 || t.NoHostPinned }

// ConsentInput is what ConsentRoute reads for one row.
type ConsentInput struct {
	Row      Relaxation
	Policy   Policy
	Tenancy  Tenancy
	Enrolled bool
	// Rule is the guard's answer for a rule row.
	Rule RuleFacts
	// Tier is read by the tier row.
	Tier TierFacts
}

// Consent is the answer of ConsentRoute.
type Consent struct {
	Route Route
	// Row is the id of the table row that decided ("C3", "T2").
	Row    string
	Code   string
	Reason string
}

type consentRow struct {
	ID      string
	Name    string
	applies func(ConsentInput) bool
	when    func(ConsentInput) bool
	route   Route
	code    string
	reason  func(ConsentInput) string
}

func ruleRow(in ConsentInput) bool { return in.Row.Type == RelaxRule }
func tierRow(in ConsentInput) bool { return in.Row.Type == RelaxTier }

func text(s string) func(ConsentInput) string { return func(ConsentInput) string { return s } }

// kindSwitchOffWords is the reason a kind's relaxation rows are not offered:
// the switch that offers them is off, named by its label and screen. The config
// key stays in RelaxConfigKey for the callers that need it.
func kindSwitchOffWords(kind ID) string {
	label := RelaxSettingLabel(kind)
	if label == "" {
		return "This assessment offers nothing to lift."
	}
	return "Turn on \"" + label + "\" in " + WhereSettings + " to offer this."
}

// consentRows is THE consent table (plan section 13.4), first match wins.
var consentRows = []consentRow{
	{
		ID: "C1", Name: "kind switch off", applies: ruleRow,
		when: func(in ConsentInput) bool { return !in.Policy.Relax[in.Row.Kind] }, route: RouteRefused, code: CodeRelaxDisabled,
		reason: func(in ConsentInput) string {
			return kindSwitchOffWords(in.Row.Kind)
		},
	},
	{
		ID: "C1", Name: "scoped approval off", applies: ruleRow,
		when: func(in ConsentInput) bool { return !in.Policy.ScopedApproval }, route: RouteRefused, code: CodeRelaxDisabled,
		reason: text("Turn on \"" + LabelScopedApproval + "\" in " + WhereSettings + " to offer this."),
	},
	{
		ID: "C2", Name: "nothing to lift", applies: ruleRow,
		when: func(in ConsentInput) bool { return in.Rule.Decision == "allow" || in.Rule.Decision == "flag" }, route: RouteNotNeeded,
		reason: text("In the guard's current mode this rule only records the command, so there is nothing to lift. In enforce mode it would ask."),
	},
	{
		ID: "C3", Name: "the org marked the rule overridable", applies: ruleRow,
		when: func(in ConsentInput) bool { return in.Rule.Lock == LockOverridable }, route: RouteSelf,
		reason: text("Your organization lets you approve this rule yourself. Your tick is the consent."),
	},
	{
		ID: "C4", Name: "untouched on an individual node", applies: ruleRow,
		when: func(in ConsentInput) bool { return in.Rule.Lock == LockUntouched && in.Tenancy == TenancyIndividual }, route: RouteSelf,
		reason: text("Your tick is the consent."),
	},
	{
		ID: "C5", Name: "the organization decides", applies: ruleRow,
		when: func(in ConsentInput) bool { return in.Enrolled }, route: RouteOrgRequest,
		reason: text("Your organization governs this rule here, so it has to approve. Observer files the request for you and holds the run until the grant is in force."),
	},
	{
		ID: "C6", Name: "no organization to ask", applies: ruleRow,
		when: func(ConsentInput) bool { return true }, route: RouteRefused, code: CodeNeedsOrg,
		reason: text("This rule is governed by an organization this node is not enrolled with, so it cannot be lifted here."),
	},

	{
		ID: "T1", Name: "kind switch off", applies: tierRow,
		when: func(in ConsentInput) bool { return !in.Policy.Relax[in.Row.Kind] }, route: RouteRefused, code: CodeRelaxDisabled,
		reason: func(in ConsentInput) string {
			return kindSwitchOffWords(in.Row.Kind)
		},
	},
	{
		ID: "T1", Name: "already confined", applies: tierRow,
		when: func(in ConsentInput) bool { return in.Tier.LiveTier() == confinedTier }, route: RouteNotNeeded,
		reason: text("The sandbox network is already limited to the model proxy, so nothing is wider than the run needs."),
	},
	{
		ID: "T1", Name: "above the configured maximum", applies: tierRow,
		when: func(in ConsentInput) bool { return in.Policy.MaxTier != "internet" }, route: RouteRefused, code: CodeTierAboveMax,
		reason: text("\"" + LabelMaxNetwork + "\" is set to \"" + LabelMaxNetworkProxyOnly + "\" in " + WhereSettings + ", so no wider network is offered."),
	},
	{
		ID: "T1", Name: "host or none tier", applies: tierRow,
		when: func(in ConsentInput) bool { return in.Tier.LiveTier() != "internet" }, route: RouteRefused, code: CodeTierUnsupported,
		reason: func(in ConsentInput) string {
			return "The sandbox network is set to " + TierName(in.Tier.LiveTier()) + ", which a run cannot be widened from: the host setting shares this machine's network and the none setting leaves the agent no route to its model. Set " + LabelSandboxNetwork + " to internet with a list of hosts, or to proxy only, in " + WhereSandbox + "."
		},
	},
	{
		ID: "T1", Name: "no host list", applies: tierRow,
		when: func(in ConsentInput) bool { return !in.Tier.Narrowed() }, route: RouteRefused, code: CodeNeedsAllowHosts,
		reason: text("The wider network is offered only with a list of hosts: add the hosts the box may reach to \"" + LabelHostList + "\" in " + WhereSandbox + " (the model proxy still works). Without a list the box could reach any public host."),
	},
	{
		ID: "T2", Name: "individual node", applies: tierRow,
		when: func(in ConsentInput) bool { return in.Tenancy == TenancyIndividual }, route: RouteSelf,
		reason: text("Your tick is the consent."),
	},
	{
		ID: "T3", Name: "managed node", applies: tierRow,
		when: func(ConsentInput) bool { return true }, route: RouteRefused, code: CodeNeedsOrgSetting,
		reason: text("On a node managed by an organization the sandbox network is the organization's setting, and there is no request type for a wider sandbox network yet. Ask your administrator to change it."),
	},
}

// ConsentRoute decides the route of one relaxation row.
func ConsentRoute(in ConsentInput) Consent {
	for _, r := range consentRows {
		if !r.applies(in) || !r.when(in) {
			continue
		}
		c := Consent{Route: r.route, Row: r.ID, Code: r.code}
		if r.reason != nil {
			c.Reason = r.reason(in)
		}
		return c
	}
	return Consent{Route: RouteRefused, Row: "C0", Code: CodeNeedsOrg, Reason: "This relaxation is not available."}
}

// ConsentRowNames lists "<id> <name>" for the table in order (the tests walk
// it so a row cannot be added without a test).
func ConsentRowNames() []string {
	out := make([]string, 0, len(consentRows))
	for _, r := range consentRows {
		out = append(out, r.ID+" "+r.Name)
	}
	return out
}

// PlanRow is one relaxation row as the plan shows it.
type PlanRow struct {
	Key   string
	Type  RelaxType
	Title string
	Lifts string
	Why   string
	Consent
}

// PlanInput is the facts the plan reads for every row of a kind.
type PlanInput struct {
	Policy   Policy
	Tenancy  Tenancy
	Enrolled bool
	// Rules is the guard's answer per rule id; a rule absent from it reads as
	// locked and undecided (the fail-closed answer).
	Rules map[string]RuleFacts
	Tier  TierFacts
}

// PlanRelaxations resolves every row of the kind to its route.
func PlanRelaxations(kind ID, in PlanInput) []PlanRow {
	out := []PlanRow{}
	for _, row := range RelaxationsFor(kind) {
		facts, ok := in.Rules[row.Key]
		if !ok {
			facts = RuleFacts{Lock: LockLocked}
		}
		c := ConsentRoute(ConsentInput{
			Row: row, Policy: in.Policy, Tenancy: in.Tenancy, Enrolled: in.Enrolled, Rule: facts, Tier: in.Tier,
		})
		out = append(out, PlanRow{Key: row.Key, Type: row.Type, Title: row.Title, Lifts: row.Lifts, Why: row.Why, Consent: c})
	}
	return out
}

// PlanRowFor returns the resolved row for key.
func PlanRowFor(rows []PlanRow, key string) (PlanRow, bool) {
	i := slices.IndexFunc(rows, func(r PlanRow) bool { return r.Key == key })
	if i < 0 {
		return PlanRow{}, false
	}
	return rows[i], true
}

// ReportInput is what ReportRoute reads.
type ReportInput struct {
	Tenancy     Tenancy
	ReportToOrg bool
}

type reportRow struct {
	ID    string
	when  func(ReportInput) bool
	write bool
}

// reportRows is THE report table (plan section 13.8), first match wins.
var reportRows = []reportRow{
	{"R1", func(in ReportInput) bool { return in.Tenancy != TenancyIndividual }, true},
	{"R2", func(in ReportInput) bool { return in.ReportToOrg }, true},
	{"R3", func(ReportInput) bool { return true }, false},
}

// ReportRoute says whether a run's audit rows are written and which row of the
// table said so. A managed (or unresolved) node always writes them; an
// individual node writes them only when its own setting says so.
func ReportRoute(in ReportInput) (write bool, row string) {
	for _, r := range reportRows {
		if r.when(in) {
			return r.write, r.ID
		}
	}
	return false, "R0"
}

// ReportValidation says whether the content-free "validated" audit row is
// written when a run's model is checked. The run must be reported at all
// (ReportRoute said so at launch); an individual node also needs its own
// switch on, while a managed or unresolved node always writes it, as it does
// every other row of a run it reports.
func ReportValidation(tenancy Tenancy, reported, switchOn bool) bool {
	return reported && (switchOn || tenancy != TenancyIndividual)
}
