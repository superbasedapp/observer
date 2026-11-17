package secassess

import "strings"

// relax.go is the closed table of relaxations (plan section 13.2): for each
// assessment kind, the guardrails a developer may lift for one run, each with
// its words. A kind with no row can never be relaxed whatever the config says.
// The decision whether a row is offered, and who consents to it, is
// ConsentRoute (consent.go); the lifecycle of one in force is RelaxStep
// (relaxstep.go).

// RelaxType is what a relaxation lifts.
type RelaxType string

// The relaxation types.
const (
	// RelaxRule lifts one guard rule's ask for this run (a guard approval or
	// an org exemption).
	RelaxRule RelaxType = "rule"
	// RelaxTier lets the run start under a wider sandbox network tier than
	// proxy_only.
	RelaxTier RelaxType = "tier"
)

// TierKey is the Key of a kind's tier relaxation row.
const TierKey = "tier"

// RuleScanner is the network and vulnerability scanner rule (R-179).
const RuleScanner = "R-179"

// Relaxation is one row of the table.
type Relaxation struct {
	Kind ID
	// Key is the guard rule id for a rule row, TierKey for the tier row.
	Key  string
	Type RelaxType
	// Title is the dialog's tick label.
	Title string
	// Lifts says in words what the relaxation allows.
	Lifts string
	// Why says why this kind may ask.
	Why string
	// PromptLine is the boundary line the prompt gains when the relaxation is
	// in force; %s is replaced with the scope words (rule rows) or the host
	// list (the tier row).
	PromptLine string
}

var relaxations = []Relaxation{
	{
		Kind: PentestLocal, Key: RuleScanner, Type: RelaxRule,
		Title:      "Allow network and vulnerability scanners",
		Lifts:      "Observer's guard stops network and vulnerability scanners (nmap, masscan, nuclei, sqlmap and similar) and asks you each time. This lifts that one rule for this run, for the project's terminal only. Every other rule still applies.",
		Why:        "Scanners aimed at the confirmed target are the ordinary tools of a penetration test.",
		PromptLine: "The developer lifted ONE guardrail for this run only: Observer's guard no longer stops network and vulnerability scanner commands (rule R-179), %s. It covers the confirmed target and nothing else. Every other rule, including those about credentials, tunnels, listeners, remote content and destructive commands, still applies and a refusal is still final.",
	},
	{
		Kind: PentestLocal, Key: TierKey, Type: RelaxTier,
		Title:      "Run under the wider sandbox network (the listed hosts only)",
		Lifts:      "The sandbox network is wider than the model proxy alone: besides the model connection the box can reach only the hosts you listed under \"" + LabelHostList + "\" in " + WhereSandbox + ", through the egress gateway, which still refuses every host-local and private address. Scope beyond that is held by the prompt and your word.",
		Why:        "The app's own dependencies or a tool may need a package registry.",
		PromptLine: "The sandbox's network is wider than usual for this run: besides the model connection the box can reach only these hosts: %s. That is for installing this project's own dependencies. Do not send a request to any host except the confirmed target and these hosts; the scope of the assessment is unchanged.",
	},
	{
		Kind: RedTeamLocal, Key: RuleScanner, Type: RelaxRule,
		Title:      "Allow network and vulnerability scanners",
		Lifts:      "Observer's guard stops network and vulnerability scanners (nmap, masscan, nuclei, sqlmap and similar) and asks you each time. This lifts that one rule for this run, for the project's terminal only. Every other rule still applies.",
		Why:        "Scanners aimed at the confirmed target are the ordinary tools of the exercise.",
		PromptLine: "The developer lifted ONE guardrail for this run only: Observer's guard no longer stops network and vulnerability scanner commands (rule R-179), %s. It covers the confirmed target and nothing else. Every other rule, including those about credentials, tunnels, listeners, remote content and destructive commands, still applies and a refusal is still final.",
	},
	{
		Kind: RedTeamLocal, Key: TierKey, Type: RelaxTier,
		Title:      "Run under the wider sandbox network (the listed hosts only)",
		Lifts:      "The sandbox network is wider than the model proxy alone: besides the model connection the box can reach only the hosts you listed under \"" + LabelHostList + "\" in " + WhereSandbox + ", through the egress gateway, which still refuses every host-local and private address. Scope beyond that is held by the prompt and your word.",
		Why:        "The app's own dependencies or a tool may need a package registry.",
		PromptLine: "The sandbox's network is wider than usual for this run: besides the model connection the box can reach only these hosts: %s. That is for installing this project's own dependencies. Do not send a request to any host except the confirmed target and these hosts; the scope of the assessment is unchanged.",
	},
}

// NeverRelaxedRule is one rule a reader could expect in the table and why it
// is not a row (plan section 13.2).
type NeverRelaxedRule struct {
	ID  string
	Why string
}

var neverRelaxed = []NeverRelaxedRule{
	{"R-177", "one id carries a listener (ask in enforce) and a reverse shell (deny); a local approval is per rule id and would lift both"},
	{"R-178", "a tunnel exposes this machine, and under the internet tier a tunnel client can reach its relay over 443"},
	{"R-174", "cloud metadata endpoints and the deny-hosts list"},
	{"R-170", "remote content piped into an interpreter"},
	{"R-172", "secrets in a network command"},
	{"R-168", "the integrity rule that asks on every use; no grant covers it"},
	{"R-165", "the rule that stops an agent changing the [security] configuration"},
}

// Relaxations returns the table in order.
func Relaxations() []Relaxation { return append([]Relaxation(nil), relaxations...) }

// RelaxationsFor returns a kind's rows in order (none for a kind with no row).
func RelaxationsFor(kind ID) []Relaxation {
	var out []Relaxation
	for _, r := range relaxations {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

// RelaxationFor returns the row for (kind, key).
func RelaxationFor(kind ID, key string) (Relaxation, bool) {
	for _, r := range relaxations {
		if r.Kind == kind && r.Key == key {
			return r, true
		}
	}
	return Relaxation{}, false
}

// NeverRelaxed returns the closed list of rules that are deliberately not
// rows, with the reason.
func NeverRelaxed() []NeverRelaxedRule { return append([]NeverRelaxedRule(nil), neverRelaxed...) }

// RelaxKinds returns the kinds that have at least one row, in table order.
func RelaxKinds() []ID {
	var out []ID
	seen := map[ID]bool{}
	for _, r := range relaxations {
		if !seen[r.Kind] {
			seen[r.Kind] = true
			out = append(out, r.Kind)
		}
	}
	return out
}

// RelaxConfigKey is the [security.assessments] key that gates a kind's rows.
func RelaxConfigKey(kind ID) string { return "relax_" + string(kind) }

// ScopeWords is the phrase a rule row's prompt line carries for a scope.
func ScopeWords(scope string) string {
	switch scope {
	case ScopeProject:
		return "for every session in this project until the run ends"
	case ScopeOrg:
		return "for this project on this machine, under your organization's grant, which ends at its own expiry"
	}
	return "for this terminal's session only"
}

// The relaxation scopes of a local approval.
const (
	ScopeSession = "session"
	ScopeProject = "project"
	// ScopeOrg is the scope of an org grant: machine, project, lane and window.
	ScopeOrg = "org"
)

// InForce is one relaxation as the prompt describes it.
type InForce struct {
	Key   string
	Scope string
	// Hosts is the host list of the tier row.
	Hosts []string
}

// RelaxPromptLines renders the boundary lines a prompt gains for the
// relaxations in force, from the table's own words. An unknown row adds
// nothing.
func RelaxPromptLines(kind ID, in []InForce) []string {
	var out []string
	for _, f := range in {
		row, ok := RelaxationFor(kind, f.Key)
		if !ok {
			continue
		}
		arg := ""
		switch row.Type {
		case RelaxRule:
			arg = ScopeWords(f.Scope)
		case RelaxTier:
			hosts := make([]string, 0, len(f.Hosts))
			for _, h := range f.Hosts {
				if c := clean(h, 80); c != "" {
					hosts = append(hosts, c)
				}
			}
			arg = strings.Join(hosts, ", ")
		}
		out = append(out, strings.Replace(row.PromptLine, "%s", arg, 1))
	}
	return out
}
