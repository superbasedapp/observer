package sandboxadvise

import "strings"

// HostListKey is the config key an offer adds a host to (and the key an
// organization pin of the host list uses, the same name).
const HostListKey = "terminal.sandbox.egress_allow_hosts"

// Scope names what an applied offer covers. The host list has no
// per-project form today ([terminal.sandbox] is one block per node), so the
// narrowest existing scope is the node: every sandboxed run on this
// computer launched after the save.
type Scope string

// ScopeNode is the only scope an offer has today.
const ScopeNode Scope = "node"

// ScopeLabel is the plain-words description of a scope, for the dashboard.
func ScopeLabel(s Scope) string {
	switch s {
	case ScopeNode:
		return "every sandboxed run on this computer that starts after the save"
	default:
		return string(s)
	}
}

// Reason is the closed vocabulary of an offer decision.
type Reason string

// The Reason vocabulary.
const (
	// ReasonOfferable: the owner may allow the host.
	ReasonOfferable Reason = "offerable"
	// ReasonRuleNotOfferable: the refusal's rule is not an allow-list miss.
	ReasonRuleNotOfferable Reason = "rule_not_offerable"
	// ReasonNotTheHostList: the refusal names another host list than the
	// owner's (the first-start install step's install hosts, tracker
	// F-009, audit finding N1-A11), which the owner's list does not change.
	ReasonNotTheHostList Reason = "not_the_host_list"
	// ReasonHostNotListable: the host cannot be written to the list (not a
	// lowercase host name the config accepts, or the gateway would still
	// refuse it with no pin in force).
	ReasonHostNotListable Reason = "host_not_listable"
	// ReasonOrgPinRefuses: with the host added, the organization's pin of
	// the host list still leaves it out.
	ReasonOrgPinRefuses Reason = "org_pin_refuses"
	// ReasonAlreadyAllowed: the config the gateway reads today already lets
	// the host through, so there is nothing to add (and adding it to an
	// empty list would narrow every run to this one host).
	ReasonAlreadyAllowed Reason = "already_allowed"
	// ReasonProviderHost: the host is a model-provider host (or a
	// subdomain of one, or one of the proxy's configured upstreams), the
	// set the gateway's provider block refuses. A refusal stored as an
	// allow-list miss can still name one, because the gateway checks the
	// host list before the provider block; listing it would let a run
	// whose provider_direct allows it reach the provider directly instead
	// of through the model proxy, so it is never offered.
	ReasonProviderHost Reason = "provider_host"
	// ReasonConfigNotWritable: the dashboard has no config file to save to.
	ReasonConfigNotWritable Reason = "config_not_writable"
	// ReasonNotInBuild: this build has no gateway host check to ask.
	ReasonNotInBuild Reason = "not_in_build"
)

// ruleRow is one refusal rule's offer policy.
type ruleRow struct {
	rule      string
	offerable bool
	why       string
}

// ruleRows is the closed refusal vocabulary (internal/sandboxnet/refusal.go,
// the frozen N1 contract) with each rule's offer policy, one row per rule.
// Only an allow-list miss is ever offered: every other rule is a floor no
// owner allow-list lifts, or a different key's decision.
var ruleRows = []ruleRow{
	{"allow-list-miss", true, ""},
	{"private-range", false, "A private address is opened by its own address-range list, never by the host allow-list."},
	{"provider-host", false, "Model provider hosts are reached through the model proxy only; they are never added to the host allow-list."},
	{"host-local", false, "This computer's own addresses are never reachable from a sandboxed run."},
	{"tier-none", false, "This run's network tier has no network at all; no host list changes that."},
	{"ssrf-floor", false, "Loopback, link-local and similar addresses are refused under every setting."},
	{"literal-ip", false, "The host allow-list names hosts, not IP addresses."},
	{"port-not-allowed", false, "Only ports 443 and 80 are reachable under a host list; allowing the host does not change the port."},
	{"tls-server-name", false, "The connection's TLS server name was missing or named another host; allowing the host does not change that."},
}

// Rules returns the refusal rules the table knows, in its fixed order.
func Rules() []string {
	out := make([]string, len(ruleRows))
	for i, r := range ruleRows {
		out[i] = r.rule
	}
	return out
}

// Facts are what the dashboard found out about one refusal, from the
// config the gateway reads and the gateway's own host check.
type Facts struct {
	// Rule is the refusal's stored rule.
	Rule string
	// Key is the refusal's stored key (the list that decided); empty is
	// read as the owner's host list, as every allow-list miss named it
	// before the install step's gateway reported.
	Key string
	// InBuild is true when the build has the gateway host check.
	InBuild bool
	// ConfigWritable is true when the dashboard has a config file to save.
	ConfigWritable bool
	// AlreadyAllowed is true when the config the gateway reads today lets
	// the host through.
	AlreadyAllowed bool
	// HostListable is true when the owner's list with the host added still
	// validates.
	HostListable bool
	// AllowedAfter is true when, with the host added to the owner's list
	// and the organization's pins applied the way the gateway's config load
	// applies them, the gateway's host check lets the host through.
	AllowedAfter bool
	// PinInForce is true when an organization pin of the host list is in
	// force on this node.
	PinInForce bool
	// ProviderHost is true when the host is in the model-provider host set
	// the gateway's provider block refuses (asked through the same
	// sandboxvocab match the block uses).
	ProviderHost bool
}

// Offer is the decision for one refusal. Explain (tracker F-013, audit
// finding N5-A6) is the capability a surface branches on instead of the
// rule's name: true when the refusal's rule is one an owner could lift
// with the host list (its rule row is offerable), so a not-offered answer
// is worth showing with its message; false for a rule no host list ever
// lifts, whose row shows nothing. Additive: an older client ignores it.
type Offer struct {
	Offerable bool   `json:"offerable"`
	Reason    Reason `json:"reason"`
	Message   string `json:"message,omitempty"`
	Explain   bool   `json:"explain"`
}

// decideRow is one step of the ordered decision table: the first row whose
// when holds decides.
type decideRow struct {
	reason Reason
	when   func(f Facts, rule *ruleRow) bool
	msg    func(rule *ruleRow) string
}

func fixed(s string) func(*ruleRow) string { return func(*ruleRow) string { return s } }

// decideRows is the decision table, walked top-down.
var decideRows = []decideRow{
	{ReasonNotInBuild, func(f Facts, _ *ruleRow) bool { return !f.InBuild }, fixed("This build has no sandbox egress gateway.")},
	{ReasonRuleNotOfferable, func(_ Facts, r *ruleRow) bool { return r == nil }, fixed("This build does not know the refusal's rule, so it offers nothing for it.")},
	{ReasonRuleNotOfferable, func(_ Facts, r *ruleRow) bool { return !r.offerable }, func(r *ruleRow) string { return r.why }},
	{ReasonNotTheHostList, func(f Facts, _ *ruleRow) bool { return f.Key != "" && f.Key != HostListKey }, fixed("This host was refused by another host list than yours (a first-start tool install, whose hosts are the tool's own install hosts), so adding it to your host allow-list would change nothing.")},
	{ReasonProviderHost, func(f Facts, _ *ruleRow) bool { return f.ProviderHost }, fixed("This is a model provider host. Model calls go through the model proxy only, so it is never added to the host allow-list.")},
	{ReasonAlreadyAllowed, func(f Facts, _ *ruleRow) bool { return f.AlreadyAllowed }, fixed("The current settings already let this host through for new runs.")},
	{ReasonHostNotListable, func(f Facts, _ *ruleRow) bool { return !f.HostListable }, fixed("This host name cannot be written to the host allow-list.")},
	{ReasonOrgPinRefuses, func(f Facts, _ *ruleRow) bool { return !f.AllowedAfter && f.PinInForce }, fixed("Your organization's host list does not include this host, so allowing it here would change nothing. Ask your organization.")},
	{ReasonHostNotListable, func(f Facts, _ *ruleRow) bool { return !f.AllowedAfter }, fixed("The egress gateway would still refuse this host after it is listed.")},
	{ReasonConfigNotWritable, func(f Facts, _ *ruleRow) bool { return !f.ConfigWritable }, fixed("The dashboard has no config file to save to.")},
}

// Decide walks the decision table for one refusal. A refusal reaches
// ReasonOfferable only when no row refuses it.
func Decide(f Facts) Offer {
	rule := lookupRule(f.Rule)
	explain := rule != nil && rule.offerable
	for _, row := range decideRows {
		if row.when(f, rule) {
			return Offer{Reason: row.reason, Message: row.msg(rule), Explain: explain}
		}
	}
	return Offer{Offerable: true, Reason: ReasonOfferable, Explain: explain}
}

func lookupRule(rule string) *ruleRow {
	for i := range ruleRows {
		if ruleRows[i].rule == rule {
			return &ruleRows[i]
		}
	}
	return nil
}

// NormalizeHost is the form an offer adds to the list: the stored host
// trimmed and lowercased (the gateway compares names lowercased, and the
// config accepts only lowercase names).
func NormalizeHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

// WithHost returns list with host appended, unless it is already there.
// The result is a new slice; list is never changed.
func WithHost(list []string, host string) []string {
	out := append(make([]string, 0, len(list)+1), list...)
	for _, h := range list {
		if h == host {
			return out
		}
	}
	return append(out, host)
}
