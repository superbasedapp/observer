package sandboxkey

import (
	"slices"
	"strings"
)

// custody.go holds the provider_injected custody rules (sandbox plan v2
// section 7.2, decision 4 of lane GATES-SBX): a hosted vendor's own secret
// broker swaps a placeholder for the real key on egress, so the key lives in
// the vendor's control plane and the agent can reach the model host past
// any in-box proxy. The custody is offered only for a vendor whose public
// documentation describes such a broker AND whose broker client Observer
// has built; it is refused while the org enforces budgets on the node (the
// counts would be box-reported), under the org's provider_key_injection =
// forbidden, and on a managed node the org did not allow it on; and a run
// under it captures at most proxy_and_transcripts (rule C2).

// BrokerStatus is how far a vendor's broker row is grounded and built.
type BrokerStatus string

// The closed BrokerStatus vocabulary.
const (
	// BrokerDocumentedNotBuilt: the vendor documents a broker; Observer has
	// no client for it yet, so the custody stays unoffered.
	BrokerDocumentedNotBuilt BrokerStatus = "documented_not_built"
	// BrokerBuilt: documented, and Observer drives it.
	BrokerBuilt BrokerStatus = "built"
)

// Broker is one vendor's documented secret broker.
type Broker struct {
	Vendor string
	// Mechanism is the documented shape, in a sentence.
	Mechanism string
	// Docs is the vendor's own documentation page; ReadOn is when it was
	// read and how.
	Docs   string
	ReadOn string
	// Caveats are what the documentation says that bears on custody.
	Caveats string
	Status  BrokerStatus
}

// brokers is the vendor table. Rows are added only with a citation; a
// vendor not here (Modal: its documentation shows a proxy sidecar the user
// runs inside the sandbox, which is in-box custody, not a vendor broker)
// never offers the custody.
var brokers = []Broker{
	{
		Vendor:    "e2b",
		Mechanism: "secrets stored with E2B and referenced by name in a network rule; E2B's egress proxy puts the real value into matching outbound HTTPS request headers outside the sandbox, so the sandbox holds only the reference",
		Docs:      "https://docs.e2b.dev/secrets/inject",
		ReadOn:    "2026-10-24, through a web search summary of the page (the page itself could not be fetched from the build sandbox)",
		Caveats:   "private beta; an unresolved reference fails open (the request is forwarded with the header omitted); network rules do not restrict egress on their own",
		Status:    BrokerDocumentedNotBuilt,
	},
	{
		Vendor:    "vercel",
		Mechanism: "a transform block in the sandbox's networkPolicy adds or replaces headers on outbound HTTPS requests to matching domains, from a value the sandbox never sees; the rules can be changed on a running sandbox",
		Docs:      "https://vercel.com/docs/sandbox/concepts/firewall",
		ReadOn:    "2026-10-24, through a web search summary of the page and of https://vercel.com/changelog/safely-inject-credentials-in-http-headers-with-vercel-sandbox (neither could be fetched from the build sandbox)",
		Caveats:   "the header is added for any request to the matching domain, so the agent can call the model host directly",
		Status:    BrokerDocumentedNotBuilt,
	},
}

// Brokers returns the vendor table (a copy).
func Brokers() []Broker { return append([]Broker(nil), brokers...) }

// BrokerFor returns vendor's row.
func BrokerFor(vendor string) (Broker, bool) {
	for _, b := range brokers {
		if b.Vendor == strings.ToLower(strings.TrimSpace(vendor)) {
			return b, true
		}
	}
	return Broker{}, false
}

// Offered reports whether provider_injected may be offered for vendor: a
// cited broker that Observer drives.
func Offered(vendor string) bool {
	b, ok := BrokerFor(vendor)
	return ok && b.Docs != "" && b.ReadOn != "" && b.Status == BrokerBuilt
}

// InjectedFacts are what the caller read about a provider_injected launch.
type InjectedFacts struct {
	Vendor string
	// Offered is Offered(Vendor), or a test's stand-in.
	Offered bool
	// OrgBudgetsEnforced: the node takes its budget caps from the org
	// ([guard.budget].from_org with caps in force, B-621 to B-624).
	OrgBudgetsEnforced bool
	// OrgForbids: the org's provider_key_injection = forbidden is in force.
	OrgForbids bool
	// Managed: the node is org-managed; OrgAllowed: the org explicitly
	// allowed the custody (no such org value exists yet, so false).
	Managed    bool
	OrgAllowed bool
}

// The provider_injected refusal codes (the selection table's spellings).
const (
	CodeCustodyNotOffered = "custody_unsatisfiable"
	CodeCustodyNotAllowed = "custody_not_allowed"
)

// custodyRule is one refusal row.
type custodyRule struct {
	refuse bool
	code   string
	why    string
}

// InjectedRefusal walks the provider_injected rules top-down; ok false is a
// refusal with its code and reason.
func InjectedRefusal(f InjectedFacts) (code, reason string, ok bool) {
	why := "no documented and built broker"
	if b, found := BrokerFor(f.Vendor); found {
		why = "its broker is " + string(b.Status) + " (" + b.Docs + ")"
	}
	rules := []custodyRule{
		{!f.Offered, CodeCustodyNotOffered, "provider_injected is not offered for " + f.Vendor + ": " + why},
		{f.OrgForbids, CodeCustodyNotAllowed, "your organization forbids provider key injection (provider_key_injection = forbidden)"},
		{f.OrgBudgetsEnforced, CodeCustodyNotAllowed, "your organization enforces budgets on this machine, and a provider-injected run's token counts are reported by the box, which could evade a cap"},
		{f.Managed && !f.OrgAllowed, CodeCustodyNotAllowed, "this machine is managed by your organization, which has not allowed provider key injection"},
	}
	for _, r := range rules {
		if r.refuse {
			return r.code, r.why, false
		}
	}
	return "", "", true
}

// InjectedCaptureCeiling is the most a provider_injected run captures (C2).
const InjectedCaptureCeiling = "proxy_and_transcripts"

// Disclosure is the consent screen's text for a custody, stated before the
// first upload together with the computed capture level. For home_relay,
// providers are the stored keys a run may bind (ids; gap H2): each is named,
// so the screen says which of the person's keys a run can use before the
// first upload. With none named the text is the one-provider text it was.
func Disclosure(custody, vendor, capture string, providers ...string) string {
	switch custody {
	case "provider_injected":
		return "Key custody: provider_injected. Your model key is stored in " + vendor + "'s secret broker, which adds it to requests leaving the box for the model host. " +
			"The agent can call the model host directly, past Observer's proxy, so token counts come from the box: capture is at most " + InjectedCaptureCeiling +
			" (this run: " + capture + "). Teardown deletes the broker rule and checks it is gone."
	case "home_relay":
		if ids := Known(providers); len(ids) > 0 {
			return "Key custody: home_relay. Your model keys stay on this machine. Keys a run can use: " + ProviderLabels(ids, "and") + ". " +
				"For each of those its agent uses, the box holds only a sentinel, which Observer's proxy swaps for that key only on requests to that provider's own model host. " +
				"Capture: " + capture + "."
		}
		return "Key custody: home_relay. Your model key stays on this machine; the box holds only a sentinel that Observer's proxy swaps for your key on requests to the model host. " +
			"Capture: " + capture + "."
	case custodyAuto:
		// Decision SBXD-1: the rule is stated once, so a resolution that
		// differs per tool needs no second consent. providers are the stored
		// keys a run can use (kept home, or put in the box for a tool that
		// nothing here serves).
		line := "Key custody: auto. For each agent, its model key stays on this machine when Observer can add it here (a key you stored for a provider the agent's requests go through Observer for, or your organization's AI gateway), and the box then holds only a sentinel. " +
			"Otherwise the agent's API key is put in the box, where the agent and anyone with access to the box can read it. The New Terminal dialog says which one each launch uses before Start."
		if ids := Known(providers); len(ids) > 0 {
			line += " Keys a run can use: " + ProviderLabels(ids, "and") + "."
		}
		return line + " Capture: " + capture + "."
	}
	return "Key custody: " + custody + ". Capture: " + capture + "."
}

// OptInDisclosure is the consent screen's sentence for the opted-in in-box
// key sources of decision SBXD-4, by tool display name: the keys a tool
// saved itself (toolKeys) and the login access token (loginSeed). "" when
// neither is opted in.
func OptInDisclosure(toolKeys, loginSeed []string) string {
	var parts []string
	if len(toolKeys) > 0 {
		parts = append(parts, "when the key is put in the box, the keys "+joinWords(toolKeys)+" saved in "+pluralOwn(len(toolKeys))+" key file are put in the box too")
	}
	if len(loginSeed) > 0 {
		parts = append(parts, "the login of "+joinWords(loginSeed)+" is copied into the box: only its short-lived access token, never the refresh token, and only while it has not expired")
	}
	if len(parts) == 0 {
		return ""
	}
	return "Also: " + strings.Join(parts, "; ") + "."
}

func pluralOwn(n int) string {
	if n == 1 {
		return "its own"
	}
	return "their own"
}

// InBoxDisclosure is the consent screen's credential line for an in-box API
// key (gap H3): where the keys come from, by provider name, and who can read
// them. env are the providers whose API-key variable the daemon's
// environment holds, stored those whose key the person stored for the box
// to use where the environment has none (ids).
func InBoxDisclosure(env, stored []string) string {
	line := "an API key is placed in the box environment, readable by the agent and by anyone with access to the box; revoke it with its provider after the run if in doubt"
	env, stored = Known(env), Known(stored)
	var fromStore []string
	for _, id := range stored {
		if !slices.Contains(env, id) {
			fromStore = append(fromStore, id)
		}
	}
	switch {
	case len(env) == 0 && len(fromStore) == 0:
		return line + ". No API key was found on this machine, so the agent starts without one"
	case len(fromStore) == 0:
		return line + ". From this machine's environment: " + ProviderLabels(env, "and")
	case len(env) == 0:
		return line + ". From the keys you stored on this machine: " + ProviderLabels(fromStore, "and")
	}
	return line + ". From this machine's environment: " + ProviderLabels(env, "and") + "; from the keys you stored on this machine: " + ProviderLabels(fromStore, "and")
}
