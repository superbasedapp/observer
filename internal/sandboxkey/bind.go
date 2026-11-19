package sandboxkey

import "slices"

// bind.go decides WHICH providers a run binds (gap H2 of the 2026-11-18
// sandbox terminal gaps): a run gets one sentinel per bound provider, each
// in that provider's own key variable, and the proxy swaps a sentinel only
// for its own provider's key on that provider's own host (match.go). Before
// it a run bound exactly one provider, so only a tool whose model catalogue
// is locked to one vendor could use injection.
//
// Every rule reads the tool's capability row as the caller resolved it
// (ToolRoute), never a tool name.

// ToolRoute is what a tool's capability row says about the providers its
// model requests use, read by the caller from internal/integration.
type ToolRoute struct {
	// VendorLocked: the tool's model catalogue is locked to its vendor's
	// providers (Families).
	VendorLocked bool
	Families     []string
	// Routed: the tool has a proxy route Observer drives (its model
	// requests reach the proxy, where a sentinel can be swapped).
	Routed bool
	// RouteProviders, when not nil, are the providers the registry says the
	// route carries (the covered built-in provider overrides, and the
	// provider of the host a route lane addresses). Nil: the registry says
	// nothing about which providers the route carries.
	RouteProviders []string
}

// toolProviderRule is one row: when match holds, providers decides.
type toolProviderRule struct {
	name      string
	match     func(ToolRoute) bool
	providers func(ToolRoute) []string
}

// usableRules decide which providers' keys a tool can use at all (an
// in-box custody copies only these): a vendor-locked tool its vendor's,
// any other tool every provider the table knows.
var usableRules = []toolProviderRule{
	{"vendor locked", func(t ToolRoute) bool { return t.VendorLocked }, func(t ToolRoute) []string { return Known(t.Families) }},
	{"any provider", func(ToolRoute) bool { return true }, func(ToolRoute) []string { return allIDs() }},
}

// injectableRules decide which providers injection may bind for a tool:
// the usable ones whose requests can reach the proxy. A vendor-locked tool
// keeps its vendor's providers whatever its route says (the rule every
// launch that ran before was decided by); a tool with no proxy route gets
// none (its requests never reach the proxy, so a sentinel would only be
// refused by the provider); a route the registry describes narrows the
// set to what it carries; otherwise every usable provider.
var injectableRules = []toolProviderRule{
	{"vendor locked", func(t ToolRoute) bool { return t.VendorLocked }, func(t ToolRoute) []string { return Known(t.Families) }},
	{"no proxy route", func(t ToolRoute) bool { return !t.Routed }, func(ToolRoute) []string { return nil }},
	{"route names its providers", func(t ToolRoute) bool { return t.RouteProviders != nil }, func(t ToolRoute) []string { return Known(t.RouteProviders) }},
	{"any provider", func(ToolRoute) bool { return true }, func(ToolRoute) []string { return allIDs() }},
}

func walkToolRules(rules []toolProviderRule, t ToolRoute) []string {
	for _, r := range rules {
		if r.match(t) {
			return r.providers(t)
		}
	}
	return nil
}

// UsableProviders are the providers whose keys a tool can use, in table
// order.
func UsableProviders(t ToolRoute) []string { return walkToolRules(usableRules, t) }

// InjectableProviders are the providers credential injection may bind for
// a tool, in table order (empty: injection cannot serve the tool).
func InjectableProviders(t ToolRoute) []string { return walkToolRules(injectableRules, t) }

// BindFacts are what a hosted run's setup read: the injectable providers of
// its tool, the providers with a stored key (ids only), and whether the org
// AI Gateway route puts the org's own key on the run's requests.
type BindFacts struct {
	Candidates []string
	Stored     []string
	OrgRoute   bool
}

// bindRule is one row: when match holds, bind decides.
type bindRule struct {
	name  string
	match func(BindFacts) bool
	bind  func(BindFacts) []string
}

// bindRules are walked top-down. Under the org route a tool with exactly
// one injectable provider still gets its sentinel with no key stored, so
// it starts and the gateway replaces the sentinel (FX3 item 5, F-L3P4-4);
// a tool with several gets a sentinel only for a provider whose key the
// person stored (never one for every provider the table knows, which would
// make the tool believe every provider is set up). Without the org route,
// only a stored key is bound.
var bindRules = []bindRule{
	{"org route, one provider", func(f BindFacts) bool { return f.OrgRoute && len(Known(f.Candidates)) == 1 }, func(f BindFacts) []string { return Known(f.Candidates) }},
	{"stored keys", func(BindFacts) bool { return true }, func(f BindFacts) []string { return Intersect(f.Candidates, f.Stored) }},
}

// BindProviders is the set of providers a hosted run binds, in table order
// (empty: none).
func BindProviders(f BindFacts) []string {
	for _, r := range bindRules {
		if r.match(f) {
			return r.bind(f)
		}
	}
	return nil
}

// LocalBindFacts are what a local run's host helper read: the injectable
// providers of its tool, the providers with a stored key, and the names of
// the variables of the box env it was launched with (names only).
type LocalBindFacts struct {
	Candidates []string
	Stored     []string
	EnvNames   []string
}

// BindLocal is the set of providers a local run binds, in table order; nil
// leaves the run without a lane (its env exactly as launched). A provider
// is bound when its key variable is in the env (never added: a tool signed
// in with a subscription is not moved onto API-key billing) and its key is
// stored. The lane stays closed when the env carries a credential variable
// of a provider the tool can use that is not bound: the lane's box env
// drops every credential it does not replace (BoxEnvSet), so opening it
// would take away a key the tool works with today.
func BindLocal(f LocalBindFacts) []string {
	var bound []string
	for _, id := range Known(f.Candidates) {
		p, _ := ProviderFor(id)
		if slices.Contains(f.EnvNames, p.KeyEnv) && slices.Contains(f.Stored, id) {
			bound = append(bound, id)
		}
	}
	if len(bound) == 0 {
		return nil
	}
	for _, n := range f.EnvNames {
		if owner := CredEnvProvider(n); owner != "" && slices.Contains(f.Candidates, owner) && !slices.Contains(bound, owner) {
			return nil
		}
	}
	return bound
}
