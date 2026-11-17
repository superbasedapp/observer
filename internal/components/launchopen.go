package components

import "sort"

// launchOpen is the explicit list of components a pooled host runs at launch
// IN ADDITION to the compiled defaults, when no availability envelope has
// ever been verified (plan 06 18.3.3 "The pooled launch floor"). It is
// reviewed in code. It is not "stable only": that would switch off the
// vendor pollers and the Plane A OTLP gateway, which the Business plan sells
// (plan 06 8.3). Every id here must be offerable in pooled (ReachPooledOffer);
// the floor can never open what a row's Reach does not allow.
var launchOpen = []string{
	"org.planea.gateway",
	"org.pollers.cc",
	"org.pollers.codex",
	"org.pollers.copilot",
	"org.pollers.cortex",
	"org.pollers.cursor",
	"org.pollers.kimchi",
	"org.pollers.m365",
	// Wave 17 lane pooled-integrations: the Integrations and vendor-exports
	// admin pages, on the request seam; staff close them with the deny list
	// or the envelope.
	"org.vendorconn",
}

// LaunchOpen returns the launch-open ids, sorted.
func LaunchOpen() []string {
	out := append([]string(nil), launchOpen...)
	sort.Strings(out)
	return out
}

// PooledFloor returns the ids of rows a pooled host runs with no verified
// envelope: every row whose Reach is on in pooled, plus the launch-open list
// (restricted to rows that are offerable in pooled), sorted. Core is
// included; the resolver never blocks it.
func PooledFloor(rows []Component) []string {
	open := toSet(launchOpen)
	var out []string
	for _, c := range rows {
		if c.Class == ClassCore || c.Reach.Has(ReachPooled) || (open[c.ID] && c.Reach.Has(ReachPooledOffer)) {
			out = append(out, c.ID)
		}
	}
	sort.Strings(out)
	return out
}
