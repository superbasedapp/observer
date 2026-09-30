package shellwrap

import "github.com/marmutapp/superbased-observer/internal/integration"

// Honesty is what wrapping a command actually buys, derived from the
// WrappedCommand capability shape (backlog item 8's rendering rule). Closed
// vocabulary; every surface renders HonestyText, never its own phrasing.
type Honesty string

const (
	// HonestyRouted: the wrapped form routes model traffic through the
	// observer proxy and a live turn through it has landed an api_turns row.
	HonestyRouted Honesty = "routed"
	// HonestyProofOwed: the wrapped form injects routing, but no live turn
	// has been proven through it yet.
	HonestyProofOwed Honesty = "proof_owed"
	// HonestyLaunchOnly: the wrapped form launches the same thing; routing is
	// unchanged (capture still rides the tool's own store / hooks).
	HonestyLaunchOnly Honesty = "launch_only"
)

// honestyRule is one row of the ordered classification table (first match
// wins, one test case per row - CLAUDE.md #5).
type honestyRule struct {
	outcome Honesty
	text    string
	match   func(w integration.WrappedCommand) bool
}

var honestyRules = []honestyRule{
	{HonestyLaunchOnly, "launches, no routing", func(w integration.WrappedCommand) bool { return !w.Routes }},
	{HonestyProofOwed, "wrapped, live proof owed", func(w integration.WrappedCommand) bool { return !w.TrafficProven }},
	{HonestyRouted, "routed through the observer proxy", func(integration.WrappedCommand) bool { return true }},
}

// HonestyFor classifies a wrapped command.
func HonestyFor(w integration.WrappedCommand) (Honesty, string) {
	for _, r := range honestyRules {
		if r.match(w) {
			return r.outcome, r.text
		}
	}
	return HonestyLaunchOnly, "launches, no routing"
}
