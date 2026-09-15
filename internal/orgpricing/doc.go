// Package orgpricing resolves ONE question, once, for the whole node: does
// this machine apply the org's negotiated prices, and do they sit above or
// below the developer's own overrides?
//
// It exists because the answer is needed in three places that must never
// disagree — the daemon's cost engine (which stamps api_turns.cost_usd at
// capture), the org-push pricer (which stamps token_usage.estimated_cost_usd
// on the way out), and every standalone CLI constructor (`observer cost`,
// `observer report`, the MCP server) — and because deriving it separately at
// each of them is exactly how `observer cost` ends up disagreeing with the
// dashboard about what a session cost (plan §3.3 / N5).
//
// It is PURE: no SQL, no HTTP, no fsnotify, no clock. The two inputs arrive
// as values — the node's own [guard.budget] block and whether its governance
// grant carries enforce.budget — and the two outputs are booleans. Nothing
// here knows what a rate is.
//
// The RULING it encodes (R2 + R3, docs/plans/enterprise-pricing-and-admin-
// assistant-plan-2026-09-08.md §6):
//
//   - Pricing rides the BUDGET opt-in, [guard.budget].from_org. A second
//     switch would let a node enforce an org cap while pricing every turn at
//     list rates, which is the exact defect the arc exists to remove: the cap
//     would be a number in a unit nobody agreed on.
//   - On an INDIVIDUAL node the org's rates go UNDER the developer's explicit
//     [intelligence.pricing] overrides. On a MANAGED node holding
//     enforce.budget they go OVER them, because otherwise one TOML key would
//     be enough to re-price out from under an org cap.
package orgpricing
