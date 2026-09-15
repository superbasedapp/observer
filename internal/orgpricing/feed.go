package orgpricing

// FeedApplies resolves, ONCE for the whole node, whether the PUBLIC pricing
// feed (docs/plans/pricing-sync-tokenomics-to-platform-plan-2026-09-11.md §C.3 /
// D8) should be consulted and applied on this machine.
//
// It exists for the same reason Mode does: the answer is needed in more than
// one place that must never disagree — the cost-engine loader that composes the
// feed rows at construction, and the `observer pricing sync` command that
// decides whether to fetch at all — and deriving it separately at each is how a
// sync that refused would still end up with feed rows in the engine, or vice
// versa.
//
// The RULING it encodes (§C.3 / D8): an ORG-ENROLLED node (individual or
// managed) IGNORES the public feed entirely. Its prices arrive through the org
// rail (internal/orgclient's FetchPricingPolicy -> org_pricing_cache), which is
// the ONE authority per enrolled node — "a managed node receives prices only
// through its org rail". Consulting a second, public source would give an
// enrolled node two answers to "what does a token cost", which is precisely the
// split the org rail exists to prevent. So the feed applies if and ONLY if the
// node is standalone (not enrolled).
//
// Note what this does NOT gate on: [guard.budget].from_org. That switch governs
// the ORG rail (via Mode); it is irrelevant to the public feed. An enrolled
// node with from_org=false still ignores the public feed — it simply prices at
// seed+local, because it has deliberately declined BOTH its org's rates and the
// public list. The feed is not a fallback for a node that opted out of its
// org's prices; it is the standalone case only.
//
// It is PURE: the one input (is this node enrolled with an org) arrives as a
// value, resolved at the daemon/CLI boundary from store.LoadEnrolment, and the
// output is a boolean. Nothing here touches a database, a clock, or a rate.
func FeedApplies(enrolled bool) bool {
	return !enrolled
}
