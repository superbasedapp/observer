package govern

import "sort"

// The [org_client.share] key -> extraction-tier ownership table (W-8). ONE
// owner maps each of the 21 internal/policyfam/nodegov.ShareKeys keys to the
// extraction authority that authorizes RAISING it on a managed node — the
// same authority governance_wire.go's lowerShareOptions gates its RaiseBool
// calls on, so the push seam and every transparency surface (the Privacy
// page's "in force" column, P4-2's node.governance ExtractionEffective wire
// field) read the raise gate off ONE table and can never disagree.
//
// The 21 key-string literals are duplicated here rather than imported from
// internal/policyfam/nodegov, following the same convention
// authorityFamilyTable already uses (see authorityfamilies.go's doc comment)
// for a small closed vocabulary owned by a sibling package: govern already
// reads these exact strings as Effective.Share map keys in LowerBool/
// RaiseBool/ShareDirective, so this table is documenting govern's OWN
// closed vocabulary, not reaching into nodegov's.
//
// policy_state and target_action_allowlist USED TO be shareTierExempt
// entries — this was a real gap, not a design choice, closed by the Plane B
// dual-mode gateway / RBAC-IA design (2026-08-29, §5.3):
//
//   - policy_state now raises under its own AuthorityExtractPolicyState
//     token (GrantsPolicyStateExtraction). It was previously believed to be
//     permanently exempt because "the channel exists to tell the org what
//     the node is doing, not the other way around" — but an org can still
//     LEGITIMATELY want the node to report richer effective-policy-state
//     detail once explicitly authorized, exactly like any other extraction
//     tier; there was simply no token minted for it yet.
//   - target_action_allowlist now raises under AuthorityExtractTargetActions
//     via RaiseList (share.go) — the missing boolean-only-RaiseBool premise
//     that justified the exemption no longer holds now that RaiseList's
//     union-semantics sibling exists.
//
// shareTierExempt is now empty but kept as a live, tested map (rather than
// deleted) so a FUTURE genuinely-exempt key has an obvious, already-covered
// home, and so TestShareTierTable_EveryShareKeyMapsOrIsExempt keeps
// enforcing the bidirectional drift guard even when the exempt set is empty.
var shareTierTable = []shareTierRow{
	{Key: "full_tool_bodies", Authority: AuthorityExtractToolBodies, Authorized: Effective.GrantsToolBodiesExtraction},
	{Key: "full_content", Authority: AuthorityExtractFolders, Authorized: Effective.GrantsFoldersExtraction},
	{Key: "routing_summary", Authority: AuthorityExtractRouting, Authorized: Effective.GrantsRoutingExtraction},
	{Key: "cache_detail", Authority: AuthorityExtractCache, Authorized: Effective.GrantsCacheExtraction},
	{Key: "routing_detail", Authority: AuthorityExtractRouting, Authorized: Effective.GrantsRoutingExtraction},
	{Key: "limit_gauge", Authority: AuthorityExtractPredictions, Authorized: Effective.GrantsPredictionsExtraction},
	{Key: "codeintel_detail", Authority: AuthorityExtractCodeintel, Authorized: Effective.GrantsCodeintelExtraction},
	{Key: "process_detail", Authority: AuthorityExtractProcess, Authorized: Effective.GrantsProcessExtraction},
	{Key: "terminal_detail", Authority: AuthorityExtractTerminal, Authorized: Effective.GrantsTerminalExtraction},
	{Key: "task_detail", Authority: AuthorityExtractTasks, Authorized: Effective.GrantsTasksExtraction},
	{Key: "tool_account_detail", Authority: AuthorityExtractToolAccounts, Authorized: Effective.GrantsToolAccountsExtraction},
	{Key: "intelligence.org_enrichment", Authority: AuthorityExtractIntel, Authorized: Effective.GrantsIntelExtraction},
	{Key: "obs.summary", Authority: AuthorityExtractTraces, Authorized: Effective.GrantsTracesExtraction},
	{Key: "obs.traces", Authority: AuthorityExtractTraces, Authorized: Effective.GrantsTracesExtraction},
	{Key: "obs.content", Authority: AuthorityExtractTraces, Authorized: Effective.GrantsTracesExtraction},
	{Key: "obs.eval_summary", Authority: AuthorityExtractTraces, Authorized: Effective.GrantsTracesExtraction},
	{Key: "obs.admission", Authority: AuthorityExtractTraces, Authorized: Effective.GrantsTracesExtraction},
	{Key: "obs.eval_items", Authority: AuthorityExtractTraces, Authorized: Effective.GrantsTracesExtraction},
	{Key: "obs.egress", Authority: AuthorityExtractObsEgress, Authorized: Effective.GrantsObsEgressExtraction},
	{Key: "policy_state", Authority: AuthorityExtractPolicyState, Authorized: Effective.GrantsPolicyStateExtraction},
	{Key: "target_action_allowlist", Authority: AuthorityExtractTargetActions, Authorized: Effective.GrantsTargetActionsExtraction},
}

// shareTierExempt is the "known and consciously unmapped" set. It is empty
// as of the Plane B dual-mode gateway / RBAC-IA design (2026-08-29): the two
// keys it used to carry (policy_state, target_action_allowlist) turned out to
// be a real gap rather than a permanent design choice — see shareTierTable's
// doc comment. TestShareTierTable_EveryShareKeyMapsOrIsExempt is the drift
// guard: a nodegov.ShareKeys row that lands in neither this map nor
// shareTierTable fails loudly instead of ExtractionAuthorized silently
// reporting false for it.
var shareTierExempt = map[string]bool{}

// shareTierRow is one row of shareTierTable.
type shareTierRow struct {
	// Key is the nodegov.ShareKey.Key literal this row governs. It is
	// relative to [org_client.share] for every row EXCEPT the one whose
	// nodegov.ShareKey carries an explicit ConfigPath
	// ("intelligence.org_enrichment", rooted under [intelligence]); the key
	// string itself is still the vocabulary identifier both tables share.
	Key string
	// Authority is the extraction authority string this tier's raise is
	// documented against. It is recorded for the drift test
	// (TestShareTierTable_EveryAuthorityIsAnExtractionAuthority) and for
	// readers of this table, NOT as the source of truth for the gate —
	// Authorized is. A headline row's Authorized also accepts the
	// extract.managed umbrella alias even though Authority names only its
	// own per-tier value, exactly like Effective.GrantsXxxExtraction's own
	// doc comments describe.
	Authority string
	// Authorized is the actual per-tier gate — always a method EXPRESSION
	// over Effective (e.g. Effective.GrantsCacheExtraction), never a
	// hand-rolled closure, so this table can never drift from the exact
	// predicates lowerShareOptions itself calls to raise a tier.
	Authorized func(Effective) bool
}

var shareTierByKey = func() map[string]shareTierRow {
	m := make(map[string]shareTierRow, len(shareTierTable))
	for _, row := range shareTierTable {
		m[row.Key] = row
	}
	return m
}()

// ExtractionAuthorized reports whether e's resolved posture currently
// authorizes RAISING the [org_client.share] key `key` on a managed node —
// the single per-tier gate the push seam (governance_wire.lowerShareOptions)
// and any transparency surface reporting "in force" (the dashboard Privacy
// card, the P4-2 node.governance ExtractionEffective wire field) must both
// consult, so the two can never disagree about which raises are actually
// live. This is the fix for MergeBool's documented over-report: MergeBool
// alone gates a raise on Managed only, which reads a tier as raised even
// when the grant lacks that SPECIFIC tier's authority; a caller reporting
// "in force" must additionally require ExtractionAuthorized(e, key).
//
// A key outside shareTierTable — including the two documented exemptions —
// always reports false: it can be LOWERED but never remotely RAISED.
func ExtractionAuthorized(e Effective, key string) bool {
	row, ok := shareTierByKey[key]
	if !ok {
		return false
	}
	return row.Authorized(e)
}

// ShareTierKeys returns every [org_client.share] tier key this package maps to
// an extraction authority (shareTierTable), sorted. It is the single owner of
// "the enumerable share tiers" — the org collection-settings surface lists an
// org-side toggle per key sourced HERE, so the toggle set can never drift from
// the raise-gate table. The two documented exemptions (currently none) are not
// included: a structurally-exempt key can be lowered but is not an enumerable
// collection tier.
func ShareTierKeys() []string {
	out := make([]string, 0, len(shareTierTable))
	for _, row := range shareTierTable {
		out = append(out, row.Key)
	}
	sort.Strings(out)
	return out
}

// KnownShareTierKey reports whether key is one of the 21
// [org_client.share] keys this package knows about: mapped in
// shareTierTable, or named in shareTierExempt as a conscious exemption. It
// lets a caller (and the drift test) distinguish "structurally exempt from
// extraction raise" from "nobody has added a row for this key yet".
func KnownShareTierKey(key string) bool {
	if _, ok := shareTierByKey[key]; ok {
		return true
	}
	return shareTierExempt[key]
}

// ExtractionTokensInForce returns the subset of a grant's HONOURED authority
// tokens (govern.HonoredAuthority(grant)) that are BOTH extraction
// authorities (ExtractionAuthority) and currently gate a live raise under e
// — i.e. shareTierTable has at least one row whose Authorized(e) is true and
// whose Authority matches, or the token is the extract.managed umbrella and
// at least one umbrella-eligible (grantsExtractionOrManaged-backed) row is
// authorized. It is P4-2's ExtractionEffective: the honest "what is this
// grant's extraction authority actually DOING right now" list, as opposed to
// AcceptedAuthority (P4-2's raw HonoredAuthority(grant), which says nothing
// about whether any of it currently raises anything).
//
// Sorted, deduplicated, nil for none. Pure over (e, acceptedAuthority) — no
// SQL/HTTP/fsnotify, matching internal/policystate's purity discipline.
func ExtractionTokensInForce(e Effective, acceptedAuthority []string) []string {
	present := make(map[string]bool, len(acceptedAuthority))
	for _, tok := range acceptedAuthority {
		present[tok] = true
	}
	out := map[string]bool{}
	for _, row := range shareTierTable {
		if !row.Authorized(e) {
			continue
		}
		if present[row.Authority] {
			out[row.Authority] = true
		}
		// The high-sensitivity rows (codeintel/process/terminal) use the
		// STRICT gate (grantsExtraction, no umbrella clause), so
		// row.Authorized(e) being true already implies row.Authority itself
		// is present — the umbrella can never satisfy them. Only the
		// headline rows (grantsExtractionOrManaged-backed) can be
		// authorized via the umbrella alone.
		if present[AuthorityExtractManaged] && e.Managed {
			out[AuthorityExtractManaged] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	result := make([]string, 0, len(out))
	for tok := range out {
		result = append(result, tok)
	}
	sort.Strings(result)
	return result
}
