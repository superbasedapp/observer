package govern

import "sort"

// The [org_client.policy] family vocabulary (internal/policyfam's closed v1
// enum), duplicated here as literal strings rather than imported. This
// mirrors the codebase's existing convention for a small closed enum owned
// by another boundary — internal/policystate/collector.go and
// internal/config.OrgClientPolicyConfig both keep their own literal copy of
// the same four strings rather than pulling in internal/policyfam, and
// govern must stay import-clean of internal/config/internal/store/etc
// (imports_test.go) regardless.
const (
	familyAdmissionInput   = "admission.input"
	familyEgressGuardrail  = "egress.routing_guardrail"
	familyGatewayProviders = "gateway.providers"
	familyNodeGovernance   = "node.governance"
	// familyNodeFeatures mirrors policyfam.FamilyNodeFeatures (`node.features`,
	// org-parity W5.1): the org-governed feature gates (terminals, remote,
	// routing apply, patterns write) and the tools.disallow list, plus the
	// request-grants G8 tool and feature grants that lift them.
	familyNodeFeatures = "node.features"
	// familyToolsMCPAccess mirrors policyfam.FamilyMCPAccess (`tools.mcp_access`,
	// Agent Access P1/P2): a full resource family with its own compiler and
	// its own row in config's accept_families allow-list.
	familyToolsMCPAccess = "tools.mcp_access"
	// familyNodeComponents mirrors policyfam.FamilyNodeComponents
	// (`node.components`, modular packaging P4, lane MP-GOV): which
	// components a managed node runs.
	familyNodeComponents = "node.components"
	// familySecurityScanning and familyTerminalsIsolation mirror
	// policyfam.FamilySecurityScanning and FamilyTerminalsIsolation (roadmap
	// F0-9/F0-10): the security and sandbox modules' raise-only floor
	// families. No authority governs them (raise-only floors need none);
	// managed consent does (managedConsentFamilies).
	familySecurityScanning   = "security.scanning"
	familyTerminalsIsolation = "terminals.isolation"
)

// authorityFamilyRow is one row of the authority-to-family table (CLAUDE.md
// #5 — a data table walked in full, never an if/else-if ladder): which
// [org_client.policy] family (or families) a KnownAuthority token governs,
// i.e. which accept_families/preauthorize_enforce entries a node must
// consent to before that authority's directive class can actually take
// effect (W-5: docs/plans/admin-controlled-plane-b-spec-2026-08-15.md and
// the operator ruling that managed enrolment auto-writes this consent).
type authorityFamilyRow struct {
	authority string
	families  []string
}

// authorityFamilyTable is the SINGLE OWNER of the authority-to-family
// mapping (CLAUDE.md #4 — one owner of this piece of state). Every row is a
// KnownAuthority token; AuthorityCaptureRaise is the one deliberate
// exemption, tracked below in exemptFromFamilyMapping, not a silent gap.
//
//   - dashboard.visibility / settings.pin / capture.pin / feature.lock and
//     every extract.* token (including the extract.managed umbrella) are
//     all directive classes of the node.governance family
//     (internal/policyfam/nodegov compiles all of them; resolve.go's
//     "sections" / "pinned" / "share" / "features" rows are the four
//     directive classes that family carries).
//
//   - feature.lock ALSO maps to node.features (review C156-04, T-354). The
//     node.features family is the org's feature-gate resource (terminals,
//     remote, routing apply, patterns write, tools.disallow): it is exactly
//     what "the org may force a feature subsystem on or off" means, so the
//     grant that carries feature.lock is the consent for it. Before this row
//     no authority named node.features, so a managed enrolment never wrote it
//     into accept_families and every org feature lock, tool disallow and G8
//     tool or feature grant was inert on every managed node. A node that
//     enrolled before the row existed gets the family backfilled once at
//     daemon start (cmd/observer's reconcileManagedPolicyAtStart, decided by
//     ManagedFamilyBackfill below).
//
//   - extract.intel maps to node.governance like every other extract.* token
//     (review C156-42): the org-enrichment raise rides the node.governance
//     share directive (intelligence.org_enrichment).
//
//   - enforce.admission lifts the §R23 structural-ignore for the
//     admission.input family (internal/obs/admission).
//
//   - enforce.egress lifts it for the egress.routing_guardrail family
//     (internal/guard's egress policy).
//
//   - enforce.routing lifts it for the gateway.providers family (the
//     Phase 3 dashboard-managed proxy lane table). Model-routing
//     enforcement is delivered through the [routing] org policy fragment,
//     which rides the gateway.providers family compiler, not a routing-
//     specific one.
//
//   - enforce.budget maps to node.governance, which is the org-budget plan
//     §3.3's DECLARED FALLBACK rather than its first choice. The plan wanted a
//     dedicated `budget.spend` family (review finding F8: every other
//     enforce.* token has one) and named the forcing condition exactly:
//     "should families.go's CompileBody switch require every family to carry
//     an org_policy_resources compiler ... map to node.governance instead".
//     It does, and the coupling reaches further than that one switch — the
//     family enum is CLOSED and load-bearing in four more places:
//     policyfam.SupportedFamilies is pinned element-for-element by
//     policyfam/families_test.go's TestSupportedFamiliesDriveDispatch (every
//     entry must compile a minimal body) and by internal/config's
//     policyfam_sync_test.go against config.policyResourceSupportedFamilies,
//     which config.Validate enforces on [org_client.policy].accept_families —
//     and cmd/observer's managedPolicyFamiliesToWrite writes exactly
//     GovernedFamilies(grant.Authority) into that key at enrolment. A family
//     with no resource body would therefore either fail the registry contract
//     test or, worse, be written into a managed node's config and make
//     config.Load REJECT it. The budget body is delivered by
//     GET /api/agent/budget, not by the resource rail, so it has no compiler
//     and cannot be a resource family.
//
//     node.governance is the honest home rather than a shrug: the budget
//     POSTURE is literally a pair of node.governance pins
//     (guard.budget.hard / guard.budget.from_org, nodegov.PinnableKeys), so a
//     grant carrying enforce.budget genuinely governs that family. Widening
//     the family does NOT widen the semantics — resolve.go gates each
//     DIRECTIVE CLASS on its own authority (settings.pin for `pinned`,
//     capture.pin/extract.* for `share`, feature.lock for `features`), so
//     enforce.budget alone still unlocks no directive class.
//
//   - enforce.mcp_access lifts the structural-ignore for the tools.mcp_access
//     family (Agent Access doc3 §12.8, parking decision B9). Unlike
//     enforce.budget's forcing condition, this family IS a real resource
//     family: policyfam.SupportedFamilies carries FamilyMCPAccess with its
//     own compiler (the signed MCP-access table the node relay publishes),
//     and config's accept_families / preauthorize_enforce allow-lists already
//     name `tools.mcp_access`, so mapping the token to its own family is the
//     enforce.admission precedent, not the node.governance fallback. A managed
//     enrolment therefore auto-consents to that family at enrol
//     (cmd/observer's managedPolicyFamiliesToWrite writes exactly
//     GovernedFamilies(grant.Authority)) — which is what makes the org mode
//     authoritative on the relay rather than accepted_inert.
var authorityFamilyTable = []authorityFamilyRow{
	{AuthorityDashboardVisibility, []string{familyNodeGovernance}},
	{AuthoritySettingsPin, []string{familyNodeGovernance}},
	{AuthorityCapturePin, []string{familyNodeGovernance}},
	{AuthorityFeatureLock, []string{familyNodeGovernance, familyNodeFeatures}},
	{AuthorityExtractManaged, []string{familyNodeGovernance}},
	{AuthorityExtractCodeintel, []string{familyNodeGovernance}},
	{AuthorityExtractProcess, []string{familyNodeGovernance}},
	{AuthorityExtractTerminal, []string{familyNodeGovernance}},
	{AuthorityExtractTasks, []string{familyNodeGovernance}},
	{AuthorityExtractToolAccounts, []string{familyNodeGovernance}},
	{AuthorityExtractIntel, []string{familyNodeGovernance}},
	{AuthorityExtractToolBodies, []string{familyNodeGovernance}},
	{AuthorityExtractFolders, []string{familyNodeGovernance}},
	{AuthorityExtractTraces, []string{familyNodeGovernance}},
	{AuthorityExtractCache, []string{familyNodeGovernance}},
	{AuthorityExtractRouting, []string{familyNodeGovernance}},
	{AuthorityExtractPredictions, []string{familyNodeGovernance}},
	{AuthorityExtractTargetActions, []string{familyNodeGovernance}},
	{AuthorityExtractScope, []string{familyNodeGovernance}},
	{AuthorityExtractPolicyState, []string{familyNodeGovernance}},
	{AuthorityExtractObsEgress, []string{familyNodeGovernance}},
	{AuthorityExtractHookActivity, []string{familyNodeGovernance}},
	{AuthorityEnforceAdmission, []string{familyAdmissionInput}},
	{AuthorityEnforceEgress, []string{familyEgressGuardrail}},
	{AuthorityEnforceRouting, []string{familyGatewayProviders}},
	{AuthorityEnforceBudget, []string{familyNodeGovernance}},
	{AuthorityEnforceMCPAccess, []string{familyToolsMCPAccess}},
	// components.govern is the consent for the node.components family
	// (modular packaging plan 6.2.1): a managed enrolment holding it writes
	// the family into accept_families, and a node that enrolled before the
	// family existed gets it backfilled at start (ManagedFamilyBackfill).
	{AuthorityComponentsGovern, []string{familyNodeComponents}},
}

// exemptFromFamilyMapping is the CONSCIOUS exemption table this package's own
// drift test (TestGovernedFamilies_EveryKnownAuthorityMapsOrIsExempt) reads:
// a KnownAuthority token that deliberately maps to zero families, with the
// reason it does (roadmap F0-7; JSP-1 R2: the list used to be a bare set
// whose only premise was "retired, grants nothing", which the two module
// tokens do not share). The test requires a non-empty reason, so a future
// exemption is a considered decision with its reason written down, never an
// oversight.
var exemptFromFamilyMapping = map[string]string{
	// AuthorityCaptureRaise is RETIRED and PERMANENTLY INERT (types.go): it
	// never governs anything, so it cannot govern a policy family either.
	AuthorityCaptureRaise: "retired: grants nothing",
	// The two module enforce tokens gate a signed managed PULL (the
	// security and sandbox rails of orgcontract.ManagedPullRails), not a
	// policy-resource family: their families' floors are raise-only and need
	// no authority (sandbox plan v2 M10, security plan 7.2 row 7; JSP-1: not
	// an enforce.budget precedent, which maps to node.governance).
	AuthorityEnforceSandbox:  "gates a managed pull, not a resource family",
	AuthorityEnforceSecurity: "gates a managed pull, not a resource family",
}

// GovernedFamilies returns the sorted, deduplicated set of [org_client.policy]
// families the given authority tokens govern, per authorityFamilyTable. A
// token this build does not recognise, or one in exemptFromFamilyMapping,
// contributes nothing — GovernedFamilies never fabricates a family for a
// token it cannot honestly attribute one to (the same honesty rule
// KnownAuthority/RetiredAuthority already follow).
func GovernedFamilies(authority []string) []string {
	set := make(map[string]bool)
	for _, tok := range authority {
		for _, row := range authorityFamilyTable {
			if row.authority == tok {
				for _, f := range row.families {
					set[f] = true
				}
			}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// managedConsentFamilies are the families a MANAGED-class consent governs on
// its own, alongside whatever its grant's tokens govern. It mirrors the
// dashboard.visibility precedent in resolve.go (a managed developer
// consented to the org deciding what this machine shows and may do, so that
// class applies on managed consent alone): node.features is the org's
// feature-gate resource, and a managed grant minted before
// ManagedEnrolmentAuthoritySet carried feature.lock (the enterprise-posture
// set never did) would otherwise leave every feature lock, tool disallow and
// G8 grant inert on that node for good (review C156-04).
//
// security.scanning and terminals.isolation join for the same reason (roadmap
// F0-10, JSP-1 R3): raise-only floors need no authority, so no grant token
// governs them, and without this row the shipped start-time backfill
// (T-354) would never offer them to a node that enrolled before they
// existed (AA-64). A managed consent governs them on its own; individual
// nodes are untouched (their lists stay their operator's own opt-in). The
// node writes them only from a build that links their compilers
// (cmd/observer's linkedManagedFamilies, audit SHR-KIT finding 1), so a
// config.toml never names a family an older binary would refuse.
var managedConsentFamilies = []string{familyNodeFeatures, familySecurityScanning, familyTerminalsIsolation}

// ManagedGovernedFamilies is GovernedFamilies for an ACCEPTED grant on a
// MANAGED enrolment: the token-governed families plus managedConsentFamilies.
// An authority that governs nothing still yields nil, so a managed grant
// holding only retired or unknown tokens is never treated as consent.
// Callers must have checked managed tenancy themselves; an individual or BYO
// enrolment uses GovernedFamilies.
func ManagedGovernedFamilies(authority []string) []string {
	base := GovernedFamilies(authority)
	if len(base) == 0 {
		return nil
	}
	set := make(map[string]bool, len(base)+len(managedConsentFamilies))
	for _, f := range base {
		set[f] = true
	}
	for _, f := range managedConsentFamilies {
		set[f] = true
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// ManagedFamilyBackfill decides which governed policy families a managed
// enrolment's node-side [org_client.policy] list must gain at daemon start
// (review C156-04: a node that enrolled before a family was mapped to its
// authority never consented to it, because the enrolment write runs once).
//
// The three inputs:
//
//   - governed: GovernedFamilies of the live managed grant's authority.
//   - offered:  the families an earlier backfill for this same enrolment
//     identity already offered. haveRecord=false means no record exists,
//     which is exactly a node that enrolled before this build: every governed
//     family it does not list yet is owed.
//   - present:  the families the list already carries.
//
// A family is added only when it is governed, not already present, and was
// never offered to this enrolment before. The last clause keeps the
// documented contract of the enrolment write: a developer who removes a
// family that was once written is not overridden at the next start; only a
// family this enrolment has never been offered is added. The result is
// sorted and deduplicated; nil when nothing is owed.
func ManagedFamilyBackfill(governed, offered []string, haveRecord bool, present []string) []string {
	have := make(map[string]bool, len(present))
	for _, f := range present {
		have[f] = true
	}
	was := make(map[string]bool, len(offered))
	if haveRecord {
		for _, f := range offered {
			was[f] = true
		}
	}
	set := make(map[string]bool)
	for _, f := range governed {
		if f == "" || have[f] || was[f] {
			continue
		}
		set[f] = true
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
