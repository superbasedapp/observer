package entitlements

import (
	"slices"
	"sort"
)

// capability.go maps every server row of the internal/components catalog to
// an entitlement gate (plan 06 17.2: "Entitlement capability keys are the
// server rows of the internal/components catalog"; "a test requires every
// server catalog row to have an entitlement mapping"). The capability key
// of a row IS its component id. The one exception is featureRows: a right
// a plan sells that no component stands for (W16-D8's org.own_idp), kept in
// the same id space and pinned never to collide with a component id.

// Gate says how a server component is entitled.
type Gate string

// The closed Gate vocabulary.
const (
	// GateIncluded: every document and every floor entitles it. It is
	// infrastructure or platform plumbing that the deployment (availability
	// and the [components] block) decides, never billing: a storage driver,
	// the log engine, the OIDC rail that the platform sign-in is a preset
	// of.
	GateIncluded Gate = "included"
	// GatePlan: entitled only when a document (or the floor) lists it.
	GatePlan Gate = "plan"
)

// CapabilityOwnIdP is the one capability that is not a component: the org
// may sign its members in through an identity provider of its own (SAML,
// or OIDC with any preset but the platform's). Lead decision W16-D8 (L-124,
// C3.ENTL-gates): a Team org on shared infrastructure signs in through the
// platform issuer only; Business and every plan above it hold this.
// PUT /api/org/auth/settings refuses to enable an own IdP without it.
const CapabilityOwnIdP = "org.own_idp"

// gateRow is one row of the mapping table.
type gateRow struct {
	id   string
	gate Gate
	// why records the ruling or default behind the gate.
	why string
}

// gateRows is the mapping table: one row per non-core server component,
// pinned against the catalog by TestEveryServerRowHasAnEntitlementMapping.
// The plan rows' selling tier is the plan catalog's (catalog.go); the gate
// only says whether billing may gate the component at all.
func gateRows() []gateRow {
	const (
		infra    = "infrastructure: the deployment chooses it, billing never gates it"
		platform = "platform plumbing every org needs"
		card     = "plan 06 8.3 price card"
		dflt     = "lane default, operator question in the w11 handback"
	)
	return []gateRow{
		{id: "org.oidc", gate: GateIncluded, why: "the platform sign-in rail is a preset of the OIDC rail (plan 06 17.2); gating it would lock pooled orgs out"},
		{id: "org.saml", gate: GatePlan, why: card + ": SAML SSO is Business"},
		{id: "org.scim", gate: GatePlan, why: card + ": SCIM is Business"},
		{id: "org.log.kafka", gate: GateIncluded, why: infra},
		{id: "org.sor.s3", gate: GateIncluded, why: infra},
		{id: "org.sor.azblob", gate: GateIncluded, why: infra},
		{id: "org.analytics.clickhouse", gate: GateIncluded, why: infra},
		{id: "org.opamp", gate: GatePlan, why: card + ": AI Apps is Business"},
		{id: CapabilityPlaneAGateway, gate: GatePlan, why: card + ": AI Apps OTLP ingest is Business; L-166 adds a capped allowance to Personal Free and Personal Pro (v2)"},
		{id: CapabilityAIGateway, gate: GatePlan, why: card + ": the AI gateway is Business; the hosted AI gateway (L-172, decision 4 of L-174) adds a capped allowance to Personal Free and Personal Pro (v3)"},
		{id: "org.agentaccess", gate: GatePlan, why: dflt},
		{id: "org.openshell", gate: GatePlan, why: dflt},
		{id: "org.sandbox", gate: GateIncluded, why: "the managed sandbox settings and their pull (wave 17 lane pooled-sandbox): every plan includes it; staff switch it per org through the availability envelope"},
		{id: "org.security", gate: GatePlan, why: card + ": Team includes guardrails"},
		{id: "org.security.relay", gate: GatePlan, why: dflt},
		{id: "org.security.ci", gate: GatePlan, why: dflt},
		{id: "org.security.githubapp", gate: GatePlan, why: dflt},
		{id: "org.assistant", gate: GatePlan, why: dflt},
		{id: "org.harness", gate: GatePlan, why: dflt},
		{id: "org.pollers.cc", gate: GatePlan, why: card + ": vendor pollers are Business"},
		{id: "org.pollers.codex", gate: GatePlan, why: card + ": vendor pollers are Business"},
		{id: "org.pollers.cursor", gate: GatePlan, why: card + ": vendor pollers are Business"},
		{id: "org.pollers.copilot", gate: GatePlan, why: card + ": vendor pollers are Business"},
		{id: "org.pollers.m365", gate: GatePlan, why: card + ": vendor pollers are Business"},
		{id: "org.pollers.cortex", gate: GatePlan, why: card + ": vendor pollers are Business"},
		{id: "org.pollers.kimchi", gate: GatePlan, why: card + ": vendor pollers are Business"},
		{id: "org.vendorconn", gate: GateIncluded, why: "staff availability decides (wave 17 lane pooled-integrations); whether a plan tier sells it is an operator question"},
		{id: "org.email", gate: GateIncluded, why: platform + ": notification delivery"},
		{id: "org.digest", gate: GatePlan, why: card + ": digests are Personal Pro, Team and Business"},
		{id: "org.pricing-feed", gate: GateIncluded, why: platform + ": the model price table"},
		{id: "org.selfobs", gate: GateIncluded, why: infra},
		{id: "org.deploy-planner", gate: GateIncluded, why: infra},
		{id: "org.managed-settings", gate: GateIncluded, why: platform + ": it generates files and applies nothing"},
		// Wave 17 lane pooled-coding: team features that were org.core.
		// Included until the operator puts one on a plan (a new plan
		// version); staff switch them through the availability envelope.
		{id: "org.coding", gate: GateIncluded, why: "a team feature every plan has had as core; staff switch it through availability"},
		{id: "org.agent-config", gate: GateIncluded, why: "a team feature every plan has had as core; staff switch it through availability"},
		{id: "org.entities", gate: GateIncluded, why: "a team feature every plan has had as core; staff switch it through availability"},
		// Wave 17 lane pooled-obs: included until the operator decides
		// whether the AI Apps price card (Business) sells it.
		{id: "org.obs.evals", gate: GateIncluded, why: "an AI Apps feature every plan has had as core; staff switch it through availability"},
		{id: "edge", gate: GatePlan, why: card + ": AI Apps is Business"},
	}
}

// featureRows are the capabilities that are not a server component: a
// right a plan sells that no component row stands for. Their ids must never
// name a catalog component (TestFeatureRowsNameNoComponent), and they are
// always GatePlan: an included feature would be no capability at all.
// Effective.Has, GateOf and the catalog treat them like the component rows.
func featureRows() []gateRow {
	return []gateRow{
		{id: CapabilityOwnIdP, gate: GatePlan, why: "L-124 C3.ENTL-gates (W16-D8): a Team org signs in through the platform issuer; SAML or an own OIDC provider is Business and above"},
	}
}

// allRows is every mapping row: the component rows, then the feature rows.
func allRows() []gateRow { return append(gateRows(), featureRows()...) }

// GateOf returns the gate of a capability id (a server component or a
// feature row), and false when the id has no mapping row.
func GateOf(id string) (Gate, bool) {
	for _, r := range allRows() {
		if r.id == id {
			return r.gate, true
		}
	}
	return "", false
}

// GatedIDs returns the ids (components and feature rows) mapped to gate g,
// sorted.
func GatedIDs(g Gate) []string {
	var out []string
	for _, r := range allRows() {
		if r.gate == g {
			out = append(out, r.id)
		}
	}
	sort.Strings(out)
	return out
}

// mappedIDs returns every mapped id, sorted.
func mappedIDs() []string {
	var out []string
	for _, r := range allRows() {
		out = append(out, r.id)
	}
	sort.Strings(out)
	return out
}

// gateReason returns why a component has its gate ("" when unmapped).
func gateReason(id string) string {
	for _, r := range allRows() {
		if r.id == id {
			return r.why
		}
	}
	return ""
}

// isPlanGated reports whether id is mapped GatePlan.
func isPlanGated(id string) bool { return slices.Contains(GatedIDs(GatePlan), id) }
