package nodecomponents

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// impact.go is the org-side reading of what a node.components policy means
// for the fleet as the nodes reported it (T-777, D-617): which components a
// published (or draft) policy requires, allows, denies or leaves off; which
// components the managed nodes actually run; and which running components a
// draft would turn off. The org server reads the posture rows
// (org_node_component_posture) and hands them here as NodeReport values; the
// decisions are made by the ONE resolver (components.Resolve), never by a
// second copy of its rules.
//
// Honesty rules:
//   - a node reports only its NON-active components one by one; the active
//     set is a digest. The running set is derived as "every node row of this
//     catalog minus the reported inactive ids" and is trusted only when its
//     digest equals the reported active digest (same catalog version too).
//     A node whose derivation does not verify is counted as unchecked, never
//     as running or as fine;
//   - the developer's own selection is not on the wire. A component a node
//     runs today only because the org pins or requires it, and that a draft
//     merely allows, keeps running only if the developer's selection keeps
//     it: that is reported as "may stop", never as a certain loss or a
//     certain keep.

// InactiveEntry is one non-active component as a node reported it.
type InactiveEntry struct {
	ID     string
	State  string
	Reason string
}

// NodeReport is one node's reported component posture, reduced to what the
// impact reading needs.
type NodeReport struct {
	// Source is the governance source the node reported (Source values, ""
	// when none was resolved).
	Source string
	// CatalogVersion is the node binary's catalog version.
	CatalogVersion int
	// ActiveDigest is components.Digest of the node's active set.
	ActiveDigest string
	// Inactive is every component the node reported as not active.
	Inactive []InactiveEntry
}

// sourceEffect is one row of the governance-source table: whether a node in
// that source is managed by the org, applies a newly published policy, and
// runs an org-owned set as require today.
type sourceEffect struct {
	source  Source
	managed bool
	follows bool
	pinned  bool
}

// sourceEffects is the table (CLAUDE.md #5), mirroring Govern's source rows:
// local and dormant nodes decide for themselves; an unauthorized node is
// managed but ignores this family; the other four apply the next policy.
var sourceEffects = []sourceEffect{
	{source: SourcePolicy, managed: true, follows: true},
	{source: SourceLastKnownGood, managed: true, follows: true},
	{source: SourceInitialGrant, managed: true, follows: true, pinned: true},
	{source: SourceLegacyPinned, managed: true, follows: true, pinned: true},
	{source: SourceUnauthorized, managed: true},
	{source: SourceLocal},
	{source: SourceDormant},
}

func effectOf(source string) sourceEffect {
	for _, e := range sourceEffects {
		if string(e.source) == source {
			return e
		}
	}
	return sourceEffect{source: Source(source)}
}

// nodeSets is one node's derived component sets.
type nodeSets struct {
	compiled []string
	active   []string
	inactive map[string]InactiveEntry
	// verified: the derived active set matches the reported digest.
	verified bool
}

func notCompiled(state string) bool {
	return state == string(components.StateAbsent) || state == string(components.StateRequiredMissing)
}

// deriveSets rebuilds a node's compiled and active sets from its report.
func deriveSets(r NodeReport) nodeSets {
	out := nodeSets{inactive: map[string]InactiveEntry{}}
	for _, e := range r.Inactive {
		out.inactive[e.ID] = e
	}
	for _, row := range components.ForBinary(components.BinaryNode) {
		e, off := out.inactive[row.ID]
		if !off || !notCompiled(e.State) {
			out.compiled = append(out.compiled, row.ID)
		}
		if !off {
			out.active = append(out.active, row.ID)
		}
	}
	out.verified = r.CatalogVersion == components.CatalogVersion && r.ActiveDigest != "" &&
		components.Digest(out.active) == r.ActiveDigest
	return out
}

// Rule is what a policy says about one governable component, in the words
// the composer shows.
type Rule string

// The closed Rule vocabulary.
const (
	RuleRequire       Rule = "require"
	RuleAllow         Rule = "allow"
	RuleDeny          Rule = "deny"
	RuleDenyGrantable Rule = "deny_grantable"
	// RuleDependency: no selector names it, but an allowed or required
	// component needs it, so it may run.
	RuleDependency Rule = "dependency"
	// RuleUnlisted: no selector names it and nothing allowed needs it, so it
	// is turned off on governed nodes.
	RuleUnlisted Rule = "unlisted"
)

// ComponentRules reduces a policy to one Rule per governable node component
// (core is never governed and is not listed).
func ComponentRules(spec PolicySpec) map[string]Rule {
	sets := spec.Sets("")
	out := map[string]Rule{}
	for _, id := range sets.Require {
		out[id] = RuleRequire
	}
	for _, id := range sets.Allow {
		out[id] = RuleAllow
	}
	grantable := toSet(sets.Grantable)
	for _, id := range sets.Deny {
		out[id] = RuleDeny
		if grantable[id] {
			out[id] = RuleDenyGrantable
		}
	}
	// What the resolver lets run when every component is compiled and
	// selected: an unnamed component that still runs does so as a
	// dependency of an allowed or required one.
	var all []string
	for _, row := range governable() {
		all = append(all, row.ID)
	}
	res := components.Resolve(components.ResolveInput{
		Binary: components.BinaryNode, Selected: all,
		Governance: &components.Governance{Policy: &sets},
	})
	for _, row := range governable() {
		if _, named := out[row.ID]; named {
			continue
		}
		out[row.ID] = RuleUnlisted
		if d, ok := res.Decision(row.ID); ok && d.Reason != components.ReasonPolicyUnlisted {
			out[row.ID] = RuleDependency
		}
	}
	return out
}

// IsBlank reports whether a policy requires and allows nothing: published,
// it turns off every non-core component on every governed node.
func IsBlank(spec PolicySpec) bool {
	sets := spec.Sets("")
	return len(sets.Require) == 0 && len(sets.Allow) == 0
}

// LossReason says why a draft would stop a running component.
type LossReason string

// The closed LossReason vocabulary.
const (
	// LossDenied: the draft denies it.
	LossDenied LossReason = "denied"
	// LossDeniedGrantable: the draft denies it, but a component access
	// grant may let one developer keep it.
	LossDeniedGrantable LossReason = "denied_grantable"
	// LossUnlisted: the draft does not name it, so it is turned off.
	LossUnlisted LossReason = "unlisted"
	// LossNeedsBlocked: it needs a component the draft turns off.
	LossNeedsBlocked LossReason = "needs_blocked"
	// LossSelectionOnly: the org requires or pins it today and the draft
	// only allows it, so it keeps running only if the developer's own
	// selection keeps it (not certain).
	LossSelectionOnly LossReason = "selection_only"
)

// lossRule maps a resolver decision for a running component to a loss.
type lossRule struct {
	reason components.Reason
	loss   LossReason
}

// lossRules is the decision-reason table for a component that would stop.
var lossRules = []lossRule{
	{reason: components.ReasonPolicyDenied, loss: LossDenied},
	{reason: components.ReasonPolicyUnlisted, loss: LossUnlisted},
	{reason: components.ReasonDeniedDependency, loss: LossNeedsBlocked},
	{reason: components.ReasonRequiresNotCompiled, loss: LossNeedsBlocked},
}

func lossFor(d components.Decision, grantable map[string]bool) LossReason {
	for _, r := range lossRules {
		if r.reason == d.Reason {
			if r.loss == LossDenied && grantable[d.ID] {
				return LossDeniedGrantable
			}
			return r.loss
		}
	}
	return LossNeedsBlocked
}

// ComponentLoss is one component a draft would stop, with how many nodes.
type ComponentLoss struct {
	Component string     `json:"component"`
	Reason    LossReason `json:"reason"`
	Nodes     int        `json:"nodes"`
	// Certain is false for LossSelectionOnly.
	Certain bool `json:"certain"`
}

// Impact is what publishing a draft would do to the reporting fleet.
type Impact struct {
	// Blank: the draft requires and allows nothing.
	Blank bool `json:"blank"`
	// Governed are reporting nodes that would apply the draft.
	Governed int `json:"governed"`
	// Unchecked are governed nodes whose running set could not be verified
	// from their report (an older catalog, or an unmatched digest).
	Unchecked int `json:"unchecked"`
	// NotGoverned are reporting nodes that would not apply it (individual,
	// dormant, or an enrolment that does not let the org govern components).
	NotGoverned int `json:"not_governed"`
	// NodesLosing would certainly turn off at least one running component.
	NodesLosing int `json:"nodes_losing"`
	// NodesMayLose may turn one off (selection-only) and lose none for sure.
	NodesMayLose int `json:"nodes_may_lose"`
	// Components lists each (component, reason) with its node count.
	Components []ComponentLoss `json:"components"`
}

// Affected is the count a publish must acknowledge: nodes that would or may
// turn off a component they run today.
func (i Impact) Affected() int { return i.NodesLosing + i.NodesMayLose }

// ImpactOf computes what publishing draft would turn off. published is the
// policy in force for nodes following a published policy (nil when none is
// published): it tells which of their running components the org requires
// today.
func ImpactOf(draft PolicySpec, published *PolicySpec, nodes []NodeReport) Impact {
	sets := draft.Sets("")
	grantable := toSet(sets.Grantable)
	out := Impact{Blank: IsBlank(draft), Components: []ComponentLoss{}}
	type key struct {
		id     string
		reason LossReason
	}
	counts := map[key]int{}
	var pubSets *components.PolicySets
	if published != nil {
		s := published.Sets("")
		pubSets = &s
	}
	for _, n := range nodes {
		eff := effectOf(n.Source)
		if !eff.follows {
			out.NotGoverned++
			continue
		}
		out.Governed++
		ns := deriveSets(n)
		if !ns.verified {
			out.Unchecked++
			continue
		}
		required := requiredToday(ns, eff, pubSets)
		res := components.Resolve(components.ResolveInput{
			Binary: components.BinaryNode, Compiled: ns.compiled, Selected: ns.active,
			Governance: &components.Governance{Policy: &sets},
		})
		certain, maybe := false, false
		for _, id := range ns.active {
			d, ok := res.Decision(id)
			if !ok {
				continue
			}
			switch {
			case d.State != components.StateActive:
				counts[key{id, lossFor(d, grantable)}]++
				certain = true
			case d.Reason == components.ReasonSelected && required[id]:
				counts[key{id, LossSelectionOnly}]++
				maybe = true
			}
		}
		switch {
		case certain:
			out.NodesLosing++
		case maybe:
			out.NodesMayLose++
		}
	}
	for k, n := range counts {
		out.Components = append(out.Components, ComponentLoss{
			Component: k.id, Reason: k.reason, Nodes: n, Certain: k.reason != LossSelectionOnly,
		})
	}
	sort.Slice(out.Components, func(i, j int) bool {
		a, b := out.Components[i], out.Components[j]
		if a.Certain != b.Certain {
			return a.Certain
		}
		if a.Nodes != b.Nodes {
			return a.Nodes > b.Nodes
		}
		if a.Component != b.Component {
			return a.Component < b.Component
		}
		return a.Reason < b.Reason
	})
	return out
}

// requiredToday is the set of a node's running components the org requires
// or pins today: everything non-core for a pinned source, the published
// policy's required components (and what they need) otherwise. With no
// published policy to read, every running component counts, so the reading
// errs toward "may stop".
func requiredToday(ns nodeSets, eff sourceEffect, pub *components.PolicySets) map[string]bool {
	out := map[string]bool{}
	if eff.pinned || pub == nil {
		for _, id := range ns.active {
			out[id] = true
		}
		return out
	}
	res := components.Resolve(components.ResolveInput{
		Binary: components.BinaryNode, Compiled: ns.compiled,
		Governance: &components.Governance{Policy: pub},
	})
	for _, d := range res.Decisions {
		if d.State == components.StateActive && d.Reason == components.ReasonPolicyRequired {
			out[d.ID] = true
		}
	}
	return out
}

// ComponentFleet is one governable component across the managed nodes.
type ComponentFleet struct {
	ID string `json:"id"`
	// Running: managed nodes verified to run it.
	Running int `json:"running"`
	// Off: managed nodes that have it in their build but do not run it.
	Off int `json:"off"`
	// NotInBuild: managed nodes whose build does not contain it.
	NotInBuild int `json:"not_in_build"`
	// Unknown: managed nodes that did not list it as inactive but whose
	// running set could not be verified.
	Unknown int `json:"unknown"`
	// Reasons counts the reported reasons over Off and NotInBuild.
	Reasons map[string]int `json:"reasons"`
}

// Fleet is the component reality of the reporting fleet.
type Fleet struct {
	// Reporting is every node that sent a component posture.
	Reporting int `json:"reporting"`
	// Managed of those are governed by the org (any managed source).
	Managed int `json:"managed"`
	// Verified of the managed nodes have a running set that verified.
	Verified int `json:"verified"`
	// BySource counts reporting nodes per governance source ("" as
	// "unknown").
	BySource map[string]int `json:"by_source"`
	// Components is one row per governable component, sorted by id.
	Components []ComponentFleet `json:"components"`
}

// FleetOf counts, for each governable component, how many managed nodes run
// it, have it off, lack it, or cannot be checked.
func FleetOf(nodes []NodeReport) Fleet {
	out := Fleet{BySource: map[string]int{}, Components: []ComponentFleet{}}
	rows := governable()
	byID := map[string]*ComponentFleet{}
	for _, row := range rows {
		out.Components = append(out.Components, ComponentFleet{ID: row.ID, Reasons: map[string]int{}})
	}
	for i := range out.Components {
		byID[out.Components[i].ID] = &out.Components[i]
	}
	for _, n := range nodes {
		out.Reporting++
		src := n.Source
		if src == "" {
			src = "unknown"
		}
		out.BySource[src]++
		if !effectOf(n.Source).managed {
			continue
		}
		out.Managed++
		ns := deriveSets(n)
		if ns.verified {
			out.Verified++
		}
		for _, row := range rows {
			c := byID[row.ID]
			e, off := ns.inactive[row.ID]
			switch {
			case off && notCompiled(e.State):
				c.NotInBuild++
				c.Reasons[reasonKey(e)]++
			case off:
				c.Off++
				c.Reasons[reasonKey(e)]++
			case ns.verified:
				c.Running++
			default:
				c.Unknown++
			}
		}
	}
	sort.Slice(out.Components, func(i, j int) bool { return out.Components[i].ID < out.Components[j].ID })
	return out
}

func reasonKey(e InactiveEntry) string {
	if e.Reason == "" {
		return e.State
	}
	return e.Reason
}

func toSet(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}
