package components

import (
	"fmt"
	"sort"
	"strings"
)

// State is a component's resolved state.
type State string

// The closed State vocabulary. The P0 dependency resolver produced the first
// four; lane MP-GOVF added the managed-policy rows of plan 6.2 to the SAME
// table (StateRequiredMissing and the policy / ceiling / grant reasons),
// never as a second resolver.
const (
	// StateActive: compiled in and active.
	StateActive State = "active"
	// StateAvailable: compiled in, not selected.
	StateAvailable State = "available"
	// StateAbsent: not compiled into this binary.
	StateAbsent State = "absent"
	// StateBlocked: compiled in but may not run (denied, a denied
	// dependency, or a dependency missing from the build).
	StateBlocked State = "blocked"
	// StateRequiredMissing: org policy requires the component but this
	// binary does not compile it in (plan 6.2 row 2). A compliance finding,
	// never silent: the next distro rollout should fix it.
	StateRequiredMissing State = "required_missing"
)

// Reason explains a resolved state.
type Reason string

// The closed Reason vocabulary.
const (
	ReasonCore                Reason = "core"
	ReasonNotCompiled         Reason = "not_compiled"
	ReasonDenied              Reason = "denied"
	ReasonDeniedDependency    Reason = "denied_dependency"
	ReasonRequiresNotCompiled Reason = "requires_not_compiled"
	ReasonSelected            Reason = "selected"
	ReasonRequiredBy          Reason = "required_by"
	ReasonNotSelected         Reason = "not_selected"

	// Managed-policy reasons (plan 6.2 and 6.2.1, lane MP-GOVF).

	// ReasonAboveCeiling: outside the local component ceiling (plan 6.2.2).
	ReasonAboveCeiling Reason = "above_ceiling"
	// ReasonPolicyDenied: a deny entry of the org's node.components policy
	// matches (and no component grant overrides a grantable entry).
	ReasonPolicyDenied Reason = "policy_denied"
	// ReasonPolicyUnlisted: the policy names nothing that matches and its
	// unlisted rule is inert (plan Q5: new components stay inert on managed
	// nodes until the policy allows them).
	ReasonPolicyUnlisted Reason = "policy_unlisted"
	// ReasonPolicyRequired: the policy requires it (Because names the
	// required component when this one is only needed by it).
	ReasonPolicyRequired Reason = "policy_required"
	// ReasonGranted: a verified component access grant activates it.
	ReasonGranted Reason = "granted"

	// Availability and entitlement reasons (plan 06 18.3.2, layers 2 and 3).

	// ReasonNotAvailable: the platform operator has not cleared the component
	// to run for this org here (the availability ceiling, layer 2).
	ReasonNotAvailable Reason = "not_available"
	// ReasonNotEntitled: the org has not paid for the component (layer 3).
	ReasonNotEntitled Reason = "not_entitled"
)

// ResolveInput is everything the dependency resolver needs. It is pure
// data: the caller reads the compiled set from the binary, the selection
// from config and the denials from whatever narrows them.
type ResolveInput struct {
	// Binary selects the rows to resolve.
	Binary Binary
	// Compiled is the compiled id set. Nil means every row of the binary.
	Compiled []string
	// Selected are the ids the operator wants active.
	Selected []string
	// Denied are ids that may not run.
	Denied []string
	// Governance is the managed-policy input (plan 6.2.1 steps 2 to 5).
	// Nil means ungoverned: the resolver behaves exactly as before it
	// existed.
	Governance *Governance
}

// Governance is the managed-policy input of Resolve, already reduced to
// exact ids by its producers (internal/policyfam/nodecomponents compiles a
// signed node.components body and picks which policy is in force;
// internal/managedconfig loads the local ceiling). Resolve only applies it,
// through rows of the one resolveRules table.
type Governance struct {
	// CeilingPinned reports that a local component ceiling is in force.
	// Ceiling is then the explicit allow-set; an empty set means core only.
	CeilingPinned bool
	Ceiling       []string
	// Policy is the node.components policy in force, or nil when none is
	// (individual node, dormant enrolment, legacy managed node pinned to its
	// compiled set).
	Policy *PolicySets
	// Granted are ids a verified component access grant activates. A grant
	// overrides a deny entry only when that entry is grantable, overrides
	// the unlisted rule, and never overrides the ceiling or a missing build
	// (plan 6.2.1 conflict table).
	Granted []string
	// Availability is the layer-2 availability ceiling (plan 06 18.3.2): nil
	// means none (single mode, private deployments). A compiled non-core id
	// outside it is blocked, not_available.
	Availability *Availability
	// Entitled is the layer-3 entitlement set: nil means none. A compiled
	// non-core id outside it is blocked, not_entitled.
	Entitled *Entitlement
}

// PolicySets is one node.components policy resolved to exact ids, each id at
// most once across Require, Allow and Deny (most specific selector wins, the
// producer's job). Ids it does not name are unlisted, which is inert.
type PolicySets struct {
	// Source names where the policy came from (policy, last_known_good,
	// initial_grant); informational, for posture and doctor.
	Source  string
	Require []string
	Allow   []string
	Deny    []string
	// Grantable is the subset of Deny that a component grant may override.
	Grantable []string
}

// Decision is one resolved row.
type Decision struct {
	ID     string `json:"id"`
	State  State  `json:"state"`
	Reason Reason `json:"reason"`
	// Because names the component that caused a required_by,
	// denied_dependency or requires_not_compiled outcome.
	Because string `json:"because,omitempty"`
}

// ResolveResult is the resolver's output.
type ResolveResult struct {
	// Decisions has one entry per row of the binary, sorted by id.
	Decisions []Decision
	// Errors are selections that cannot be honoured, each naming the
	// reason and, where one exists, the distro that has the component.
	Errors []string
}

// Decision returns the decision for one id.
func (r ResolveResult) Decision(id string) (Decision, bool) {
	for _, d := range r.Decisions {
		if d.ID == id {
			return d, true
		}
	}
	return Decision{}, false
}

// Active returns the active ids, sorted.
func (r ResolveResult) Active() []string {
	var out []string
	for _, d := range r.Decisions {
		if d.State == StateActive {
			out = append(out, d.ID)
		}
	}
	return out
}

// resolveCtx is the per-call state the rule table reads.
type resolveCtx struct {
	compiled map[string]bool
	selected map[string]bool
	denied   map[string]bool
	// deniedBy maps a transitively denied id to the denied id that caused it.
	deniedBy map[string]string
	// wantedBy maps a transitively required id to a selected id needing it.
	wantedBy map[string]string
	// missingDep maps an id to a requires / requires_compiled id that is
	// not compiled.
	missingDep map[string]string

	// Governance (all empty when ResolveInput.Governance is nil).

	// aboveCeiling: compiled ids outside a pinned local ceiling.
	aboveCeiling map[string]bool
	// policy reports that a node.components policy is in force.
	policy bool
	// policyDenied: ids a policy deny entry blocks after grants are applied.
	policyDenied map[string]bool
	// policyAllowed: ids the policy lets run (allow, require, granted, and
	// everything those transitively require).
	policyAllowed map[string]bool
	// policyRequired maps a required id to "" and an id a required component
	// transitively needs to that required component.
	policyRequired map[string]string
	// granted: ids a component grant activates.
	granted map[string]bool
	// unavailable: compiled non-core ids outside the availability ceiling.
	unavailable map[string]bool
	// unentitled: compiled non-core ids outside the entitlement set.
	unentitled map[string]bool
}

// blockedOwn reports whether a component is blocked by its own row (local
// denial, policy, ceiling) rather than through a dependency. Core is never
// blocked.
func (ctx *resolveCtx) blockedOwn(c Component) bool {
	if c.Class == ClassCore {
		return false
	}
	return ctx.denied[c.ID] || ctx.unavailable[c.ID] || ctx.unentitled[c.ID] || ctx.aboveCeiling[c.ID] || ctx.policyDenied[c.ID] || ctx.unlisted(c)
}

// unlisted reports a compiled, non-core component a policy in force does
// not let run.
func (ctx *resolveCtx) unlisted(c Component) bool {
	return ctx.policy && c.Class != ClassCore && !ctx.policyAllowed[c.ID]
}

// policyRequires reports whether the policy in force requires the component
// (directly or as a requirement of a required component).
func (ctx *resolveCtx) policyRequires(c Component) bool {
	_, ok := ctx.policyRequired[c.ID]
	return ctx.policy && ok
}

// resolveRule is one row of the ordered resolution table: the first rule
// whose match returns true decides the component's state.
type resolveRule struct {
	name    string
	match   func(ctx *resolveCtx, c Component) bool
	state   State
	reason  Reason
	because func(ctx *resolveCtx, c Component) string
}

// resolveRules is the ordered resolution table (CLAUDE.md #5: decision logic
// is a data table walked top-down, one test row each). It is the ONE
// resolver: the P0 dependency rows and the managed-policy rows of plan 6.2 /
// 6.2.1 (lane MP-GOVF) live here together, in the precedence order of the
// lattice: compiled set, local ceiling, org policy, component grants, local
// selection.
var resolveRules = []resolveRule{
	{
		name: "core", state: StateActive, reason: ReasonCore,
		match: func(_ *resolveCtx, c Component) bool { return c.Class == ClassCore },
	},
	{
		name: "required by policy but not compiled", state: StateRequiredMissing, reason: ReasonPolicyRequired,
		match:   func(ctx *resolveCtx, c Component) bool { return !ctx.compiled[c.ID] && ctx.policyRequires(c) },
		because: func(ctx *resolveCtx, c Component) string { return ctx.policyRequired[c.ID] },
	},
	{
		name: "not compiled", state: StateAbsent, reason: ReasonNotCompiled,
		match: func(ctx *resolveCtx, c Component) bool { return !ctx.compiled[c.ID] },
	},
	{
		name: "not cleared by the availability ceiling", state: StateBlocked, reason: ReasonNotAvailable,
		match: func(ctx *resolveCtx, c Component) bool { return ctx.unavailable[c.ID] },
	},
	{
		name: "not entitled", state: StateBlocked, reason: ReasonNotEntitled,
		match: func(ctx *resolveCtx, c Component) bool { return ctx.unentitled[c.ID] },
	},
	{
		name: "outside the local ceiling", state: StateBlocked, reason: ReasonAboveCeiling,
		match: func(ctx *resolveCtx, c Component) bool { return ctx.aboveCeiling[c.ID] },
	},
	{
		name: "denied by policy", state: StateBlocked, reason: ReasonPolicyDenied,
		match: func(ctx *resolveCtx, c Component) bool { return ctx.policyDenied[c.ID] },
	},
	{
		name: "denied", state: StateBlocked, reason: ReasonDenied,
		match: func(ctx *resolveCtx, c Component) bool { return ctx.denied[c.ID] },
	},
	{
		name: "not named by policy (unlisted is inert)", state: StateBlocked, reason: ReasonPolicyUnlisted,
		match: func(ctx *resolveCtx, c Component) bool { return ctx.unlisted(c) },
	},
	{
		name: "requires a denied component", state: StateBlocked, reason: ReasonDeniedDependency,
		match:   func(ctx *resolveCtx, c Component) bool { return ctx.deniedBy[c.ID] != "" },
		because: func(ctx *resolveCtx, c Component) string { return ctx.deniedBy[c.ID] },
	},
	{
		name: "a dependency is not compiled", state: StateBlocked, reason: ReasonRequiresNotCompiled,
		match:   func(ctx *resolveCtx, c Component) bool { return ctx.missingDep[c.ID] != "" },
		because: func(ctx *resolveCtx, c Component) string { return ctx.missingDep[c.ID] },
	},
	{
		name: "granted", state: StateActive, reason: ReasonGranted,
		match: func(ctx *resolveCtx, c Component) bool { return ctx.granted[c.ID] },
	},
	{
		name: "required by policy", state: StateActive, reason: ReasonPolicyRequired,
		match:   func(ctx *resolveCtx, c Component) bool { return ctx.policyRequires(c) },
		because: func(ctx *resolveCtx, c Component) string { return ctx.policyRequired[c.ID] },
	},
	{
		name: "selected", state: StateActive, reason: ReasonSelected,
		match: func(ctx *resolveCtx, c Component) bool { return ctx.selected[c.ID] },
	},
	{
		name: "required by a selected component", state: StateActive, reason: ReasonRequiredBy,
		match:   func(ctx *resolveCtx, c Component) bool { return ctx.wantedBy[c.ID] != "" },
		because: func(ctx *resolveCtx, c Component) string { return ctx.wantedBy[c.ID] },
	},
	{
		name: "otherwise", state: StateAvailable, reason: ReasonNotSelected,
		match: func(_ *resolveCtx, _ Component) bool { return true },
	},
}

// Resolve resolves one binary's rows against a compiled set, a selection
// and a denial set. Properties (each a test row): requires is transitive;
// selecting a component selects what it requires; denying a component
// that a selected component requires blocks the dependant too and says so;
// selecting a component that is not compiled in is an error naming the
// distros that have it; a requires_compiled dependency missing from the
// build blocks the component.
func Resolve(in ResolveInput) ResolveResult {
	rows := ForBinary(in.Binary)
	by := map[string]Component{}
	for _, c := range rows {
		by[c.ID] = c
	}
	ctx := &resolveCtx{
		compiled:   map[string]bool{},
		selected:   toSet(in.Selected),
		denied:     toSet(in.Denied),
		deniedBy:   map[string]string{},
		wantedBy:   map[string]string{},
		missingDep: map[string]string{},
	}
	if in.Compiled == nil {
		for _, c := range rows {
			ctx.compiled[c.ID] = true
		}
	} else {
		ctx.compiled = toSet(in.Compiled)
	}

	var errs []string
	for _, id := range sortedKeys(ctx.selected) {
		if _, ok := by[id]; !ok {
			errs = append(errs, fmt.Sprintf("%s: unknown %s component", id, in.Binary))
		}
	}

	// Transitive requires closure of each id (requires only; a
	// requires_compiled edge needs code, not activity).
	var closure func(id string, seen map[string]bool) []string
	closure = func(id string, seen map[string]bool) []string {
		var out []string
		for _, r := range by[id].Requires {
			if seen[r] {
				continue
			}
			seen[r] = true
			out = append(out, r)
			out = append(out, closure(r, seen)...)
		}
		return out
	}

	applyGovernance(ctx, in.Governance, rows, closure)

	// Denied closure: X is blocked when anything it (transitively)
	// requires is blocked by its own row (denied locally or by policy,
	// outside the ceiling, or unlisted by the policy in force).
	for _, c := range rows {
		if ctx.blockedOwn(c) {
			continue
		}
		for _, r := range closure(c.ID, map[string]bool{}) {
			if rc, ok := by[r]; ctx.denied[r] || (ok && ctx.compiled[r] && ctx.blockedOwn(rc)) {
				ctx.deniedBy[c.ID] = r
				break
			}
		}
	}
	// Missing dependency: a requires or requires_compiled target (direct or
	// through requires) that is not compiled in.
	for _, c := range rows {
		deps := append(append([]string(nil), c.RequiresCompiled...), closure(c.ID, map[string]bool{})...)
		for _, r := range by[c.ID].RequiresCompiled {
			deps = append(deps, by[r].RequiresCompiled...)
		}
		for _, r := range deps {
			if !ctx.compiled[r] {
				ctx.missingDep[c.ID] = r
				break
			}
		}
	}
	// Wanted closure from the selection, in sorted order so "because" is
	// deterministic.
	for _, id := range sortedKeys(ctx.selected) {
		for _, r := range closure(id, map[string]bool{}) {
			if _, ok := ctx.wantedBy[r]; !ok && !ctx.selected[r] {
				ctx.wantedBy[r] = id
			}
		}
	}

	res := ResolveResult{}
	for _, c := range rows {
		for _, rule := range resolveRules {
			if !rule.match(ctx, c) {
				continue
			}
			d := Decision{ID: c.ID, State: rule.state, Reason: rule.reason}
			if rule.because != nil {
				d.Because = rule.because(ctx, c)
			}
			res.Decisions = append(res.Decisions, d)
			break
		}
	}
	sort.Slice(res.Decisions, func(i, j int) bool { return res.Decisions[i].ID < res.Decisions[j].ID })

	errs = append(errs, selectionErrors(ctx, res, by)...)
	sort.Strings(errs)
	res.Errors = errs
	return res
}

// selectionErrors lists the selections that cannot be honoured and the
// conflicts between active components.
func selectionErrors(ctx *resolveCtx, res ResolveResult, by map[string]Component) []string {
	var errs []string
	// Policy compliance findings, whatever the local selection says: a
	// required component that this build lacks or that cannot run is never
	// silent (plan 6.2.2 "Required but not compiled in").
	for _, d := range res.Decisions {
		c := by[d.ID]
		if !ctx.policyRequires(c) {
			continue
		}
		why := ""
		if b := ctx.policyRequired[d.ID]; b != "" {
			why = " (needed by required " + b + ")"
		}
		switch {
		case d.State == StateRequiredMissing:
			errs = append(errs, fmt.Sprintf("%s%s: required by the organization's component policy but not in this build; %s", d.ID, why, distrosHaving(d.ID)))
		case d.State == StateBlocked:
			errs = append(errs, fmt.Sprintf("%s%s: required by the organization's component policy but blocked (%s)", d.ID, why, d.Reason))
		}
	}
	for _, d := range res.Decisions {
		if ctx.policyRequires(by[d.ID]) {
			continue
		}
		wanted := ctx.selected[d.ID] || ctx.wantedBy[d.ID] != ""
		if !wanted {
			continue
		}
		why := ""
		if !ctx.selected[d.ID] {
			why = " (required by " + ctx.wantedBy[d.ID] + ")"
		}
		switch d.Reason {
		case ReasonNotAvailable:
			errs = append(errs, fmt.Sprintf("%s%s: not available here (the platform operator has not cleared it)", d.ID, why))
		case ReasonNotEntitled:
			errs = append(errs, fmt.Sprintf("%s%s: not included in this organization's plan", d.ID, why))
		case ReasonAboveCeiling:
			errs = append(errs, fmt.Sprintf("%s%s: outside this machine's local component ceiling", d.ID, why))
		case ReasonPolicyDenied:
			errs = append(errs, fmt.Sprintf("%s%s: denied by the organization's component policy", d.ID, why))
		case ReasonNotCompiled:
			errs = append(errs, fmt.Sprintf("%s%s: not in this build; %s", d.ID, why, distrosHaving(d.ID)))
		case ReasonDenied:
			errs = append(errs, fmt.Sprintf("%s%s: denied", d.ID, why))
		case ReasonDeniedDependency:
			errs = append(errs, fmt.Sprintf("%s%s: requires %s, which is denied", d.ID, why, d.Because))
		case ReasonRequiresNotCompiled:
			errs = append(errs, fmt.Sprintf("%s%s: needs %s, which is not in this build; %s", d.ID, why, d.Because, distrosHaving(d.Because)))
		}
	}
	// Conflicts between active components.
	active := toSet(res.Active())
	for _, id := range sortedKeys(active) {
		for _, k := range by[id].Conflicts {
			if active[k] && id < k {
				errs = append(errs, fmt.Sprintf("%s: conflicts with %s, and both are active", id, k))
			}
		}
	}
	return errs
}

// applyGovernance fills the governance part of the resolver context. With a
// nil Governance every map stays empty and every governance row of
// resolveRules never matches, so the result is exactly the ungoverned one.
func applyGovernance(ctx *resolveCtx, g *Governance, rows []Component, closure func(string, map[string]bool) []string) {
	ctx.aboveCeiling = map[string]bool{}
	ctx.policyDenied = map[string]bool{}
	ctx.policyAllowed = map[string]bool{}
	ctx.policyRequired = map[string]string{}
	ctx.unavailable = map[string]bool{}
	ctx.unentitled = map[string]bool{}
	ctx.granted = map[string]bool{}
	if g == nil {
		return
	}
	layerBlock(ctx, g.Availability, rows, ctx.unavailable)
	if g.Entitled != nil {
		layerBlock(ctx, &Availability{Allow: g.Entitled.Allow}, rows, ctx.unentitled)
	}
	if g.CeilingPinned {
		ceiling := toSet(g.Ceiling)
		for _, c := range rows {
			if c.Class != ClassCore && ctx.compiled[c.ID] && !ceiling[c.ID] {
				ctx.aboveCeiling[c.ID] = true
			}
		}
	}
	p := g.Policy
	if p == nil {
		return
	}
	ctx.policy = true
	grantable := toSet(p.Grantable)
	granted := toSet(g.Granted)
	for _, id := range p.Deny {
		if granted[id] && grantable[id] {
			continue // a grant overrides only a grantable deny entry
		}
		ctx.policyDenied[id] = true
	}
	for _, id := range sortedKeys(granted) {
		if !ctx.policyDenied[id] {
			ctx.granted[id] = true
		}
	}
	// Allowing, requiring or granting a component lets what it needs run
	// too, the same rule as a local selection; an explicit deny still wins.
	allow := func(id string) {
		ctx.policyAllowed[id] = true
		for _, r := range closure(id, map[string]bool{}) {
			ctx.policyAllowed[r] = true
		}
	}
	for _, id := range p.Allow {
		allow(id)
	}
	for _, id := range sortedKeys(ctx.granted) {
		allow(id)
	}
	required := uniqSortedIDs(p.Require)
	for _, id := range required {
		allow(id)
		ctx.policyRequired[id] = ""
	}
	for _, id := range required {
		for _, r := range closure(id, map[string]bool{}) {
			if _, ok := ctx.policyRequired[r]; !ok {
				ctx.policyRequired[r] = id
			}
		}
	}
}

func uniqSortedIDs(ids []string) []string {
	return sortedKeys(toSet(ids))
}

// BuildsHaving is the "where do I get it" clause for a component this
// binary lacks ("builds that include it: full, developer"), the same text
// the resolver's refusals carry, for surfaces outside this package (doctor,
// teardown) that name a compiled-out component (T-726).
func BuildsHaving(id string) string { return distrosHaving(id) }

// distrosHaving names the prebuilt distros that compile id in.
func distrosHaving(id string) string {
	c, ok := Get(id)
	if !ok || c.Binary != BinaryNode {
		return "no prebuilt node distro includes it"
	}
	var has []string
	for _, d := range Distros() {
		if c.Distros[d].Compiled() {
			has = append(has, string(d))
		}
	}
	if len(has) == 0 {
		return "no prebuilt distro includes it"
	}
	return "builds that include it: " + strings.Join(has, ", ")
}

func toSet(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// layerBlock marks into dst every compiled non-core row a pinned allow-set
// layer does not clear. A nil layer marks nothing.
func layerBlock(ctx *resolveCtx, layer *Availability, rows []Component, dst map[string]bool) {
	if layer == nil {
		return
	}
	allow := toSet(layer.Allow)
	for _, c := range rows {
		if c.Class != ClassCore && ctx.compiled[c.ID] && !allow[c.ID] {
			dst[c.ID] = true
		}
	}
}
