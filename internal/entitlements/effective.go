package entitlements

import (
	"slices"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// Source says where an effective entitlement came from.
type Source string

// The closed Source vocabulary.
const (
	// SourceDocument: a verified document in force, composed with the floor.
	SourceDocument Source = "document"
	// SourceFloor: the floor alone.
	SourceFloor Source = "floor"
)

// Fallback says why the floor applies alone.
type Fallback string

// The closed Fallback vocabulary ("" when a document is in force).
const (
	// FallbackNone: a document is in force.
	FallbackNone Fallback = ""
	// FallbackUnknownKind: the kind has no floor; nothing but core is
	// entitled (fail closed).
	FallbackUnknownKind Fallback = "unknown_kind"
	// FallbackNoDocument: no verified document.
	FallbackNoDocument Fallback = "no_document"
	// FallbackKindMismatch: the document is of another kind.
	FallbackKindMismatch Fallback = "kind_mismatch"
	// FallbackNotYetValid: now is before the document's not_before.
	FallbackNotYetValid Fallback = "not_yet_valid"
	// FallbackExpired: now is at or after the document's not_after.
	FallbackExpired Fallback = "expired"
)

// Limit is one effective cap.
type Limit struct {
	// N is the cap when finite.
	N int64
	// Unlimited reports that the entitlement does not limit it.
	Unlimited bool
	// Set reports that the cap applies to this kind at all. An unset
	// limit allows nothing (fail closed): a caller asked about a cap that
	// does not apply to the org.
	Set bool
}

// Allows reports whether a quantity of n is within the limit ("at most N").
// To admit one more item, ask Allows(current + 1).
func (l Limit) Allows(n int64) bool {
	if !l.Set {
		return false
	}
	return l.Unlimited || n <= l.N
}

// Effective is the entitlement in force for one org: the floor of its kind
// composed with the verified document in force, if any. It is immutable;
// every accessor returns copies.
type Effective struct {
	kind     Kind
	source   Source
	fallback Fallback
	plan     PlanRef
	version  int64
	granted  map[string]bool
	caps     map[CapName]int64
	terms    map[TermName]string
	ignored  []string
}

// docRule is one row of the "is the document in force" table, walked
// top-down: the first that matches sends the org to its floor.
type docRule struct {
	fallback Fallback
	match    func(kind Kind, d *Document, now int64) bool
}

func docRules() []docRule {
	return []docRule{
		{fallback: FallbackNoDocument, match: func(_ Kind, d *Document, _ int64) bool { return d == nil }},
		{fallback: FallbackKindMismatch, match: func(k Kind, d *Document, _ int64) bool { return d.Body.Kind != k }},
		{fallback: FallbackNotYetValid, match: func(_ Kind, d *Document, now int64) bool { return now < d.Body.NotBefore }},
		{fallback: FallbackExpired, match: func(_ Kind, d *Document, now int64) bool {
			return d.Body.NotAfter != 0 && now >= d.Body.NotAfter
		}},
	}
}

// Evaluate returns the entitlement in force for an org of kind k at now,
// given the verified document the host holds (nil when none). It never
// fails: anything wrong with the document leaves the floor (plan 06 6.1
// row L7), and an unknown kind entitles core only.
func Evaluate(k Kind, d *Document, now time.Time) Effective {
	floor, ok := Floor(k)
	if !ok {
		return Effective{kind: k, source: SourceFloor, fallback: FallbackUnknownKind, granted: map[string]bool{}, caps: map[CapName]int64{}, terms: map[TermName]string{}}
	}
	e := fromBody(floor, k)
	e.source, e.fallback = SourceFloor, FallbackNone
	unix := now.Unix()
	for _, r := range docRules() {
		if r.match(k, d, unix) {
			e.fallback = r.fallback
			return e
		}
	}
	e.compose(d.Body)
	e.source = SourceDocument
	e.plan = d.Body.Plan
	e.version = d.Version
	return e
}

func fromBody(b Body, k Kind) Effective {
	e := Effective{
		kind:    k,
		plan:    b.Plan,
		granted: map[string]bool{},
		caps:    map[CapName]int64{},
		terms:   map[TermName]string{},
	}
	e.compose(b)
	return e
}

// composeRule is how one value of a document joins the floor.
//
//	capability: union (a document only adds)
//	cap:        the larger; Unlimited above every number
//	term:       the document's value replaces the floor's
//
// A value this binary does not know, or that does not apply to the kind,
// is ignored and listed in Ignored: a host cannot enforce what it does not
// know, and an additive issuer change must not break an older host.
func (e *Effective) compose(b Body) {
	for _, id := range b.Capabilities {
		if !isPlanGated(id) {
			e.ignored = append(e.ignored, "capability "+id)
			continue
		}
		e.granted[id] = true
	}
	for _, n := range sortedCapNames(b.Caps) {
		r, ok := capRuleFor(n)
		if !ok || !slices.Contains(r.kinds, e.kind) {
			e.ignored = append(e.ignored, "cap "+string(n))
			continue
		}
		v := b.Caps[n]
		if cur, ok := e.caps[n]; ok {
			v = joinCap(cur, v)
		}
		e.caps[n] = v
	}
	for _, n := range sortedTermNames(b.Terms) {
		r, ok := termRuleFor(n)
		if !ok || !slices.Contains(r.kinds, e.kind) {
			e.ignored = append(e.ignored, "term "+string(n))
			continue
		}
		e.terms[n] = b.Terms[n]
	}
}

// joinCap is the cap join: Unlimited wins, else the larger.
func joinCap(a, b int64) int64 {
	if a == Unlimited || b == Unlimited {
		return Unlimited
	}
	return max(a, b)
}

// Kind returns the org kind the entitlement was evaluated for.
func (e Effective) Kind() Kind { return e.kind }

// Source says whether a document is in force or the floor alone.
func (e Effective) Source() Source { return e.source }

// Fallback says why the floor applies alone (FallbackNone otherwise).
func (e Effective) Fallback() Fallback { return e.fallback }

// Plan names the plan in force (the document's, or the floor's).
func (e Effective) Plan() PlanRef { return e.plan }

// OnFloorPlan reports whether the plan in force is its kind's floor plan
// (any version of it): the floor alone, or a document of the floor's plan
// (an issuer re-issues the floor as a document). False for an unknown kind.
// A rule that treats the floor differently from the plans above it (the AI
// gateway's grace: the floor stops at its allowance, plans above it get a
// grace) reads it, never a plan name.
func (e Effective) OnFloorPlan() bool {
	if e.fallback == FallbackUnknownKind {
		return false
	}
	f, ok := Floor(e.kind)
	return ok && e.plan.Name == f.Plan.Name
}

// Version is the document version in force (0 on the floor alone).
func (e Effective) Version() int64 { return e.version }

// Ignored lists, sorted, the document values this binary did not apply.
func (e Effective) Ignored() []string {
	out := slices.Clone(e.ignored)
	sort.Strings(out)
	return out
}

// Has reports whether the org is entitled to a server component: core
// always (on a known kind), an included component always, a plan-gated one
// when the floor or the document lists it. An unknown id is not entitled.
func (e Effective) Has(id string) bool {
	if e.fallback == FallbackUnknownKind {
		return isCore(id)
	}
	if isCore(id) {
		return true
	}
	if g, ok := GateOf(id); ok && g == GateIncluded {
		return true
	}
	return e.granted[id]
}

// Cap returns the effective cap n.
func (e Effective) Cap(n CapName) Limit {
	v, ok := e.caps[n]
	if !ok {
		return Limit{}
	}
	if v == Unlimited {
		return Limit{Unlimited: true, Set: true}
	}
	return Limit{N: v, Set: true}
}

// Term returns the effective term n.
func (e Effective) Term(n TermName) (string, bool) {
	v, ok := e.terms[n]
	return v, ok
}

// Capabilities returns every server component id the org is entitled to
// besides core, sorted: the included ones and the granted ones.
func (e Effective) Capabilities() []string {
	if e.fallback == FallbackUnknownKind {
		return nil
	}
	set := map[string]bool{}
	for _, id := range GatedIDs(GateIncluded) {
		set[id] = true
	}
	for id := range e.granted {
		set[id] = true
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ComponentInput is the layer-3 input of components.Resolve
// (Governance.Entitled): the entitled ids. A compiled non-core component
// outside it resolves blocked, not_entitled, and is refused through the
// resolver's one component_not_installed body.
func (e Effective) ComponentInput() *components.Entitlement {
	return &components.Entitlement{Allow: e.Capabilities()}
}

func isCore(id string) bool {
	c, ok := components.Get(id)
	return ok && c.Class == components.ClassCore
}
