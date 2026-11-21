package components

import (
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// availability.go evaluates a verified availability envelope body
// (sbo-availability-v1, plan 06 18.3.5) into the resolver's layer-2 input.
// Verifying the signature is not done here: callers pass a body that
// VerifyAvailability already accepted and Validate already passed.

// Availability is the layer-2 resolver input (Governance.Availability): the
// ids the platform operator clears to run for this org on this host. A
// compiled non-core id outside Allow resolves blocked / not_available. A nil
// *Availability means no ceiling (single mode, private deployments).
type Availability struct {
	// Allow lists the cleared ids. Empty means core only.
	Allow []string
}

// Entitlement is the layer-3 resolver input (Governance.Entitled): the ids
// the org has paid for. Built by internal/entitlements (M7b.1), not here. A
// compiled non-core id outside Allow resolves blocked / not_entitled. Nil
// means no entitlement layer.
type Entitlement struct {
	// Allow lists the entitled ids. Empty means core only.
	Allow []string
}

// Shape is a deployment shape.
type Shape string

// Deployment shapes.
const (
	// ShapeSingle is a self-hosted single-tenant server: the [components]
	// block is the ceiling and the envelope does not apply.
	ShapeSingle Shape = "single"
	// ShapeDedicated is a dedicated deployment: as compiled and selected.
	ShapeDedicated Shape = "dedicated"
	// ShapePooled is pooled SaaS: the envelope and the launch floor apply.
	ShapePooled Shape = "pooled"
)

// Subject is who the availability is evaluated for.
type Subject struct {
	// Org is the org id.
	Org string
	// Cohorts are the rollout cohorts the org belongs to.
	Cohorts []string
}

// EvaluateAvailability reduces a verified body to the layer-2 input for one
// subject on one deployment shape, over the given rows (the host's compiled
// rows). Rules (the envelope reach table below holds the per-reach ones):
//
//   - single and dedicated: nil (no ceiling; "as compiled and selected");
//   - an unknown shape: allow nothing (fail closed);
//   - pooled, nil body (no envelope ever verified): PooledFloor;
//   - pooled, no row for the component: the floor rule for that component;
//   - core is always allowed.
func EvaluateAvailability(body *platformcontract.AvailabilityBody, shape Shape, subj Subject, rows []Component) *Availability {
	switch shape {
	case ShapeSingle, ShapeDedicated:
		return nil
	case ShapePooled:
	default:
		return &Availability{}
	}
	floor := toSet(PooledFloor(rows))
	if body == nil {
		return &Availability{Allow: sortedKeys(floor)}
	}
	entries := make(map[string]platformcontract.ComponentAvailability, len(body.Components))
	for _, e := range body.Components {
		entries[e.Component] = e
	}
	cohorts := toSet(subj.Cohorts)
	allow := map[string]bool{}
	for _, c := range rows {
		if c.Class == ClassCore {
			allow[c.ID] = true
			continue
		}
		e, ok := entries[c.ID]
		if !ok {
			if floor[c.ID] {
				allow[c.ID] = true
			}
			continue
		}
		if envelopeAllows(e, c, subj, cohorts, floor[c.ID]) {
			allow[c.ID] = true
		}
	}
	return &Availability{Allow: sortedKeys(allow)}
}

// envReachRule is one row of the envelope reach table: whether a components
// entry of that reach clears the row for the subject.
type envReachRule struct {
	reach platformcontract.Reach
	allow func(e platformcontract.ComponentAvailability, c Component, subj Subject, cohorts map[string]bool, floor bool) bool
}

// envReachRules is the envelope reach table (one test row each). An envelope
// narrows below a row's reach or widens within its stage, never beyond.
var envReachRules = []envReachRule{
	{platformcontract.ReachOff, func(platformcontract.ComponentAvailability, Component, Subject, map[string]bool, bool) bool {
		return false
	}},
	{platformcontract.ReachStageDefault, func(_ platformcontract.ComponentAvailability, _ Component, _ Subject, _ map[string]bool, floor bool) bool {
		return floor
	}},
	{platformcontract.ReachNamed, func(e platformcontract.ComponentAvailability, c Component, subj Subject, _ map[string]bool, _ bool) bool {
		return c.Reach.Has(ReachPooledOffer) && containsID(e.Orgs, subj.Org)
	}},
	{platformcontract.ReachCohort, func(e platformcontract.ComponentAvailability, c Component, _ Subject, cohorts map[string]bool, _ bool) bool {
		return c.Reach.Has(ReachPooledOffer) && c.Stability != StabilityExperimental && cohorts[e.Cohort]
	}},
}

func envelopeAllows(e platformcontract.ComponentAvailability, c Component, subj Subject, cohorts map[string]bool, floor bool) bool {
	for _, r := range envReachRules {
		if r.reach == e.Reach {
			return r.allow(e, c, subj, cohorts, floor)
		}
	}
	return false // unknown reach: fail closed
}

func containsID(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// CheckEnvelope is the verification-time check that an envelope tries to
// widen nothing a catalog row does not allow (the shape rules are
// platformcontract's; this is the catalog side, plan 06 18.3.7 "refused at
// verification"). It names every problem, sorted, in one error.
func CheckEnvelope(body platformcontract.AvailabilityBody) error {
	return checkEnvelope(body, Get)
}

// checkEnvelope is CheckEnvelope over a catalog lookup (the catalog in
// production; a synthetic one in the tests, since no shipped org row is
// experimental today).
func checkEnvelope(body platformcontract.AvailabilityBody, get func(string) (Component, bool)) error {
	var p []string
	for _, e := range body.Components {
		c, ok := get(e.Component)
		switch {
		case !ok:
			p = append(p, fmt.Sprintf("%s: unknown component", e.Component))
		case c.Class == ClassCore:
			p = append(p, fmt.Sprintf("%s: core is always available and cannot be listed", e.Component))
		case (e.Reach == platformcontract.ReachNamed || e.Reach == platformcontract.ReachCohort) && !c.Reach.Has(ReachPooledOffer):
			p = append(p, fmt.Sprintf("%s: not offerable in pooled; an envelope cannot widen its reach", e.Component))
		case e.Reach == platformcontract.ReachCohort && c.Stability == StabilityExperimental:
			p = append(p, fmt.Sprintf("%s: experimental components are open to named orgs only, never a cohort", e.Component))
		}
	}
	if len(p) == 0 {
		return nil
	}
	sort.Strings(p)
	return fmt.Errorf("components.CheckEnvelope: %s", strings.Join(p, "; "))
}
