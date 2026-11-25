package availcompose

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/marmutapp/superbased-observer/internal/components"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// orgComponentIDs is the table of components the staff console turns on or
// off for one org (lane SR-17: org.security first). A row must be a catalog
// component that an envelope may open to named orgs in pooled
// (components.ReachPooledOffer) and that is not on the pooled launch floor,
// so "off" is its default and "on for this org" is a named reach
// (TestOrgComponentsAreNamedOffers). org.aigateway is the hosted AI
// gateway's beta switch (L-172, plan hosted-ai-gateway 3.14): staff name
// the orgs it runs for; its general availability goes through component
// reach, not this table.
var orgComponentIDs = []string{"org.security", "org.aigateway"}

// OrgComponent is one per-org component the console controls.
type OrgComponent struct {
	// ID is the catalog component id.
	ID string `json:"component"`
	// Title is the catalog title.
	Title string `json:"title"`
}

// OrgComponents returns the per-org component table, with catalog titles.
// An id this build's catalog does not know is left out.
func OrgComponents() []OrgComponent {
	out := make([]OrgComponent, 0, len(orgComponentIDs))
	for _, id := range orgComponentIDs {
		if c, ok := components.Get(id); ok {
			out = append(out, OrgComponent{ID: id, Title: c.Title})
		}
	}
	return out
}

// IsOrgComponent reports whether id is in the per-org component table.
func IsOrgComponent(id string) bool { return slices.Contains(orgComponentIDs, id) }

// Offered reports whether body offers component to org on a pooled host: the
// host's own layer-2 evaluation (components.EvaluateAvailability) over the
// component's catalog row, with no cohort (cohort membership is the host's
// to know). A nil body is "no envelope issued yet": the launch floor.
// Entitlement (layer 3) is the org's plan, not this envelope's.
func Offered(body *pc.AvailabilityBody, component, org string) bool {
	c, ok := components.Get(component)
	if !ok {
		return false
	}
	av := components.EvaluateAvailability(body, components.ShapePooled, components.Subject{Org: org}, []components.Component{c})
	return av != nil && slices.Contains(av.Allow, component)
}

// onFloor reports whether component runs on the pooled launch floor.
func onFloor(component string) bool {
	c, ok := components.Get(component)
	return ok && slices.Contains(components.PooledFloor([]components.Component{c}), component)
}

// ErrToggle marks a toggle the console cannot express for one org; its
// message says where to change it instead.
var ErrToggle = errors.New("availcompose: this change cannot be made for one org")

// toggleAction is what a toggle rule does.
type toggleAction int

const (
	// actAdd puts the org in the named list (a new named row if needed).
	actAdd toggleAction = iota + 1
	// actRemove takes the org out of the named list (the row goes when the
	// list empties).
	actRemove
	// actNone changes nothing (the org is already in that state).
	actNone
	// actRefuse cannot be done per org.
	actRefuse
)

// toggleRule is one row of the toggle table: for a stored reach ("" = no
// row) and a wanted state, the action (floor: whether the component is on
// the launch floor; nil matches both).
type toggleRule struct {
	reach  pc.Reach
	on     bool
	floor  *bool
	action toggleAction
	why    string
}

var (
	yes = true
	no  = false
)

// toggleRules is THE toggle table, walked top down, first match wins.
var toggleRules = []toggleRule{
	{reach: pc.ReachCohort, on: true, action: actRefuse, why: "the component's reach is a cohort; change it on the Availability page"},
	{reach: pc.ReachCohort, on: false, action: actRefuse, why: "the component's reach is a cohort; change it on the Availability page"},
	{reach: pc.ReachNamed, on: true, action: actAdd},
	{reach: pc.ReachNamed, on: false, action: actRemove},
	{reach: pc.ReachOff, on: true, action: actAdd, why: "replaces the platform-wide off with this org alone"},
	{reach: pc.ReachOff, on: false, action: actNone},
	// No row, or the stage default: the launch floor decides.
	{reach: "", on: true, floor: &no, action: actAdd},
	{reach: "", on: false, floor: &no, action: actNone},
	{reach: "", on: true, floor: &yes, action: actNone},
	{reach: "", on: false, floor: &yes, action: actRefuse, why: "the component is on for every org by default; switching it off for one org is not a named reach"},
	{reach: pc.ReachStageDefault, on: true, floor: &no, action: actAdd},
	{reach: pc.ReachStageDefault, on: false, floor: &no, action: actNone},
	{reach: pc.ReachStageDefault, on: true, floor: &yes, action: actNone},
	{reach: pc.ReachStageDefault, on: false, floor: &yes, action: actRefuse, why: "the component is on for every org by default; switching it off for one org is not a named reach"},
}

func toggleRuleFor(reach pc.Reach, on, floor bool) (toggleRule, bool) {
	for _, r := range toggleRules {
		if r.reach == reach && r.on == on && (r.floor == nil || *r.floor == floor) {
			return r, true
		}
	}
	return toggleRule{}, false
}

// Toggled is the result of Toggle.
type Toggled struct {
	// Value is the components input value to write; nil means remove the
	// row.
	Value json.RawMessage
	// Changed is false when the org is already in the wanted state (nothing
	// to write).
	Changed bool
}

// Toggle returns the components input for component that turns it on or off
// for org, from the stored input value (nil: no row). It refuses a component
// outside the per-org table, an org that is not a canonical org id, and a
// stored row it cannot read.
func Toggle(component string, current []byte, org string, on bool) (Toggled, error) {
	if !IsOrgComponent(component) {
		return Toggled{}, fmt.Errorf("%w: %s is not a per-org component", ErrToggle, component)
	}
	if !canonicalOrgID(org) {
		return Toggled{}, fmt.Errorf("%w: %q is not an org id", ErrToggle, org)
	}
	var v reachValue
	if current != nil {
		if err := decodeStrict(current, &v); err != nil {
			return Toggled{}, fmt.Errorf("%w: the stored input does not decode (%w); fix it on the Availability page", ErrToggle, err)
		}
	}
	rule, ok := toggleRuleFor(v.Reach, on, onFloor(component))
	if !ok {
		return Toggled{}, fmt.Errorf("%w: unknown reach %q", ErrToggle, v.Reach)
	}
	named := []string(nil)
	if v.Reach == pc.ReachNamed {
		named = append(named, v.Orgs...)
	}
	switch rule.action {
	case actAdd:
		if slices.Contains(named, org) {
			return Toggled{Value: current, Changed: false}, nil
		}
		return namedValue(component, append(named, org))
	case actRemove:
		if !slices.Contains(named, org) {
			return Toggled{Value: current, Changed: false}, nil
		}
		rest := slices.DeleteFunc(named, func(o string) bool { return o == org })
		if len(rest) == 0 {
			return Toggled{Value: nil, Changed: true}, nil
		}
		return namedValue(component, rest)
	case actNone:
		return Toggled{Value: current, Changed: false}, nil
	default:
		return Toggled{}, fmt.Errorf("%w: %s", ErrToggle, rule.why)
	}
}

// namedValue is the named-reach value for orgs (sorted), checked as an
// input.
func namedValue(component string, orgs []string) (Toggled, error) {
	raw, err := json.Marshal(reachValue{Reach: pc.ReachNamed, Orgs: sortedCopy(orgs)})
	if err != nil {
		return Toggled{}, fmt.Errorf("availcompose.Toggle: %w", err)
	}
	if err := ValidateInput(SectionComponents, component, raw); err != nil {
		return Toggled{}, err
	}
	return Toggled{Value: raw, Changed: true}, nil
}

// InputOffered reports whether the stored components input for component
// (nil: no row) offers it to org, on its own (other inputs do not change a
// component's reach). A value that does not compose offers nothing.
func InputOffered(component string, current []byte, org string) bool {
	if current == nil {
		return Offered(&pc.AvailabilityBody{IssuedAt: rowCheckTime}, component, org)
	}
	b, err := checkRow(Input{Section: SectionComponents, Key: component, Value: current, Reason: "check", Author: "staff:check"})
	if err != nil {
		return false
	}
	return Offered(&b, component, org)
}
