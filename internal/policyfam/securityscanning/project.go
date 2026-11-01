package securityscanning

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/postureop"
)

// Project sections (security plan section 7.11 "Family bodies
// (security.scanning sections) merge with their per-field raise-only
// operators", lane sec-p3): an org may publish a body for one or more of its
// projects. On a node, in a directory that matched those projects, the floor
// in force is the org-wide body with every matched project's sections merged
// over it, per axis, keeping the stronger floor (the same operators Effective
// raises the node's own values with); several matched projects take the
// strictest of them. A project section only ever raises: merging never
// weakens an axis the org-wide body (or an earlier section) set.

// floorWriters stores an axis's floor into a body: one row per axis, the
// counterpart of floorReaders.
var floorWriters = map[string]func(b *Body, v postureop.Value){
	AxisComponents:           func(b *Body, v postureop.Value) { reqW(b).Components = v.Set },
	AxisPrelaunchTrust:       func(b *Body, v postureop.Value) { reqW(b).PrelaunchTrust = v.S },
	AxisCommitGate:           func(b *Body, v postureop.Value) { reqW(b).CommitGate = v.S },
	AxisQuickScanBudget:      func(b *Body, v postureop.Value) { reqW(b).QuickScanBudgetS = num(v.N) },
	AxisMaxScanStaleness:     func(b *Body, v postureop.Value) { reqW(b).MaxScanStalenessMin = num(v.N) },
	AxisMaxAdvisoryDBAge:     func(b *Body, v postureop.Value) { reqW(b).MaxAdvisoryDBAgeH = num(v.N) },
	AxisMinBlockingSeverity:  func(b *Body, v postureop.Value) { reqW(b).MinBlockingSeverity = v.S },
	AxisInstallUnknown:       func(b *Body, v postureop.Value) { reqW(b).InstallUnknown = v.S },
	AxisOnlineChecks:         func(b *Body, v postureop.Value) { reqW(b).OnlineChecks = v.S },
	AxisInstallOnlineUnknown: func(b *Body, v postureop.Value) { reqW(b).InstallOnlineUnknown = v.S },
	AxisHistoryScanOnEnrol: func(b *Body, v postureop.Value) {
		on := v.S == "true"
		reqW(b).HistoryScanOnEnrol = &on
	},
	AxisFindingRetention:     func(b *Body, v postureop.Value) { reqW(b).FindingRetentionDays = num(v.N) },
	AxisAllowDrivers:         func(b *Body, v postureop.Value) { allowW(b).Drivers = v.Set },
	AxisAllowCustomManifests: func(b *Body, v postureop.Value) { allowW(b).CustomManifests = v.Set },
	AxisAllowScannerSources:  func(b *Body, v postureop.Value) { allowW(b).ScannerSources = v.Set },
	AxisAllowOnlineChecks:    func(b *Body, v postureop.Value) { allowW(b).OnlineChecks = v.S },
	AxisRulePackMinVersion:   func(b *Body, v postureop.Value) { b.RulePack = &RulePack{MinVersion: v.S} },
}

func reqW(b *Body) *Require {
	if b.Require == nil {
		b.Require = &Require{}
	}
	return b.Require
}

func allowW(b *Body) *Allow {
	if b.Allow == nil {
		b.Allow = &Allow{}
	}
	return b.Allow
}

func num(n int64) *int64 { return &n }

// ErrSectionConflict is a project section that cannot merge over the floor
// already in force (an allow-set whose intersection would allow nothing, or
// a combination the decoder refuses, such as online checks both required and
// forbidden). The section is not applied; what was in force stays.
var ErrSectionConflict = errors.New("policyfam/securityscanning: the project section cannot merge over the floor in force")

// MergeSpecs is over merged onto base, axis by axis: where both set a floor
// the stronger one is kept (enum order, numbers, retention, version,
// required components unioned, allow-sets intersected), where one does its
// floor is kept, and the sections are unioned. An allow-set intersection
// that would allow nothing, or a merged body the decoder would refuse, is
// ErrSectionConflict naming the axis.
func MergeSpecs(base, over PolicySpec) (PolicySpec, error) {
	var out Body
	for _, ax := range Axes {
		bv, bset := floorValue(base.Body, ax.Name)
		ov, oset := floorValue(over.Body, ax.Name)
		var v postureop.Value
		switch {
		case bset && oset:
			merged, err := mergeFloor(ax, bv, ov)
			if err != nil {
				return PolicySpec{}, fmt.Errorf("%w: %s: %w", ErrSectionConflict, ax.Name, err)
			}
			v = merged
		case bset:
			v = bv
		case oset:
			v = ov
		default:
			continue
		}
		floorWriters[ax.Name](&out, v)
	}
	if len(base.Body.Sections)+len(over.Body.Sections) > 0 {
		out.Sections = map[string]Section{}
		for id, s := range base.Body.Sections {
			out.Sections[id] = s
		}
		for id, s := range over.Body.Sections {
			out.Sections[id] = s
		}
	}
	out = normalize(out)
	if err := validate(out); err != nil {
		return PolicySpec{}, fmt.Errorf("%w: %w", ErrSectionConflict, err)
	}
	return PolicySpec{Body: out}, nil
}

// mergeFloor keeps the stronger of two floors on one axis. Unlike raise (a
// floor over the node's own value), both sides here are floors: a required
// component set is unioned and an allow-set is intersected even when one
// side lists every value.
func mergeFloor(ax postureop.Axis, a, b postureop.Value) (postureop.Value, error) {
	switch ax.Kind {
	case postureop.AxisSubsetStronger:
		v, err := postureop.SetIntersection(a.Set, false, b.Set)
		if err != nil {
			return postureop.Value{}, err
		}
		if len(v) == 0 {
			return postureop.Value{}, postureop.ErrEmptyIntersection
		}
		return postureop.Value{Set: v}, nil
	case postureop.AxisSupersetStronger:
		return postureop.Value{Set: postureop.AdditiveMask(a.Set, b.Set)}, nil
	default:
		return raise(ax, a, b)
	}
}

// ProjectSection is one project section to merge: the org project it was
// published for, its sequence and its compiled body. Project and Version
// are the stated tie-break order (see MergeProjectSections), never the order
// the caller happens to pass the sections in.
type ProjectSection struct {
	Project string
	Version int64
	Spec    PolicySpec
}

// AxisRefusal is one axis of one project section that is not applied.
type AxisRefusal struct {
	Axis string
	Err  error
}

// SectionOutcome is what merging one project section did. A section is
// refused per AXIS (SEC-P3 merge, finding 2): an axis that conflicts is not
// applied and is named in Refused, and every other axis the section sets
// still applies.
type SectionOutcome struct {
	// Applied: every axis the section sets merged (a section that sets no
	// axis, only capability sections, is applied).
	Applied bool
	// Partial: some axes were refused and at least one other part of the
	// section (an axis or a capability section) still applies.
	Partial bool
	// Refused lists the axes not applied, sorted by axis name.
	Refused []AxisRefusal
	// Err joins the refusals (nil when Applied); it wraps
	// ErrSectionConflict.
	Err error
}

// RefusedAxes returns the names of the refused axes, sorted, each once. It
// is the only source of the policy-state wire's RefusedAxes
// (orgcontract.ProjectFamilySectionState), so it is the normalizer that
// keeps that field a closed vocabulary: a name that is not a row of Axes
// (LookupAxis) is dropped here and never travels, whatever an outcome
// carries.
func (o SectionOutcome) RefusedAxes() []string {
	var out []string
	for _, r := range o.Refused {
		if _, ok := LookupAxis(r.Axis); !ok || (len(out) > 0 && out[len(out)-1] == r.Axis) {
			continue
		}
		out = append(out, r.Axis)
	}
	return out
}

// axisContradiction is a pair of axis values the decoder refuses together
// (validate). keep names the axis whose value stands when both values come
// from project sections; when one of them is the org-wide floor's own, the
// org-wide floor stands and the sections' value on the other axis is
// refused.
type axisContradiction struct {
	a, av string
	b, bv string
	keep  string
}

// axisContradictions is the closed table of cross-axis contradictions, one
// row per pair validate refuses. Online checks both required and forbidden:
// when two projects disagree, the privacy floor (forbidden: nothing leaves
// the machine) is kept and the requirement is refused.
var axisContradictions = []axisContradiction{
	{a: AxisOnlineChecks, av: "required", b: AxisAllowOnlineChecks, bv: "forbidden", keep: AxisAllowOnlineChecks},
}

// MergeProjectSections is the floor in force for a directory: base (the
// org-wide floor in force, nil when none) with every section merged over it,
// axis by axis, the stronger floor winning. The result does not depend on
// the order of sections:
//
//   - an axis value that conflicts with the org-wide floor (an allow-set
//     intersection that would allow nothing) is refused for that section;
//   - the remaining values on an axis are merged strictest-first; on an
//     allow-set axis, where two sections can together allow nothing, the
//     stated tie-break is the order (project id, then sequence, then the
//     canonical body): the earlier section's value stands and the later
//     one's axis is refused;
//   - a cross-axis contradiction (axisContradictions) refuses the losing
//     axis of every section that set it to the contradicting value.
//
// A refused axis never lowers anything: what was in force on it stays. It
// returns nil when base is nil and nothing applied.
func MergeProjectSections(base *PolicySpec, sections []ProjectSection) (*PolicySpec, []SectionOutcome) {
	outcomes := make([]SectionOutcome, len(sections))
	var baseBody Body
	if base != nil {
		baseBody = base.Body
	}
	order := sectionOrder(sections)
	refused := make([]map[string]error, len(sections))
	refuse := func(i int, axis string, err error) {
		if refused[i] == nil {
			refused[i] = map[string]error{}
		}
		if _, done := refused[i][axis]; !done {
			refused[i][axis] = err
		}
	}
	// Against the org-wide floor first, each section alone, so a section
	// that conflicts with it never displaces another section's value.
	refuseFloorConflicts(baseBody, sections, order, refuse)
	values := map[string]postureop.Value{}
	fold := func(ax postureop.Axis) {
		delete(values, ax.Name)
		cur, ok := floorValue(baseBody, ax.Name)
		var from []string
		for _, i := range order {
			if _, gone := refused[i][ax.Name]; gone {
				continue
			}
			sv, sset := floorValue(sections[i].Spec.Body, ax.Name)
			if !sset {
				continue
			}
			label := fmt.Sprintf("project %s section v%d", sections[i].Project, sections[i].Version)
			if !ok {
				cur, ok, from = sv, true, append(from, label)
				continue
			}
			merged, err := mergeFloor(ax, cur, sv)
			if err != nil {
				refuse(i, ax.Name, fmt.Errorf("conflicts with %s (the earlier by project id, then sequence): %w", strings.Join(from, ", "), err))
				continue
			}
			cur, from = merged, append(from, label)
		}
		if ok {
			values[ax.Name] = cur
		}
	}
	for _, ax := range Axes {
		fold(ax)
	}
	for _, c := range axisContradictions {
		if values[c.a].S != c.av || values[c.b].S != c.bv {
			continue
		}
		loser, lv, other, ov := c.a, c.av, c.b, c.bv
		if c.keep == c.a {
			loser, lv, other, ov = c.b, c.bv, c.a, c.av
		}
		if v, ok := floorValue(baseBody, loser); ok && v.S == lv {
			// The org-wide floor holds the losing value itself: it stands,
			// and the sections' value on the other axis is refused.
			loser, lv, other, ov = other, ov, loser, lv
		}
		for _, i := range order {
			if sv, ok := floorValue(sections[i].Spec.Body, loser); ok && sv.S == lv {
				refuse(i, loser, fmt.Errorf("%s = %s contradicts %s = %s", loser, lv, other, ov))
			}
		}
		ax, _ := LookupAxis(loser)
		fold(ax)
	}
	var out Body
	for _, ax := range Axes {
		if v, ok := values[ax.Name]; ok {
			floorWriters[ax.Name](&out, v)
		}
	}
	out.Sections = mergedSectionMap(baseBody, sections, order)
	out = normalize(out)
	if err := validate(out); err != nil {
		// Defensive: every pair validate refuses is a row of
		// axisContradictions. Should one be missed, nothing a section set
		// applies and the org-wide floor stays.
		for i := range sections {
			outcomes[i] = SectionOutcome{Err: fmt.Errorf("%w: %w", ErrSectionConflict, err)}
		}
		if base == nil {
			return nil, outcomes
		}
		b := *base
		return &b, outcomes
	}
	for i, s := range sections {
		outcomes[i] = sectionOutcome(s.Spec, refused[i])
	}
	if base == nil && reflect.DeepEqual(out, normalize(Body{})) {
		return nil, outcomes
	}
	return &PolicySpec{Body: out}, outcomes
}

// refuseFloorConflicts refuses each section's axis value that conflicts
// with the org-wide floor's, section by section (MergeProjectSections' first
// pass).
func refuseFloorConflicts(baseBody Body, sections []ProjectSection, order []int, refuse func(i int, axis string, err error)) {
	for _, ax := range Axes {
		bv, bset := floorValue(baseBody, ax.Name)
		if !bset {
			continue
		}
		for _, i := range order {
			sv, sset := floorValue(sections[i].Spec.Body, ax.Name)
			if !sset {
				continue
			}
			if _, err := mergeFloor(ax, bv, sv); err != nil {
				refuse(i, ax.Name, fmt.Errorf("conflicts with the org-wide floor: %w", err))
			}
		}
	}
}

// mergedSectionMap is the org-wide floor's sections overlaid by each
// project section's, in order (nil when none has any).
func mergedSectionMap(baseBody Body, sections []ProjectSection, order []int) map[string]Section {
	var out Body
	for _, i := range append([]int{-1}, order...) {
		secs := baseBody.Sections
		if i >= 0 {
			secs = sections[i].Spec.Body.Sections
		}
		for id, s := range secs {
			if out.Sections == nil {
				out.Sections = map[string]Section{}
			}
			out.Sections[id] = s
		}
	}
	return out.Sections
}

// sectionOrder is the stated tie-break order of MergeProjectSections:
// project id, then sequence, then the canonical body.
func sectionOrder(sections []ProjectSection) []int {
	order := make([]int, len(sections))
	keys := make([]string, len(sections))
	for i, s := range sections {
		order[i] = i
		raw, _ := json.Marshal(normalize(s.Spec.Body))
		keys[i] = string(raw)
	}
	sort.SliceStable(order, func(x, y int) bool {
		a, b := sections[order[x]], sections[order[y]]
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return keys[order[x]] < keys[order[y]]
	})
	return order
}

// sectionOutcome builds one section's outcome from its refused axes.
func sectionOutcome(spec PolicySpec, refused map[string]error) SectionOutcome {
	if len(refused) == 0 {
		return SectionOutcome{Applied: true}
	}
	var o SectionOutcome
	set := 0
	for _, ax := range Axes {
		if _, ok := floorValue(spec.Body, ax.Name); ok {
			set++
		}
	}
	names := make([]string, 0, len(refused))
	for axis := range refused {
		names = append(names, axis)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, axis := range names {
		o.Refused = append(o.Refused, AxisRefusal{Axis: axis, Err: refused[axis]})
		parts = append(parts, axis+": "+refused[axis].Error())
	}
	o.Partial = set > len(names) || len(spec.Body.Sections) > 0
	o.Err = fmt.Errorf("%w: %s", ErrSectionConflict, strings.Join(parts, "; "))
	return o
}

// SpecsEqual reports whether two compiled specs carry the same floors.
func SpecsEqual(a, b *PolicySpec) bool {
	if a == nil || b == nil {
		return a == b
	}
	return reflect.DeepEqual(normalize(a.Body), normalize(b.Body))
}
