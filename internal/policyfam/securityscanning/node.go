package securityscanning

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/postureop"
)

// NodeFacts is what the node-side evaluation needs to know about this
// machine, resolved by the cmd layer (cmd/observer/security_scanning_wire.go)
// so this package never reads config, the store or the component state.
type NodeFacts struct {
	// Managed is a managed-tenancy enrolment whose grant is in force.
	Managed bool
	// Active is the set of security component ids active on this node.
	Active map[string]bool
	// Local is the node's own value on every axis that has a setting built
	// on this node. An axis absent here has no setting yet: a floor on it is
	// not_applicable: not_built.
	Local postureop.Posture
	// Held is the floor accepted and in force now, nil when none.
	Held *PolicySpec
	// ModuleOff is true when the security module itself is not active on
	// this node (skipped, or switched off): no floor key applies, each is
	// not_applicable: module_inactive. The zero value is a node whose module
	// runs, so an existing caller is unchanged.
	ModuleOff bool
}

// Key states and reasons, as reported by Evaluate (and shown by `observer
// security status`).
const (
	StateApplied       = "applied"
	StateNotApplicable = "not_applicable"
	StateRefused       = "refused"

	ReasonComponentAbsent = "component_absent"
	ReasonIndividualNode  = "individual_node"
	ReasonNotBuilt        = "not_built"
	ReasonModuleInactive  = "module_inactive"
)

// KeyState is one body key's outcome on this node.
type KeyState struct {
	// Key is the dotted body key ("require.commit_gate",
	// "sections.deps", "require.components:security.deps").
	Key    string
	State  string
	Reason string
	// Floor is the floor value as shown to people, "" for a section.
	Floor string
}

// String renders "key: state (reason)".
func (k KeyState) String() string {
	if k.Reason == "" {
		return k.Key + ": " + k.State
	}
	return k.Key + ": " + k.State + ": " + k.Reason
}

var (
	factsMu       sync.RWMutex
	factsProvider func() NodeFacts
)

// SetNodeFactsProvider binds the one provider of this node's facts. The cmd
// layer calls it at daemon start; a nil f unbinds. It returns a func that
// restores the previous provider (tests).
func SetNodeFactsProvider(f func() NodeFacts) (restore func()) {
	factsMu.Lock()
	prev := factsProvider
	factsProvider = f
	factsMu.Unlock()
	return func() {
		factsMu.Lock()
		factsProvider = prev
		factsMu.Unlock()
	}
}

func currentFacts() (NodeFacts, bool) {
	factsMu.RLock()
	f := factsProvider
	factsMu.RUnlock()
	if f == nil {
		return NodeFacts{}, false
	}
	return f(), true
}

// ErrNoNodeFacts is CheckPosture's refusal when no provider is bound: the
// node cannot tell what the body would do, so it keeps what it has.
var ErrNoNodeFacts = errors.New("policyfam/securityscanning: this node's security facts are not available")

// LiveCapabilities is the node side of the section tokens. An individual
// node advertises every section token: a section for an absent child is
// reported not_applicable there, never refused. A managed node advertises
// only the tokens of active children, so a body naming an absent child is
// refused at the capability gate with the token in the detail (security plan
// 4.9). No provider bound: none.
func LiveCapabilities() []string {
	facts, ok := currentFacts()
	if !ok {
		return nil
	}
	var out []string
	for _, c := range Children {
		if !facts.Managed || facts.Active[c.Component] {
			out = append(out, CapabilityToken(c.ID))
		}
	}
	return out
}

// floorReaders reads each axis's floor from a body: one row per axis, the
// second result false when the body sets no floor there.
var floorReaders = map[string]func(b Body) (postureop.Value, bool){
	AxisComponents:           func(b Body) (postureop.Value, bool) { return setOf(req(b).Components) },
	AxisPrelaunchTrust:       func(b Body) (postureop.Value, bool) { return strOf(req(b).PrelaunchTrust) },
	AxisCommitGate:           func(b Body) (postureop.Value, bool) { return strOf(req(b).CommitGate) },
	AxisQuickScanBudget:      func(b Body) (postureop.Value, bool) { return numOf(req(b).QuickScanBudgetS) },
	AxisMaxScanStaleness:     func(b Body) (postureop.Value, bool) { return numOf(req(b).MaxScanStalenessMin) },
	AxisMaxAdvisoryDBAge:     func(b Body) (postureop.Value, bool) { return numOf(req(b).MaxAdvisoryDBAgeH) },
	AxisMinBlockingSeverity:  func(b Body) (postureop.Value, bool) { return strOf(req(b).MinBlockingSeverity) },
	AxisInstallUnknown:       func(b Body) (postureop.Value, bool) { return strOf(req(b).InstallUnknown) },
	AxisOnlineChecks:         func(b Body) (postureop.Value, bool) { return strOf(req(b).OnlineChecks) },
	AxisInstallOnlineUnknown: func(b Body) (postureop.Value, bool) { return strOf(req(b).InstallOnlineUnknown) },
	AxisHistoryScanOnEnrol: func(b Body) (postureop.Value, bool) {
		if v := req(b).HistoryScanOnEnrol; v != nil {
			return postureop.Value{S: strconv.FormatBool(*v)}, true
		}
		return postureop.Value{}, false
	},
	AxisFindingRetention:     func(b Body) (postureop.Value, bool) { return numOf(req(b).FindingRetentionDays) },
	AxisAllowDrivers:         func(b Body) (postureop.Value, bool) { return setOf(allow(b).Drivers) },
	AxisAllowCustomManifests: func(b Body) (postureop.Value, bool) { return setOf(allow(b).CustomManifests) },
	AxisAllowScannerSources:  func(b Body) (postureop.Value, bool) { return setOf(allow(b).ScannerSources) },
	AxisAllowOnlineChecks:    func(b Body) (postureop.Value, bool) { return strOf(allow(b).OnlineChecks) },
	AxisRulePackMinVersion: func(b Body) (postureop.Value, bool) {
		if b.RulePack == nil {
			return postureop.Value{}, false
		}
		return strOf(b.RulePack.MinVersion)
	},
}

func req(b Body) Require {
	if b.Require == nil {
		return Require{}
	}
	return *b.Require
}

func allow(b Body) Allow {
	if b.Allow == nil {
		return Allow{}
	}
	return *b.Allow
}

func strOf(s string) (postureop.Value, bool) { return postureop.Value{S: s}, s != "" }

func setOf(v []string) (postureop.Value, bool) { return postureop.Value{Set: v}, v != nil }

func numOf(n *int64) (postureop.Value, bool) {
	if n == nil {
		return postureop.Value{}, false
	}
	return postureop.Value{N: *n}, true
}

// floorValue is the body's floor on axis, if it sets one.
func floorValue(b Body, axis string) (postureop.Value, bool) {
	if read, ok := floorReaders[axis]; ok {
		return read(b)
	}
	return postureop.Value{}, false
}

// keyApplicability is the ordered applicability table for one floor key,
// walked top-down: the first row that matches decides (CLAUDE.md rule 5).
var keyApplicability = []struct {
	match  func(r keyRule, f NodeFacts) bool
	state  string
	reason string
}{
	{func(_ keyRule, f NodeFacts) bool { return f.ModuleOff }, StateNotApplicable, ReasonModuleInactive},
	{func(r keyRule, f NodeFacts) bool { return r.ManagedOnly && !f.Managed }, StateNotApplicable, ReasonIndividualNode},
	{func(r keyRule, f NodeFacts) bool { return r.Component != "" && !f.Active[r.Component] }, StateNotApplicable, ReasonComponentAbsent},
	{func(r keyRule, f NodeFacts) bool { _, ok := f.Local[r.Axis]; return !ok }, StateNotApplicable, ReasonNotBuilt},
	{func(keyRule, NodeFacts) bool { return true }, StateApplied, ""},
}

func applicability(r keyRule, f NodeFacts) (state, reason string) {
	for _, row := range keyApplicability {
		if row.match(r, f) {
			return row.state, row.reason
		}
	}
	return StateApplied, ""
}

// Evaluate reports, for every key the body sets, what it does on this node.
// Nothing is silently dropped: each key is applied, not_applicable with a
// reason, or refused. Sections and required components are reported per
// child.
func Evaluate(s PolicySpec, f NodeFacts) []KeyState {
	var out []KeyState
	absent := func() (string, string) {
		if f.ModuleOff {
			return StateNotApplicable, ReasonModuleInactive
		}
		if f.Managed {
			return StateRefused, ReasonComponentAbsent
		}
		return StateNotApplicable, ReasonComponentAbsent
	}
	if r := s.Body.Require; r != nil {
		for _, comp := range r.Components {
			ks := KeyState{Key: AxisComponents + ":" + comp, State: StateApplied}
			if f.ModuleOff || !f.Active[comp] {
				ks.State, ks.Reason = absent()
			}
			out = append(out, ks)
		}
	}
	for _, rule := range keyRules {
		if rule.Axis == AxisComponents {
			continue
		}
		v, ok := floorValue(s.Body, rule.Axis)
		if !ok {
			continue
		}
		ax, _ := LookupAxis(rule.Axis)
		st, why := applicability(rule, f)
		out = append(out, KeyState{Key: rule.Axis, State: st, Reason: why, Floor: show(ax, v)})
	}
	ids := make([]string, 0, len(s.Body.Sections))
	for id := range s.Body.Sections {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		c, _ := LookupChild(id)
		ks := KeyState{Key: "sections." + id, State: StateApplied}
		if f.ModuleOff || !f.Active[c.Component] {
			ks.State, ks.Reason = absent()
		}
		out = append(out, ks)
	}
	return out
}

// Effective is the node's posture with spec's applicable floors merged over
// its own values (nil spec: the node's own). Floors only raise. An allow-set
// whose intersection with a non-empty local set is empty is refused with
// postureop.ErrEmptyIntersection, naming the axis.
func Effective(spec *PolicySpec, f NodeFacts) (postureop.Posture, error) {
	out := make(postureop.Posture, len(f.Local))
	for k, v := range f.Local {
		out[k] = v
	}
	if spec == nil {
		return out, nil
	}
	for _, rule := range keyRules {
		local, built := f.Local[rule.Axis]
		if !built {
			continue
		}
		floor, set := floorValue(spec.Body, rule.Axis)
		if !set {
			continue
		}
		if st, _ := applicability(rule, f); st != StateApplied {
			continue
		}
		ax, _ := LookupAxis(rule.Axis)
		merged, err := raise(ax, local, floor)
		if err != nil {
			return nil, &AxisError{Axis: rule.Axis, Err: err}
		}
		out[rule.Axis] = merged
	}
	return out, nil
}

// AxisError is a floor that cannot merge on one axis (an allow-set that
// would allow nothing, a value outside the axis order).
type AxisError struct {
	Axis string
	Err  error
}

func (e *AxisError) Error() string { return e.Axis + ": " + e.Err.Error() }

func (e *AxisError) Unwrap() error { return e.Err }

// raise merges a floor over a local value on one axis, keeping the stronger.
func raise(ax postureop.Axis, local, floor postureop.Value) (postureop.Value, error) {
	switch ax.Kind {
	case postureop.AxisEnum:
		li, fi := indexOf(ax.Order, local.S), indexOf(ax.Order, floor.S)
		if fi < 0 {
			return postureop.Value{}, fmt.Errorf("floor %q is outside the axis order %v", floor.S, ax.Order)
		}
		if li < fi {
			return floor, nil
		}
		return local, nil
	case postureop.AxisHigherStronger:
		return postureop.Value{N: postureop.RaiseInt(local.N, floor.N)}, nil
	case postureop.AxisLowerStronger:
		if floor.N > 0 && (local.N <= 0 || floor.N < local.N) {
			return floor, nil
		}
		return local, nil
	case postureop.AxisRetention:
		return postureop.Value{N: postureop.RaiseRetention(local.N, floor.N)}, nil
	case postureop.AxisSubsetStronger:
		if len(local.Set) == 0 {
			// Nothing is enabled locally, so nothing is narrowed.
			return local, nil
		}
		v, err := postureop.SetIntersection(local.Set, false, floor.Set)
		if err != nil {
			return postureop.Value{}, err
		}
		return postureop.Value{Set: v}, nil
	case postureop.AxisSupersetStronger:
		return postureop.Value{Set: postureop.AdditiveMask(local.Set, floor.Set)}, nil
	case postureop.AxisVersion:
		c, err := postureop.VersionCmp(floor.S, local.S)
		if err != nil {
			return postureop.Value{}, err
		}
		if c > 0 {
			return floor, nil
		}
		return local, nil
	}
	return postureop.Value{}, fmt.Errorf("unknown axis kind %d", ax.Kind)
}

// CheckPosture is the family's result-based posture check (roadmap F0-8):
// it refuses a body that would leave this node weaker than the floor in
// force now on any axis, naming the first one. On a managed node the org
// may lower its own floors (the floor never goes below the developer's own
// value either way, because floors only raise), so only an allow-set that
// would allow nothing is refused there. No provider bound: refused.
func CheckPosture(s PolicySpec) (axis string, err error) {
	f, ok := currentFacts()
	if !ok {
		return "node_facts", ErrNoNodeFacts
	}
	return checkPosture(s, f)
}

func checkPosture(s PolicySpec, f NodeFacts) (string, error) {
	after, err := Effective(&s, f)
	if err != nil {
		var ae *AxisError
		if errors.As(err, &ae) {
			return ae.Axis, err
		}
		return "", err
	}
	if f.Managed {
		return "", nil
	}
	before, err := Effective(f.Held, f)
	if err != nil {
		// The floor in force no longer merges (the node's own set changed);
		// compare against the node's own values instead.
		before, _ = Effective(nil, f)
	}
	if axis, detail := postureop.FirstLoosened(Axes, before, after); axis != "" {
		return axis, errors.New(detail)
	}
	return "", nil
}

func indexOf(order []string, v string) int {
	for i, o := range order {
		if o == v {
			return i
		}
	}
	return -1
}

func show(ax postureop.Axis, v postureop.Value) string {
	switch ax.Kind {
	case postureop.AxisEnum, postureop.AxisVersion:
		return v.S
	case postureop.AxisSubsetStronger, postureop.AxisSupersetStronger:
		return fmt.Sprint(v.Set)
	case postureop.AxisRetention:
		if v.N <= 0 {
			return "forever"
		}
	}
	return strconv.FormatInt(v.N, 10)
}
