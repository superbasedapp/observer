package componentstate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// BaseAll is the base of an unconfigured or distro-less selection in an
// unstamped build: every component this binary was built with. A distro
// build (components.BuildDistro) starts from its distro's BaseSet instead.
const BaseAll = "all"

// BaseCustom is the base of an unconfigured or distro-less selection in a
// custom build (plan 5.3, lane MP-CUST): the manifest's default selection
// (its base distro's on and cond cells it compiles, plus every component it
// adds), never everything compiled.
const BaseCustom = "custom"

// buildDistro is components.BuildDistro, a variable so tests can stamp a
// snapshot without a distro build.
var buildDistro = components.BuildDistro

// buildCustomDefaults returns a custom build's default selection, ok false
// in every other build (and for a custom binary whose stamp does not
// resolve: its compiled set is then the mandatory components only, which
// the legacy base already yields). A variable so tests can stamp one.
var buildCustomDefaults = func() ([]string, bool) {
	cb, stamped, err := components.BuildCustom()
	if !stamped || err != nil {
		return nil, false
	}
	return cb.DefaultSelection, true
}

// RefusalExitCode is the exit code a CLI verb of an inactive component
// returns (plan 7.3): distinct from a usage error (1) and from cobra's own
// failures.
const RefusalExitCode = 3

// Snapshot is the resolved component state of one node at one moment. It is
// a value: build a new one when the [components] block changes.
type Snapshot struct {
	// Configured reports whether the [components] block says anything. An
	// unconfigured snapshot is the legacy everything-active posture.
	Configured bool
	// Base is BaseAll, BaseCustom or a prebuilt distro name.
	Base string
	// BlockDistro is the block's own distro line, verbatim (trimmed); "" when
	// the block names none, in which case Base is the build's default. It is
	// what tells a recorded base choice from an add-only block (T-745).
	BlockDistro string
	// Add and Remove echo the block's deltas, sorted and deduplicated.
	Add, Remove []string
	// Selected is the resolved selection handed to the resolver, sorted.
	Selected []string
	// Compiled is the binary's compiled node set, sorted.
	Compiled []string
	// Result is the catalog resolver's output for the node rows.
	Result components.ResolveResult
	// Issues are the selection problems an operator should see: unknown
	// ids, an unknown distro, a removal another selection overrides, and the
	// resolver's own errors. Always empty for an unconfigured snapshot.
	Issues []string

	// Governed is the managed-governance input this snapshot was resolved
	// with (the zero value for an individual node or a plain Resolve).
	Governed Governed
	// Ignored lists the parts of the local [components] block a managed
	// node did not apply (ledger MODPKG-7, ruling D-434): the base distro
	// and every remove entry. Empty on an individual node.
	Ignored []string

	decisions map[string]components.Decision
}

// Governed is the managed-governance input of a snapshot, produced at the
// cmd boundary (the enrolment, the grant, the verified node.components
// policy and the local ceiling are all read there) and handed in as plain
// data, so this package keeps no I/O.
type Governed struct {
	// OrgManaged reports that an organization governs this node's
	// components: a managed-tenancy enrolment whose grant is live
	// (internal/policyfam/nodecomponents sources unauthorized, policy,
	// last_known_good, initial_grant and legacy_pinned). While it is true
	// the local [components] block may widen within what the organization
	// allows but never narrow (ruling D-434): its base distro and its
	// remove entries are ignored and reported.
	OrgManaged bool
	// OrgName names the organization for every refusal and warning.
	OrgName string
	// Source is the nodecomponents source that decided (local, dormant,
	// unauthorized, policy, last_known_good, initial_grant, legacy_pinned);
	// empty when no governance was resolved.
	Source string
	// Rule names the source-table row that decided.
	Rule string
	// Governance is the resolver input (ceiling, policy sets, grants); nil
	// means ungoverned.
	Governance *components.Governance
	// Notes are governance facts an operator should see (a ceiling source
	// that failed a check, an ignored policy id).
	Notes []string
}

// OrgLabel is the organization's name for copy, never empty.
func (g Governed) OrgLabel() string {
	if strings.TrimSpace(g.OrgName) != "" {
		return g.OrgName
	}
	return "your organization"
}

// ManagedRefusal is the one sentence a managed node answers a local change
// that would narrow it with (CLI, dashboard, start warning).
func (g Governed) ManagedRefusal(what string) string {
	return fmt.Sprintf("%s: this machine is managed by %s, which decides which components run; a local change cannot narrow it (request a change from your organization)", what, g.OrgLabel())
}

// FromConfig resolves the snapshot of a loaded config against this
// binary's compiled set.
func FromConfig(cfg config.Config) Snapshot {
	return Resolve(cfg.Components, nil)
}

// Legacy is the unconfigured snapshot for this binary: everything compiled
// is active. Callers that could not load a config use it, matching the
// fail-open posture of every other daemon gate on a missing config.
func Legacy() Snapshot {
	return Resolve(config.ComponentsConfig{}, nil)
}

// Resolve builds a snapshot from a [components] block and a compiled set
// (nil means this binary's own compiled set, components.Compiled).
func Resolve(sec config.ComponentsConfig, compiled []string) Snapshot {
	return ResolveGoverned(sec, compiled, Governed{})
}

// ResolveGoverned is Resolve with the managed-governance input. With the
// zero Governed it is exactly Resolve. On an org-managed node the block's
// narrowing parts (the base distro and the remove entries) are ignored and
// listed in Ignored and Issues, the add entries still count (a component the
// policy allows may be selected locally, plan 6.2 row 6), and the governance
// rows of the one resolver decide the rest.
func ResolveGoverned(sec config.ComponentsConfig, compiled []string, g Governed) Snapshot {
	if compiled == nil {
		compiled = components.Compiled(components.BinaryNode)
	}
	compiled = uniqSorted(compiled)
	s := Snapshot{
		Configured:  sec.Configured(),
		Base:        BaseAll,
		BlockDistro: strings.TrimSpace(sec.Distro),
		Add:         uniqSorted(sec.Add),
		Remove:      uniqSorted(sec.Remove),
		Compiled:    compiled,
		Governed:    g,
	}
	var issues []string
	removes := s.Remove
	distro := strings.TrimSpace(sec.Distro)
	if g.OrgManaged {
		if distro != "" {
			s.Ignored = append(s.Ignored, "distro "+distro)
			issues = append(issues, g.ManagedRefusal(fmt.Sprintf("[components] distro %q is ignored", distro)))
			distro = ""
		}
		if len(removes) > 0 {
			s.Ignored = append(s.Ignored, "remove "+strings.Join(removes, ","))
			issues = append(issues, g.ManagedRefusal(fmt.Sprintf("[components] remove %v is ignored", removes)))
			removes = nil
		}
	}

	base := toSet(compiled)
	// A distro build (phase P3) starts from its own distro's default set,
	// exactly as if the block said `distro = "<name>"`; an unstamped build
	// (today's release, full) keeps the legacy everything-compiled base.
	if stamp := buildDistro(); stamp != "" {
		s.Base = string(stamp)
		base = toSet(BaseSet(stamp))
	} else if defaults, ok := buildCustomDefaults(); ok {
		s.Base = BaseCustom
		base = toSet(defaults)
	}
	if d := distro; d != "" {
		if dist := components.Distro(d); dist.Valid() {
			s.Base = d
			base = toSet(BaseSet(dist))
		} else {
			issues = append(issues, fmt.Sprintf("[components] distro %q is not a prebuilt distro (one of %s); every component this build contains stays active", d, distroNames()))
		}
	}
	sel := map[string]bool{}
	for id := range base {
		sel[id] = true
	}
	for _, id := range s.Add {
		c, ok := components.Get(id)
		switch {
		case !ok:
			issues = append(issues, fmt.Sprintf("[components] add: %q is not a component (observer components list shows the ids)", id))
			continue
		case c.Binary != components.BinaryNode:
			issues = append(issues, fmt.Sprintf("[components] add: %q is an org server component, not a node one", id))
			continue
		}
		sel[id] = true
	}
	for _, id := range removes {
		c, ok := components.Get(id)
		switch {
		case !ok:
			issues = append(issues, fmt.Sprintf("[components] remove: %q is not a component (observer components list shows the ids)", id))
			continue
		case c.Binary != components.BinaryNode:
			issues = append(issues, fmt.Sprintf("[components] remove: %q is an org server component, not a node one", id))
			continue
		case c.Class == components.ClassCore:
			issues = append(issues, fmt.Sprintf("[components] remove: %q is core and cannot be removed", id))
			continue
		}
		delete(sel, id)
	}
	s.Selected = sortedKeys(sel)
	s.Result = components.Resolve(components.ResolveInput{
		Binary:     components.BinaryNode,
		Compiled:   compiled,
		Selected:   s.Selected,
		Governance: g.Governance,
	})
	s.decisions = make(map[string]components.Decision, len(s.Result.Decisions))
	for _, d := range s.Result.Decisions {
		s.decisions[d.ID] = d
	}
	// A removal another selection overrides: the resolver keeps a required
	// component active, so say which selection holds it.
	for _, id := range removes {
		if d, ok := s.decisions[id]; ok && d.State == components.StateActive && d.Reason == components.ReasonRequiredBy {
			issues = append(issues, fmt.Sprintf("[components] remove: %q stays active because %s requires it; remove %s too", id, d.Because, d.Because))
		}
	}
	// A governed snapshot always reports: the resolver's compliance
	// findings (required but missing or blocked) and the governance notes
	// are never silent, configured block or not.
	governed := g.Governance != nil || g.OrgManaged
	if s.Configured || governed {
		issues = append(issues, s.Result.Errors...)
		issues = append(issues, g.Notes...)
		sort.Strings(issues)
		s.Issues = issues
	}
	return s
}

// BaseSet is the selection a prebuilt distro starts from: its
// default-active cells plus its conditional ones ("cond" activates on a
// stated condition such as enrolment, which the component itself checks).
func BaseSet(d components.Distro) []string {
	var out []string
	for _, c := range components.ForBinary(components.BinaryNode) {
		switch c.Distros[d] {
		case components.DefaultOn, components.DefaultCond:
			out = append(out, c.ID)
		}
	}
	if !contains(out, "core") {
		out = append(out, "core")
	}
	sort.Strings(out)
	return out
}

// Active reports whether component id is active. An id the catalog does not
// know answers true: a gate that names a component the catalog dropped must
// fail open to today's behaviour, never switch a feature off. Tests pin
// every id the wiring tables use to a catalog row.
//
// Active is for gates in front of behaviour that already ships. A gate in
// front of an OPTIONAL MODULE's surface (security, terminals.sandbox and
// their drivers) uses ModuleActive, which fails the other way (module.go).
func (s Snapshot) Active(id string) bool {
	d, ok := s.decisions[id]
	if !ok {
		return true
	}
	return d.State == components.StateActive
}

// AnyActive reports whether at least one of ids is active (a goroutine
// shared by several components runs when any of them is active). No ids
// means core: always true.
func (s Snapshot) AnyActive(ids ...string) bool {
	if len(ids) == 0 {
		return true
	}
	for _, id := range ids {
		if s.Active(id) {
			return true
		}
	}
	return false
}

// AdapterActive reports whether the adapter row of a registry tool is
// active. A cross-OS "<tool>-windows" target, an Xcode agent-home
// "<tool>-xcode" target (internal/hook's XcodeTargetBase, FU-145) and a
// Windows to WSL "<tool>-wsl" twin (WSLTwinBase, FU-197) resolve to their
// base tool (the suffixes are those tables' naming, pinned by a test), so a
// removed adapter keeps every target of it off.
func (s Snapshot) AdapterActive(tool string) bool {
	base := tool
	for _, suffix := range []string{"-windows", "-xcode", "-wsl"} {
		if b, ok := strings.CutSuffix(tool, suffix); ok {
			base = b
			break
		}
	}
	return s.Active(components.AdapterID(base))
}

// Decision returns the resolver's decision for one id.
func (s Snapshot) Decision(id string) (components.Decision, bool) {
	d, ok := s.decisions[id]
	return d, ok
}

// ActiveIDs returns the active node ids, sorted.
func (s Snapshot) ActiveIDs() []string { return s.Result.Active() }

// Inactive returns the node ids that are not active (available, absent or
// blocked), sorted.
func (s Snapshot) Inactive() []string {
	var out []string
	for _, d := range s.Result.Decisions {
		if d.State != components.StateActive {
			out = append(out, d.ID)
		}
	}
	return out
}

// Section renders the snapshot's inputs back as a [components] block.
func (s Snapshot) Section() config.ComponentsConfig {
	out := config.ComponentsConfig{Add: s.Add, Remove: s.Remove}
	if s.Base != BaseAll && s.Base != BaseCustom {
		out.Distro = s.Base
	}
	return out
}

// RefusalLine is the one line a CLI verb of an inactive component prints
// (plan 7.3): the state and the fix, never a bare "unknown command".
func (s Snapshot) RefusalLine(id string) string {
	d, _ := s.decisions[id]
	title := id
	if c, ok := components.Get(id); ok && c.Title != "" {
		title = c.Title + " (" + id + ")"
	}
	switch d.State {
	case components.StateAbsent:
		// D-514: name the build and the fix in one line.
		return fmt.Sprintf("%s is not in this build (distro %s); %s. Install a build that includes it (%s).",
			title, components.DistroOf(s.Compiled), components.DistrosHaving(id), components.SettingsHint())
	case components.StateBlocked:
		why := string(d.Reason)
		if d.Because != "" {
			why += " " + d.Because
		}
		return fmt.Sprintf("%s is blocked on this machine (%s). %s explains why.", title, why, components.SettingsHint())
	default:
		return fmt.Sprintf("%s is installed but inactive on this machine. Turn it on %s.", title, components.WhereToChange("`observer components add "+id+"`"))
	}
}

func distroNames() string {
	var names []string
	for _, d := range components.Distros() {
		names = append(names, string(d))
	}
	return strings.Join(names, ", ")
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

func uniqSorted(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
