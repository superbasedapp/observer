package componentstate

import (
	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
)

// view.go is the ONE JSON shape of a node's component STATE, shared by
// `observer components status --json` and the dashboard (lane MP-DASH: the
// Components page, the nav filter and the NotInstalled state). The catalog
// itself (titles, surfaces, levels) stays components.Report; a consumer joins
// the two on id. Field names are snake_case and additive only.

// RowView is one node component's resolved state.
type RowView struct {
	ID string `json:"id"`
	// State is active | available | absent | blocked.
	State components.State `json:"state"`
	// Reason is the resolver's reason (core, selected, required_by,
	// not_selected, not_compiled, denied, denied_dependency,
	// requires_not_compiled).
	Reason components.Reason `json:"reason"`
	// Because names the component behind required_by, denied_dependency or
	// requires_not_compiled.
	Because string `json:"because,omitempty"`
	// Compiled reports whether this binary was built with it.
	Compiled bool `json:"compiled"`
	// Selected reports whether the operator's selection names it (base plus
	// add minus remove), before dependency resolution.
	Selected bool `json:"selected"`
	// InBase reports whether the selection's base includes it.
	InBase bool `json:"in_base"`
}

// View is the whole node's component state.
type View struct {
	// Configured is false for an install with no [components] block: the
	// legacy posture in which every compiled component is active.
	Configured bool `json:"configured"`
	// Base is "all", "custom" (a custom build's manifest defaults) or a
	// prebuilt distro name.
	Base   string   `json:"base"`
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
	// BinaryDistro is the prebuilt distro whose compiled set this binary
	// matches, or "custom".
	BinaryDistro     components.Distro `json:"binary_distro"`
	ComponentsDigest string            `json:"components_digest"`
	CompiledCount    int               `json:"compiled_count"`
	ActiveCount      int               `json:"active_count"`
	Components       []RowView         `json:"components"`
	Issues           []string          `json:"issues"`
	// RestartNote says plainly when a change takes effect.
	RestartNote string `json:"restart_note"`
	// OrgManaged is true when an organization governs this node's
	// components: local changes may not narrow it (ruling D-434).
	OrgManaged bool `json:"org_managed"`
	// OrgName names that organization ("" on an individual node).
	OrgName string `json:"org_name,omitempty"`
	// GovernanceSource is the nodecomponents source in force (local,
	// dormant, unauthorized, policy, last_known_good, initial_grant,
	// legacy_pinned); "" when no governance was resolved.
	GovernanceSource string `json:"governance_source,omitempty"`
	// Ignored lists the parts of the local block a managed node did not
	// apply.
	Ignored []string `json:"ignored"`
}

// RestartNote is the honest one-liner every surface shows with the state:
// the daemon resolves the effective set once at start.
const RestartNote = "The daemon reads this selection when it starts. A change applies to new commands at once and to the daemon's background work after the next restart."

// View renders the snapshot as JSON-ready data.
func (s Snapshot) View() View {
	compiled := toSet(s.Compiled)
	selected := toSet(s.Selected)
	var base map[string]bool
	switch s.Base {
	case BaseAll:
		base = compiled
	case BaseCustom:
		defaults, _ := buildCustomDefaults()
		base = toSet(defaults)
	default:
		base = toSet(BaseSet(components.Distro(s.Base)))
	}
	v := View{
		Configured:       s.Configured,
		Base:             s.Base,
		Add:              nonNil(s.Add),
		Remove:           nonNil(s.Remove),
		BinaryDistro:     components.DistroOf(s.Compiled),
		ComponentsDigest: components.Digest(s.Compiled),
		CompiledCount:    len(s.Compiled),
		Issues:           nonNil(s.Issues),
		RestartNote:      RestartNote,
		Components:       []RowView{},
		OrgManaged:       s.Governed.OrgManaged,
		GovernanceSource: s.Governed.Source,
		Ignored:          nonNil(s.Ignored),
	}
	if s.Governed.OrgManaged {
		v.OrgName = s.Governed.OrgLabel()
	}
	for _, d := range s.Result.Decisions {
		if d.State == components.StateActive {
			v.ActiveCount++
		}
		v.Components = append(v.Components, RowView{
			ID: d.ID, State: d.State, Reason: d.Reason, Because: d.Because,
			Compiled: compiled[d.ID], Selected: selected[d.ID], InBase: base[d.ID],
		})
	}
	return v
}

// NotActiveBody is the JSON error body a dashboard route of an inactive
// component answers with (plan 7.3:
// 404 {"error":"component_not_installed","component":"codeintel","state":"absent"}).
// Lane MP-DASH owns the route guard that writes it; the shape lives here so
// the CLI, the API and the SPA's apiFailure class agree.
//
// The embedded settingslink.Fields add the deep link: "settings" opens
// Settings > Components with this component focused, "settings_label" names
// that place, and "command" is the CLI equivalent when the component can be
// turned on here (state available). The SPA's one renderer for "needs a
// setting" errors keys on "settings".
type NotActiveBody struct {
	Error     string            `json:"error"`
	Component string            `json:"component"`
	State     components.State  `json:"state"`
	Reason    components.Reason `json:"reason"`
	Message   string            `json:"message"`
	settingslink.Fields
}

// NotActiveError is the closed error code of NotActiveBody.
const NotActiveError = "component_not_installed"

// NotActive builds the error body for an inactive component.
func (s Snapshot) NotActive(id string) NotActiveBody {
	d, _ := s.decisions[id]
	return NotActiveBody{
		Error: NotActiveError, Component: id, State: d.State, Reason: d.Reason,
		Message: s.RefusalLine(id),
		Fields:  NotActiveLink(id, d.State),
	}
}

// NotActiveLink is the deep link of a component_not_installed body: always
// Settings > Components with the component focused (an absent component's
// row lists the builds that carry it; a blocked one's row says why), plus the
// CLI command only when the component can be turned on here.
func NotActiveLink(id string, state components.State) settingslink.Fields {
	f := settingslink.Component(id).Fields()
	if state != components.StateAbsent && state != components.StateBlocked {
		f = f.WithCommand(settingslink.ComponentCommand(id))
	}
	return f
}

func nonNil(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}
