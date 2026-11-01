package componentstate

import (
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// module.go is the shared optional-module contract (lane OPTMOD), the one
// helper every OPTIONAL MODULE gates its surfaces with: the security pillar
// (component `security` and its `security.*` rows) and the sandbox module
// (`terminals.sandbox` and its `terminals.sandbox.*` drivers). Before it the
// security plan carried a private `secgate.Active` and the sandbox plan used
// Snapshot.Active directly, which answers TRUE for an id the catalog does not
// know.
//
// Which predicate to use:
//
//   - Snapshot.Active: a gate in front of behaviour that already ships and
//     must keep running if its catalog row is ever renamed or dropped. An
//     unknown id answers true ("fail open to today's behaviour").
//   - Snapshot.ModuleActive: a gate in front of anything an optional module
//     ADDS (a route, a loop, a page, a verb, a config section, a sidecar, a
//     process, an outbound call). An unknown id answers false ("fail
//     invisible"): a misspelt or dropped id keeps the surface off, never on.
//
// The two agree on every id the catalog knows once a snapshot is resolved;
// they differ only on an id the snapshot holds no decision for. A module pins
// every id its wiring tables use with UnknownNodeIDs in a test, so a typo
// fails the build rather than silently hiding (or, with Active, silently
// showing) the module.

// ModuleActive reports whether the optional-module component id is active.
// It answers false for an id this snapshot holds no decision for: an id the
// node catalog does not know, an org server id, or any id of the zero
// Snapshot (nothing was resolved, so nothing optional runs).
func (s Snapshot) ModuleActive(id string) bool {
	d, ok := s.decisions[id]
	return ok && d.State == components.StateActive
}

// AnyModuleActive reports whether at least one of ids is active under
// ModuleActive. No ids answers false: a module surface always names the
// component that owns it (contrast AnyActive, where no ids means core).
func (s Snapshot) AnyModuleActive(ids ...string) bool {
	for _, id := range ids {
		if s.ModuleActive(id) {
			return true
		}
	}
	return false
}

// UnknownNodeIDs returns the ids that are not node catalog rows (an unknown
// id, or an org server id), sorted and deduplicated; nil when every id is a
// node row. A module's wiring test calls it on every id its tables name.
func UnknownNodeIDs(ids ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if seen[id] {
			continue
		}
		seen[id] = true
		if c, ok := components.Get(id); !ok || c.Binary != components.BinaryNode {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// moduleGate is the config.ComponentGate this package registers: a
// component-owned config section is validated by config.Load only while its
// component is active under ModuleActive for the loaded [components] block.
// It resolves without managed governance (config loads before governance is
// read); internal/config/component_sections.go states what that means.
func moduleGate(sel config.ComponentsConfig, id string) bool {
	return Resolve(sel, nil).ModuleActive(id)
}

func init() {
	// The one resolver config.Load uses for component-owned sections
	// (config.SetComponentGate). Registered here because this package is the
	// one owner of component state and imports config, not the reverse.
	config.SetComponentGate(moduleGate)
}

// BlockSelects reports whether the [components] block itself selects the
// opt-in component id: the block lists id in add, or names a prebuilt
// distro whose base set holds id. An opt-in module runs only then (D-MU3).
// A block that only adds or removes other components selects nothing
// opt-in: before this, the opt-in rules asked only whether a block
// existed, so a first `observer components add integration.service` on a
// defaults install (a block with no distro, whose base is every compiled
// component) switched on every opt-in sandbox driver, the evidence seal
// and the opt-in security children (live macOS install 2026-10-29: 114 to
// 129 active). On an org-managed node, where the block's distro is ignored
// and the organization's policy decides, a block still selects as before.
func (s Snapshot) BlockSelects(id string) bool {
	if !s.Configured {
		return false
	}
	if s.Governed.OrgManaged {
		return true
	}
	for _, a := range s.Add {
		if a == id {
			return true
		}
	}
	if d := components.Distro(s.BlockDistro); s.BlockDistro != "" && d.Valid() {
		for _, b := range BaseSet(d) {
			if b == id {
				return true
			}
		}
	}
	return false
}
