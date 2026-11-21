package guard

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Policy layer names as PolicyState.Layer and LayerDrop.Layer carry them.
const (
	PolicyLayerOrg            = layerOrg
	PolicyLayerUser           = layerUser
	PolicyLayerTrustedProject = layerTrustedProject
	PolicyLayerProject        = layerProject
)

// LayerDrop is one policy layer an engine build ran WITHOUT because the
// layer did not build with the layers it composes with (the fallback
// ladders: buildBaseLadder for the base engine, projectLadder for a project
// engine). It is the typed form of the load issue recorded with it, so a
// caller can tell "a whole layer is off" from "one row was dropped", which
// is only an issue string. A row-level drop (a reused id, an override on a
// disabled or unknown rule, a relaxation below the org floor) is never a
// LayerDrop.
//
// The recipe service refuses an apply whose preview guard reports a
// LayerDrop the current guard does not (compare Layer, ProjectRoot and
// Paths): such an apply would switch a layer off.
type LayerDrop struct {
	// Layer is the dropped layer: PolicyLayerOrg, PolicyLayerUser,
	// PolicyLayerTrustedProject or PolicyLayerProject. For a project
	// engine, PolicyLayerOrg means the org project sections of that root
	// (the org-wide layer is in the base engine).
	Layer string `json:"layer"`
	// ProjectRoot is the root whose project engine dropped the layer; ""
	// for the base engine.
	ProjectRoot string `json:"project_root,omitempty"`
	// Paths are the files that made up the dropped layer, when known (the
	// own file and its applied recipe, the repository files, the org
	// bundle cache or the org project envelopes).
	Paths []string `json:"paths,omitempty"`
	// Issue is the load issue recorded with the drop (one of LoadIssues).
	Issue string `json:"issue"`
}

// recordDrops records layer drops and their issues (one issue per distinct
// text: a drop of two layers for one cause records it once).
func (g *Guard) recordDrops(drops []LayerDrop) {
	if len(drops) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	last := ""
	for _, d := range drops {
		g.drops = append(g.drops, d)
		if d.Issue != last {
			g.issues = append(g.issues, d.Issue)
			last = d.Issue
		}
	}
}

// LayerDrops returns the layer drops recorded so far: the base engine's at
// construction, and each project engine's as it is built (a project engine
// builds on the first event, or EffectiveRulesFor, in its root).
func (g *Guard) LayerDrops() []LayerDrop {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]LayerDrop, len(g.drops))
	copy(out, g.drops)
	return out
}

// withDropPaths fills each drop's Paths from the states of its layer and
// sets its ProjectRoot.
func withDropPaths(drops []LayerDrop, projectRoot string, states []PolicyState) []LayerDrop {
	for i := range drops {
		drops[i].ProjectRoot = projectRoot
		if drops[i].Paths != nil {
			continue
		}
		for _, st := range states {
			if st.Layer == drops[i].Layer {
				drops[i].Paths = append(drops[i].Paths, st.Path)
			}
		}
	}
	return drops
}

// RuleIDCollision is a [[rule]] of a candidate policy text whose id a more
// trusted source already defines. The guard drops such a row alone when it
// loads the text (ruleIDOwners, RC-1/RC-2), so an authoring surface (the
// recipe service's global apply) can refuse the text before it is written.
type RuleIDCollision struct {
	// RuleID is the reused id.
	RuleID string `json:"rule_id"`
	// Owner is the source that defines it: "builtin", "rule_pack" or
	// PolicyLayerOrg.
	Owner string `json:"owner"`
}

// UserRuleIDCollisions parses raw as a user-layer policy text (a global
// recipe or the user policy file) and reports each [[rule]] whose id this
// guard's effective org layer, its rule pack or the built-in catalog already
// defines, in file order. The org layer is the one the guard holds: verified
// under the enrolment key pin (or its last verified copy), the same layer the
// user text will merge under. err is raw's parse error (the user-layer
// parser rejects a built-in id itself, so "builtin" only appears for a text
// that parses under a newer catalog).
func (g *Guard) UserRuleIDCollisions(raw []byte) ([]RuleIDCollision, error) {
	pf, err := parsePolicyFile(raw, layerUser)
	if err != nil {
		return nil, fmt.Errorf("guard.UserRuleIDCollisions: %w", err)
	}
	owner := map[string]string{}
	for _, info := range policy.Catalog() {
		owner[info.ID] = "builtin"
	}
	for i := range g.packRules {
		if _, ok := owner[g.packRules[i].ID]; !ok {
			owner[g.packRules[i].ID] = "rule_pack"
		}
	}
	if es := g.set.Load(); es != nil && es.orgLayer != nil {
		for i := range es.orgLayer.rules {
			if _, ok := owner[es.orgLayer.rules[i].ID]; !ok {
				owner[es.orgLayer.rules[i].ID] = PolicyLayerOrg
			}
		}
	}
	var out []RuleIDCollision
	for i := range pf.rules {
		if by, ok := owner[pf.rules[i].ID]; ok {
			out = append(out, RuleIDCollision{RuleID: pf.rules[i].ID, Owner: by})
		}
	}
	return out, nil
}
