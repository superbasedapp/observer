package guardrecipesvc

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// DroppedLayersFunc returns one reason per policy layer, or project policy,
// that g did not load: the guard's typed "layer dropped" load issue. The
// service compares the guard as it is with the guard an apply or remove
// would leave, and refuses the change when the second drops a layer the
// first kept (sweep findings RC-1, RC-2, RC-4: an apply that costs the
// person their own layer must never pass with only an issue line).
//
// nil uses the guard's typed signal (guard.LayerDrops) plus the recipe-file
// issues below; a test can inject its own.
type DroppedLayersFunc func(g *guard.Guard) []string

// UserLintFunc lints candidate user-layer policy text with the
// organization's layer in view (the user layer's analogue of
// guard.LintTrustedProject): an override that relaxes the org floor, and a
// [[rule]] id an org rule already holds, are problems. nil uses guard.Lint
// at the user layer plus the guard's own org-collision lint
// (Guard.UserRuleIDCollisions); a test can inject its own.
type UserLintFunc func(cfg config.GuardConfig, home string, text []byte) []string

// recipeFileIssue matches the load issue readLayerWithRecipe writes when a
// recipe sibling itself does not parse ("<layer> recipe <path>: <error>").
// That is a load issue, not a guard.LayerDrop (the own file still loads), so
// it is matched by text.
func recipeFileIssue(s string) bool {
	return strings.HasPrefix(s, "user policy recipe ") || strings.HasPrefix(s, "trusted project policy recipe ")
}

// droppedLayer is one dropped layer: key identifies it across two guards,
// issue is what the person reads.
type droppedLayer struct{ key, issue string }

// droppedLayers is env's DroppedLayersFunc when set, else the guard's typed
// layer drops (whole layers an engine build ran without) plus the recipe
// files that did not parse.
func (e Env) droppedLayers(g *guard.Guard) []droppedLayer {
	var out []droppedLayer
	if e.DroppedLayers != nil {
		for _, s := range e.DroppedLayers(g) {
			out = append(out, droppedLayer{key: s, issue: s})
		}
		return out
	}
	for _, d := range g.LayerDrops() {
		out = append(out, droppedLayer{
			key:   d.Layer + "\x00" + d.ProjectRoot + "\x00" + strings.Join(d.Paths, "\x00"),
			issue: d.Issue,
		})
	}
	for _, s := range g.LoadIssues() {
		if recipeFileIssue(s) {
			out = append(out, droppedLayer{key: "issue\x00" + s, issue: s})
		}
	}
	return out
}

// newlyDropped returns the layer drops next has that cur does not.
func newlyDropped(env Env, cur, next *guard.Guard) []string {
	seen := map[string]bool{}
	for _, d := range env.droppedLayers(cur) {
		seen[d.key] = true
	}
	var out []string
	for _, d := range env.droppedLayers(next) {
		if !seen[d.key] {
			seen[d.key] = true
			out = append(out, "the change would drop a policy layer, so it is refused: "+d.issue)
		}
	}
	return out
}

// userRuleIDCollisions names each [[rule]] id in a candidate user-layer file
// that a more trusted owner already holds (the org layer, a rule pack or a
// built-in), through the guard's own org-collision lint: on the user layer
// such a row would be dropped, so the recipe that carries it is refused.
func userRuleIDCollisions(g *guard.Guard, text []byte) []string {
	if g == nil {
		return nil
	}
	cols, err := g.UserRuleIDCollisions(text)
	if err != nil {
		return nil // a parse error is the plain lint's to report
	}
	var out []string
	for _, c := range cols {
		out = append(out, "recipe rule "+c.RuleID+": "+collisionOwnerText(c.Owner)+" defines a rule with this id; a recipe rule needs its own id")
	}
	return out
}

// collisionOwnerText names a rule id's owner in a problem line.
func collisionOwnerText(owner string) string {
	switch owner {
	case guard.PolicyLayerOrg:
		return "your organization's policy"
	case "rule_pack":
		return "a rule pack"
	default:
		return "a built-in rule"
	}
}

// orgRuleIDCollisions names each recipe rule id that a rule the
// organization defines already holds: on the user layer that id would
// collide with the org's rule. It reads the org-defined rules off g (the
// guard as it is), so it needs no org context of its own.
func orgRuleIDCollisions(g *guard.Guard, projectRoot string, ids []string) []string {
	if g == nil || len(ids) == 0 {
		return nil
	}
	org := map[string]bool{}
	for _, r := range g.EffectiveRulesFor(projectRoot) {
		if r.Source == policy.SourceOrg && !policy.IsBuiltinRuleID(r.ID) {
			org[r.ID] = true
		}
	}
	var out []string
	for _, id := range ids {
		if org[id] {
			out = append(out, "recipe rule "+id+": your organization's policy defines a rule with this id; a recipe rule needs its own id")
		}
	}
	return out
}
