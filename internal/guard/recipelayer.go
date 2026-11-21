package guard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Guard recipes (docs/guard-recipes.md): an applied recipe is a managed
// policy file BESIDE a layer's own file (<file>.recipe.toml next to
// <file>.toml), folded into that layer ahead of the layer's own rows, so the
// person's own edits win over the recipe and the org floor wins over both.
// Two layers carry one: the user layer (scope global) and the trusted
// per-project layer (scope project). Keeping the recipe in its own file
// keeps it separate from the person's rules and removable by deleting one
// file; internal/guardrecipesvc is its one writer, and the resolvers below
// are the ONE place both the loader and the writer take its path from.

// RecipeFileSuffix is the suffix that marks an applied recipe file.
const RecipeFileSuffix = ".recipe.toml"

// recipeSibling maps a layer file path to its recipe file path.
func recipeSibling(p string) string {
	if p == "" {
		return ""
	}
	if base, ok := strings.CutSuffix(p, ".toml"); ok {
		return base + RecipeFileSuffix
	}
	return p + RecipeFileSuffix
}

// UserRecipePolicyPath is the applied global recipe file: the user policy
// file's recipe sibling (~/.observer/guard-policy.recipe.toml by default).
// Empty when no user policy is configured (the recipe has no layer then).
func UserRecipePolicyPath(cfg config.GuardConfig, home string) string {
	return recipeSibling(UserPolicyPath(cfg, home))
}

// TrustedProjectRecipePath is one project's applied recipe file: the trusted
// per-project file's recipe sibling (<trusted_project_dir>/<hash>.recipe.toml).
// Empty when the trusted layer is off or the root is empty.
func TrustedProjectRecipePath(cfg config.GuardConfig, home, projectRoot string) string {
	return recipeSibling(TrustedProjectPolicyPath(cfg, home, projectRoot))
}

// RecipeDir is the directory of the person's own recipes: guard-recipes
// beside the user policy file (~/.observer/guard-recipes by default). Like
// the policy files it sits inside R-160's deny surface, so an agent cannot
// write a recipe a person might later apply. Empty when no user policy is
// configured.
func RecipeDir(cfg config.GuardConfig, home string) string {
	p := UserPolicyPath(cfg, home)
	if p == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(p), "guard-recipes")
}

// readLayerWithRecipe reads one layer's own policy file and its recipe
// sibling and folds them into the one policyFile the merge sees, recipe
// rows first. Each file degrades on its own: a parse failure in one is a
// recorded issue and the other still loads. states carries one entry per
// file that loaded.
func (g *Guard) readLayerWithRecipe(ownPath, layer string) (*policyFile, []PolicyState, []string) {
	var issues []string
	var states []PolicyState
	label := map[string]string{layerUser: "user policy", layerTrustedProject: "trusted project policy"}[layer]
	read := func(path, what string, sibling bool) *policyFile {
		if path == "" {
			return nil
		}
		raw, err := g.readFile(path)
		switch {
		case err == nil:
		case os.IsNotExist(err):
			return nil
		case sibling && errors.Is(err, syscall.ENOTDIR):
			// A parent of the layer path is a file: the recipe file cannot
			// exist, and the layer's own read already reports the cause.
			return nil
		default:
			issues = append(issues, fmt.Sprintf("%s %s: %v", what, path, err))
			return nil
		}
		pf, perr := parsePolicyFile(raw, layer)
		if perr != nil {
			issues = append(issues, fmt.Sprintf("%s %s: %v", what, path, perr))
			return nil
		}
		states = append(states, PolicyState{Layer: layer, Path: path, ContentHash: sha256hex(raw)})
		return pf
	}
	own := read(ownPath, label, false)
	recipe := read(recipeSibling(ownPath), label+" recipe", true)
	if recipe != nil {
		var dropped []string
		recipe, dropped = g.dropUnknownRecipeTargets(recipe, own, recipeSibling(ownPath))
		issues = append(issues, dropped...)
	}
	return foldRecipeLayer(recipe, own), states, issues
}

// dropUnknownRecipeTargets drops a recipe's override rows that name a rule
// no engine of this binary holds (a built-in, a rule pack row, or a rule the
// recipe or the layer's own file defines), each with a recorded issue. A
// recipe applied by a newer binary, or naming a pack rule of a module this
// node does not run, must never cost the person their own layer, which an
// unknown override would (engine construction refuses it and the base
// ladder drops the whole layer). Security pack ids keep the merge's own
// "not loaded" drop.
func (g *Guard) dropUnknownRecipeTargets(recipe, own *policyFile, path string) (*policyFile, []string) {
	known := map[string]bool{}
	for _, r := range g.packRules {
		known[r.ID] = true
	}
	for i := range recipe.rules {
		known[recipe.rules[i].ID] = true
	}
	if own != nil {
		for i := range own.rules {
			known[own.rules[i].ID] = true
		}
	}
	var issues []string
	kept := recipe.overrides[:0:0]
	for _, ov := range recipe.overrides {
		if known[ov.RuleID] || policy.IsBuiltinRuleID(ov.RuleID) || strings.HasPrefix(ov.RuleID, policy.SecurityRuleIDPrefix) {
			kept = append(kept, ov)
			continue
		}
		issues = append(issues, fmt.Sprintf("recipe %s: override on %s dropped: this Observer has no such rule (re-apply the recipe after updating)", path, ov.RuleID))
	}
	out := *recipe
	out.overrides = kept
	return &out, issues
}

// foldRecipeLayer joins a layer's recipe file and own file into one
// policyFile: recipe rules and overrides first (the engine applies overrides
// in order, last wins, so the own file's rows win), disable lists unioned. A
// rule the own file defines under the same id as a recipe rule replaces the
// recipe's.
func foldRecipeLayer(recipe, own *policyFile) *policyFile {
	if recipe == nil {
		return own
	}
	if own == nil {
		return recipe
	}
	out := *own
	ownIDs := map[string]bool{}
	for i := range own.rules {
		ownIDs[own.rules[i].ID] = true
	}
	rules := make([]policy.Rule, 0, len(recipe.rules)+len(own.rules))
	for i := range recipe.rules {
		if !ownIDs[recipe.rules[i].ID] {
			rules = append(rules, recipe.rules[i])
		}
	}
	rules = append(rules, own.rules...)
	out.rules = rules
	out.overrides = append(append([]rawOverride(nil), recipe.overrides...), own.overrides...)
	out.disable = unionDisable(recipe.disable, own.disable)
	out.notes = append(append([]string(nil), recipe.notes...), own.notes...)
	return &out
}
