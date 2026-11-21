package guardrecipesvc

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardrecipe"
)

// OverrideView is one recipe [[override]] row as a surface shows it.
type OverrideView struct {
	Rule     string `json:"rule"`
	Decision string `json:"decision,omitempty"`
	// Enforce is true (holds in observe mode), false (capped at flag) or
	// null (unset).
	Enforce *bool  `json:"enforce"`
	Note    string `json:"note,omitempty"`
}

// RecipeView is a recipe as the CLI's --json and the dashboard show it: the
// labels, what it sets, and the ids of the rules it adds. The raw file is
// served separately (show), so a catalog listing stays small.
type RecipeView struct {
	Name       string             `json:"name"`
	Kind       guardrecipe.Kind   `json:"kind"`
	Title      string             `json:"title"`
	Summary    string             `json:"summary"`
	Version    int                `json:"version"`
	Order      int                `json:"order,omitempty"`
	Mode       string             `json:"mode,omitempty"`
	PromptMode string             `json:"prompt_mode,omitempty"`
	Extends    string             `json:"extends,omitempty"`
	Advice     []string           `json:"advice"`
	Inputs     []string           `json:"inputs"`
	Source     guardrecipe.Source `json:"source"`
	Overrides  []OverrideView     `json:"overrides"`
	RuleIDs    []string           `json:"rule_ids"`
}

// ViewOf renders one recipe for a surface.
func ViewOf(r *guardrecipe.Recipe) RecipeView {
	v := RecipeView{
		Name: r.Name, Kind: r.Kind, Title: r.Title, Summary: r.Summary,
		Version: r.Version, Order: r.Order, Mode: r.Mode, PromptMode: r.PromptMode,
		Extends: r.Extends, Source: r.Source,
		Advice:    append([]string{}, r.Advice...),
		Inputs:    append([]string{}, r.Inputs...),
		Overrides: make([]OverrideView, 0, len(r.Overrides)),
		RuleIDs:   make([]string, 0, len(r.Rules)),
	}
	for _, o := range r.Overrides {
		v.Overrides = append(v.Overrides, OverrideView{Rule: o.Rule, Decision: o.Decision, Enforce: o.Enforce, Note: o.Note})
	}
	for _, row := range r.Rules {
		if id := guardrecipe.RuleID(row); id != "" {
			v.RuleIDs = append(v.RuleIDs, id)
		}
	}
	return v
}

// CatalogViews renders the whole catalog in its listing order (levels by
// strictness, then packs by name).
func CatalogViews(set *guardrecipe.Set) []RecipeView {
	all := set.All()
	out := make([]RecipeView, 0, len(all))
	for _, r := range all {
		out = append(out, ViewOf(r))
	}
	return out
}

// LevelDrift explains why the machine's applied recipe is not simply what is
// in force ("" when it is): a [guard] level key that disagrees with the
// applied global recipe (the key is a label the apply writes; a hand edit
// does not apply a recipe, so a surface says so instead of trusting the
// key), and, for an applied recipe, the in-force checks of inForceNotes
// (sweep findings RC-12, CFG-4). It builds the current guard to see which
// policy files loaded.
func LevelDrift(env Env, global *Applied) string {
	var notes []string
	if s := levelKeyDrift(env, global); s != "" {
		notes = append(notes, s)
	}
	if global != nil && global.Readable {
		notes = append(notes, inForceNotes(env, nil, global)...)
	}
	return strings.Join(notes, " ")
}

// levelKeyDrift compares the [guard] level key with the applied level.
func levelKeyDrift(env Env, global *Applied) string {
	key := env.Config.Guard.Level
	applied := ""
	if global != nil && global.Readable {
		applied = global.Meta.LevelName()
	}
	switch {
	case key == applied:
		return ""
	case applied == "":
		return fmt.Sprintf("[guard] level says %q, but no level recipe is applied on this machine: the key is only a label, so nothing changed. Apply the level to put it in force.", key)
	case key == "":
		return fmt.Sprintf("The applied recipe is level %q, but [guard] level is empty: re-apply or remove the recipe to bring the two back together.", applied)
	default:
		return fmt.Sprintf("[guard] level says %q, but the applied recipe is level %q: the key is only a label; the applied recipe is what loads.", key, applied)
	}
}

// inForceNotes says what keeps an applied recipe from being what is in
// force: the guard off as a whole, the machine-wide mode off under a project
// recipe, the mode or prompt mode changed since a global apply set them, and
// a recipe file the guard did not load. g is the current guard (nil builds
// one).
func inForceNotes(env Env, g *guard.Guard, a *Applied) []string {
	gc := env.Config.Guard
	var notes []string
	// Nothing is judged with the guard off or the mode off, so whether the
	// file loaded says nothing about what is in force then.
	off := !gc.Enabled || modeOr(gc.Mode) == "off"
	switch {
	case !gc.Enabled:
		notes = append(notes, "The guard is turned off ([guard] enabled = false): the applied recipe is recorded, but nothing is judged.")
	case a.Scope == guardrecipe.ScopeProject && modeOr(gc.Mode) == "off":
		notes = append(notes, "The machine-wide mode is off: the project recipe is recorded, but nothing is judged in this project.")
	}
	if a.Scope == guardrecipe.ScopeGlobal {
		m := a.Meta
		if m.Mode != "" && modeOr(gc.Mode) != m.Mode {
			notes = append(notes, fmt.Sprintf("The applied recipe set the mode to %q, but the mode is %q: the recipe's rules load, its mode is not in force.", m.Mode, modeOr(gc.Mode)))
		}
		if m.PromptMode != "" && gc.Prompt.Mode != m.PromptMode {
			notes = append(notes, fmt.Sprintf("The applied recipe set the prompt mode to %q, but the prompt mode is %q.", m.PromptMode, gc.Prompt.Mode))
		}
	}
	if !off && !recipeLoaded(env, g, a) {
		notes = append(notes, fmt.Sprintf("The applied recipe file %s did not load (observer guard status names the load issue): its rules are not in force.", a.Path))
	}
	return notes
}

// recipeLoaded reports whether the guard loaded a's recipe file (it is among
// the guard's policy states). It reports true when no guard can be built:
// the drift line then makes no claim either way.
func recipeLoaded(env Env, g *guard.Guard, a *Applied) bool {
	if g == nil {
		var err error
		g, err = guard.New(guard.Options{Config: env.Config.Guard, Home: env.Home, KnownProjectRoots: env.KnownProjectRoots, PackRules: env.PackRules})
		if err != nil {
			return true
		}
	}
	if a.Scope == guardrecipe.ScopeProject {
		// A project's layers load lazily, on its first evaluation.
		g.EffectiveRulesFor(a.ProjectRoot)
	}
	for _, st := range g.PolicyStates() {
		if samePath(st.Path, a.Path) {
			return true
		}
	}
	return false
}

// guardOffNote is the preview note for a guard turned off as a whole: a
// recipe is recorded, but nothing is judged until the guard is on.
const guardOffNote = "The guard is turned off ([guard] enabled = false): the recipe is recorded, but nothing is judged until you turn the guard on."
