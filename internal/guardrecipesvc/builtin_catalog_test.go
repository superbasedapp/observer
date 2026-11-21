package guardrecipesvc

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardrecipe"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestBuiltinRecipesCompileAndLint is the catalog's drift gate against the
// rule table: every built-in level and pack, alone and every level with every
// pack, compiles at both scopes and lints clean at the layer it joins, and
// every override names a rule this binary has (the built-in catalog or one of
// the recipe chain's own RC- rules). A rule renamed or removed under a recipe
// fails here, not at a developer's apply.
func TestBuiltinRecipesCompileAndLint(t *testing.T) {
	f := newFixture(t, "")
	env := f.env(t)
	set, err := guardrecipe.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Issues) > 0 {
		t.Fatalf("built-in catalog issues: %v", set.Issues)
	}
	known := map[string]bool{}
	for _, r := range policy.Catalog() {
		known[r.ID] = true
	}
	own := map[string]bool{}
	for _, r := range set.All() {
		for _, row := range r.Rules {
			id := guardrecipe.RuleID(row)
			if !strings.HasPrefix(id, "RC-") {
				t.Errorf("%s: recipe rule %q must carry the RC- prefix", r.Name, id)
			}
			if own[id] {
				t.Errorf("%s: recipe rule id %s is used by another built-in recipe", r.Name, id)
			}
			own[id] = true
		}
	}
	for _, r := range set.All() {
		for _, o := range r.Overrides {
			if !known[o.Rule] && !own[o.Rule] {
				t.Errorf("%s: override on %s, which is neither a built-in rule nor a recipe rule", r.Name, o.Rule)
			}
		}
	}

	var sels []guardrecipe.Selection
	for _, l := range set.Levels() {
		sels = append(sels, guardrecipe.Selection{Level: l.Name})
		for _, p := range set.Packs() {
			sels = append(sels, guardrecipe.Selection{Level: l.Name, Packs: []string{p.Name}})
		}
	}
	for _, p := range set.Packs() {
		sels = append(sels, guardrecipe.Selection{Packs: []string{p.Name}})
	}
	var allPacks []string
	for _, p := range set.Packs() {
		allPacks = append(allPacks, p.Name)
	}
	sels = append(sels, guardrecipe.Selection{Level: "lockdown", Packs: allPacks})

	for _, sel := range sels {
		for _, scope := range []guardrecipe.Scope{guardrecipe.ScopeGlobal, guardrecipe.ScopeProject} {
			sel.Scope = scope
			name := string(scope) + "/" + sel.Level + "+" + strings.Join(sel.Packs, ",")
			c, err := guardrecipe.Compile(set, sel, CatalogRules(), guardrecipe.Meta{Scope: scope})
			if err != nil {
				t.Errorf("%s: compile: %v", name, err)
				continue
			}
			// A built-in pack only adds or tightens, against every level
			// (RC-3): no row of one may be a lowering the compiler refuses.
			if len(c.Problems) > 0 {
				t.Errorf("%s: problems: %v", name, c.Problems)
			}
			var problems []string
			if scope == guardrecipe.ScopeProject {
				problems = guard.LintTrustedProject(env.Config.Guard, env.Home, c.Text)
			} else {
				problems = guard.Lint(c.Text, "user")
			}
			if len(problems) > 0 {
				t.Errorf("%s: lint: %v", name, problems)
			}
		}
	}
}

// TestBuiltinRecipesApplyClean applies every level machine-wide and every
// pack in a project through the real service, and checks the guard then
// loads the result with no new load issue.
func TestBuiltinRecipesApplyClean(t *testing.T) {
	set, err := guardrecipe.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range set.Levels() {
		f := newFixture(t, "")
		env := f.env(t)
		pv, err := PreviewApply(env, set, Request{Level: l.Name, Scope: guardrecipe.ScopeGlobal})
		if err != nil {
			t.Fatalf("level %s: %v", l.Name, err)
		}
		if len(pv.Problems) > 0 || len(pv.Issues) > 0 {
			t.Errorf("level %s: problems %v issues %v", l.Name, pv.Problems, pv.Issues)
		}
	}
	for _, p := range set.Packs() {
		f := newFixture(t, "")
		env := f.env(t)
		pv, err := PreviewApply(env, set, Request{Packs: []string{p.Name}, Scope: guardrecipe.ScopeProject, ProjectRoot: f.root})
		if err != nil {
			t.Fatalf("pack %s: %v", p.Name, err)
		}
		if len(pv.Problems) > 0 || len(pv.Issues) > 0 {
			t.Errorf("pack %s: problems %v issues %v", p.Name, pv.Problems, pv.Issues)
		}
		if len(pv.Changes) == 0 {
			t.Errorf("pack %s changes no rule in a project", p.Name)
		}
	}
}
