package guardrecipesvc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardrecipe"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// fixture is a throwaway home with a config file whose guard paths and
// database all sit inside it, so config.Load reads nothing of the machine's.
type fixture struct {
	home, cfgPath, root string
}

func newFixture(t *testing.T, guardTOML string) fixture {
	t.Helper()
	home := t.TempDir()
	obs := filepath.Join(home, ".observer")
	if err := os.MkdirAll(obs, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, "proj")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	slash := filepath.ToSlash
	body := "[observer]\ndb_path = '" + slash(filepath.Join(obs, "observer.db")) + "'\n\n" +
		"[guard]\nenabled = true\nmode = \"observe\"\n" + guardTOML + "\n" +
		"[guard.rules]\nuser_policy = '" + slash(filepath.Join(obs, "guard-policy.toml")) + "'\n" +
		"trusted_project_dir = '" + slash(filepath.Join(obs, "guard-project-policies")) + "'\n" +
		"org_bundle = '" + slash(filepath.Join(obs, "org-policy-bundle.json")) + "'\n"
	cfgPath := filepath.Join(obs, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return fixture{home: home, cfgPath: cfgPath, root: root}
}

func (f fixture) env(t *testing.T) Env {
	t.Helper()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: f.cfgPath, Env: func(string) string { return "" }, GovernanceSidecar: config.NoGovernanceSidecar})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return Env{Config: cfg, Home: f.home, KnownProjectRoots: []string{f.root}, Now: func() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }}
}

func (f fixture) writer() ConfigWriter { return FileConfigWriter(f.cfgPath) }

func catalog(t *testing.T, env Env) *guardrecipe.Set {
	t.Helper()
	set, err := Catalog(env)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func changeFor(p *Preview, id string) (Change, bool) {
	for _, c := range p.Changes {
		if c.RuleID == id {
			return c, true
		}
	}
	return Change{}, false
}

// TestApplyRemove_Global applies the balanced level machine-wide and removes
// it: the recipe file lands beside the user policy, [guard] level, mode and
// prompt mode move, and remove puts every one back.
func TestApplyRemove_Global(t *testing.T) {
	f := newFixture(t, "")
	env := f.env(t)
	set := catalog(t, env)

	pv, err := PreviewApply(env, set, Request{Level: "balanced", Scope: guardrecipe.ScopeGlobal, Via: "cli"})
	if err != nil {
		t.Fatal(err)
	}
	if pv.ModeBefore != "observe" || pv.ModeAfter != "enforce" || pv.LevelAfter != "balanced" || pv.PromptModeAfter != "ask-once" {
		t.Errorf("preview config = %+v", pv)
	}
	if c, ok := changeFor(pv, "R-101"); !ok || c.Before != "flag" || c.After != "deny" {
		t.Errorf("R-101 change = %+v %v", c, ok)
	}
	if len(pv.Problems) != 0 {
		t.Errorf("problems = %v", pv.Problems)
	}

	res, err := Apply(env, set, Request{Level: "balanced", Scope: guardrecipe.ScopeGlobal, Via: "cli"}, f.writer())
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(f.home, ".observer", "guard-policy.recipe.toml")
	if !samePath(res.Wrote, want) || !res.ConfigChanged {
		t.Fatalf("result = %+v", res)
	}
	raw, err := os.ReadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	meta, ok := guardrecipe.ParseMeta(raw)
	if !ok || meta.LevelName() != "balanced" || meta.Previous == nil || meta.Previous.Mode != "observe" {
		t.Fatalf("meta = %+v %v", meta, ok)
	}
	env2 := f.env(t)
	if g := env2.Config.Guard; g.Level != "balanced" || g.Mode != "enforce" || g.Prompt.Mode != "ask-once" {
		t.Fatalf("config after apply = level %q mode %q prompt %q", g.Level, g.Mode, g.Prompt.Mode)
	}
	prevPrompt := env.Config.Guard.Prompt.Mode

	if _, ok, err := Remove(env2, catalog(t, env2), guardrecipe.ScopeGlobal, "", f.writer()); err != nil || !ok {
		t.Fatalf("Remove = %v %v", ok, err)
	}
	if _, err := os.Stat(want); !os.IsNotExist(err) {
		t.Fatalf("recipe file still there: %v", err)
	}
	env3 := f.env(t)
	if g := env3.Config.Guard; g.Level != "" || g.Mode != "observe" || g.Prompt.Mode != prevPrompt {
		t.Fatalf("config after remove = level %q mode %q prompt %q", g.Level, g.Mode, g.Prompt.Mode)
	}
	if _, ok, err := Remove(env3, catalog(t, env3), guardrecipe.ScopeGlobal, "", f.writer()); err != nil || ok {
		t.Fatalf("second Remove = %v %v, want no recipe", ok, err)
	}
}

// TestRemove_KeepsLaterModeChange pins that remove restores the mode only
// while it still holds what the recipe set.
func TestRemove_KeepsLaterModeChange(t *testing.T) {
	f := newFixture(t, "")
	env := f.env(t)
	if _, err := Apply(env, catalog(t, env), Request{Level: "balanced", Scope: guardrecipe.ScopeGlobal}, f.writer()); err != nil {
		t.Fatal(err)
	}
	if err := f.writer()(func(g *config.GuardConfig) { g.Mode = "off" }); err != nil {
		t.Fatal(err)
	}
	env2 := f.env(t)
	pv, ok, err := PreviewRemove(env2, catalog(t, env2), guardrecipe.ScopeGlobal, "")
	if err != nil || !ok || !strings.Contains(pv.ModeNote, "mode stays") {
		t.Fatalf("preview = %+v %v %v", pv, ok, err)
	}
	if _, _, err := Remove(env2, catalog(t, env2), guardrecipe.ScopeGlobal, "", f.writer()); err != nil {
		t.Fatal(err)
	}
	if g := f.env(t).Config.Guard; g.Mode != "off" || g.Level != "" {
		t.Fatalf("after remove mode %q level %q", g.Mode, g.Level)
	}
}

// TestApply_ProjectLooseCaps applies loose to one project: the trusted
// layer's recipe sibling holds the caps, the machine-wide mode is untouched,
// and the guard built from disk applies the caps in that project only.
func TestApply_ProjectLooseCaps(t *testing.T) {
	// No allow_paths: the test home sits under the temp directory, which
	// the default allow list exempts from R-150.
	f := newFixture(t, "\n[guard.boundary]\nallow_paths = []\n")
	if err := f.writer()(func(g *config.GuardConfig) { g.Mode = "enforce" }); err != nil {
		t.Fatal(err)
	}
	env := f.env(t)
	req := Request{Level: "loose", Scope: guardrecipe.ScopeProject, ProjectRoot: f.root}
	res, err := Apply(env, catalog(t, env), req, f.writer())
	if err != nil {
		t.Fatal(err)
	}
	if res.ConfigChanged || res.Preview.ModeNote == "" {
		t.Errorf("project apply touched config or gave no mode note: %+v", res)
	}
	if !strings.HasSuffix(res.Wrote, guard.RecipeFileSuffix) || !strings.Contains(res.Preview.Text, "enforce = false") {
		t.Fatalf("wrote %s:\n%s", res.Wrote, res.Preview.Text)
	}
	if c, ok := changeFor(res.Preview, "R-150"); !ok || c.Before != "ask" || c.After != "flag" {
		t.Errorf("R-150 change = %+v %v", c, ok)
	}
	if _, ok := changeFor(res.Preview, "R-101"); ok {
		t.Errorf("R-101 changed although loose keeps it enforced")
	}
	env2 := f.env(t)
	if env2.Config.Guard.Mode != "enforce" {
		t.Fatalf("mode = %q", env2.Config.Guard.Mode)
	}
	g, err := guard.New(guard.Options{Config: env2.Config.Guard, Home: f.home, KnownProjectRoots: []string{f.root}})
	if err != nil {
		t.Fatal(err)
	}
	ev := policy.Event{Kind: policy.KindFileAccess, ActionType: "write_file", Target: filepath.ToSlash(filepath.Join(f.home, "elsewhere.txt")), ProjectRoot: filepath.ToSlash(f.root)}
	inProject, err := g.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}
	if inProject.RuleID != "R-150" || inProject.Decision != policy.DecisionFlag {
		t.Errorf("in the project = %s %v, want R-150 flag (capped)", inProject.RuleID, inProject.Decision)
	}
	outside := ev
	outside.ProjectRoot = filepath.ToSlash(filepath.Join(f.home, "other"))
	outside.Target = filepath.ToSlash(filepath.Join(f.home, "elsewhere2.txt"))
	if v, _ := g.Evaluate(outside); v.RuleID != "R-150" || v.Decision != policy.DecisionAsk {
		t.Errorf("another project = %s %v, want R-150 ask (machine-wide enforce)", v.RuleID, v.Decision)
	}
}

// TestFold_OwnEditsWin pins the fold order: the person's own policy file
// loads after the recipe, so their override beats the recipe's.
func TestFold_OwnEditsWin(t *testing.T) {
	f := newFixture(t, "")
	env := f.env(t)
	if _, err := Apply(env, catalog(t, env), Request{Packs: []string{"baseline-guard"}, Scope: guardrecipe.ScopeGlobal}, f.writer()); err != nil {
		t.Fatal(err)
	}
	own := "[[override]]\nrule = \"R-110\"\ndecision = \"ask\"\n"
	if err := os.WriteFile(filepath.Join(f.home, ".observer", "guard-policy.toml"), []byte(own), 0o600); err != nil {
		t.Fatal(err)
	}
	env2 := f.env(t)
	g, err := guard.New(guard.Options{Config: env2.Config.Guard, Home: f.home})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range g.EffectiveRules() {
		switch r.ID {
		case "R-110":
			if r.Enforce != policy.DecisionAsk {
				t.Errorf("R-110 enforce = %v, want ask (own file wins)", r.Enforce)
			}
		case "R-101":
			if r.Enforce != policy.DecisionDeny || !r.Enforced {
				t.Errorf("R-101 = %+v, want the recipe's deny + enforced", r)
			}
		}
	}
	if len(g.PolicyStates()) < 2 {
		t.Errorf("states = %+v, want the user file and its recipe", g.PolicyStates())
	}
}

// TestFold_UnknownRuleDropped pins that a recipe naming a rule this binary
// lacks costs only that row, never the person's own layer.
func TestFold_UnknownRuleDropped(t *testing.T) {
	f := newFixture(t, "")
	obs := filepath.Join(f.home, ".observer")
	recipe := "# observer-guard-recipe: {\"format\":1,\"scope\":\"global\"}\n[[override]]\nrule = \"R-999\"\ndecision = \"deny\"\n"
	if err := os.WriteFile(filepath.Join(obs, "guard-policy.recipe.toml"), []byte(recipe), 0o600); err != nil {
		t.Fatal(err)
	}
	own := "[[override]]\nrule = \"R-104\"\ndecision = \"deny\"\n"
	if err := os.WriteFile(filepath.Join(obs, "guard-policy.toml"), []byte(own), 0o600); err != nil {
		t.Fatal(err)
	}
	env := f.env(t)
	g, err := guard.New(guard.Options{Config: env.Config.Guard, Home: f.home})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range g.LoadIssues() {
		if strings.Contains(s, "R-999") && strings.Contains(s, "dropped") {
			found = true
		}
	}
	if !found {
		t.Errorf("issues = %v, want the R-999 drop", g.LoadIssues())
	}
	for _, r := range g.EffectiveRules() {
		if r.ID == "R-104" && r.Enforce != policy.DecisionDeny {
			t.Errorf("own R-104 override lost: %+v", r)
		}
	}
}

// TestUserRecipes is one case per save/delete outcome.
func TestUserRecipes(t *testing.T) {
	f := newFixture(t, "")
	env := f.env(t)
	good := "name = \"mine\"\nkind = \"pack\"\ntitle = \"Mine\"\nversion = 1\nextends = \"baseline-guard\"\n[[override]]\nrule = \"R-104\"\ndecision = \"deny\"\n"
	if _, err := SaveUserRecipe(env, "mine", []byte(good)); err != nil {
		t.Fatal(err)
	}
	set := catalog(t, env)
	if r, ok := set.Get("mine"); !ok || r.Source != guardrecipe.SourceUser {
		t.Fatalf("mine = %v %v (issues %v)", r, ok, set.Issues)
	}
	cases := []struct {
		name, file, body, want string
	}{
		{"built-in name", "strict", strings.Replace(good, "mine", "strict", 1), "built-in"},
		{"bad toml", "x", "name =", "guardrecipe.Parse"},
		{"unknown rule", "y", "name = \"y\"\nkind = \"pack\"\ntitle = \"Y\"\nversion = 1\n[[override]]\nrule = \"R-999\"\ndecision = \"deny\"\n", "lint"},
		{"missing extends", "z", "name = \"z\"\nkind = \"pack\"\ntitle = \"Z\"\nversion = 1\nextends = \"nope\"\n", "does not fit"},
	}
	for _, tc := range cases {
		if _, err := SaveUserRecipe(env, tc.file, []byte(tc.body)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	if err := DeleteUserRecipe(env, "strict"); err == nil {
		t.Error("deleted a built-in")
	}
	if err := DeleteUserRecipe(env, "mine"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUserRecipe(env, "mine"); err == nil {
		t.Error("deleted twice")
	}
}

// TestReadApplied_Updates pins the update and missing reports.
func TestReadApplied_Updates(t *testing.T) {
	f := newFixture(t, "")
	env := f.env(t)
	header := "# observer-guard-recipe: {\"format\":1,\"scope\":\"global\",\"level\":{\"name\":\"balanced\",\"version\":0},\"packs\":[{\"name\":\"gone\",\"version\":1}]}\n"
	if err := os.WriteFile(filepath.Join(f.home, ".observer", "guard-policy.recipe.toml"), []byte(header), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := ReadApplied(env, catalog(t, env), guardrecipe.ScopeGlobal, "")
	if err != nil || a == nil || !a.Readable {
		t.Fatalf("applied = %+v %v", a, err)
	}
	if len(a.Updates) != 1 || !strings.HasPrefix(a.Updates[0], "balanced v0 -> v") || len(a.Missing) != 1 || a.Missing[0] != "gone" {
		t.Errorf("updates %v missing %v", a.Updates, a.Missing)
	}
}
