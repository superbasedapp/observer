package guard

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Layer-isolation findings from the 2026-11-08 guard layering sweep
// (RC-1, RC-2, RC-4): a defect in a less trusted layer must cost that row,
// or at worst that layer, and never a more trusted one.

// projectLockdownRecipe is the part of an applied lockdown project recipe the
// RC-1 tests need: R-176 raised to an enforced deny and lockdown's own
// out-of-project write rule.
const projectLockdownRecipe = `[[override]]
rule = "R-176"
decision = "deny"
enforce = true

[[rule]]
id = "RC-LCK-01"
doc = "write outside the project root (lockdown level: denied)"
advice = "Write inside the project root, or ask the developer to make the change."
category = "boundary"
severity = "high"
decision = "deny"
enforce = true
[rule.match]
sink = "out_of_project_write"
`

// inRepoReusingRecipeID is the RC-1 repository file: one [[rule]] that reuses
// the recipe's id with another category and severity.
const inRepoReusingRecipeID = `[[rule]]
id = "RC-LCK-01"
category = "destructive"
severity = "warn"
decision = "flag"
[rule.match]
command_base = "x"
`

func trustedRecipeKey(cfg config.GuardConfig, root string) string {
	return filepath.ToSlash(TrustedProjectRecipePath(cfg, "/home/u", root))
}

// TestInRepoRuleReusingHigherIDIsDroppedAlone is RC-1: a repository file that
// reuses a project recipe's rule id must cost only that row, never the
// project recipe, the trusted file or the org project layer.
func TestInRepoRuleReusingHigherIDIsDroppedAlone(t *testing.T) {
	t.Parallel()
	cfg := trustedCfg()
	root := "/home/u/proj"
	g := newTestGuardCfg(t, cfg, map[string]string{
		trustedRecipeKey(cfg, root): projectLockdownRecipe,
		trustedKey(cfg, root):       "[[override]]\nrule = \"R-104\"\ndecision = \"deny\"\nenforce = true\n",
		root + "/.observer/guard-policy.toml": inRepoReusingRecipeID +
			"\n[[override]]\nrule = \"R-153\"\ndecision = \"deny\"\n",
	})

	v, _ := g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "curl https://example.com/x", ProjectRoot: root})
	if v.RuleID != "R-176" || v.Decision != policy.DecisionDeny {
		t.Errorf("recipe R-176 = %+v, want R-176/deny (the project recipe must survive the repository file)", v)
	}
	v, _ = g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "git reset --hard", ProjectRoot: root})
	if v.RuleID != "R-104" || v.Decision != policy.DecisionDeny {
		t.Errorf("trusted R-104 = %+v, want R-104/deny (the trusted file must survive the repository file)", v)
	}
	// The repository row is gone, the recipe's row keeps its category.
	if got := g.CategoryFor("RC-LCK-01"); got != "boundary" {
		t.Errorf("RC-LCK-01 category = %q, want the recipe's boundary", got)
	}
	v, _ = g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "x", ProjectRoot: root})
	if v.RuleID == "RC-LCK-01" {
		t.Errorf("the repository's reused RC-LCK-01 row still fires: %+v", v)
	}
	issues := g.LoadIssues()
	if !hasIssue(issues, "RC-LCK-01", "dropped") {
		t.Errorf("no load issue names the dropped repository row: %v", issues)
	}
	if hasIssue(issues, "project policy for") {
		t.Errorf("the project policy was dropped: %v", issues)
	}
	if drops := g.LayerDrops(); len(drops) != 0 {
		t.Errorf("layer drops = %+v, want none (only a row was dropped)", drops)
	}
}

// TestInRepoOverrideOnTrustedRuleIsEscalateOnly is RC-1's override half: a
// repository [[override]] on a rule the trusted layer (here its applied
// project recipe) defines is held to the one-way check like an override on
// any other rule. It used to find no reference stance (the trusted layer
// folds after the repository file) and could set the recipe's deny to allow
// or cap it at flag.
func TestInRepoOverrideOnTrustedRuleIsEscalateOnly(t *testing.T) {
	t.Parallel()
	root := "/home/u/proj"
	for _, ov := range []string{"decision = \"allow\"\n", "enforce = false\n", "decision = \"flag\"\n"} {
		cfg := trustedCfg()
		g := newTestGuardCfg(t, cfg, map[string]string{
			trustedRecipeKey(cfg, root):           projectLockdownRecipe,
			root + "/.observer/guard-policy.toml": "[[override]]\nrule = \"RC-LCK-01\"\n" + ov,
		})
		v, _ := g.Evaluate(policy.Event{Kind: policy.KindFileAccess, ActionType: "write_file", Target: "/etc/passwd", ProjectRoot: root})
		if v.RuleID != "RC-LCK-01" || v.Decision != policy.DecisionDeny {
			t.Errorf("%q: verdict = %+v, want RC-LCK-01/deny", ov, v)
		}
		if !hasIssue(g.LoadIssues(), "project override on RC-LCK-01 dropped") {
			t.Errorf("%q: no issue for the dropped relaxation: %v", ov, g.LoadIssues())
		}
	}
	// An escalation of a trusted rule still applies.
	cfg := trustedCfg()
	g := newTestGuardCfg(t, cfg, map[string]string{
		trustedKey(cfg, root):                 "[[rule]]\nid = \"TP-1\"\ncategory = \"destructive\"\ndecision = \"flag\"\n[rule.match]\ncommand_base = \"nuke\"\n",
		root + "/.observer/guard-policy.toml": "[[override]]\nrule = \"TP-1\"\ndecision = \"deny\"\nenforce = true\n",
	})
	v, _ := g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "nuke it", ProjectRoot: root})
	if v.RuleID != "TP-1" || v.Decision != policy.DecisionDeny {
		t.Errorf("escalated trusted rule = %+v, want TP-1/deny", v)
	}
}

// TestInRepoRuleReusingIDHeldAbove pins the ownership order for every more
// trusted definer of an id: the trusted file itself, the user layer, the org
// layer. The repository row is dropped and the owner's row keeps firing.
func TestInRepoRuleReusingIDHeldAbove(t *testing.T) {
	t.Parallel()
	const ownerRule = `[[rule]]
id = "OWN-1"
category = "boundary"
severity = "high"
decision = "deny"
enforce = true
[rule.match]
command_base = "danger"
`
	const reuse = `[[rule]]
id = "OWN-1"
category = "destructive"
severity = "warn"
decision = "flag"
[rule.match]
command_base = "x"
`
	root := "/home/u/proj"
	cases := []struct {
		name  string
		files func(cfg config.GuardConfig) map[string]string
		org   bool
	}{
		{name: "trusted file", files: func(cfg config.GuardConfig) map[string]string {
			return map[string]string{trustedKey(cfg, root): ownerRule}
		}},
		{name: "user policy", files: func(config.GuardConfig) map[string]string {
			return map[string]string{"/home/u/.observer/guard-policy.toml": ownerRule}
		}},
		{name: "user recipe", files: func(config.GuardConfig) map[string]string {
			return map[string]string{"/home/u/.observer/guard-policy.recipe.toml": ownerRule}
		}},
		{name: "org bundle", org: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := trustedCfg()
			files := map[string]string{root + "/.observer/guard-policy.toml": reuse}
			pin := ""
			if tc.org {
				cfg.Rules.OrgBundle = "~/.observer/org-policy-bundle.json"
				var env string
				env, pin = signedEnvelope(t, 3, ownerRule)
				files[orgBundlePath] = env
			} else {
				for k, v := range tc.files(cfg) {
					files[k] = v
				}
			}
			g, err := New(Options{Config: cfg, Home: "/home/u", KnownProjectRoots: []string{root}, ReadFile: fsMap(files), OrgKeyPinHash: pin})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			v, _ := g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "danger now", ProjectRoot: root})
			if v.RuleID != "OWN-1" || v.Decision != policy.DecisionDeny {
				t.Errorf("owner row = %+v, want OWN-1/deny", v)
			}
			if got := g.CategoryFor("OWN-1"); got != "boundary" {
				t.Errorf("OWN-1 category = %q, want the owner's boundary", got)
			}
			if !hasIssue(g.LoadIssues(), "OWN-1", "dropped") {
				t.Errorf("no issue for the reused id: %v", g.LoadIssues())
			}
			if len(g.LayerDrops()) != 0 {
				t.Errorf("layer drops = %+v, want none", g.LayerDrops())
			}
		})
	}
}

// TestUserRuleReusingOrgIDKeepsTheOrgFloor is RC-2: a user [[rule]] reusing
// an org rule's id is dropped alone; the org layer and the rest of the user
// layer stay.
func TestUserRuleReusingOrgIDKeepsTheOrgFloor(t *testing.T) {
	t.Parallel()
	orgTOML := `[[override]]
rule = "R-101"
decision = "deny"
enforce = true

[[rule]]
id = "ORG-1"
category = "exfil"
severity = "critical"
decision = "deny"
enforce = true
[rule.match]
command_base = "leak"
`
	envelope, pin := signedEnvelope(t, 7, orgTOML)
	user := `[[rule]]
id = "ORG-1"
category = "posture"
severity = "info"
decision = "flag"
[rule.match]
command_base = "x"

[[override]]
rule = "R-104"
decision = "deny"
enforce = true
`
	g, err := New(Options{
		Config: guardCfgOrg(), Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
		ReadFile: fsMap(map[string]string{
			orgBundlePath:                         envelope,
			"/home/u/.observer/guard-policy.toml": user,
		}),
		OrgKeyPinHash: pin,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !hasLayer(g.PolicyStates(), layerOrg) || !hasLayer(g.PolicyStates(), layerUser) {
		t.Fatalf("layers = %+v, want org and user both loaded", g.PolicyStates())
	}
	v, _ := g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "rm -rf ~/x", ProjectRoot: "/home/u/proj"})
	if v.RuleID != "R-101" || v.Decision != policy.DecisionDeny {
		t.Errorf("org floor R-101 = %+v, want R-101/deny", v)
	}
	v, _ = g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "leak data", ProjectRoot: "/home/u/proj"})
	if v.RuleID != "ORG-1" || v.Decision != policy.DecisionDeny {
		t.Errorf("org rule ORG-1 = %+v, want ORG-1/deny", v)
	}
	v, _ = g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "git reset --hard", ProjectRoot: "/home/u/proj"})
	if v.RuleID != "R-104" || v.Decision != policy.DecisionDeny {
		t.Errorf("user R-104 = %+v, want R-104/deny (the rest of the user layer survives)", v)
	}
	if got := g.CategoryFor("ORG-1"); got != "exfil" {
		t.Errorf("ORG-1 category = %q, want the org's exfil", got)
	}
	issues := g.LoadIssues()
	if hasIssue(issues, "org policy layer dropped") || hasIssue(issues, "user policy layer dropped") {
		t.Errorf("a layer was dropped: %v", issues)
	}
	if !hasIssue(issues, "ORG-1", "dropped") {
		t.Errorf("no issue for the reused org id: %v", issues)
	}
	// The recipe service's lint: the same text reports the collision.
	cols, err := g.UserRuleIDCollisions([]byte(user))
	if err != nil {
		t.Fatalf("UserRuleIDCollisions: %v", err)
	}
	if len(cols) != 1 || cols[0].RuleID != "ORG-1" || cols[0].Owner != layerOrg {
		t.Errorf("collisions = %+v, want ORG-1 owned by org", cols)
	}
}

// TestBaseLadderDropsUserBeforeOrg is RC-2's ladder half: when the org and
// user layers do not build together, the user layer (with its recipe
// sibling, one folded layer) goes first, whatever the cause.
func TestBaseLadderDropsUserBeforeOrg(t *testing.T) {
	t.Parallel()
	org := &policyFile{layer: layerOrg}
	user := &policyFile{layer: layerUser}
	errBoth := errors.New("the two layers disagree")
	cases := []struct {
		name             string
		fails            func(org, user *policyFile) bool
		keepOrg, keepUsr bool
		issue            string
	}{
		{name: "together only", fails: func(o, u *policyFile) bool { return o != nil && u != nil }, keepOrg: true, issue: "user policy layer dropped"},
		{name: "user alone broken", fails: func(_, u *policyFile) bool { return u != nil }, keepOrg: true, issue: "user policy layer dropped"},
		{name: "org alone broken", fails: func(o, _ *policyFile) bool { return o != nil }, keepUsr: true, issue: "org policy layer dropped"},
		{name: "both broken", fails: func(o, u *policyFile) bool { return o != nil || u != nil }, issue: "org+user policy layers dropped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var tried []string
			build := func(o, u *policyFile) (*policy.Engine, []string, error) {
				tried = append(tried, ladderLabel(o, u))
				if tc.fails(o, u) {
					return nil, nil, errBoth
				}
				eng, err := policy.New(policy.Config{})
				return eng, nil, err
			}
			lr, err := baseLadderWith(build, org, user)
			if err != nil || lr.eng == nil {
				t.Fatalf("ladder: %v", err)
			}
			if (lr.org != nil) != tc.keepOrg || (lr.user != nil) != tc.keepUsr {
				t.Errorf("kept org=%v user=%v, want %v %v (tried %v)", lr.org != nil, lr.user != nil, tc.keepOrg, tc.keepUsr, tried)
			}
			var issues []string
			dropped := map[string]bool{}
			for _, d := range lr.drops {
				issues = append(issues, d.Issue)
				dropped[d.Layer] = true
			}
			if !hasIssue(issues, tc.issue) {
				t.Errorf("issues = %v, want %q", issues, tc.issue)
			}
			if dropped[PolicyLayerOrg] == tc.keepOrg || dropped[PolicyLayerUser] == tc.keepUsr {
				t.Errorf("typed drops = %+v, want org dropped=%v user dropped=%v", lr.drops, !tc.keepOrg, !tc.keepUsr)
			}
			if len(tried) > 1 && tried[1] != "org" {
				t.Errorf("second try = %q, want org alone (the user layer goes first): %v", tried[1], tried)
			}
		})
	}
}

func ladderLabel(o, u *policyFile) string {
	switch {
	case o != nil && u != nil:
		return "org+user"
	case o != nil:
		return "org"
	case u != nil:
		return "user"
	}
	return "none"
}

// TestProjectLadderDropsLeastTrustedFirst pins the project engine's fallback
// order as a table: the linked worktree files, then the repository file,
// then the trusted layer, then the user layer in that root, and the org
// project sections only last.
func TestProjectLadderDropsLeastTrustedFirst(t *testing.T) {
	t.Parallel()
	want := []projectRung{
		{inRepo: inRepoAll, trusted: true, user: true},
		{inRepo: inRepoMain, trusted: true, user: true},
		{inRepo: inRepoNone, trusted: true, user: true},
		{inRepo: inRepoNone, trusted: false, user: true},
		{inRepo: inRepoNone, trusted: false, user: false},
	}
	if len(projectLadder) != len(want) {
		t.Fatalf("ladder = %+v, want %+v", projectLadder, want)
	}
	for i := range want {
		if projectLadder[i].inRepo != want[i].inRepo || projectLadder[i].trusted != want[i].trusted || projectLadder[i].user != want[i].user {
			t.Errorf("rung %d = %+v, want %+v", i, projectLadder[i], want[i])
		}
	}
	// No rung keeps a less trusted layer it dropped a more trusted one for:
	// once a layer is gone it stays gone.
	for i := 1; i < len(projectLadder); i++ {
		p, c := projectLadder[i-1], projectLadder[i]
		if c.inRepo < p.inRepo || (c.trusted && !p.trusted) || (c.user && !p.user) {
			t.Errorf("rung %d re-adds a layer rung %d dropped", i, i-1)
		}
	}
}

// TestRecipeOverrideOnDisabledRuleKeepsTheUserLayer is RC-4: a config-level
// disable of a rule the applied global recipe tunes costs that recipe row,
// not the user's own rules.
func TestRecipeOverrideOnDisabledRuleKeepsTheUserLayer(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Rules.Disable = []string{"R-150"}
	files := map[string]string{
		"/home/u/.observer/guard-policy.recipe.toml": "[[override]]\nrule = \"R-150\"\ndecision = \"ask\"\nenforce = true\n\n[[override]]\nrule = \"R-171\"\ndecision = \"deny\"\nenforce = true\n",
		"/home/u/.observer/guard-policy.toml":        "[[override]]\nrule = \"R-104\"\ndecision = \"deny\"\nenforce = true\n",
	}
	g := newTestGuardCfg(t, cfg, files)
	v, _ := g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "git reset --hard", ProjectRoot: "/home/u/proj"})
	if v.RuleID != "R-104" || v.Decision != policy.DecisionDeny {
		t.Errorf("own R-104 = %+v, want R-104/deny (the user layer must survive)", v)
	}
	issues := g.LoadIssues()
	if hasIssue(issues, "user policy layer dropped") {
		t.Fatalf("the user layer was dropped: %v", issues)
	}
	if !hasIssue(issues, "R-150", "disabled") {
		t.Errorf("no issue names the dropped R-150 override: %v", issues)
	}
	// The status check agrees with the loader.
	st := CheckUserPolicy(cfg, "/home/u", fsMap(files))
	if !st.Valid {
		t.Errorf("CheckUserPolicy = %+v, want valid", st)
	}
}

// TestTrustedDisableWithProjectRecipeOverride is RC-4's project half: the
// trusted file's own disable list plus a project recipe override on the same
// rule costs that override, not the whole project policy.
func TestTrustedDisableWithProjectRecipeOverride(t *testing.T) {
	t.Parallel()
	cfg := trustedCfg()
	root := "/home/u/proj"
	g := newTestGuardCfg(t, cfg, map[string]string{
		trustedRecipeKey(cfg, root): "[[override]]\nrule = \"R-150\"\ndecision = \"ask\"\nenforce = true\n\n[[override]]\nrule = \"R-176\"\ndecision = \"deny\"\nenforce = true\n",
		trustedKey(cfg, root):       "disable = [\"R-150\"]\n\n[[override]]\nrule = \"R-104\"\ndecision = \"deny\"\nenforce = true\n",
	})
	v, _ := g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "git reset --hard", ProjectRoot: root})
	if v.RuleID != "R-104" || v.Decision != policy.DecisionDeny {
		t.Errorf("trusted R-104 = %+v, want R-104/deny", v)
	}
	v, _ = g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "curl https://example.com/x", ProjectRoot: root})
	if v.RuleID != "R-176" || v.Decision != policy.DecisionDeny {
		t.Errorf("recipe R-176 = %+v, want R-176/deny", v)
	}
	issues := g.LoadIssues()
	if hasIssue(issues, "project policy for") {
		t.Fatalf("the project policy was dropped: %v", issues)
	}
	if !hasIssue(issues, "R-150", "disabled") {
		t.Errorf("no issue names the dropped R-150 override: %v", issues)
	}
}

// TestLayerDropsAreTyped pins the typed drop signal: a layer the guard runs
// without is a LayerDrop beside its load issue, for the base engine and for a
// project engine; a dropped row is not.
func TestLayerDropsAreTyped(t *testing.T) {
	t.Parallel()
	cfg := trustedCfg()
	root := "/home/u/proj"
	userPath := "/home/u/.observer/guard-policy.toml"
	g := newTestGuardCfg(t, cfg, map[string]string{
		// An override on a rule no layer holds does not build on its own.
		userPath: "[[override]]\nrule = \"R-999\"\ndecision = \"deny\"\n",
	})
	drops := g.LayerDrops()
	if len(drops) != 1 || drops[0].Layer != PolicyLayerUser || drops[0].ProjectRoot != "" || drops[0].Issue == "" {
		t.Fatalf("drops = %+v, want one base user-layer drop", drops)
	}
	if len(drops[0].Paths) != 1 || filepath.ToSlash(drops[0].Paths[0]) != userPath {
		t.Errorf("drop paths = %v, want the user file", drops[0].Paths)
	}
	if !hasIssue(g.LoadIssues(), drops[0].Issue) {
		t.Errorf("the drop's issue %q is not a load issue: %v", drops[0].Issue, g.LoadIssues())
	}

	// A project engine whose every rung fails records its project layers.
	g2 := newTestGuardCfg(t, cfg, map[string]string{
		trustedKey(cfg, root): "[[override]]\nrule = \"R-104\"\ndecision = \"deny\"\n",
	})
	pb := g2.buildProjectEngineWith(g2.set.Load(), root, "", func(projectCandidate) bool { return true })
	if pb.loaded {
		t.Fatal("every rung failed, yet the project engine reports loaded")
	}
	drops = g2.LayerDrops()
	if len(drops) != 1 || drops[0].Layer != PolicyLayerTrustedProject || drops[0].ProjectRoot != root || !strings.Contains(drops[0].Issue, "project policy for") {
		t.Errorf("drops = %+v, want the trusted layer of %s", drops, root)
	}
}

// TestProjectLadderKeepsTrustedWhenRepoFileBreaks drives the project ladder
// with a repository layer that does not build (the fault hook stands in for
// a defect no row-level filter catches): the build drops the repository
// layer only, and the trusted layer keeps applying.
func TestProjectLadderKeepsTrustedWhenRepoFileBreaks(t *testing.T) {
	t.Parallel()
	cfg := trustedCfg()
	root := "/home/u/proj"
	g := newTestGuardCfg(t, cfg, map[string]string{
		trustedKey(cfg, root): "[[override]]\nrule = \"R-104\"\ndecision = \"deny\"\nenforce = true\n",
		root + "/.observer/guard-policy.toml": `[[rule]]
id = "REPO-1"
category = "destructive"
severity = "warn"
decision = "flag"
[rule.match]
command_base = "x"
`,
	})
	es := g.set.Load()
	pb := g.buildProjectEngineWith(es, root, "", func(c projectCandidate) bool { return c.inRepo != nil })
	if !pb.loaded {
		t.Fatal("the project engine fell back to the base engine; the trusted layer must survive a repository failure")
	}
	if hasLayer(pb.states, layerProject) {
		t.Errorf("the repository layer is reported loaded: %+v", pb.states)
	}
	if !hasLayer(pb.states, layerTrustedProject) {
		t.Errorf("the trusted layer is not reported loaded: %+v", pb.states)
	}
	v := pb.eng.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "git reset --hard", ProjectRoot: root})
	if v.RuleID != "R-104" || v.Decision != policy.DecisionDeny {
		t.Errorf("trusted R-104 = %+v, want R-104/deny", v)
	}
	found := false
	for _, d := range g.LayerDrops() {
		if d.Layer == PolicyLayerProject && d.ProjectRoot == root {
			found = true
		}
	}
	if !found {
		t.Errorf("no project-layer drop recorded: %+v", g.LayerDrops())
	}
}

// TestCheckUserPolicyJudgesTheFoldedLayer is RC-4's status half: the T-323
// check reads the own file with its applied recipe and the config disable
// list, as the loader does, so it agrees with New in both directions.
func TestCheckUserPolicyJudgesTheFoldedLayer(t *testing.T) {
	t.Parallel()
	const own = "/home/u/.observer/guard-policy.toml"
	const recipe = "/home/u/.observer/guard-policy.recipe.toml"
	recipeRule := `[[rule]]
id = "RC-MINE-01"
category = "destructive"
severity = "high"
decision = "ask"
[rule.match]
command_base = "nuke"
`
	cases := []struct {
		name    string
		files   map[string]string
		disable []string
		valid   bool
	}{
		{name: "own override on a recipe rule", valid: true, files: map[string]string{
			recipe: recipeRule,
			own:    "[[override]]\nrule = \"RC-MINE-01\"\ndecision = \"deny\"\n",
		}},
		{name: "recipe override on a disabled rule", valid: true, disable: []string{"R-150"}, files: map[string]string{
			recipe: "[[override]]\nrule = \"R-150\"\ndecision = \"ask\"\n",
			own:    "[[override]]\nrule = \"R-104\"\ndecision = \"deny\"\n",
		}},
		{name: "own override on a disabled rule", valid: true, disable: []string{"R-150"}, files: map[string]string{
			own: "[[override]]\nrule = \"R-150\"\ndecision = \"ask\"\n",
		}},
		{name: "own override on an unknown rule", valid: false, files: map[string]string{
			recipe: recipeRule,
			own:    "[[override]]\nrule = \"R-999\"\ndecision = \"deny\"\n",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.GuardConfig{Enabled: true, Mode: "observe"}
			cfg.Rules.UserPolicy = "~/.observer/guard-policy.toml"
			cfg.Rules.Disable = tc.disable
			st := CheckUserPolicy(cfg, "/home/u", fsMap(tc.files))
			if st.Valid != tc.valid {
				t.Errorf("CheckUserPolicy = %+v, want valid=%v", st, tc.valid)
			}
			g, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: fsMap(tc.files)})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if hasLayer(g.PolicyStates(), layerUser) != st.Valid {
				t.Errorf("New loaded the user layer=%v but CheckUserPolicy valid=%v (issues %v)", hasLayer(g.PolicyStates(), layerUser), st.Valid, g.LoadIssues())
			}
		})
	}
}
