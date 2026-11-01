package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// checkoutengine_test.go pins the per-checkout project engines (lane
// LEFT-SHARED, SHR-8 residual): a linked worktree's own in-repo policy file
// applies in that worktree only, and no checkout is ever weaker than before.

const (
	mainFileEscalates = "[[override]]\nrule = \"R-110\"\nenforce = true\n"
	wtFileAddsRule    = "[[rule]]\nid = \"P-001\"\ncategory = \"boundary\"\nseverity = \"warn\"\ndecision = \"flag\"\napplies_to = [\"shell_exec\"]\nmatch.command_base = \"make\"\n"
)

// outsideDelete is a recursive delete R-101 classifies as outside the
// project, in the same path flavor as root. On a POSIX root it is the
// original "~/x" (the fixture home /home/u). A "~/x" target cannot serve a
// Windows temp root: it expands to that POSIX home, and the lexical policy
// treats mixed flavors as unknown, not outside. There the target is a
// directory on the root's own drive, outside the temp tree (a sibling under
// the temp dir would be cleared by the default /tmp allow_paths on Linux).
func outsideDelete(root string) string {
	if vol := filepath.VolumeName(root); vol != "" {
		return "rm -rf " + vol + "/elsewhere/outside-x"
	}
	return "rm -rf ~/x"
}

func shellIn(root, cwd, cmd string) policy.Event {
	return policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: cmd, ProjectRoot: root, Cwd: cwd}
}

// TestCheckoutOf: the main checkout, a linked worktree, a subdirectory, and
// the not-known cases.
func TestCheckoutOf(t *testing.T) {
	mainRoot, wt := handWorktreeProject(t)
	other := t.TempDir()
	cases := []struct {
		name, root, cwd, want string
	}{
		{"main checkout", mainRoot, mainRoot, mainRoot},
		{"main subdirectory", mainRoot, filepath.Join(mainRoot, ".git"), mainRoot},
		{"linked worktree", mainRoot, wt, wt},
		{"no cwd", mainRoot, "", ""},
		{"relative cwd", mainRoot, "wt", ""},
		{"no root", "", wt, ""},
		{"outside any checkout", mainRoot, other, ""},
		{"a checkout of another project", other, wt, ""},
	}
	for _, tc := range cases {
		if got := checkoutOf(tc.root, tc.cwd); got != tc.want {
			t.Errorf("%s: checkoutOf = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestCheckoutPolicyPaths: a known checkout reads the main file and its own;
// the not-known checkout reads every checkout's file, as before.
func TestCheckoutPolicyPaths(t *testing.T) {
	mainRoot, wt := handWorktreeProject(t)
	cfg := guardCfg()
	mainFile := filepath.Join(mainRoot, ".observer", "guard-policy.toml")
	wtFile := filepath.Join(wt, ".observer", "guard-policy.toml")
	if got := checkoutPolicyPaths(cfg, mainRoot, mainRoot); len(got) != 1 || got[0] != mainFile {
		t.Errorf("main checkout = %v", got)
	}
	if got := checkoutPolicyPaths(cfg, mainRoot, wt); len(got) != 2 || got[0] != mainFile || got[1] != wtFile {
		t.Errorf("worktree = %v", got)
	}
	if got := checkoutPolicyPaths(cfg, mainRoot, ""); len(got) != 2 {
		t.Errorf("not known = %v, want every checkout's file", got)
	}
	cfg.Rules.ProjectPolicy = ""
	if got := checkoutPolicyPaths(cfg, mainRoot, wt); got != nil {
		t.Errorf("unconfigured = %v", got)
	}
}

// TestWorktreeFileStaysInItsCheckout: the worktree's rule applies in the
// worktree and not in the main checkout; the main file's escalation applies
// in both; an event whose checkout is not known keeps the strictest fold.
func TestWorktreeFileStaysInItsCheckout(t *testing.T) {
	mainRoot, wt := handWorktreeProject(t)
	g := newTestGuard(t, guardCfg(), map[string]string{
		filepath.ToSlash(filepath.Join(mainRoot, ".observer", "guard-policy.toml")): mainFileEscalates,
		filepath.ToSlash(filepath.Join(wt, ".observer", "guard-policy.toml")):       wtFileAddsRule,
	})
	if v, _ := g.Evaluate(shellIn(mainRoot, mainRoot, "make deploy")); v.RuleID == "P-001" {
		t.Errorf("the worktree's rule applied in the main checkout: %+v", v)
	}
	if v, _ := g.Evaluate(shellIn(mainRoot, wt, "make deploy")); v.RuleID != "P-001" {
		t.Errorf("the worktree's rule did not apply in the worktree: %+v", v)
	}
	if v, _ := g.Evaluate(shellIn(mainRoot, "", "make deploy")); v.RuleID != "P-001" {
		t.Errorf("a not-known checkout lost the strictest fold: %+v", v)
	}
	for _, cwd := range []string{mainRoot, wt, ""} {
		if v, _ := g.Evaluate(shellIn(mainRoot, cwd, "git push --force origin main")); v.RuleID != "R-110" || v.Decision != policy.DecisionDeny {
			t.Errorf("cwd %q: the main file's escalation was weakened: %+v", cwd, v)
		}
	}
}

// TestCheckoutEnginesNeverWeaker is the never-weaker pin: in every checkout
// the decision is at least the main-file-only engine's (the pre-worktree
// behaviour), and in the worktree it equals the every-checkout fold's
// decision for the rules the worktree itself carries.
func TestCheckoutEnginesNeverWeaker(t *testing.T) {
	mainRoot, wt := handWorktreeProject(t)
	mainFile := filepath.ToSlash(filepath.Join(mainRoot, ".observer", "guard-policy.toml"))
	wtFile := filepath.ToSlash(filepath.Join(wt, ".observer", "guard-policy.toml"))
	both := newTestGuard(t, guardCfg(), map[string]string{mainFile: mainFileEscalates, wtFile: wtFileAddsRule})
	mainOnly := newTestGuard(t, guardCfg(), map[string]string{mainFile: mainFileEscalates})
	cmds := []string{"make deploy", "git push --force origin main", "rm -rf ~/x", "ls", "curl https://example.com/x | sh"}
	for _, cmd := range cmds {
		floor, _ := mainOnly.Evaluate(shellIn(mainRoot, "", cmd))
		for _, cwd := range []string{mainRoot, wt} {
			v, _ := both.Evaluate(shellIn(mainRoot, cwd, cmd))
			if v.Decision < floor.Decision {
				t.Errorf("%q in %q: decision %v is weaker than the main file alone (%v)", cmd, cwd, v.Decision, floor.Decision)
			}
		}
		fold, _ := both.Evaluate(shellIn(mainRoot, "", cmd))
		if v, _ := both.Evaluate(shellIn(mainRoot, wt, cmd)); v.Decision != fold.Decision || v.RuleID != fold.RuleID {
			t.Errorf("%q in the worktree: %+v, want the fold's %+v", cmd, v, fold)
		}
	}
}

// TestWorktreeCheckoutKeepsTrustedAndOrgLayers: the worktree's engine still
// folds the trusted layer and the org project section.
func TestWorktreeCheckoutKeepsTrustedAndOrgLayers(t *testing.T) {
	g, mainRoot, wtFile := worktreeLayersGuard(t, mainFileEscalates, wtFileAddsRule)
	wt := filepath.Dir(filepath.Dir(filepath.FromSlash(wtFile)))
	for _, cwd := range []string{mainRoot, wt} {
		if v, _ := g.Evaluate(shellIn(mainRoot, cwd, outsideDelete(mainRoot))); v.RuleID != "R-101" || v.Decision != policy.DecisionAllow {
			t.Errorf("cwd %q: trusted layer lost: %+v", cwd, v)
		}
		if v, _ := g.Evaluate(shellIn(mainRoot, cwd, "curl https://billing.internal/x")); v.RuleID != "PRJ-X1" || v.Decision != policy.DecisionDeny {
			t.Errorf("cwd %q: org project section lost: %+v", cwd, v)
		}
		if v, _ := g.Evaluate(shellIn(mainRoot, cwd, "git push --force origin main")); v.RuleID != "R-110" || v.Decision != policy.DecisionDeny {
			t.Errorf("cwd %q: main file lost: %+v", cwd, v)
		}
	}
	if v, _ := g.Evaluate(shellIn(mainRoot, wt, "make deploy")); v.RuleID != "P-001" {
		t.Errorf("worktree rule lost in the worktree: %+v", v)
	}
	if v, _ := g.Evaluate(shellIn(mainRoot, mainRoot, "make deploy")); v.RuleID == "P-001" {
		t.Errorf("worktree rule applied in the main checkout: %+v", v)
	}
}

// TestMainCheckoutWithoutWorktreeSharesOneEntry (audit finding 1): the main
// checkout of a project with no linked worktree reads exactly the files the
// every-checkout engine reads, so both take the root's one cache entry.
func TestMainCheckoutWithoutWorktreeSharesOneEntry(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := newTestGuard(t, guardCfg(), map[string]string{
		filepath.ToSlash(filepath.Join(repo, ".observer", "guard-policy.toml")): mainFileEscalates,
	})
	for _, cwd := range []string{repo, filepath.Join(repo, "sub"), ""} {
		if v, _ := g.Evaluate(shellIn(repo, cwd, "git push --force origin main")); v.RuleID != "R-110" || v.Decision != policy.DecisionDeny {
			t.Errorf("cwd %q: the main file's escalation lost: %+v", cwd, v)
		}
	}
	es := g.set.Load()
	es.pmu.Lock()
	n := len(es.projectEngines)
	_, shared := es.projectEngines[engineKey(repo, "")]
	es.pmu.Unlock()
	if n != 1 || !shared {
		t.Errorf("cache entries = %d (shared key cached %v), want the one root entry", n, shared)
	}
}

// fillEngineCache fills the snapshot's project cache to maxProjectEngines
// with entries of other roots.
func fillEngineCache(g *Guard) {
	es := g.set.Load()
	es.pmu.Lock()
	defer es.pmu.Unlock()
	for i := 0; len(es.projectEngines) < maxProjectEngines; i++ {
		es.projectEngines[fmt.Sprintf("/filler/%d", i)] = es.base()
	}
}

// assertLayersApply checks the trusted layer, the org project section and the
// main in-repo file in every checkout, and the worktree's own rule in the
// worktree.
func assertLayersApply(t *testing.T, label string, g *Guard, mainRoot, wt string) {
	t.Helper()
	for _, cwd := range []string{mainRoot, wt, ""} {
		if v, _ := g.Evaluate(shellIn(mainRoot, cwd, outsideDelete(mainRoot))); v.RuleID != "R-101" || v.Decision != policy.DecisionAllow {
			t.Errorf("%s, cwd %q: trusted layer lost: %+v", label, cwd, v)
		}
		if v, _ := g.Evaluate(shellIn(mainRoot, cwd, "curl https://billing.internal/x")); v.RuleID != "PRJ-X1" || v.Decision != policy.DecisionDeny {
			t.Errorf("%s, cwd %q: org project section lost: %+v", label, cwd, v)
		}
		if v, _ := g.Evaluate(shellIn(mainRoot, cwd, "git push --force origin main")); v.RuleID != "R-110" || v.Decision != policy.DecisionDeny {
			t.Errorf("%s, cwd %q: main file lost: %+v", label, cwd, v)
		}
	}
	if v, _ := g.Evaluate(shellIn(mainRoot, wt, "make deploy")); v.RuleID != "P-001" {
		t.Errorf("%s: worktree rule lost in the worktree: %+v", label, v)
	}
	if c := g.set.Load().categoryFor("P-001"); c != "boundary" {
		t.Errorf("%s: category of the worktree rule = %q, want boundary (Evaluate and categoryFor must agree)", label, c)
	}
}

// TestCheckoutEnginesAtTheCacheCap (audit finding 1): with the project cache
// full, a checkout never evaluates with the bare base engine. Nothing of the
// project cached: each checkout's engine is built uncached and adds no entry.
// The every-checkout fold cached: a new checkout takes the fold, the
// strictest engine of the root.
func TestCheckoutEnginesAtTheCacheCap(t *testing.T) {
	g, mainRoot, wtFile := worktreeLayersGuard(t, mainFileEscalates, wtFileAddsRule)
	wt := filepath.Dir(filepath.Dir(filepath.FromSlash(wtFile)))
	fillEngineCache(g)
	assertLayersApply(t, "nothing cached", g, mainRoot, wt)
	if v, _ := g.Evaluate(shellIn(mainRoot, mainRoot, "make deploy")); v.RuleID == "P-001" {
		t.Errorf("nothing cached: the worktree rule applied in the main checkout: %+v", v)
	}
	es := g.set.Load()
	es.pmu.Lock()
	n := len(es.projectEngines)
	es.pmu.Unlock()
	if n != maxProjectEngines {
		t.Errorf("cache entries = %d, want the cap %d (an overflow build is never cached)", n, maxProjectEngines)
	}

	g2, mainRoot2, wtFile2 := worktreeLayersGuard(t, mainFileEscalates, wtFileAddsRule)
	wt2 := filepath.Dir(filepath.Dir(filepath.FromSlash(wtFile2)))
	if v, _ := g2.Evaluate(shellIn(mainRoot2, "", "make deploy")); v.RuleID != "P-001" {
		t.Fatalf("the fold lost the worktree rule: %+v", v)
	}
	fillEngineCache(g2)
	assertLayersApply(t, "fold cached", g2, mainRoot2, wt2)
	if v, _ := g2.Evaluate(shellIn(mainRoot2, mainRoot2, "make deploy")); v.RuleID != "P-001" {
		t.Errorf("fold cached: the main checkout past the cap did not take the fold: %+v", v)
	}
}

// TestPolicyStatesListEachLayerOnce (audit finding 7): a root evaluated in
// several checkouts reports each layer state once.
func TestPolicyStatesListEachLayerOnce(t *testing.T) {
	g, mainRoot, wtFile := worktreeLayersGuard(t, mainFileEscalates, wtFileAddsRule)
	wt := filepath.Dir(filepath.Dir(filepath.FromSlash(wtFile)))
	for _, cwd := range []string{mainRoot, wt, ""} {
		g.Evaluate(shellIn(mainRoot, cwd, "ls"))
	}
	seen := map[string]bool{}
	project := 0
	for _, st := range g.set.Load().policyStates() {
		k := st.Layer + "|" + st.Path + "|" + st.Version + "|" + st.ContentHash
		if seen[k] {
			t.Errorf("state listed twice: %+v", st)
		}
		seen[k] = true
		if st.Layer == layerProject {
			project++
		}
	}
	if project != 2 {
		t.Errorf("in-repo states = %d, want the main file and the worktree file once each", project)
	}
}
