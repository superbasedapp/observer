package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// handWorktreeProject lays out a main checkout with one linked worktree in
// git's own layout (hand-made, no git binary) and returns both top levels.
func handWorktreeProject(t *testing.T) (mainRoot, wt string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mainRoot, wt = filepath.Join(base, "main"), filepath.Join(base, "wt")
	admin := filepath.Join(mainRoot, ".git", "worktrees", "wt")
	w(filepath.Join(mainRoot, ".git", "HEAD"), "ref: refs/heads/main\n")
	w(filepath.Join(admin, "HEAD"), "ref: refs/heads/wt\n")
	w(filepath.Join(admin, "commondir"), "../..\n")
	w(filepath.Join(admin, "gitdir"), "../../../../wt/.git\n")
	w(filepath.Join(wt, ".git"), "gitdir: ../main/.git/worktrees/wt\n")
	return mainRoot, wt
}

// TestProjectPolicyPaths: the main checkout's file, then each linked
// worktree's; an ordinary repository and an unconfigured key are unchanged.
func TestProjectPolicyPaths(t *testing.T) {
	mainRoot, wt := handWorktreeProject(t)
	cfg := guardCfg()
	got := ProjectPolicyPaths(cfg, mainRoot)
	want := []string{
		filepath.Join(mainRoot, ".observer", "guard-policy.toml"),
		filepath.Join(wt, ".observer", "guard-policy.toml"),
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("ProjectPolicyPaths = %v, want %v", got, want)
	}
	plain := t.TempDir()
	if got := ProjectPolicyPaths(cfg, plain); len(got) != 1 || got[0] != ProjectPolicyPath(cfg, plain) {
		t.Errorf("plain repository = %v", got)
	}
	cfg.Rules.ProjectPolicy = ""
	if got := ProjectPolicyPaths(cfg, mainRoot); got != nil {
		t.Errorf("unconfigured = %v", got)
	}
	// The trusted file stays keyed on the project root.
	tcfg := guardCfg()
	tcfg.Rules.TrustedProjectDir = "~/.observer/guard-projects"
	if a, b := TrustedProjectPolicyPath(tcfg, "/home/u", mainRoot), TrustedProjectPolicyPath(tcfg, "/home/u", wt); a == "" || a == b {
		t.Errorf("trusted paths %q and %q: want one per root", a, b)
	}
}

// TestWorktreePolicyFileApplies (lane shr-worktree2, PT-39): a worktree's
// own in-repo policy file applies to the project's events with the main
// checkout's; the strictest stance wins whichever checkout relaxes.
func TestWorktreePolicyFileApplies(t *testing.T) {
	mainRoot, wt := handWorktreeProject(t)
	mainFile := filepath.ToSlash(filepath.Join(mainRoot, ".observer", "guard-policy.toml"))
	wtFile := filepath.ToSlash(filepath.Join(wt, ".observer", "guard-policy.toml"))
	g := newTestGuard(t, guardCfg(), map[string]string{
		mainFile: `
[[override]]
rule = "R-110"
enforce = true
`,
		wtFile: `
[[rule]]
id = "P-001"
category = "boundary"
severity = "warn"
decision = "flag"
applies_to = ["shell_exec"]
match.command_base = "make"

[[override]]
rule = "R-110"
decision = "flag"
`,
	})
	v, _ := g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "make deploy", ProjectRoot: mainRoot})
	if v.RuleID != "P-001" {
		t.Errorf("the worktree's rule did not apply: %+v", v)
	}
	v, _ = g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "git push --force origin main", ProjectRoot: mainRoot})
	if v.RuleID != "R-110" || v.Decision != policy.DecisionDeny {
		t.Errorf("the main checkout's escalation was weakened: %+v", v)
	}
	if n := countProjectStates(g); n != 2 {
		t.Errorf("project states = %d, want 2 (both files)", n)
	}
}

// TestWorktreePolicyFileIdenticalCountsOnce: a worktree holding the same
// file as the main checkout loads one layer.
func TestWorktreePolicyFileIdenticalCountsOnce(t *testing.T) {
	mainRoot, wt := handWorktreeProject(t)
	body := "[[override]]\nrule = \"R-110\"\nenforce = true\n"
	g := newTestGuard(t, guardCfg(), map[string]string{
		filepath.ToSlash(filepath.Join(mainRoot, ".observer", "guard-policy.toml")): body,
		filepath.ToSlash(filepath.Join(wt, ".observer", "guard-policy.toml")):       body,
	})
	v, _ := g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "git push --force origin main", ProjectRoot: mainRoot})
	if v.RuleID != "R-110" || v.Decision != policy.DecisionDeny {
		t.Errorf("escalation = %+v", v)
	}
	if n := countProjectStates(g); n != 1 {
		t.Errorf("project states = %d, want 1", n)
	}
	for _, issue := range g.LoadIssues() {
		t.Errorf("unexpected load issue: %s", issue)
	}
}

func countProjectStates(g *Guard) int {
	n := 0
	for _, s := range g.PolicyStates() {
		if s.Layer == layerProject {
			n++
		}
	}
	return n
}

// worktreeLayersGuard builds a guard over a hand-made worktree project whose
// main checkout matched org project X, with a trusted per-project file and
// the two in-repo files given (empty skips one).
func worktreeLayersGuard(t *testing.T, mainBody, wtBody string) (g *Guard, mainRoot, wtFile string) {
	t.Helper()
	mainRoot, wt := handWorktreeProject(t)
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": `
[[rule]]
id = "PRJ-X1"
category = "exfil"
severity = "high"
decision = "deny"
applies_to = ["shell_exec"]
match.command_regex = '(?i)\bcurl\b.*\bbilling\.internal\b'
enforce = true
`})
	f.match(mainRoot, "X")
	cfg := guardCfgOrg()
	cfg.Rules.TrustedProjectDir = trustedProjectDir
	files := f.files
	files[trustedKey(cfg, mainRoot)] = "[[override]]\nrule = \"R-101\"\ndecision = \"allow\"\n"
	wtFile = filepath.ToSlash(filepath.Join(wt, ".observer", "guard-policy.toml"))
	if mainBody != "" {
		files[filepath.ToSlash(filepath.Join(mainRoot, ".observer", "guard-policy.toml"))] = mainBody
	}
	if wtBody != "" {
		files[wtFile] = wtBody
	}
	g, err := New(Options{Config: cfg, Home: "/home/u", KnownProjectRoots: []string{mainRoot}, ReadFile: fsMap(files)})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	return g, mainRoot, wtFile
}

// TestWorktreePolicyFileCannotDropTheProjectPolicy (audit finding 1, lane
// shr-worktree2): a worktree's in-repo file that names a rule no layer
// loads, or that cannot fold with the main checkout's file, never costs the
// project its own policy. The main file's escalation, the trusted layer and
// the org project section stay in force, and the issue names the file.
func TestWorktreePolicyFileCannotDropTheProjectPolicy(t *testing.T) {
	const mainEscalates = "[[rule]]\nid = \"P-001\"\ncategory = \"boundary\"\nseverity = \"warn\"\ndecision = \"flag\"\napplies_to = [\"shell_exec\"]\nmatch.command_base = \"make\"\n\n[[override]]\nrule = \"R-110\"\nenforce = true\n"
	cases := []struct {
		name, mainBody, wtBody string
		issue                  []string // substrings one load issue must carry
		wantStates             int
	}{
		{
			name:     "worktree file names an unknown rule",
			mainBody: mainEscalates,
			wtBody:   "[[override]]\nrule = \"R-999\"\ndecision = \"deny\"\n",
			issue:    []string{"guard-policy.toml", "R-999", "not loaded"}, wantStates: 2,
		},
		{
			name:     "main file names an unknown rule too",
			mainBody: mainEscalates + "\n[[override]]\nrule = \"R-998\"\ndecision = \"deny\"\n",
			wtBody:   "[[override]]\nrule = \"R-999\"\ndecision = \"deny\"\n",
			issue:    []string{"R-998", "not loaded"}, wantStates: 2,
		},
		{
			name:     "worktree file cannot fold with the main file",
			mainBody: mainEscalates,
			wtBody:   "[[rule]]\nid = \"P-001\"\ncategory = \"exfil\"\nseverity = \"high\"\ndecision = \"deny\"\napplies_to = [\"shell_exec\"]\nmatch.command_base = \"make\"\n",
			issue:    []string{"linked worktree policy files for", "P-001"}, wantStates: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, mainRoot, wtFile := worktreeLayersGuard(t, tc.mainBody, tc.wtBody)
			if v, _ := g.Evaluate(shell(mainRoot, "git push --force origin main")); v.RuleID != "R-110" || v.Decision != policy.DecisionDeny {
				t.Errorf("main file's escalation lost: %+v (issues %v)", v, g.LoadIssues())
			}
			if v, _ := g.Evaluate(shell(mainRoot, "make deploy")); v.RuleID != "P-001" || v.Decision != policy.DecisionFlag {
				t.Errorf("main file's rule lost: %+v", v)
			}
			if v, _ := g.Evaluate(shell(mainRoot, outsideDelete(mainRoot))); v.RuleID != "R-101" || v.Decision != policy.DecisionAllow {
				t.Errorf("trusted layer lost: %+v", v)
			}
			if v, _ := g.Evaluate(shell(mainRoot, "curl https://billing.internal/x")); v.RuleID != "PRJ-X1" || v.Decision != policy.DecisionDeny {
				t.Errorf("org project section lost: %+v", v)
			}
			if tc.name == "worktree file names an unknown rule" && !hasIssue(g.LoadIssues(), filepath.FromSlash(wtFile), "R-999") {
				t.Errorf("no issue names the worktree file and the rule: %v", g.LoadIssues())
			}
			if !hasIssue(g.LoadIssues(), tc.issue...) {
				t.Errorf("no issue with %q: %v", tc.issue, g.LoadIssues())
			}
			for _, is := range g.LoadIssues() {
				if strings.Contains(is, "project policy for") {
					t.Errorf("the project policy was dropped: %s", is)
				}
			}
			if n := countProjectStates(g); n != tc.wantStates {
				t.Errorf("project states = %d, want %d", n, tc.wantStates)
			}
		})
	}
}
