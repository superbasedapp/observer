package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// trustedProjectDir is where the fsMap-backed trusted-layer tests place
// the daemon-local per-project files ([guard.rules] trusted_project_dir).
const trustedProjectDir = "~/.observer/guard-project-policies"

// trustedCfg is guardCfg with the trusted per-project dir configured
// (the config.Default shape once this arc lands).
func trustedCfg() config.GuardConfig {
	cfg := guardCfg()
	cfg.Rules.TrustedProjectDir = trustedProjectDir
	return cfg
}

// trustedKey returns the fsMap key for a root's trusted per-project file,
// computed through the SAME resolver the loader uses so the load side and
// the test always agree on the path. ToSlash keeps the key platform-stable
// (fsMap normalizes separators, but the map literal is authored in "/").
func trustedKey(cfg config.GuardConfig, root string) string {
	return filepath.ToSlash(TrustedProjectPolicyPath(cfg, "/home/u", root))
}

// TestTrustedProject_WeakeningApplies pins the core new capability: a
// trusted per-project override may RELAX a built-in (unlike the in-repo
// project layer), scoped to that root only.
func TestTrustedProject_WeakeningApplies(t *testing.T) {
	t.Parallel()
	cfg := trustedCfg()
	g := newTestGuardCfg(t, cfg, map[string]string{
		trustedKey(cfg, "/home/u/proj"): "[[override]]\nrule = \"R-101\"\ndecision = \"allow\"\n",
	})
	if issues := g.LoadIssues(); len(issues) != 0 {
		t.Fatalf("unexpected load issues: %v", issues)
	}

	// In the trusted project: R-101 relaxed to allow.
	v, _ := g.Evaluate(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "rm -rf ~/x", ProjectRoot: "/home/u/proj",
	})
	if v.RuleID != "R-101" || v.Decision != policy.DecisionAllow {
		t.Errorf("trusted-weakened verdict = %+v, want R-101/allow", v)
	}

	// Another project (no trusted file): R-101 still flags — the
	// weakening is scoped to its root.
	v, _ = g.Evaluate(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "rm -rf ~/x", ProjectRoot: "/home/u/other",
	})
	if v.RuleID != "R-101" || v.Decision != policy.DecisionFlag {
		t.Errorf("other-project verdict = %+v, want R-101/flag (weakening must not leak)", v)
	}
}

// TestTrustedProject_InRepoStillEscalateOnly pins that adding the trusted
// layer did NOT weaken the in-repo project layer: an in-repo relaxation is
// still dropped with a recorded issue (§4.6 one-way trust holds).
func TestTrustedProject_InRepoStillEscalateOnly(t *testing.T) {
	t.Parallel()
	cfg := trustedCfg()
	g := newTestGuardCfg(t, cfg, map[string]string{
		// In-repo file (agent-writable) tries to relax R-101 — must drop.
		"/home/u/proj/.observer/guard-policy.toml": "[[override]]\nrule = \"R-101\"\ndecision = \"allow\"\n",
	})
	v, _ := g.Evaluate(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "rm -rf ~/x", ProjectRoot: "/home/u/proj",
	})
	if v.RuleID != "R-101" || v.Decision != policy.DecisionFlag {
		t.Errorf("in-repo relaxation was applied: %+v (must be dropped per §4.6)", v)
	}
	found := false
	for _, issue := range g.LoadIssues() {
		if strings.Contains(issue, "R-101") && strings.Contains(issue, "relax") {
			found = true
		}
	}
	if !found {
		t.Errorf("dropped in-repo relaxation not recorded: %v", g.LoadIssues())
	}
}

// TestTrustedProject_OrgFloorBlocksRelaxation pins the hard limit: the
// trusted layer weakens built-ins but can NEVER relax below the org floor.
func TestTrustedProject_OrgFloorBlocksRelaxation(t *testing.T) {
	t.Parallel()
	orgTOML := "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\n"
	envelope, pin := signedEnvelope(t, 5, orgTOML)

	cfg := guardCfgOrg()
	cfg.Rules.TrustedProjectDir = trustedProjectDir
	g, err := New(Options{
		Config:            cfg,
		Home:              "/home/u",
		KnownProjectRoots: []string{"/home/u/proj"},
		ReadFile: fsMap(map[string]string{
			orgBundlePath:                   envelope,
			trustedKey(cfg, "/home/u/proj"): "[[override]]\nrule = \"R-110\"\ndecision = \"allow\"\n",
		}),
		OrgKeyPinHash: pin,
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}

	// R-110 is org-floored at deny; the trusted allow attempt is dropped.
	v, _ := g.Evaluate(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "git push --force origin main", ProjectRoot: "/home/u/proj",
	})
	if v.RuleID != "R-110" || v.Decision != policy.DecisionDeny {
		t.Errorf("floored verdict = %+v, want R-110/deny (org floor holds)", v)
	}
	found := false
	for _, issue := range g.LoadIssues() {
		if strings.Contains(issue, "R-110") && strings.Contains(issue, "floor") {
			found = true
		}
	}
	if !found {
		t.Errorf("dropped trusted relaxation-below-floor not recorded: %v", g.LoadIssues())
	}
}

// TestTrustedProject_DisableUnions pins that a trusted file's top-level
// `disable` list unions into the per-project engine's Disabled set, scoped
// to that root.
func TestTrustedProject_DisableUnions(t *testing.T) {
	t.Parallel()
	cfg := trustedCfg()
	g := newTestGuardCfg(t, cfg, map[string]string{
		trustedKey(cfg, "/home/u/proj"): "disable = [\"R-101\"]\n",
	})
	if issues := g.LoadIssues(); len(issues) != 0 {
		t.Fatalf("unexpected load issues: %v", issues)
	}

	// R-101 removed for the trusted project → no longer fires.
	v, _ := g.Evaluate(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "rm -rf ~/x", ProjectRoot: "/home/u/proj",
	})
	if v.RuleID == "R-101" {
		t.Errorf("R-101 still fired after trusted disable: %+v", v)
	}

	// Other project: R-101 still active (disable scoped to its root).
	v, _ = g.Evaluate(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "rm -rf ~/x", ProjectRoot: "/home/u/other",
	})
	if v.RuleID != "R-101" {
		t.Errorf("other-project verdict = %+v, want R-101 (disable must not leak)", v)
	}
}

// TestTrustedProject_DisableCannotBypassOrgFloor pins the security limit
// on the disable path: a trusted `disable` of an ORG-FLOORED rule is
// dropped (the rule stays in the per-project engine) with a recorded
// issue, at BOTH the runtime build and the dashboard LintTrustedProject
// gate. Disabling an org-floored rule would otherwise remove it entirely
// (policy.New only exempts protected budget rows) and silently defeat the
// org floor.
func TestTrustedProject_DisableCannotBypassOrgFloor(t *testing.T) {
	t.Parallel()
	orgTOML := "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\n"
	envelope, pin := signedEnvelope(t, 5, orgTOML)

	// (a) Runtime per-project engine: the floored rule survives the
	// trusted disable, and the drop is recorded.
	cfg := guardCfgOrg()
	cfg.Rules.TrustedProjectDir = trustedProjectDir
	g, err := New(Options{
		Config:            cfg,
		Home:              "/home/u",
		KnownProjectRoots: []string{"/home/u/proj"},
		ReadFile: fsMap(map[string]string{
			orgBundlePath:                   envelope,
			trustedKey(cfg, "/home/u/proj"): "disable = [\"R-110\"]\n",
		}),
		OrgKeyPinHash: pin,
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	v, _ := g.Evaluate(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "git push --force origin main", ProjectRoot: "/home/u/proj",
	})
	if v.RuleID != "R-110" || v.Decision != policy.DecisionDeny {
		t.Errorf("floored rule verdict = %+v, want R-110/deny (trusted disable must not remove it)", v)
	}
	found := false
	for _, issue := range g.LoadIssues() {
		if strings.Contains(issue, "R-110") && strings.Contains(issue, "disable") {
			found = true
		}
	}
	if !found {
		t.Errorf("dropped trusted disable-of-floored not recorded: %v", g.LoadIssues())
	}

	// (b) Dashboard gate: LintTrustedProject (org bundle read from real
	// disk) surfaces the same drop as a problem.
	tdir := t.TempDir()
	orgPath := filepath.Join(tdir, "org-policy-bundle.json")
	if werr := os.WriteFile(orgPath, []byte(envelope), 0o600); werr != nil {
		t.Fatalf("write org bundle: %v", werr)
	}
	lintCfg := guardCfg()
	lintCfg.Rules.OrgBundle = filepath.ToSlash(orgPath)
	problems := LintTrustedProject(lintCfg, "/home/u", []byte("disable = [\"R-110\"]\n"))
	floorProblem := false
	for _, p := range problems {
		if strings.Contains(p, "R-110") && strings.Contains(p, "disable") {
			floorProblem = true
		}
	}
	if !floorProblem {
		t.Errorf("LintTrustedProject problems = %v, want a floored-disable problem naming R-110", problems)
	}
}

// TestTrustedProject_DisableKeyLayerScoped pins the grammar split: a
// top-level `disable` key is honored ONLY for the trusted-project layer;
// for the user + in-repo-project layers it stays an unknown-key error.
// The ORG layer is the exception on the other side (GUARD-FWD-1): a
// signed bundle carrying the key loads with `disable` IGNORED and noted,
// never rejected — rejecting would strand the node on a stale bundle.
func TestTrustedProject_DisableKeyLayerScoped(t *testing.T) {
	t.Parallel()
	body := "disable = [\"R-101\"]\n"

	for _, layer := range []string{layerUser, layerProject} {
		if _, err := parsePolicyFile([]byte(body), layer); err == nil {
			t.Errorf("layer %q: disable key accepted, want unknown-key error", layer)
		} else if !strings.Contains(err.Error(), "disable") {
			t.Errorf("layer %q: error %q, want it to name the disable key", layer, err)
		}
	}
	if opf, err := parsePolicyFile([]byte(body), layerOrg); err != nil {
		t.Errorf("org: disable key rejected (%v), want it ignored + noted (GUARD-FWD-1)", err)
	} else if len(opf.disable) != 0 || len(opf.notes) != 1 || opf.notes[0] != "disable" {
		t.Errorf("org: disable = %v, notes = %v; want no disable list and the one note \"disable\"", opf.disable, opf.notes)
	}

	pf, err := parsePolicyFile([]byte(body), layerTrustedProject)
	if err != nil {
		t.Fatalf("trusted_project: parse error on a legal disable key: %v", err)
	}
	if len(pf.disable) != 1 || pf.disable[0] != "R-101" {
		t.Errorf("trusted disable = %v, want [R-101]", pf.disable)
	}

	// The dashboard-facing Lint agrees: a disable key lints dirty for the
	// user layer, clean for the trusted layer.
	if got := Lint([]byte(body), layerUser); len(got) == 0 {
		t.Error("user-layer disable key linted clean, want a problem")
	}
	if got := Lint([]byte(body), layerTrustedProject); len(got) != 0 {
		t.Errorf("trusted-layer disable key linted dirty: %v", got)
	}
}

// --- F1: R-160/R-161 as a protected INTEGRITY FLOOR --------------------

// integrityEvent returns the config-change write event that triggers the
// given integrity rule: R-160 on a ~/.observer write, R-161 on an in-repo
// project guard-policy write. Both are scoped to /home/u/proj so the
// trusted per-project engine (which carries the disable/override under
// test) is the one selected.
func integrityEvent(ruleID string) policy.Event {
	target := "/home/u/.observer/guard-policy.toml" // R-160 (user-level observer config)
	if ruleID == "R-161" {
		target = "/home/u/proj/.observer/guard-policy.toml" // in-repo project policy
	}
	return policy.Event{
		Kind: policy.KindConfigChange, ActionType: "write_file",
		Target: target, ProjectRoot: "/home/u/proj",
	}
}

func hasIssue(issues []string, must ...string) bool {
	for _, is := range issues {
		ok := true
		for _, m := range must {
			if !strings.Contains(is, m) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// TestIntegrityRule_TrustedDisableDropped pins F1(b): a trusted-project
// `disable = ["R-160"|"R-161"]` — with NO org bundle in scope — is DROPPED
// (the integrity rule still evaluates) with a recorded issue, and the
// dashboard save-gate LintTrustedProject flags it. R-160/R-161 are the
// guard's own tamper-evidence; disabling R-160 for one project would let
// an agent write ~/.observer/** freely.
func TestIntegrityRule_TrustedDisableDropped(t *testing.T) {
	t.Parallel()
	for _, rule := range []string{"R-160", "R-161"} {
		rule := rule
		t.Run(rule, func(t *testing.T) {
			t.Parallel()
			cfg := trustedCfg()
			g := newTestGuardCfg(t, cfg, map[string]string{
				trustedKey(cfg, "/home/u/proj"): "disable = [\"" + rule + "\"]\n",
			})
			v, _ := g.Evaluate(integrityEvent(rule))
			if v.RuleID != rule {
				t.Errorf("verdict = %+v, want %s to still fire (integrity disable must be dropped)", v, rule)
			}
			if !hasIssue(g.LoadIssues(), rule, "integrity") {
				t.Errorf("integrity-disable drop not recorded: %v", g.LoadIssues())
			}
			// Dashboard save-gate: no org bundle, but the integrity floor is
			// intrinsic (not org-derived), so it is still flagged.
			problems := LintTrustedProject(guardCfg(), "/home/u", []byte("disable = [\""+rule+"\"]\n"))
			if !hasIssue(problems, rule, "integrity") {
				t.Errorf("LintTrustedProject problems = %v, want an integrity problem naming %s", problems, rule)
			}
		})
	}
}

// TestIntegrityRule_TrustedOverrideDropped pins F1(a): a trusted-project
// override that would RELAX an integrity rule (decision=allow) is dropped
// with a recorded issue; the rule keeps its built-in stance.
func TestIntegrityRule_TrustedOverrideDropped(t *testing.T) {
	t.Parallel()
	// R-160 built-in observe stance is flag; R-161's is flag — if the relax
	// wrongly applied, the verdict would be allow.
	for _, rule := range []string{"R-160", "R-161"} {
		rule := rule
		t.Run(rule, func(t *testing.T) {
			t.Parallel()
			cfg := trustedCfg()
			g := newTestGuardCfg(t, cfg, map[string]string{
				trustedKey(cfg, "/home/u/proj"): "[[override]]\nrule = \"" + rule + "\"\ndecision = \"allow\"\n",
			})
			v, _ := g.Evaluate(integrityEvent(rule))
			if v.RuleID != rule || v.Decision != policy.DecisionFlag {
				t.Errorf("verdict = %+v, want %s/flag (integrity relax must be dropped)", v, rule)
			}
			if !hasIssue(g.LoadIssues(), rule, "integrity") {
				t.Errorf("integrity-relax drop not recorded: %v", g.LoadIssues())
			}
		})
	}
}

// TestIntegrityRule_UserLayerBlocked pins F1's note that the USER layer
// also loses the ability to weaken/disable R-160/R-161: a config-level
// disable (Config.Disabled) is kept by the policy.New backstop, and a
// user-policy-file override relaxation is dropped by the merge layer.
func TestIntegrityRule_UserLayerBlocked(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Rules.Disable = []string{"R-160", "R-161"} // config-level disable (backstop keeps them)
	// User policy file (base layer) tries to relax both to allow.
	userTOML := "[[override]]\nrule = \"R-160\"\ndecision = \"allow\"\n" +
		"[[override]]\nrule = \"R-161\"\ndecision = \"allow\"\n"
	g := newTestGuardCfg(t, cfg, map[string]string{
		"/home/u/.observer/guard-policy.toml": userTOML,
	})
	for _, rule := range []string{"R-160", "R-161"} {
		v, _ := g.Evaluate(integrityEvent(rule))
		if v.RuleID != rule || v.Decision != policy.DecisionFlag {
			t.Errorf("user-layer %s verdict = %+v, want %s/flag (disable+relax must be blocked)", rule, v, rule)
		}
		if !hasIssue(g.LoadIssues(), rule, "integrity") {
			t.Errorf("user-layer integrity drop not recorded for %s: %v", rule, g.LoadIssues())
		}
	}
}

// TestIntegrityRule_ConfigDisableBackstop pins that a config-level
// [guard.rules] disable of R-160 does NOT remove it — the policy.New
// disable-filter backstop keeps the row even with no policy files present.
func TestIntegrityRule_ConfigDisableBackstop(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Rules.Disable = []string{"R-160"}
	g := newTestGuardCfg(t, cfg, nil)
	v, _ := g.Evaluate(integrityEvent("R-160"))
	if v.RuleID != "R-160" {
		t.Errorf("verdict = %+v, want R-160 to survive config disable (policy.New backstop)", v)
	}
}

// TestIntegrityRule_EscalationApplies pins that ESCALATION is untouched: a
// trusted-project override raising R-161 flag->deny applies (only weakening
// is refused).
func TestIntegrityRule_EscalationApplies(t *testing.T) {
	t.Parallel()
	cfg := trustedCfg()
	g := newTestGuardCfg(t, cfg, map[string]string{
		trustedKey(cfg, "/home/u/proj"): "[[override]]\nrule = \"R-161\"\ndecision = \"deny\"\n",
	})
	if issues := g.LoadIssues(); len(issues) != 0 {
		t.Fatalf("unexpected load issues on a clean escalation: %v", issues)
	}
	v, _ := g.Evaluate(integrityEvent("R-161"))
	if v.RuleID != "R-161" || v.Decision != policy.DecisionDeny {
		t.Errorf("escalation verdict = %+v, want R-161/deny (escalation must apply)", v)
	}
}

// TestTrustedProjectPolicyPath_FullDigest pins F4: the trusted per-project
// filename is the FULL 64-hex-char sha256 digest, not a truncated prefix.
func TestTrustedProjectPolicyPath_FullDigest(t *testing.T) {
	t.Parallel()
	cfg := trustedCfg()
	p := TrustedProjectPolicyPath(cfg, "/home/u", "/home/u/proj")
	base := filepath.Base(filepath.ToSlash(p))
	name := strings.TrimSuffix(base, ".toml")
	if len(name) != 64 {
		t.Errorf("trusted filename hash length = %d (%q), want 64 hex chars", len(name), name)
	}
	for _, r := range name {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Errorf("trusted filename %q is not lowercase hex", name)
			break
		}
	}
}

// newTestGuardCfg is newTestGuard with a caller-supplied config (the
// trusted-layer tests need TrustedProjectDir set).
func newTestGuardCfg(t *testing.T, cfg config.GuardConfig, files map[string]string) *Guard {
	t.Helper()
	g, err := New(Options{
		Config:            cfg,
		Home:              "/home/u",
		KnownProjectRoots: []string{"/home/u/proj", "/home/u/other"},
		ReadFile:          fsMap(files),
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	return g
}
