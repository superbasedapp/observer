package guard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Paths the enforce-cap table writes its layers to (fsMap keys).
const (
	capUserPolicy    = "/home/u/.observer/guard-policy.toml"
	capInRepoProject = "/home/u/proj/.observer/guard-policy.toml"
)

// enforceCapLayers builds the files (and, for the org layer, the key pin)
// that put `body` on one policy layer.
func enforceCapLayers(t *testing.T, layer, body string, version int64) (files map[string]string, pin string) {
	t.Helper()
	cfg := trustedCfg()
	switch layer {
	case "org":
		env, p := signedEnvelope(t, version, body)
		return map[string]string{orgBundlePath: env}, p
	case "user":
		return map[string]string{capUserPolicy: body}, ""
	case "trusted_project":
		return map[string]string{trustedKey(cfg, "/home/u/proj"): body}, ""
	case "project":
		return map[string]string{capInRepoProject: body}, ""
	}
	t.Fatalf("unknown layer %q", layer)
	return nil, ""
}

func enforceCapGuard(t *testing.T, mode, promptMode, layer, body string, version int64) *Guard {
	t.Helper()
	cfg := promptCfg(mode, promptMode, nil)
	cfg.Rules.TrustedProjectDir = trustedCfg().Rules.TrustedProjectDir
	cfg.Rules.OrgBundle = guardCfgOrg().Rules.OrgBundle
	files, pin := enforceCapLayers(t, layer, body, version)
	g, err := New(Options{
		Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
		ReadFile: fsMap(files), OrgKeyPinHash: pin,
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	g.SetPromptReconsiderStore(newMemPromptStore().funcs())
	return g
}

// TestEnforceFalseCapsEveryRuleAtFlag pins Sol A2-06 (D-030): an explicit
// `enforce = false` caps a rule at FLAG on the tool seam as well as the
// prompt lanes, from every layer allowed to relax (org, user, trusted
// project), under both global modes. The agent-writable in-repo project
// layer may only escalate, so its `enforce = false` is dropped.
func TestEnforceFalseCapsEveryRuleAtFlag(t *testing.T) {
	t.Parallel()
	const toolCap = "[[override]]\nrule = \"R-101\"\nenforce = false\n"
	const promptCap = "[[override]]\nrule = \"R-172\"\nenforce = false\n"
	cases := []struct {
		layer, mode string
		wantTool    policy.Decision
		wantPrompt  policy.Decision
		wantOrgCap  bool
	}{
		{"org", "enforce", policy.DecisionFlag, policy.DecisionFlag, true},
		{"org", "observe", policy.DecisionFlag, policy.DecisionFlag, true},
		{"user", "enforce", policy.DecisionFlag, policy.DecisionFlag, false},
		{"user", "observe", policy.DecisionFlag, policy.DecisionFlag, false},
		{"trusted_project", "enforce", policy.DecisionFlag, policy.DecisionFlag, false},
		{"trusted_project", "observe", policy.DecisionFlag, policy.DecisionFlag, false},
		// Dropped: the uncapped decisions stand (R-101 denies in enforce
		// mode and flags in observe; the prompt lane asks once).
		{"project", "enforce", policy.DecisionDeny, policy.DecisionAsk, false},
		{"project", "observe", policy.DecisionFlag, policy.DecisionAsk, false},
	}
	for i, tc := range cases {
		t.Run(tc.layer+"/"+tc.mode, func(t *testing.T) {
			g := enforceCapGuard(t, tc.mode, "ask-once", tc.layer, toolCap, int64(300+2*i))
			v, gerr := g.Evaluate(policy.Event{
				Kind: policy.KindShellExec, ActionType: "run_command",
				Target: "rm -rf ~/projects", Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj",
			})
			if gerr != nil {
				t.Fatalf("Evaluate: %v", gerr)
			}
			if v.RuleID != "R-101" || v.Decision != tc.wantTool {
				t.Errorf("tool verdict = %s %s, want R-101 %s (issues %v)", v.RuleID, v.Decision, tc.wantTool, g.LoadIssues())
			}

			g = enforceCapGuard(t, tc.mode, "ask-once", tc.layer, promptCap, int64(301+2*i))
			secrets, pii, _ := g.BuildPromptFindings("push with " + fakeFinePAT + " please")
			pv := g.EvaluatePrompt(policy.Event{
				Kind: policy.KindUserPrompt, Tool: "claude-code", SessionID: "s-cap",
				Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj",
				Secrets: secrets, PIIFindings: pii,
			})
			if pv.Verdict.RuleID != "R-172" || pv.Verdict.Decision != tc.wantPrompt || pv.OrgCapped != tc.wantOrgCap {
				t.Errorf("prompt verdict = %s %s orgCapped=%v, want R-172 %s orgCapped=%v",
					pv.Verdict.RuleID, pv.Verdict.Decision, pv.OrgCapped, tc.wantPrompt, tc.wantOrgCap)
			}
		})
	}
}

// TestEnforceFalseBelowOrgCannotCapProtectedRules pins the two limits on a
// below-org cap: an org-floored rule and an integrity rule keep their
// decision, and the drop is reported as a load issue.
func TestEnforceFalseBelowOrgCannotCapProtectedRules(t *testing.T) {
	t.Parallel()
	t.Run("org-floored rule", func(t *testing.T) {
		env, pin := signedEnvelope(t, 400, "[[override]]\nrule = \"R-101\"\nenforce = true\n")
		cfg := guardCfgOrg()
		cfg.Mode = "observe"
		g, err := New(Options{
			Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
			ReadFile: fsMap(map[string]string{
				orgBundlePath: env,
				capUserPolicy: "[[override]]\nrule = \"R-101\"\nenforce = false\n",
			}),
			OrgKeyPinHash: pin,
		})
		if err != nil {
			t.Fatal(err)
		}
		v, _ := g.Evaluate(policy.Event{
			Kind: policy.KindShellExec, ActionType: "run_command",
			Target: "rm -rf ~/projects", Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj",
		})
		if v.Decision != policy.DecisionDeny {
			t.Errorf("decision = %s, want deny (the org enforces R-101)", v.Decision)
		}
		if !anyContains(g.LoadIssues(), "org-floored rule at flag") {
			t.Errorf("no load issue for the dropped cap: %v", g.LoadIssues())
		}
	})
	t.Run("integrity rule", func(t *testing.T) {
		cfg := guardCfg()
		cfg.Mode = "enforce"
		g := newTestGuard(t, cfg, map[string]string{
			capUserPolicy: "[[override]]\nrule = \"R-160\"\nenforce = false\n",
		})
		if !anyContains(g.LoadIssues(), "integrity rule and cannot be capped") {
			t.Errorf("no load issue for the dropped integrity cap: %v", g.LoadIssues())
		}
		if g.set.Load().base().RuleEnforceCapped("R-160") {
			t.Error("R-160 capped by a user layer")
		}
	})
}

// TestEnforceTrueClearsALowerCap pins the tri-state composition: a later
// explicit `enforce = true` (an escalation, allowed from any layer)
// clears an earlier cap.
func TestEnforceTrueClearsALowerCap(t *testing.T) {
	t.Parallel()
	env, pin := signedEnvelope(t, 410, "[[override]]\nrule = \"R-101\"\nenforce = false\n")
	cfg := guardCfgOrg()
	cfg.Mode = "observe"
	g, err := New(Options{
		Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
		ReadFile: fsMap(map[string]string{
			orgBundlePath: env,
			capUserPolicy: "[[override]]\nrule = \"R-101\"\nenforce = true\n",
		}),
		OrgKeyPinHash: pin,
	})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := g.Evaluate(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "rm -rf ~/projects", Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj",
	})
	if v.Decision != policy.DecisionDeny || v.EnforceCappedBy != "" {
		t.Errorf("verdict = %s cappedBy=%q, want deny uncapped", v.Decision, v.EnforceCappedBy)
	}
}

func anyContains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
