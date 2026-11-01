package guard

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestOrgPinnedDecisionFloorsPromptMode pins the guard-rules live audit
// fix (2026-10-15, F1): an organization rule that pins a prompt rule's
// decision is a FLOOR under the node's local [guard.prompt] mode. Before
// the fix an org deny resolved to the local ask-once default, so an
// identical resend went through on every tool. Each row sends the same
// prompt twice (10 s apart, past the retry floor) and checks both sends.
func TestOrgPinnedDecisionFloorsPromptMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		layer      string
		body       string
		localMode  string
		wantFirst  policy.Decision
		wantResend policy.Decision
	}{
		{
			"org deny+enforce over local ask-once blocks every send", "org",
			"[[override]]\nrule = \"R-172\"\ndecision = \"deny\"\nenforce = true\n", "ask-once",
			policy.DecisionDeny, policy.DecisionDeny,
		},
		{
			"org enforce only (catalog deny) over local ask-once blocks", "org",
			"[[override]]\nrule = \"R-172\"\nenforce = true\n", "ask-once",
			policy.DecisionDeny, policy.DecisionDeny,
		},
		{
			"org deny over local warn blocks", "org",
			"[[override]]\nrule = \"R-172\"\ndecision = \"deny\"\nenforce = true\n", "warn",
			policy.DecisionDeny, policy.DecisionDeny,
		},
		{
			"org deny over local redact blocks", "org",
			"[[override]]\nrule = \"R-172\"\ndecision = \"deny\"\nenforce = true\n", "redact",
			policy.DecisionDeny, policy.DecisionDeny,
		},
		{
			"org deny over local off blocks (off is a local mode too)", "org",
			"[[override]]\nrule = \"R-172\"\ndecision = \"deny\"\nenforce = true\n", "off",
			policy.DecisionDeny, policy.DecisionDeny,
		},
		{
			"overridable org deny floors at ask-once (developer may confirm)", "org",
			"[[override]]\nrule = \"R-172\"\ndecision = \"deny\"\nenforce = true\noverridable = true\n", "warn",
			policy.DecisionAsk, policy.DecisionFlag,
		},
		{
			"org enforce=false still caps at warn", "org",
			"[[override]]\nrule = \"R-172\"\nenforce = false\n", "block",
			policy.DecisionFlag, policy.DecisionFlag,
		},
		{
			"user deny sets no floor (local mode decides)", "user",
			"[[override]]\nrule = \"R-172\"\ndecision = \"deny\"\nenforce = true\n", "ask-once",
			policy.DecisionAsk, policy.DecisionFlag,
		},
		{
			"no override keeps the local ask-once default", "user",
			"", "ask-once",
			policy.DecisionAsk, policy.DecisionFlag,
		},
		{
			"local block stays block without an org rule", "user",
			"", "block",
			policy.DecisionDeny, policy.DecisionDeny,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := enforceCapGuard(t, "enforce", tc.localMode, tc.layer, tc.body, int64(700+i))
			secrets, pii, _ := g.BuildPromptFindings("push with " + fakeFinePAT + " please")
			now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
			ev := policy.Event{
				Kind: policy.KindUserPrompt, Tool: "claude-code", SessionID: "s-floor",
				Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj",
				Secrets: secrets, PIIFindings: pii, Now: now,
			}
			first := g.EvaluatePrompt(ev)
			if first.Verdict.RuleID != "R-172" || first.Verdict.Decision != tc.wantFirst {
				t.Fatalf("first send = %s %s, want R-172 %s (issues %v)",
					first.Verdict.RuleID, first.Verdict.Decision, tc.wantFirst, g.LoadIssues())
			}
			ev.Now = now.Add(10 * time.Second)
			resend := g.EvaluatePrompt(ev)
			if resend.Verdict.Decision != tc.wantResend {
				t.Fatalf("identical resend = %s (outcome %s), want %s",
					resend.Verdict.Decision, resend.Outcome, tc.wantResend)
			}
		})
	}
}

// TestPromptModeFloorTable walks promptDecisionFloor row by row.
func TestPromptModeFloorTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		v    policy.Verdict
		want PromptMode
	}{
		{"org deny", policy.Verdict{Decision: policy.DecisionDeny, DecisionPinnedBy: layerOrg}, PromptModeBlock},
		{"org overridable deny", policy.Verdict{Decision: policy.DecisionDeny, Overridable: true, DecisionPinnedBy: layerOrg}, PromptModeAskOnce},
		{"org ask", policy.Verdict{Decision: policy.DecisionAsk, DecisionPinnedBy: layerOrg}, PromptModeAskOnce},
		{"org flag", policy.Verdict{Decision: policy.DecisionFlag, DecisionPinnedBy: layerOrg}, PromptModeWarn},
		{"org allow", policy.Verdict{Decision: policy.DecisionAllow, DecisionPinnedBy: layerOrg}, PromptModeOff},
		{"user deny", policy.Verdict{Decision: policy.DecisionDeny, DecisionPinnedBy: "user"}, PromptModeOff},
		{"unpinned deny", policy.Verdict{Decision: policy.DecisionDeny}, PromptModeOff},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := promptModeFloor(tc.v); got != tc.want {
				t.Fatalf("promptModeFloor = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestOrgPromptFloorClosesTheHookPosture pins the integration security review
// fix (2026-10-15): when an org pin floors the prompt lane above the local
// mode, the gate posture behind the hook failure path says the prompt family
// is enforced, so a hook timeout or crash fails closed rather than open.
func TestOrgPromptFloorClosesTheHookPosture(t *testing.T) {
	t.Parallel()
	const deny = "[[override]]\nrule = \"R-190\"\ndecision = \"deny\"\nenforce = true\n"
	cases := []struct {
		name, layer, body, localMode string
		want                         bool
	}{
		{"org deny over local warn closes the prompt gate", "org", deny, "warn", true},
		{
			"org overridable deny over local warn closes it (ask-once)", "org",
			"[[override]]\nrule = \"R-190\"\ndecision = \"deny\"\nenforce = true\noverridable = true\n", "warn", true,
		},
		{"org enforce=false leaves it open", "org", "[[override]]\nrule = \"R-190\"\nenforce = false\n", "warn", false},
		{"a user deny sets no floor", "user", deny, "warn", false},
		{"no override keeps the local warn posture", "user", "", "warn", false},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := enforceCapGuard(t, "observe", tc.localMode, tc.layer, tc.body, int64(760+i))
			if got := g.GateEnforcement().Prompt; got != tc.want {
				t.Fatalf("GateEnforcement().Prompt = %v, want %v (issues %v)", got, tc.want, g.LoadIssues())
			}
		})
	}
}
