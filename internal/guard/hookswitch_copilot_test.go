package guard

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestR162StillGuardsCopilotCLIDisableAllHooks pins the FU-159 precaution
// through the real table projection: Copilot CLI 1.0.105 did not honour
// disableAllHooks for hooks, so nothing reports it as turning hooks off, but
// an agent write that sets it in any of Copilot's three settings files is
// still denied under enforce (R-162), a shell write naming it too, and the
// same write with the switch false still passes.
func TestR162StillGuardsCopilotCLIDisableAllHooks(t *testing.T) {
	const home, root = "/home/u", "/home/u/proj"
	e, err := policy.New(policy.Config{Mode: policy.ModeEnforce, Home: home, HookSwitches: hookSwitchesForPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	write := func(target, body string) policy.Verdict {
		return e.Evaluate(policy.Event{
			Kind: policy.KindFileAccess, ActionType: "write_file", Target: target,
			Cwd: root, ProjectRoot: root, SessionID: "s1", Now: now,
			Edits: []policy.ProposedEdit{{Kind: policy.EditWhole, New: body}},
		})
	}
	for _, target := range []string{
		home + "/.copilot/settings.json",
		root + "/.github/copilot/settings.json",
		root + "/.github/copilot/settings.local.json",
	} {
		if v := write(target, `{"disableAllHooks":true}`); v.RuleID != "R-162" || v.Decision != policy.DecisionDeny {
			t.Errorf("%s: write setting disableAllHooks = %s/%s (%q), want R-162 deny", target, v.RuleID, v.Decision, v.Reason)
		}
		if v := write(target, `{"disableAllHooks":false}`); v.RuleID == "R-162" || v.RuleID == "R-163" {
			t.Errorf("%s: write with the switch false hit %s", target, v.RuleID)
		}
	}
	v := e.Evaluate(policy.Event{
		Kind: policy.KindShellExec, Target: `jq '.disableAllHooks = true' .github/copilot/settings.json > t && mv t .github/copilot/settings.json`,
		Cwd: root, ProjectRoot: root, SessionID: "s1", Now: now,
	})
	if v.RuleID != "R-162" || v.Decision != policy.DecisionDeny {
		t.Errorf("shell write = %s/%s (%q), want R-162 deny", v.RuleID, v.Decision, v.Reason)
	}
}
