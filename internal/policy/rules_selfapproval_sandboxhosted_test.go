package policy

import "testing"

// TestSelfApprovalSandboxHostedConsentAndKeySources (sandbox terminal gaps,
// decisions SBXD-4 and SBXD-5): recording a hosted consent and turning on a
// tool's own keys or login as an in-box key source are the person's; an
// agent's POST to either route is denied by R-165, and the consent screen's
// GET stays a read.
func TestSelfApprovalSandboxHostedConsentAndKeySources(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		sh("POST the hosted consent", `curl -X POST -H 'X-Observer-Confirm: t' -H 'Content-Type: application/json' -d '{"provider":"daytona","workspace":"/w"}' http://127.0.0.1:8821/api/terminal/sandbox/hosted/consent`, "R-165", DecisionDeny),
		sh("POST a key source", `curl -X POST -d '{"tool":"opencode","source":"tool_keys","on":true}' http://127.0.0.1:8821/api/terminal/sandbox/hosted/key-sources`, "R-165", DecisionDeny),
		sh("POST a dot-segment form", `curl -X POST -d '{}' http://127.0.0.1:8821/api/terminal/sandbox/x/../hosted/consent`, "R-165", DecisionDeny),
		sh("GET the consent screen is a read", `curl 'http://127.0.0.1:8821/api/terminal/sandbox/hosted/consent?provider=daytona&workspace=/w'`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}
