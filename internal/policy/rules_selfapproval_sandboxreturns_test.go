package policy

import "testing"

// TestSelfApprovalSandboxReturns (lane RETURNS): opening a sandboxed run's
// saved diff as a branch, removing a saved diff and removing a run's copy
// are the person's clicks; an agent's POST to any of the panel's routes is
// denied by R-165, and the list and the diff preview stay readable.
func TestSelfApprovalSandboxReturns(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		sh("POST open as a branch", `curl -X POST -H 'X-Observer-Confirm: t' -H 'Content-Type: application/json' -d '{"run":"run00000000000000a1"}' http://127.0.0.1:8821/api/terminal/sandbox/returns/branch`, "R-165", DecisionDeny),
		sh("POST remove a diff", `curl -X POST -d '{"run":"run00000000000000a1"}' http://127.0.0.1:8821/api/terminal/sandbox/returns/remove-diff`, "R-165", DecisionDeny),
		sh("POST remove a copy", `curl --request POST --data '{"run":"abc"}' http://localhost:8821/api/terminal/sandbox/returns/remove-copy`, "R-165", DecisionDeny),
		sh("POST a dot-segment form", `curl -X POST -d '{}' http://127.0.0.1:8821/api/terminal/sandbox/x/../returns/branch`, "R-165", DecisionDeny),
		sh("POST a percent-encoded form", `curl -X POST -d '{}' http://127.0.0.1:8821/api/terminal/sandbox/%72eturns/branch`, "R-165", DecisionDeny),
		// SBXD-2 (lane COPIES): the one-click removal of every safe copy.
		sh("POST remove every safe copy", `curl -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:8821/api/terminal/sandbox/returns/remove-safe-copies`, "R-165", DecisionDeny),
		sh("GET the list is a read", `curl http://127.0.0.1:8821/api/terminal/sandbox/returns`, "", 0),
		sh("GET the preview is a read", `curl 'http://127.0.0.1:8821/api/terminal/sandbox/returns/diff?run=run00000000000000a1'`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}
