package policy

import "testing"

// TestSelfApprovalSandboxCredentials (lane GATES-SBX, G24): storing a
// provider key for credential injection is the person's call; an agent's
// `observer sandbox credentials add` and the route's POST are denied by
// R-165, and the reads stay allowed.
func TestSelfApprovalSandboxCredentials(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		sh("credentials add", `observer sandbox credentials add anthropic`, "R-165", DecisionDeny),
		sh("credentials add piped", `echo sk-x | observer sandbox credentials add openai`, "R-165", DecisionDeny),
		sh("credentials add via npx", `npx -y @superbased/observer sandbox credentials add anthropic`, "R-165", DecisionDeny),
		sh("flags before: credentials add (OSH-141)", `observer sandbox credentials --x y add anthropic`, "R-165", DecisionDeny),
		sh("flags before: credentials list is a read", `observer sandbox --x y credentials list`, "", 0),
		sh("credentials list is a read", `observer sandbox credentials list`, "", 0),
		sh("credentials remove only takes injection away", `observer sandbox credentials remove anthropic`, "", 0),
		sh("POST the key route", `curl -X POST -H 'X-Observer-Confirm: t' -d '{"provider":"anthropic","key":"k"}' http://127.0.0.1:8821/api/terminal/sandbox/credentials`, "R-165", DecisionDeny),
		sh("GET the key route is a read", `curl http://127.0.0.1:8821/api/terminal/sandbox/credentials`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}

// TestSelfApprovalSandboxReadopt (lane GATES-SBX, audit F5): re-adopting,
// ending, checkpointing and restoring a sandboxed container run are the
// person's actions; an agent's verbs and the routes' POSTs are denied by
// R-165, and the list stays allowed.
func TestSelfApprovalSandboxReadopt(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		sh("readopt", `observer sandbox readopt run00000000000000a1`, "R-165", DecisionDeny),
		sh("readopt --end", `observer sandbox readopt run00000000000000a1 --end`, "R-165", DecisionDeny),
		sh("checkpoint", `observer sandbox checkpoint run00000000000000a1`, "R-165", DecisionDeny),
		sh("restore", `observer sandbox restore run00000000000000a1`, "R-165", DecisionDeny),
		sh("restore via npx", `npx -y @superbased/observer sandbox restore run00000000000000a1`, "R-165", DecisionDeny),
		sh("flags before: readopt (OSH-141)", `observer sandbox --x y readopt run00000000000000a1`, "R-165", DecisionDeny),
		sh("flags before: checkpoint", `observer -x y sandbox checkpoint run00000000000000a1`, "R-165", DecisionDeny),
		sh("flags before: runs is a read", `observer sandbox --x y runs`, "", 0),
		sh("runs is a read", `observer sandbox runs`, "", 0),
		sh("POST end", `curl -X POST -H 'X-Observer-Confirm: t' -d '{"run":"run00000000000000a1"}' http://127.0.0.1:8821/api/terminal/sandbox/readopt/end`, "R-165", DecisionDeny),
		sh("POST checkpoint", `curl -X POST -d '{"run":"run00000000000000a1"}' http://127.0.0.1:8821/api/terminal/sandbox/readopt/checkpoint`, "R-165", DecisionDeny),
		sh("POST restore", `curl -X POST -d '{"run":"run00000000000000a1"}' http://127.0.0.1:8821/api/terminal/sandbox/readopt/restore`, "R-165", DecisionDeny),
		sh("GET the list is a read", `curl http://127.0.0.1:8821/api/terminal/sandbox/readopt`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}
