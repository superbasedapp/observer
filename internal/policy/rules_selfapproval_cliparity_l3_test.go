package policy

import "testing"

// TestSelfApprovalCLIParityL3 (dashboard CLI parity plan, lane L3): the new
// sandbox routes that store a credential or loosen isolation are the
// person's, never an agent's. The hosted Connect form (B-G2), a sandbox
// settings save or a More settings key write that leaves the MXC tier floor
// off process_container (B-G6), and the readopt re-attach terminal (B-G3,
// under the readopt prefix) are denied by R-165; the disconnect, a save that
// keeps or omits the floor, and the reads stay allowed.
func TestSelfApprovalCLIParityL3(t *testing.T) {
	t.Parallel()
	const base = "http://127.0.0.1:8821"
	cases := []coreRuleCase{
		sh("POST the hosted connect", `curl -X POST -H 'X-Observer-Confirm: t' -d '{"provider":"e2b","fields":{"E2B_API_KEY":"k"}}' `+base+`/api/terminal/sandbox/hosted/connect`, "R-165", DecisionDeny),
		sh("the CLI twin of the hosted connect", `observer sandbox hosted connect e2b`, "R-165", DecisionDeny),
		sh("POST the hosted disconnect only takes access away", `curl -X POST -d '{"provider":"e2b"}' `+base+`/api/terminal/sandbox/hosted/disconnect`, "", 0),
		sh("GET the hosted status is a read", `curl `+base+`/api/terminal/sandbox/hosted`, "", 0),
		sh("PUT the sandbox editor onto the AppContainer tier", `curl -X PUT `+base+`/api/terminal/sandbox/config -d '{"enabled":true,"windows":{"mxc_tier":"appcontainer"}}'`, "R-165", DecisionDeny),
		sh("PUT the sandbox editor clearing the floor", `curl -X PUT `+base+`/api/terminal/sandbox/config -d '{"enabled":true,"windows":{"mxc_tier":""}}'`, "R-165", DecisionDeny),
		sh("PUT the sandbox editor with an empty windows block", `curl -X PUT `+base+`/api/terminal/sandbox/config -d '{"windows":{}}'`, "R-165", DecisionDeny),
		sh("PUT the sandbox editor with a later duplicate key", `curl -X PUT `+base+`/api/terminal/sandbox/config -d '{"windows":{"mxc_tier":"process_container","MXC_TIER":"appcontainer"}}'`, "R-165", DecisionDeny),
		sh("PUT the sandbox editor holding the floor", `curl -X PUT `+base+`/api/terminal/sandbox/config -d '{"enabled":true,"windows":{"mxc_tier":"process_container"}}'`, "", 0),
		sh("PUT the sandbox editor without the windows block", `curl -X PUT `+base+`/api/terminal/sandbox/config -d '{"enabled":true,"wslc":{"path":"","image":""}}'`, "", 0),
		sh("PUT the sandbox editor keeping the saved block", `curl -X PUT `+base+`/api/terminal/sandbox/config -d '{"enabled":true,"windows":null}'`, "", 0),
		sh("PUT the floor key", `curl -X PUT `+base+`/api/config/keys -d '{"patches":[{"key":"terminal.sandbox.windows.mxc_tier","value":"appcontainer"}]}'`, "R-165", DecisionDeny),
		sh("PUT the floor key in another case", `curl -X PUT `+base+`/api/config/keys -d '{"patches":[{"key":"Terminal.Sandbox.Windows.MXC_TIER","value":""}]}'`, "R-165", DecisionDeny),
		sh("PUT another sandbox key", `curl -X PUT `+base+`/api/config/keys -d '{"patches":[{"key":"terminal.sandbox.wslc.image","value":""}]}'`, "", 0),
		sh("POST the readopt re-attach terminal", `curl -X POST -H 'X-Observer-Confirm: t' -d '{"run":"run00000000000000a1"}' `+base+`/api/terminal/sandbox/readopt/attach`, "R-165", DecisionDeny),
	}
	runCoreRuleCases(t, cases, "R-165")
}
