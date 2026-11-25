package policy

import "testing"

// TestSettingsProposalsAreSelfApproval pins the D19 rows (Plane A W2-8): an
// agent files a settings proposal through MCP set_setting, but approving or
// rejecting it, and writing a D19 key directly, is the person's call.
func TestSettingsProposalsAreSelfApproval(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		sh("approve a proposal", `observer config proposals approve 3 --yes`, "R-165", DecisionDeny),
		sh("reject a proposal", `observer config proposals reject 3`, "R-165", DecisionDeny),
		sh("list proposals is a read", `observer config proposals`, "", 0),
		sh("config get is a read", `observer config get observability.sdk.destination`, "", 0),
		sh("config set the SDK destination", `observer config set observability.sdk.destination online --yes`, "R-165", DecisionDeny),
		sh("config set the content key", `observer config set observability.store_content true --yes`, "R-165", DecisionDeny),
		sh("config set a share key", `observer config set org_client.share.full_content true`, "R-165", DecisionDeny),
		sh("config set an ordinary obs key", `observer config set observability.alerts.eval_interval_minutes 5`, "", 0),
		sh("GET the proposals list is a read", `curl http://127.0.0.1:8081/api/config/proposals`, "", 0),
		sh("POST approve route", `curl -X POST http://127.0.0.1:8081/api/config/proposals/3/approve`, "R-165", DecisionDeny),
		sh("sdk sign-in", `observer sdk sign-in`, "R-165", DecisionDeny),
		sh("sdk sign-out", `observer sdk sign-out`, "R-165", DecisionDeny),
		sh("sdk status is a read", `observer sdk status --json`, "", 0),
		sh("sdk use-key", `observer sdk use-key --gateway-url https://gw.example.com`, "R-165", DecisionDeny),
		sh("sdk use-key with the key piped from a file", `observer sdk use-key --gateway-url https://gw.example.com < key.txt`, "R-165", DecisionDeny),
		sh("sdk use-key with the key piped from echo", `echo ik_x.fakeValue | observer sdk use-key --gateway-url https://gw.example.com`, "R-165", DecisionDeny),
		sh("sdk use-key with --config first", `observer sdk use-key --config /tmp/c.toml --gateway-url https://gw.example.com`, "R-165", DecisionDeny),
		sh("sdk use-key help is still the command", `observer sdk use-key --help`, "R-165", DecisionDeny),
		sh("POST the SDK sign-in route", `curl -X POST http://127.0.0.1:8081/api/sdk/credential`, "R-165", DecisionDeny),
		// A DELETE narrows (httpWriteMethods: it revokes, which never widens
		// where data goes), so the route form of sign-out is let through; the
		// CLI verb above is denied because its --all reaches every machine.
		// Pinned as is; lane note docs/audits/sdk-use-key-2026-11-25.md.
		sh("DELETE the SDK sign-out route narrows", `curl -X DELETE http://127.0.0.1:8081/api/sdk/credential`, "", 0),
		sh("POST the SDK key install route", `curl -X POST http://127.0.0.1:8081/api/sdk/credential/key -H 'Content-Type: application/json' -d '{"key":"ik_x.fakeValue","gateway_url":"https://gw.example.com"}'`, "R-165", DecisionDeny),
		sh("POST the SDK key install route on localhost", `curl -X POST http://localhost:8081/api/sdk/credential/key -d @body.json`, "R-165", DecisionDeny),
		sh("GET the SDK receiver route is a read", `curl http://127.0.0.1:8081/api/sdk/receiver`, "", 0),
		sh("GET the SDK discovery route is a read", `curl http://127.0.0.1:8081/api/sdk/destination`, "", 0),
		sh("config keys body names the destination", `curl -X PUT http://127.0.0.1:8081/api/config/keys -d '{"patches":[{"key":"observability.sdk.destination","value":"both"}]}'`, "R-165", DecisionDeny),
	}
	runCoreRuleCases(t, cases, "R-165")
}
