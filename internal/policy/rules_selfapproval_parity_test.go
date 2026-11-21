package policy

import "testing"

// TestSelfApprovalParityEditors (dashboard CLI parity follow-up, ledger
// PARITY-7): an agent's write to the launch binary path editor, and a
// routing section save that sets the privacy rules, the path classes or the
// local upstreams, are denied in enforce and flagged in observe, POSIX and
// PowerShell. Reads, and routing saves that touch none of them, pass.
func TestSelfApprovalParityEditors(t *testing.T) {
	t.Parallel()
	ps := func(name, target, rule string, enforce Decision) coreRuleCase {
		return coreRuleCase{name: name, kind: KindShellExec, dialect: DialectPowerShell, target: target, wantRule: rule, wantEnforce: enforce}
	}
	cases := []coreRuleCase{
		sh("PUT a launch binary path", `curl -X PUT http://127.0.0.1:8821/api/launch/tool-paths -d '{"tool":"claude-code","path":"/tmp/x"}'`, "R-165", DecisionDeny),
		sh("PUT a launch binary path dry run", `curl -X PUT 'http://127.0.0.1:8821/api/launch/tool-paths?dry_run=1' -d '{"tool":"claude-code","path":null}'`, "R-165", DecisionDeny),
		ps("Invoke-RestMethod a launch binary path", `Invoke-RestMethod -Method Put -Uri http://127.0.0.1:8821/api/launch/tool-paths -Body '{"tool":"codex","path":"C:\\x.exe"}'`, "R-165", DecisionDeny),
		sh("GET launch binary paths is a read", `curl http://127.0.0.1:8821/api/launch/tool-paths`, "", 0),
		sh("PUT routing privacy rules", `curl -X PUT http://127.0.0.1:8821/api/config/section/routing -d '{"SetPrivacyRules":[]}'`, "R-165", DecisionDeny),
		sh("PUT routing privacy rules, lower case", `curl -X PUT http://127.0.0.1:8821/api/config/section/routing -d '{"setprivacyrules":[]}'`, "R-165", DecisionDeny),
		sh("PUT routing privacy rules, escaped key", `curl -X PUT http://127.0.0.1:8821/api/config/section/routing -d '{"\u0053etPrivacyRules":[]}'`, "R-165", DecisionDeny),
		sh("PUT routing local upstreams", `curl -X PUT http://127.0.0.1:8821/api/config/section/routing -d '{"Enabled":true,"SetLocalUpstreams":[{"name":"x","base_url":"http://evil.example"}]}'`, "R-165", DecisionDeny),
		sh("PUT routing body unreadable", `curl -X PUT http://127.0.0.1:8821/api/config/section/routing -d @body.json`, "R-165", DecisionDeny),
		ps("Invoke-RestMethod routing local upstreams", `Invoke-RestMethod -Method Put -Uri http://127.0.0.1:8821/api/config/section/routing -Body '{"SetLocalUpstreams":[]}'`, "R-165", DecisionDeny),
		sh("PUT routing path classes", `curl -X PUT http://127.0.0.1:8821/api/config/section/routing -d '{"SetPathClasses":{"secrets":["/nowhere/**"]}}'`, "R-165", DecisionDeny),
		sh("PUT routing tiers only", `curl -X PUT http://127.0.0.1:8821/api/config/section/routing -d '{"SetTiers":{"gpt-5":"fast"}}'`, "", 0),
		sh("PUT routing mode only", `curl -X PUT http://127.0.0.1:8821/api/config/section/routing -d '{"Enabled":true,"Mode":"advise"}'`, "", 0),
		sh("GET routing section is a read", `curl http://127.0.0.1:8821/api/config/section/routing`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}
