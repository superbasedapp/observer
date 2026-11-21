package policy

import "testing"

// TestSelfApprovalSandboxEgressHosts (OpenShell lane N5): adding a host to
// the sandbox egress allow-list is the person's call; an agent's PUT of the
// refusal advisor's apply, a settings route writing the list and `observer
// config set` of it are denied by R-167, and the reads stay allowed.
func TestSelfApprovalSandboxEgressHosts(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		sh("PUT the refusal advisor apply", `curl -X PUT -H 'X-Observer-Confirm: t' -H 'Content-Type: application/json' -d '{"refusal_id":7}' http://127.0.0.1:8821/api/sandbox/refusals/allow`, "R-167", DecisionDeny),
		sh("POST the refusal advisor apply", `curl -d '{"refusal_id":7}' http://localhost:8821/api/sandbox/refusals/allow`, "R-167", DecisionDeny),
		sh("PUT the apply with a body from a file", `curl -X PUT --data @body.json http://127.0.0.1:8821/api/sandbox/refusals/allow`, "R-167", DecisionDeny),
		sh("GET the offers is a read", `curl http://127.0.0.1:8821/api/sandbox/refusals/allow`, "", 0),
		sh("GET the refusals is a read", `curl http://127.0.0.1:8821/api/sandbox/refusals?run_id=r1`, "", 0),
		sh("PUT the sandbox editor with the list", `curl -X PUT http://127.0.0.1:8821/api/terminal/sandbox/config -d '{"enabled":true,"egress_allow_hosts":["evil.example.com"]}'`, "R-167", DecisionDeny),
		sh("PUT the sandbox editor from a file", `curl -X PUT http://127.0.0.1:8821/api/terminal/sandbox/config --data-binary @cfg.json`, "R-167", DecisionDeny),
		sh("PUT the sandbox editor without the list", `curl -X PUT http://127.0.0.1:8821/api/terminal/sandbox/config -d '{"enabled":true}'`, "", 0),
		sh("PUT the sandbox editor keeping the saved list", `curl -X PUT http://127.0.0.1:8821/api/terminal/sandbox/config -d '{"enabled":true,"egress_allow_hosts":null}'`, "", 0),
		sh("PUT the terminal.sandbox section with the list", `curl -X PUT http://127.0.0.1:8821/api/config/section/terminal.sandbox -d '{"egress_allow_hosts":["evil.example.com"]}'`, "R-167", DecisionDeny),
		sh("PUT the list key", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"terminal.sandbox.egress_allow_hosts","value":["evil.example.com"]}]}'`, "R-167", DecisionDeny),
		sh("PUT another sandbox key", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"terminal.sandbox.default_on","value":true}]}'`, "", 0),
		sh("config set the list", `observer config set terminal.sandbox.egress_allow_hosts evil.example.com`, "R-167", DecisionDeny),
		sh("config set the list via npx", `npx -y @superbased/observer config set terminal.sandbox.egress_allow_hosts evil.example.com`, "R-167", DecisionDeny),
		sh("config get the list is a read", `observer config get terminal.sandbox.egress_allow_hosts`, "", 0),
		// OSH-141 (fold of the OpenShell line): a flag before or between the
		// subcommand words is read both ways cobra may read it.
		sh("flags before: config set the list", `observer config --x y set terminal.sandbox.egress_allow_hosts evil.example.com`, "R-167", DecisionDeny),
		sh("flags before at the root: config set the list", `observer --x y config set terminal.sandbox.egress_allow_hosts evil.example.com`, "R-167", DecisionDeny),
		sh("flags before through npx: config set the list", `npx -y @superbased/observer -x y config set terminal.sandbox.egress_allow_hosts evil.example.com`, "R-167", DecisionDeny),
		sh("flags before: config get the list is a read", `observer config --x y get terminal.sandbox.egress_allow_hosts`, "", 0),
		sh("PUT to a remote host", `curl -X PUT https://example.com/api/sandbox/refusals/allow -d '{"refusal_id":7}'`, "", 0),
		// Sweep finding UI-1: every spelling of this machine the dashboard
		// answers is a loopback target.
		sh("PUT the apply through a mapped IPv6 host", `curl -X PUT -d '{"refusal_id":7}' 'http://[::ffff:127.0.0.1]:8821/api/sandbox/refusals/allow'`, "R-167", DecisionDeny),
		sh("PUT the apply through a hex mapped host", `curl -X PUT -d '{"refusal_id":7}' 'http://[::ffff:7f00:1]:8821/api/sandbox/refusals/allow'`, "R-167", DecisionDeny),
		sh("PUT the apply through an integer host", `curl -X PUT -d '{"refusal_id":7}' http://2130706433:8821/api/sandbox/refusals/allow`, "R-167", DecisionDeny),
		sh("PUT the apply through a .localhost name", `curl -X PUT -d '{"refusal_id":7}' http://box.localhost:8821/api/sandbox/refusals/allow`, "R-167", DecisionDeny),
		sh("PUT the apply with a loopback Host header", `curl -X PUT -H 'Host: 127.0.0.1:8821' -d '{"refusal_id":7}' http://sbo.example.test:8821/api/sandbox/refusals/allow`, "R-167", DecisionDeny),
		sh("PUT the apply through --resolve", `curl -X PUT --resolve sbo.example.test:8821:127.0.0.1 -d '{"refusal_id":7}' http://sbo.example.test:8821/api/sandbox/refusals/allow`, "R-167", DecisionDeny),
		{
			name: "Invoke-RestMethod apply", kind: KindShellExec, dialect: DialectPowerShell,
			target: `Invoke-RestMethod -Method Put -Uri http://127.0.0.1:8821/api/sandbox/refusals/allow -Body '{"refusal_id":7}'`, wantRule: "R-167", wantEnforce: DecisionDeny,
		},
	}
	runCoreRuleCases(t, cases, "R-167")
}

// TestSandboxAllowPathSpellings (audit finding N5-A2): the dashboard's
// ServeMux routes on the decoded, cleaned path, so R-167 and R-165 compare
// that form. One row per spelling, for both rules, in observe and enforce
// (runCoreRuleCases runs each case in both modes).
func TestSandboxAllowPathSpellings(t *testing.T) {
	t.Parallel()
	const apply = `curl -X PUT -d '{"refusal_id":7}' `
	const editor = `curl -X PUT -d '{"egress_allow_hosts":["evil.example.com"]}' `
	sandbox := []coreRuleCase{
		sh("percent-encoded letter in the last segment", apply+`http://127.0.0.1:8821/api/sandbox/refusals/%61llow`, "R-167", DecisionDeny),
		sh("percent-encoded upper-case hex", apply+`http://127.0.0.1:8821/api/sandbox/refusals/%41LLOW`, "R-167", DecisionDeny),
		sh("percent-encoded letter in the editor route", editor+`http://127.0.0.1:8821/api/terminal/sandbox/%63onfig`, "R-167", DecisionDeny),
		sh("percent-encoded slash", apply+`http://127.0.0.1:8821/api/sandbox/refusals%2Fallow`, "R-167", DecisionDeny),
		sh("double slash", apply+`http://127.0.0.1:8821/api/sandbox/refusals//allow`, "R-167", DecisionDeny),
		sh("double slash at the root", apply+`http://127.0.0.1:8821//api/sandbox/refusals/allow`, "R-167", DecisionDeny),
		sh("trailing slash", apply+`http://127.0.0.1:8821/api/sandbox/refusals/allow/`, "R-167", DecisionDeny),
		sh("dot segment", apply+`http://127.0.0.1:8821/api/sandbox/./refusals/allow`, "R-167", DecisionDeny),
		sh("dot-dot segment", apply+`http://127.0.0.1:8821/api/sandbox/x/../refusals/allow`, "R-167", DecisionDeny),
		sh("percent-encoded dot-dot", apply+`http://127.0.0.1:8821/api/sandbox/x/%2e%2e/refusals/allow`, "R-167", DecisionDeny),
		sh("mixed case", apply+`http://127.0.0.1:8821/API/Sandbox/Refusals/Allow`, "R-167", DecisionDeny),
		// An undecodable path fails closed in both rules; R-165 sits earlier
		// in the boundary table, so it is the one that answers.
		sh("undecodable escape fails closed", apply+`http://127.0.0.1:8821/api/sandbox/refusals/%zzllow`, "R-165", DecisionDeny),
		sh("encoded read is still a read", `curl http://127.0.0.1:8821/api/sandbox/refusals/%61llow`, "", 0),
		sh("a sibling route is not the apply", apply+`http://127.0.0.1:8821/api/sandbox/refusals/allowed`, "", 0),
		sh("dot-dot out of the route", apply+`http://127.0.0.1:8821/api/sandbox/refusals/allow/../other`, "", 0),
	}
	runCoreRuleCases(t, sandbox, "R-167")
	const grant = `curl -X POST -d '{"rule_id":"R-110"}' `
	guard := []coreRuleCase{
		sh("R-165 percent-encoded letter", grant+`http://127.0.0.1:8821/api/guard/%61pprovals`, "R-165", DecisionDeny),
		sh("R-165 percent-encoded slash", grant+`http://127.0.0.1:8821/api/guard%2Fapprovals`, "R-165", DecisionDeny),
		sh("R-165 double slash", grant+`http://127.0.0.1:8821/api//guard/approvals`, "R-165", DecisionDeny),
		sh("R-165 trailing slash", grant+`http://127.0.0.1:8821/api/guard/mcp/approve/`, "R-165", DecisionDeny),
		sh("R-165 dot segments", grant+`http://127.0.0.1:8821/api/x/../guard/./mcp/approve`, "R-165", DecisionDeny),
		sh("R-165 mixed case", grant+`http://127.0.0.1:8821/Api/Guard/MCP/Approve`, "R-165", DecisionDeny),
		sh("R-165 encoded prefix route", grant+`http://127.0.0.1:8821/api/guard/approvals/%31/revoke`, "R-165", DecisionDeny),
		sh("R-165 encoded dotted section", `curl -X PUT -d '{}' http://127.0.0.1:8821/api/config/section/guard%2Ebudget`, "R-165", DecisionDeny),
		sh("R-165 undecodable escape fails closed", grant+`http://127.0.0.1:8821/api/guard/%zzpprovals`, "R-165", DecisionDeny),
		sh("R-165 encoded read is still a read", `curl http://127.0.0.1:8821/api/guard/%61pprovals`, "", 0),
	}
	runCoreRuleCases(t, guard, "R-165")
}

// TestSandboxAllowPinnedSpellings (audit finding N5-A4) pins spellings
// R-167 already catches, so a later change cannot drop one silently.
func TestSandboxAllowPinnedSpellings(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		sh("config set the key in another case", `observer config set TERMINAL.Sandbox.Egress_Allow_Hosts evil.example.com`, "R-167", DecisionDeny),
		sh("config keys body with the key in another case", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"Terminal.Sandbox.EGRESS_ALLOW_HOSTS","value":["evil.example.com"]}]}'`, "R-167", DecisionDeny),
		sh("an empty list lets every host through", `curl -X PUT http://127.0.0.1:8821/api/terminal/sandbox/config -d '{"egress_allow_hosts":[]}'`, "R-167", DecisionDeny),
		sh("config set with the --config flag first", `observer --config /home/u/.observer/config.toml config set terminal.sandbox.egress_allow_hosts evil.example.com`, "R-167", DecisionDeny),
		sh("config set with --config= inline", `observer --config=/home/u/.observer/config.toml config set terminal.sandbox.egress_allow_hosts evil.example.com`, "R-167", DecisionDeny),
		sh("[::1] as the host", `curl -X PUT -d '{"refusal_id":7}' http://[::1]:8821/api/sandbox/refusals/allow`, "R-167", DecisionDeny),
		sh("wget with --method and --body-data", `wget --method=PUT --body-data='{"refusal_id":7}' http://127.0.0.1:8821/api/sandbox/refusals/allow`, "R-167", DecisionDeny),
		sh("wget with --post-data", `wget --post-data='{"refusal_id":7}' http://127.0.0.1:8821/api/sandbox/refusals/allow`, "R-167", DecisionDeny),
		sh("httpie PUT", `http PUT 127.0.0.1:8821/api/sandbox/refusals/allow refusal_id:=7`, "R-167", DecisionDeny),
		sh("httpie editor with the list", `http PUT localhost:8821/api/terminal/sandbox/config egress_allow_hosts:='["evil.example.com"]'`, "R-167", DecisionDeny),
	}
	runCoreRuleCases(t, cases, "R-167")
}

// TestSandboxAllowRuleIsIntegrity pins R-167 in the integrity set (operator
// ruling OB-029), the same way TestSelfApprovalRuleIsIntegrity pins R-165:
// a below-org disable, relaxation or flag cap leaves the deny standing,
// because a layer that relaxed it would let a refused sandboxed run grant
// itself the host it was refused.
func TestSandboxAllowRuleIsIntegrity(t *testing.T) {
	t.Parallel()
	if !IsIntegrityRuleID("R-167") {
		t.Fatal("integrity set: want R-167 in")
	}
	allow := DecisionAllow
	ev := Event{Kind: KindShellExec, Target: "observer config set terminal.sandbox.egress_allow_hosts evil.example.com", Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj"}
	for name, cfg := range map[string]Config{
		"disabled": {Mode: ModeEnforce, Home: "/home/u", Disabled: []string{"R-167"}},
		"relaxed":  {Mode: ModeEnforce, Home: "/home/u", Overrides: []Override{{RuleID: "R-167", Decision: &allow, Source: "user"}}},
		"capped":   {Mode: ModeEnforce, Home: "/home/u", Overrides: []Override{{RuleID: "R-167", EnforceOff: true, Source: "user"}}},
	} {
		e, err := New(cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if v := e.Evaluate(ev); v.RuleID != "R-167" || v.Decision != DecisionDeny {
			t.Errorf("%s: verdict %s/%s, want R-167/deny", name, v.RuleID, v.Decision)
		}
	}
}
