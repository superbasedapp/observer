package policy

import "testing"

// TestSelfApprovalUpdateRollback (lane SEC-P4 decision 7, SECP-6): an
// agent's `observer update rollback --yes` and the /api/update/apply body
// that asks for a rollback are denied in enforce and flagged in observe,
// POSIX and PowerShell; the preview without --yes, a plain apply and its
// dry run pass. A rollback body with dry_run still rolls back (the daemon
// takes the rollback branch first), so it matches.
func TestSelfApprovalUpdateRollback(t *testing.T) {
	t.Parallel()
	ps := func(name, target, rule string, enforce Decision) coreRuleCase {
		return coreRuleCase{name: name, kind: KindShellExec, dialect: DialectPowerShell, target: target, wantRule: rule, wantEnforce: enforce}
	}
	cases := []coreRuleCase{
		sh("CLI rollback", `observer update rollback --yes`, "R-165", DecisionDeny),
		sh("CLI rollback, explicit true", `observer update rollback --yes=true`, "R-165", DecisionDeny),
		sh("CLI rollback via npx", `npx -y @superbased/observer update rollback --yes`, "R-165", DecisionDeny),
		sh("CLI rollback preview", `observer update rollback`, "", 0),
		sh("CLI rollback --yes=false previews", `observer update rollback --yes=false`, "", 0),
		sh("CLI update history is a read", `observer update history`, "", 0),
		ps("PowerShell rollback", `observer.exe update rollback --yes`, "R-165", DecisionDeny),
		ps("PowerShell call operator rollback", `& "C:\Program Files\SuperBased\observer.exe" update rollback --yes`, "R-165", DecisionDeny),
		sh("route rollback", `curl -X POST http://127.0.0.1:8821/api/update/apply -d '{"rollback":true}'`, "R-165", DecisionDeny),
		sh("route rollback, escaped key", `curl -X POST http://127.0.0.1:8821/api/update/apply -d '{"\u0072ollback":true}'`, "R-165", DecisionDeny),
		sh("route rollback behind a false duplicate", `curl -X POST http://127.0.0.1:8821/api/update/apply -d '{"rollback":false,"rollback":true}'`, "R-165", DecisionDeny),
		sh("route rollback with dry_run still rolls back", `curl -X POST http://127.0.0.1:8821/api/update/apply -d '{"rollback":true,"dry_run":true}'`, "R-165", DecisionDeny),
		sh("route body unreadable", `curl -X POST http://127.0.0.1:8821/api/update/apply -d @body.json`, "R-165", DecisionDeny),
		ps("Invoke-RestMethod rollback", `Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8821/api/update/apply -Body '{"rollback":true}'`, "R-165", DecisionDeny),
		sh("route plain apply", `curl -X POST http://127.0.0.1:8821/api/update/apply -d '{"version":"1.9.1"}'`, "", 0),
		sh("route apply dry run", `curl -X POST http://127.0.0.1:8821/api/update/apply -d '{"dry_run":true}'`, "", 0),
		sh("route rollback false", `curl -X POST http://127.0.0.1:8821/api/update/apply -d '{"rollback":false}'`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}
