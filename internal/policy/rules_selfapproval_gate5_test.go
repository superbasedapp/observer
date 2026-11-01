package policy

import "testing"

// TestSelfApprovalGate5 (lane SEC-GATE5 milestone 3, R-165): the code
// rules' pack import by CLI and route, and switching security.feedback off
// by `config set`, the config routes (JSON bodies decoded, escapes and
// all), the settings backup restore and the components remove; POSIX and
// PowerShell spellings. Reads stay allowed.
//
// Code is the truth (recorded): `config set security.*`, the section and
// keys routes and the components remove already matched every
// security.feedback form through the security tree rows; the backup
// restore and the code rules route are the rows this lane adds.
func TestSelfApprovalGate5(t *testing.T) {
	t.Parallel()
	ps := func(name, target, rule string, enforce Decision) coreRuleCase {
		return coreRuleCase{name: name, kind: KindShellExec, dialect: DialectPowerShell, target: target, wantRule: rule, wantEnforce: enforce}
	}
	cases := []coreRuleCase{
		// The code rules' pack import, the route form.
		sh("POST code rules import", `curl -X POST http://127.0.0.1:8821/api/security/code/rules/import -d '{"path":"/tmp/pack"}'`, "R-165", DecisionDeny),
		sh("PUT code rules", `curl -X PUT http://localhost:8821/api/security/code/rules -d '{}'`, "R-165", DecisionDeny),
		sh("GET code rules is a read", `curl http://127.0.0.1:8821/api/security/code/rules`, "", 0),
		ps("Invoke-RestMethod code rules import", `Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8821/api/security/code/rules/import -Body '{"path":"C:\\packs"}'`, "R-165", DecisionDeny),

		// security.feedback off: config set.
		sh("config set feedback off", `observer config set security.feedback.after_write false`, "R-165", DecisionDeny),
		sh("config set feedback section", `observer config set security.feedback false`, "R-165", DecisionDeny),
		sh("config set feedback via npx", `npx -y @superbased/observer config set security.feedback.after_write false`, "R-165", DecisionDeny),
		ps("PowerShell config set feedback off", `observer.exe config set security.feedback.after_write false`, "R-165", DecisionDeny),
		ps("PowerShell call operator config set feedback off", `& "C:\Program Files\SuperBased\observer.exe" config set security.feedback.after_write false`, "R-165", DecisionDeny),
		// The config routes.
		sh("PUT the feedback section", `curl -X PUT http://127.0.0.1:8821/api/config/section/security.feedback -d '{"after_write":false}'`, "R-165", DecisionDeny),
		sh("PUT the feedback key", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"security.feedback.after_write","value":false}]}'`, "R-165", DecisionDeny),
		sh("PUT the feedback key, escaped", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"\u0073ecurity.feedback.after_write","value":false}]}'`, "R-165", DecisionDeny),
		sh("PUT the feedback key, escaped key name", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"\u006bey":"security.feedback.after_write","value":false}]}'`, "R-165", DecisionDeny),
		sh("PUT the feedback key behind a harmless one", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"compression.enabled","value":true},{"key":"security.feedback.after_write","value":false}]}'`, "R-165", DecisionDeny),
		ps("Invoke-RestMethod the feedback key", `Invoke-RestMethod -Method Put -Uri http://127.0.0.1:8821/api/config/keys -Body '{"patches":[{"key":"security.feedback.after_write","value":false}]}'`, "R-165", DecisionDeny),
		sh("GET the feedback section is a read", `curl http://127.0.0.1:8821/api/config/section/security.feedback`, "", 0),
		// The settings backup restore.
		sh("POST settings backup restore", `curl -X POST http://127.0.0.1:8821/api/config/backup`, "R-165", DecisionDeny),
		ps("Invoke-WebRequest settings backup restore", `Invoke-WebRequest -Method Post -Uri http://127.0.0.1:8821/api/config/backup`, "R-165", DecisionDeny),
		sh("GET settings backup is a read", `curl http://127.0.0.1:8821/api/config/backup`, "", 0),
		// The components deselect path (already covered by the security
		// tree rows; pinned here for the feedback child).
		sh("components remove feedback", `observer components remove security.feedback --yes`, "R-165", DecisionDeny),
		sh("components remove feedback preview", `observer components remove security.feedback`, "", 0),
		ps("PowerShell components remove feedback", `observer.exe components remove security.feedback --yes`, "R-165", DecisionDeny),
		sh("API remove feedback", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"remove":["security.feedback"]}'`, "R-165", DecisionDeny),
		sh("API remove feedback, escaped", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"remove":["\u0073ecurity.feedback"]}'`, "R-165", DecisionDeny),
		sh("API teardown feedback", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.feedback"]}'`, "R-165", DecisionDeny),
		sh("API teardown feedback preview", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.feedback"],"dry_run":true}'`, "", 0),
		// Explain stays allowed: it reads a finding.
		sh("security explain is a read", `observer security explain 01JX`, "", 0),
	}
	// Enforce denies, observe flags (runCoreRuleCases checks both modes);
	// a read never reaches R-165.
	runCoreRuleCases(t, cases, "R-165")
}
