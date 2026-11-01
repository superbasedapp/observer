package policy

import "testing"

func TestSelfApprovalRuleR165(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		// CLI grant row: one case per selfApprovalVerbs grant row.
		sh("guard approve", `observer guard approve R-110 --session s1`, "R-165", DecisionDeny),
		sh("guard mcp approve", `observer guard mcp approve github`, "R-165", DecisionDeny),
		sh("guard prompt allow", `observer guard prompt allow email --session s1`, "R-165", DecisionDeny),
		sh("guard disable", `observer guard disable`, "R-165", DecisionDeny),
		sh("guard enable (observe)", `observer guard enable`, "R-165", DecisionDeny),
		sh("config set guard key", `observer config set guard.mode off`, "R-165", DecisionDeny),
		sh("security trust accept", `observer security trust accept --all`, "R-165", DecisionDeny),
		sh("security trust check is a read", `observer security trust check`, "", 0),
		sh("security scanners import", `observer security scanners import --template gosec --confirm abc`, "R-165", DecisionDeny),
		sh("security scanners list is a read", `observer security scanners list`, "", 0),
		// Lane SEC-G1: the code rules' pack import is the developer's call.
		sh("security code rules import", `observer security code rules import /tmp/pack`, "R-165", DecisionDeny),
		sh("security code rules import via npx", `npx -y @superbased/observer security code rules import ./pack`, "R-165", DecisionDeny),
		sh("security code rules import, flag first", `observer --config /tmp/c.toml security code rules import /tmp/pack`, "R-165", DecisionDeny),
		{
			name: "PowerShell security code rules import", kind: KindShellExec, dialect: DialectPowerShell,
			target: `observer.exe security code rules import C:\packs\observer-code`, wantRule: "R-165", wantEnforce: DecisionDeny,
		},
		{
			name: "PowerShell call operator security code rules import", kind: KindShellExec, dialect: DialectPowerShell,
			target: `& "C:\Program Files\SuperBased\observer.exe" security code rules import .\pack`, wantRule: "R-165", wantEnforce: DecisionDeny,
		},
		sh("security code rules list is a read", `observer security code rules list`, "", 0),
		sh("security code install-opengrep only prints", `observer security code install-opengrep`, "", 0),
		sh("security code status is a read", `observer security code status`, "", 0),
		sh("flag value before the subcommand", `observer --config /tmp/c.toml guard approve R-101 --global`, "R-165", DecisionDeny),
		sh("exe path", `/usr/local/bin/observer.exe guard approve R-101 --project`, "R-165", DecisionDeny),
		sh("npx package", `npx -y @superbased/observer@1.40.0 guard approve R-101 --global`, "R-165", DecisionDeny),
		sh("pnpm dlx package", `pnpm dlx @superbased/observer guard disable`, "R-165", DecisionDeny),
		sh("inside a script line", `cd /tmp && observer guard approve R-160 --global`, "R-165", DecisionDeny),
		sh("guard enable --enforce tightens", `observer guard enable --enforce`, "", 0),
		sh("config set other key", `observer config set compression.conversation.enabled false`, "", 0),
		sh("guard approvals list", `observer guard approvals`, "", 0),
		sh("guard revoke", `observer guard revoke 3`, "", 0),
		sh("guard status", `observer guard status`, "", 0),
		sh("npx of another package", `npx other-tool guard approve R-1`, "", 0),
		// HTTP row: one case per guardGrantRoutes row.
		sh("POST approvals", `curl -X POST http://127.0.0.1:8821/api/guard/approvals -d '{"rule_id":"R-110"}'`, "R-165", DecisionDeny),
		sh("POST mcp approve, no scheme", `curl -d '{}' localhost:8821/api/guard/mcp/approve`, "R-165", DecisionDeny),
		sh("POST repository trust accept", `curl -X POST -H 'Content-Type: application/json' -d '{"all":true}' http://127.0.0.1:8821/api/security/trust`, "R-165", DecisionDeny),
		sh("GET repository trust is a read", `curl http://127.0.0.1:8821/api/security/trust?dir=/r`, "", 0),
		sh("POST package checks consent", `curl -X POST -H 'X-Observer-Confirm: t' http://127.0.0.1:8821/api/security/deps -d '{}'`, "R-165", DecisionDeny),
		sh("GET package checks is a read", `curl http://127.0.0.1:8821/api/security/deps`, "", 0),
		sh("deps disclosure accept", `observer security deps disclosure --accept`, "R-165", DecisionDeny),
		sh("deps disclosure accept via npx", `npx @superbased/observer security deps disclosure --accept`, "R-165", DecisionDeny),
		sh("deps disclosure is a read", `observer security deps disclosure`, "", 0),
		// Operator ruling PT-19 (2): the scanner database accept.
		sh("scan db accept", `observer security scan db accept --yes`, "R-165", DecisionDeny),
		sh("scan db accept, no flag", `observer security scan db accept`, "R-165", DecisionDeny),
		sh("scan db accept via npx", `npx -y @superbased/observer security scan db accept --yes`, "R-165", DecisionDeny),
		sh("scan db refresh is not the accept", `observer security scan db refresh`, "", 0),
		sh("scan status is a read", `observer security scan status`, "", 0),
		sh("POST scanner database accept", `curl -X POST -H 'X-Observer-Confirm: t' http://127.0.0.1:8821/api/security/scanners/db -d '{}'`, "R-165", DecisionDeny),
		sh("GET scanner database state is a read", `curl http://127.0.0.1:8821/api/security/scanners/db`, "", 0),
		// Lane SEC-G2: the guided Opengrep install and its size consent.
		sh("security code install", `observer security code install --yes`, "R-165", DecisionDeny),
		sh("security code install, no flag", `observer security code install`, "R-165", DecisionDeny),
		sh("security code install via npx", `npx -y @superbased/observer security code install --yes`, "R-165", DecisionDeny),
		sh("security code install --plan is a read", `observer security code install --plan`, "", 0),
		sh("security iac install", `observer security iac install --engine trivy --yes`, "R-165", DecisionDeny),
		sh("security iac install, no flag", `observer security iac install`, "R-165", DecisionDeny),
		sh("security iac install --plan is a read", `observer security iac install --plan`, "", 0),
		sh("security iac status is a read", `observer security iac status`, "", 0),
		// Audit finding 1 of lane SEC-G2: only an explicit --plan is a read.
		sh("security code install --plan=true is a read", `observer security code install --plan=true --yes`, "", 0),
		sh("security code install --yes --plan is a read", `observer security code install --yes --plan`, "", 0),
		sh("security code install --plan=false installs", `observer security code install --plan=false --yes`, "R-165", DecisionDeny),
		sh("security code install --plan= installs", `observer security code install --plan= --yes`, "R-165", DecisionDeny),
		// Audit finding 7 of lane SEC-G4: pflag reads --plan=1 as true (strconv.ParseBool).
		sh("security code install --plan=1 is a read", `observer security code install --plan=1 --yes`, "", 0),
		sh("security code install --plan=yes is not read as a plan", `observer security code install --plan=yes --yes`, "R-165", DecisionDeny),
		sh("security code install --plan then --plan=false installs", `observer security code install --plan --plan=false --yes`, "R-165", DecisionDeny),
		sh("security code install, --config swallows --plan", `observer security code install --config --plan --yes`, "R-165", DecisionDeny),
		sh("security code install, root --config swallows --plan", `observer --config --plan security code install --yes`, "R-165", DecisionDeny),
		sh("security code install, --plan after --", `observer security code install --yes -- --plan`, "R-165", DecisionDeny),
		sh("security code install --plan via npx is a read", `npx -y @superbased/observer security code install --plan`, "", 0),
		// Lane SEC-G4 milestone 1 (decision log P-073): the teardown row reads
		// --dry-run the way the CLI's bool flag does, mirroring --plan above.
		sh("components teardown --dry-run=true previews", `observer components teardown security.githooks --dry-run=true`, "", 0),
		sh("components teardown --dry-run first previews", `observer components teardown --dry-run security.githooks`, "", 0),
		sh("components teardown --dry-run=false tears down", `observer components teardown security.githooks --dry-run=false`, "R-165", DecisionDeny),
		sh("components teardown --dry-run= tears down", `observer components teardown security.githooks --dry-run=`, "R-165", DecisionDeny),
		sh("components teardown --dry-run then --dry-run=false tears down", `observer components teardown security.githooks --dry-run --dry-run=false`, "R-165", DecisionDeny),
		sh("components teardown, --config swallows --dry-run", `observer components teardown security.githooks --config --dry-run`, "R-165", DecisionDeny),
		sh("components teardown, --dry-run after --", `observer components teardown security.githooks -- --dry-run`, "R-165", DecisionDeny),
		sh("components teardown --dry-run=1 previews", `observer components teardown security.githooks --dry-run=1`, "", 0),
		sh("components teardown --dry-run=TRUE previews", `observer components teardown security.githooks --dry-run=TRUE`, "", 0),
		sh("components teardown --dry-run=0 tears down", `observer components teardown security.githooks --dry-run=0`, "R-165", DecisionDeny),
		sh("components teardown --dry-run=on tears down", `observer components teardown security.githooks --dry-run=on`, "R-165", DecisionDeny),
		sh("components teardown --dry-run=false via npx", `npx -y @superbased/observer components teardown security.githooks --dry-run=false`, "R-165", DecisionDeny),
		sh("install-opengrep only prints", `observer security code install-opengrep`, "", 0),
		sh("security code refresh is not a consent", `observer security code refresh`, "", 0),
		sh("POST the guided install", `curl -X POST -H 'X-Observer-Confirm: t' http://127.0.0.1:8821/api/security/code/install -d '{}'`, "R-165", DecisionDeny),
		sh("GET the code rules state is a read", `curl http://127.0.0.1:8821/api/security/code/install`, "", 0),
		sh("POST the IaC guided install", `curl -X POST -H 'X-Observer-Confirm: t' http://127.0.0.1:8821/api/security/iac/install -d '{"engine":"trivy"}'`, "R-165", DecisionDeny),
		// Turning a code rules trigger off goes through the [security] keys,
		// already the developer's only (config set and the keys route).
		sh("config set post-write scans off", `observer config set security.scan.opengrep.post_write false`, "R-165", DecisionDeny),
		sh("PUT commit diff scans off", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"security.scan.opengrep.commit_diff","value":false}]}'`, "R-165", DecisionDeny),
		sh("PUT the [security.scan.opengrep] section", `curl -X PUT http://127.0.0.1:8821/api/config/section/security.scan.opengrep -d '{"schedule_hours":0}'`, "R-165", DecisionDeny),
		{
			name: "Invoke-RestMethod scanner database accept", kind: KindShellExec, dialect: DialectPowerShell,
			target: `Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8821/api/security/scanners/db -Body '{}'`, wantRule: "R-165", wantEnforce: DecisionDeny,
		},
		// Operator ruling PT-19: an agent switching the signed index download
		// off lowers the package checks (the config set row and the keys
		// route both carry every [security] key).
		sh("config set index download off", `observer config set security.deps.index_download false`, "R-165", DecisionDeny),
		sh("PUT index download off", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"security.deps.index_download","value":false}]}'`, "R-165", DecisionDeny),
		sh("POST prompt allow", `curl --json '{}' http://[::1]:8821/api/guard/prompt/allow`, "R-165", DecisionDeny),
		sh("PUT policy", `curl -X PUT http://localhost:8821/api/guard/policy --data @p.toml`, "R-165", DecisionDeny),
		sh("PUT trusted project policy", `curl -X PUT http://localhost:8821/api/guard/policy/project -d x`, "R-165", DecisionDeny),
		sh("PATCH a rule", `curl -X PATCH http://localhost:8821/api/guard/rules/R-110 -d '{}'`, "R-165", DecisionDeny),
		sh("POST policy backup restore", `curl -X POST http://127.0.0.1:8821/api/guard/policy/backup`, "R-165", DecisionDeny),
		sh("POST a custom scanner accept", `curl -X POST http://127.0.0.1:8821/api/security/scanners/custom/accept -d '{}'`, "R-165", DecisionDeny),
		sh("PUT the guard config section", `curl -X PUT http://127.0.0.1:8821/api/config/section/guard -d '{}'`, "R-165", DecisionDeny),
		sh("PUT a guard subsection", `curl -X PUT http://127.0.0.1:8821/api/config/section/guard.budget -d '{}'`, "R-165", DecisionDeny),
		sh("PUT a guard key", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"guard.mode","value":"observe"}]}'`, "R-165", DecisionDeny),
		sh("PUT another config key", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"compression.enabled","value":true}]}'`, "", 0),
		sh("PUT another config section", `curl -X PUT http://127.0.0.1:8821/api/config/section/guardian -d '{}'`, "", 0),
		sh("GET policy backup", `curl http://127.0.0.1:8821/api/guard/policy/backup`, "", 0),
		sh("wget post", `wget --post-data='{}' http://127.0.0.1:8821/api/guard/approvals`, "R-165", DecisionDeny),
		{
			name: "Invoke-RestMethod post", kind: KindShellExec, dialect: DialectPowerShell,
			target: `Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8821/api/guard/approvals -Body '{}'`, wantRule: "R-165", wantEnforce: DecisionDeny,
		},
		sh("httpie post", `http POST localhost:8821/api/guard/approvals rule_id=R-110`, "R-165", DecisionDeny),
		sh("GET approvals", `curl http://127.0.0.1:8821/api/guard/approvals`, "", 0),
		sh("DELETE an approval (revoke)", `curl -X DELETE http://127.0.0.1:8821/api/guard/approvals/3`, "", 0),
		sh("POST policy lint", `curl -X POST http://127.0.0.1:8821/api/guard/policy/lint -d x`, "", 0),
		sh("POST to a remote host", `curl -X POST https://example.com/api/guard/approvals -d '{}'`, "", 0),
		// SQL row.
		sh("sqlite3 insert", `sqlite3 /home/u/.observer/observer.db "INSERT INTO guard_approvals (rule_id) VALUES ('R-110')"`, "R-165", DecisionDeny),
		sh("sqlite3 update through a heredoc", "sqlite3 db.sqlite <<EOF\nUPDATE guard_approvals SET expires_at = 9999999999;\nEOF", "R-165", DecisionDeny),
		sh("python one-liner insert", `python3 -c "import sqlite3; sqlite3.connect('o.db').execute('insert or replace into guard_approvals values (1)')"`, "R-165", DecisionDeny),
		sh("sqlite3 select", `sqlite3 db.sqlite "SELECT * FROM guard_approvals"`, "", 0),
		sh("sqlite3 trust accept", `sqlite3 o.db "UPDATE sec_config_baseline SET accepted_at = 'now'"`, "R-165", DecisionDeny),
		// Lane sec-c3: finding exceptions and baselines.
		sh("security exception add", `observer security exception add 01JX --reason false_positive --expires 30d`, "R-165", DecisionDeny),
		sh("security baseline approve", `observer security baseline --approve HEAD`, "R-165", DecisionDeny),
		sh("security baseline show", `observer security baseline`, "", 0),
		sh("security exception list", `observer security exception list`, "", 0),
		sh("security githooks uninstall", `observer security githooks uninstall`, "R-165", DecisionDeny),
		sh("security githooks status", `observer security githooks status`, "", 0),
		// Lane sec-gate2 (decision log P-025): the githooks install is the
		// developer's consent; the security settings and their HTTP forms;
		// deleting findings.
		sh("security githooks install", `observer security githooks install`, "R-165", DecisionDeny),
		// Lane sec-f2a: the AI change records' consent and key reset.
		sh("security provenance consent", `observer security provenance consent --notes=true`, "R-165", DecisionDeny),
		sh("security provenance consent withdraw", `observer security provenance consent --trailer=false`, "R-165", DecisionDeny),
		sh("security provenance rotate-key", `observer security provenance rotate-key`, "R-165", DecisionDeny),
		sh("security provenance status", `observer security provenance status`, "", 0),
		sh("security provenance records", `observer security provenance records --json`, "", 0),
		sh("components remove security.provenance", `observer components remove security.provenance --yes`, "R-165", DecisionDeny),
		sh("POST provenance consent", `curl -X POST http://127.0.0.1:8821/api/security/provenance -d '{"action":"consent","notes":true}'`, "R-165", DecisionDeny),
		sh("sqlite3 consent insert", `sqlite3 o.db "INSERT INTO sec_change_consent (project_root_hash, root_path, trailer) VALUES ('h','/r',1)"`, "R-165", DecisionDeny),
		sh("sqlite3 key update", `sqlite3 o.db "UPDATE sec_change_keys SET retired_at = ''"`, "R-165", DecisionDeny),
		sh("forge an agent-commit marker", `echo '{}' > /home/u/.observer/security/provenance/pending/abc.json`, "R-165", DecisionDeny),
		sh("config set the write check off", `observer config set security.secrets.write_check false`, "R-165", DecisionDeny),
		sh("config set the commit check off", `observer config set security.secrets.commit_check false`, "R-165", DecisionDeny),
		sh("config set the post-write cap", `observer config set security.secrets.postwrite_cap_kib 64`, "R-165", DecisionDeny),
		sh("config set a security key, mixed case", `observer config set Security.Secrets.Write_Check off`, "R-165", DecisionDeny),
		sh("config set a key named like it", `observer config set securityx.enabled false`, "", 0),
		sh("PUT the security config section", `curl -X PUT http://127.0.0.1:8821/api/config/section/security -d '{}'`, "R-165", DecisionDeny),
		sh("PUT a security subsection", `curl -X PUT http://127.0.0.1:8821/api/config/section/security.secrets -d '{"write_check":false}'`, "R-165", DecisionDeny),
		sh("PUT a security key", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"security.secrets.write_check","value":false}]}'`, "R-165", DecisionDeny),
		sh("GET the security section", `curl http://127.0.0.1:8821/api/config/section/security`, "", 0),
		sh("POST githooks install", `curl -X POST http://127.0.0.1:8821/api/security/githooks -d '{"project":"h","action":"install"}'`, "R-165", DecisionDeny),
		sh("POST githooks uninstall", `curl -X POST http://127.0.0.1:8821/api/security/githooks -d '{"project":"h","action":"uninstall"}'`, "R-165", DecisionDeny),
		sh("GET githooks state", `curl 'http://127.0.0.1:8821/api/security/githooks?project=h'`, "", 0),
		// (An unconditional DELETE or a DROP through a database CLI is R-120's
		// as well; these are the forms only R-165 sees.)
		sh("sqlite3 delete the open findings", `sqlite3 o.db "DELETE FROM sec_findings WHERE status = 'open'"`, "R-165", DecisionDeny),
		sh("sqlite3 delete one finding", `sqlite3 o.db "delete from sec_findings where id='x'"`, "R-165", DecisionDeny),
		sh("python one-liner drop", `python3 -c "import sqlite3; sqlite3.connect('o.db').execute('drop table sec_findings')"`, "R-165", DecisionDeny),
		sh("sqlite3 delete an approval (revoke)", `sqlite3 o.db "DELETE FROM guard_approvals WHERE id=3"`, "", 0),
		sh("sqlite3 delete scan runs", `sqlite3 o.db "DELETE FROM sec_scan_runs"`, "", 0),
		sh("security exception revoke", `observer security exception revoke 3`, "", 0),
		sh("POST an exception", `curl -X POST http://127.0.0.1:8821/api/security/exceptions -d '{"finding_id":"x"}'`, "R-165", DecisionDeny),
		sh("POST a baseline", `curl -X POST http://localhost:8821/api/security/baseline -d '{"action":"approve"}'`, "R-165", DecisionDeny),
		sh("POST a revoke", `curl -X POST http://127.0.0.1:8821/api/security/exceptions/revoke -d '{"id":1}'`, "", 0),
		sh("sqlite3 finding status", `sqlite3 o.db "update sec_findings set status='suppressed'"`, "R-165", DecisionDeny),
		sh("sqlite3 exception insert", `sqlite3 o.db "INSERT INTO sec_finding_exceptions (finding_id) VALUES ('x')"`, "R-165", DecisionDeny),
		sh("sqlite3 findings read", `sqlite3 o.db "SELECT * FROM sec_findings"`, "", 0),
		// Lane sec-gate3 milestone 2a: removing the security module or a
		// child, and their HTTP forms.
		sh("components remove security", `observer components remove security --yes`, "R-165", DecisionDeny),
		sh("components remove a security child", `observer components remove security.secrets --yes`, "R-165", DecisionDeny),
		sh("components remove a child among others", `observer components remove codeintel Security.Code --yes`, "R-165", DecisionDeny),
		sh("components remove through npx", `npx @superbased/observer components remove security.githooks --yes`, "R-165", DecisionDeny),
		sh("components remove preview", `observer components remove security`, "", 0),
		sh("components remove another component", `observer components remove codeintel --yes`, "", 0),
		sh("components remove a name like it", `observer components remove securityx --yes`, "", 0),
		sh("components add security tightens", `observer components add security.githooks --yes`, "", 0),
		sh("components teardown security", `observer components teardown security.githooks`, "R-165", DecisionDeny),
		sh("components teardown dry run", `observer components teardown security.githooks --dry-run`, "", 0),
		sh("components teardown another", `observer components teardown codeintel`, "", 0),
		sh("POST an apply removing security", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"remove":["security.secrets"]},"fingerprint":"f"}'`, "R-165", DecisionDeny),
		sh("POST an apply removing the root, escaped", `curl -X POST http://127.0.0.1:8821/api/components/apply -d "{\"change\":{\"remove\":[\"codeintel\",\"security\"]},\"fingerprint\":\"f\"}"`, "R-165", DecisionDeny),
		sh("POST an apply adding security", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"add":["security.githooks"]},"fingerprint":"f"}'`, "", 0),
		sh("POST an apply removing another", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"remove":["codeintel"],"add":["security"]},"fingerprint":"f"}'`, "", 0),
		sh("POST an apply from a file", `curl -X POST http://127.0.0.1:8821/api/components/apply --data-binary @change.json`, "R-165", DecisionDeny),
		sh("POST a teardown of security", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.githooks"]}'`, "R-165", DecisionDeny),
		sh("POST a teardown of another", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["codeintel"]}'`, "", 0),
		sh("POST a preview removing security", `curl -X POST http://127.0.0.1:8821/api/components/preview -d '{"change":{"remove":["security"]}}'`, "", 0),
		// Audit finding 1 of lane sec-gate3: removing what the security
		// tree requires (guard) cascades to the security module.
		sh("components remove guard", `observer components remove guard --yes`, "R-165", DecisionDeny),
		sh("components remove guard among others, other case", `observer components remove codeintel Guard --yes`, "R-165", DecisionDeny),
		sh("components remove guard through npx", `npx @superbased/observer components remove guard --yes`, "R-165", DecisionDeny),
		sh("components remove guard preview", `observer components remove guard`, "", 0),
		sh("components remove a guard child", `observer components remove guard.cloud --yes`, "", 0),
		sh("POST an apply removing guard", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"remove":["guard"]},"fingerprint":"f"}'`, "R-165", DecisionDeny),
		sh("POST an apply removing guard, escaped", `curl -X POST http://127.0.0.1:8821/api/components/apply -d "{\"change\":{\"remove\":[\"codeintel\",\"Guard\"]},\"fingerprint\":\"f\"}"`, "R-165", DecisionDeny),
		sh("POST an apply removing a guard child", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"remove":["guard.cloud"]},"fingerprint":"f"}'`, "", 0),
		sh("POST an apply adding guard", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"add":["guard"]},"fingerprint":"f"}'`, "", 0),
		// Lane sec-gate4 milestone 2b: a base selection that leaves the
		// security module off, and a selection reset, CLI and API forms.
		sh("components select minimal", `observer components select minimal --yes`, "R-165", DecisionDeny),
		sh("components select managed, other case", `observer components select Managed --yes`, "R-165", DecisionDeny),
		sh("components select a typo", `observer components select minmal --yes`, "R-165", DecisionDeny),
		sh("components select minimal through npx", `npx @superbased/observer components select minimal --yes`, "R-165", DecisionDeny),
		sh("components select minimal preview", `observer components select minimal`, "", 0),
		sh("components select all", `observer components select all --yes`, "", 0),
		// developer compiles security.scan.scalibr out (offered since P-036).
		sh("components select developer", `observer components select developer --yes`, "R-165", DecisionDeny),
		sh("components select full", `observer components select full --yes`, "", 0),
		sh("POST an apply selecting minimal", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"set_base":"minimal"},"fingerprint":"f"}'`, "R-165", DecisionDeny),
		sh("POST an apply selecting managed, escaped", `curl -X POST http://127.0.0.1:8821/api/components/apply -d "{\"change\":{\"set_base\":\"managed\"},\"fingerprint\":\"f\"}"`, "R-165", DecisionDeny),
		sh("POST an apply selecting all", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"set_base":"all"},"fingerprint":"f"}'`, "", 0),
		sh("POST an apply selecting developer", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"set_base":"developer"},"fingerprint":"f"}'`, "R-165", DecisionDeny),
		sh("POST an apply resetting", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"reset":true},"fingerprint":"f"}'`, "R-165", DecisionDeny),
		sh("POST an apply not resetting", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"reset":false,"add":["codeintel"]},"fingerprint":"f"}'`, "", 0),
		sh("PowerShell apply selecting minimal", `Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8821/api/components/apply -Body '{"change":{"set_base":"minimal"},"fingerprint":"f"}'`, "R-165", DecisionDeny),
		sh("POST a preview selecting minimal", `curl -X POST http://127.0.0.1:8821/api/components/preview -d '{"change":{"set_base":"minimal"}}'`, "", 0),
		// Lane sec-gate4 milestone 2c: a teardown body with dry_run true
		// only previews.
		sh("POST a teardown dry run of security", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.githooks"],"dry_run":true}'`, "", 0),
		sh("POST a teardown, dry run false", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.githooks"],"dry_run":false}'`, "R-165", DecisionDeny),
		sh("POST a teardown dry run from a file", `curl -X POST http://127.0.0.1:8821/api/components/teardown --data-binary @t.json`, "R-165", DecisionDeny),
		// Lane sec-gate4 audit finding 1: the dry run allows only when the
		// decoded body's top-level dry_run is true, every occurrence of it.
		sh("POST a teardown, duplicate dry_run ending false", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.githooks"],"dry_run":true,"dry_run":false}'`, "R-165", DecisionDeny),
		sh("POST a teardown, duplicate dry_run in another case", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.githooks"],"DRY_RUN":false,"dry_run":true}'`, "R-165", DecisionDeny),
		sh("POST a teardown, duplicate dry_run both true", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.githooks"],"dry_run":true,"dry_run":true}'`, "", 0),
		sh("POST a teardown, dry_run in a header", `curl -X POST -H 'X-Note: {"dry_run":true}' http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.githooks"]}'`, "R-165", DecisionDeny),
		sh("POST a teardown, dry_run in a nested field", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.githooks"],"opts":{"dry_run":true}}'`, "R-165", DecisionDeny),
		sh("POST a teardown, dry_run a string", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.githooks"],"dry_run":"true"}'`, "R-165", DecisionDeny),
		sh("POST a teardown, two bodies", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.githooks"]}' -d '{"dry_run":true}'`, "R-165", DecisionDeny),
		sh("POST a teardown dry run, escaped key", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.githooks"],"dry_run":true}'`, "", 0),
		sh("POST a teardown, escaped ids", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["security.githooks"]}'`, "R-165", DecisionDeny),
		sh("POST a teardown, escaped ids key", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["Security"]}'`, "R-165", DecisionDeny),
		sh("POST a teardown of another component", `curl -X POST http://127.0.0.1:8821/api/components/teardown -d '{"ids":["codeintel"]}'`, "", 0),
		// Audit finding 2: the decoded values, escapes and keys included,
		// and an undecodable body that names the route is denied.
		sh("POST an apply selecting minimal, unicode escape", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"set_base":"minimal"},"fingerprint":"f"}'`, "R-165", DecisionDeny),
		sh("POST an apply selecting managed, escaped key", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"set_base":"managed"},"fingerprint":"f"}'`, "R-165", DecisionDeny),
		sh("POST an apply selecting all, unicode escape", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"set_base":"all"},"fingerprint":"f"}'`, "", 0),
		sh("POST an apply selecting full", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"set_base":"full"},"fingerprint":"f"}'`, "", 0),
		sh("POST an apply, duplicate set_base", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"set_base":"all","set_base":"minimal"},"fingerprint":"f"}'`, "R-165", DecisionDeny),
		sh("POST an apply resetting, escaped key", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"reset":true},"fingerprint":"f"}'`, "R-165", DecisionDeny),
		sh("POST an apply resetting, other case", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"RESET":true},"fingerprint":"f"}'`, "R-165", DecisionDeny),
		sh("POST an apply removing guard, unicode escape", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"remove":["guard"]},"fingerprint":"f"}'`, "R-165", DecisionDeny),
		sh("POST an apply removing security, escaped key", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"remove":["security.secrets"]},"fingerprint":"f"}'`, "R-165", DecisionDeny),
		sh("POST an apply, undecodable body", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"add":["codeintel"]'`, "R-165", DecisionDeny),
		sh("POST an apply, form body", `curl -X POST http://127.0.0.1:8821/api/components/apply -d 'set_base=minimal'`, "R-165", DecisionDeny),
		sh("POST an apply, trailing second value", `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"add":["codeintel"]}} {"change":{"reset":true}}'`, "R-165", DecisionDeny),
		sh("httpie apply items", `http POST localhost:8821/api/components/apply change:='{"add":["codeintel"]}'`, "R-165", DecisionDeny),
		sh("PUT a guard key, escaped key", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"guard.mode","value":"off"}]}'`, "R-165", DecisionDeny),
		sh("PUT a security key, escaped value", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"security.secrets.write_check","value":false}]}'`, "R-165", DecisionDeny),
		// Lane sec-gate3 milestone 2b: schema-qualified names, and the
		// config keys body read by key path.
		sh("sqlite3 delete, schema-qualified", `sqlite3 o.db "DELETE FROM main.sec_findings WHERE status = 'open'"`, "R-165", DecisionDeny),
		sh("sqlite3 delete, quoted schema", `sqlite3 o.db 'DELETE FROM "main"."sec_findings" WHERE 1'`, "R-165", DecisionDeny),
		sh("sqlite3 update, schema-qualified", `sqlite3 o.db "UPDATE main.sec_findings SET status='suppressed'"`, "R-165", DecisionDeny),
		sh("sqlite3 insert, schema-qualified", `sqlite3 o.db "INSERT INTO main . guard_approvals (rule_id) VALUES ('R-1')"`, "R-165", DecisionDeny),
		sh("sqlite3 delete held commits", `sqlite3 o.db "DELETE FROM sec_finding_commits WHERE 1"`, "R-165", DecisionDeny),
		sh("sqlite3 read, schema-qualified", `sqlite3 o.db "SELECT * FROM main.sec_findings"`, "", 0),
		sh("PUT another key whose value says security", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"compression.mode","value":"security"}]}'`, "", 0),
		sh("PUT another key with a security header", `curl -X PUT -H 'X-Security: 1' http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"ui.theme","value":"dark"}]}'`, "", 0),
		sh("PUT a guard key, escaped quotes", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d "{\"patches\":[{\"key\":\"guard.mode\",\"value\":\"off\"}]}"`, "R-165", DecisionDeny),
		sh("PUT keys from a file", `curl -X PUT http://127.0.0.1:8821/api/config/keys -d @patch.json`, "R-165", DecisionDeny),
		// Lane sec-deps4 audit finding 1: writing the consent records directly
		// is giving the consent, so it is R-165's, ahead of R-160.
		sh("echo into the database accept record", `echo '{"version":1,"accepted_at":"2026-10-21T09:00:00Z","surface":"cli"}' > /home/u/.observer/security/osv-db-consent.json`, "R-165", DecisionDeny),
		sh("redirect with a tilde", `printf '{}' > ~/.observer/security/osv-db-consent.json`, "R-165", DecisionDeny),
		sh("append to the disclosure record", `echo '{}' >> ~/.observer/security/online-disclosure.json`, "R-165", DecisionDeny),
		sh("tee the database accept record", `echo '{}' | tee /home/u/.observer/security/osv-db-consent.json`, "R-165", DecisionDeny),
		sh("cp onto the disclosure record", `cp /tmp/d.json /home/u/.observer/security/online-disclosure.json`, "R-165", DecisionDeny),
		sh("mv onto the database accept record", `mv /tmp/c.json ~/.observer/security/osv-db-consent.json`, "R-165", DecisionDeny),
		sh("cd then redirect", `cd ~/.observer/security && echo '{}' > osv-db-consent.json`, "R-165", DecisionDeny),
		sh("another observer home", `echo '{}' > /srv/obs/security/osv-db-consent.json`, "R-165", DecisionDeny),
		sh("python one-liner write", `python3 -c "open('/home/u/.observer/security/osv-db-consent.json','w').write('{}')"`, "R-165", DecisionDeny),
		sh("node one-liner write", `node -e "require('fs').writeFileSync('/home/u/.observer/security/online-disclosure.json','{}')"`, "R-165", DecisionDeny),
		{
			name: "PowerShell Set-Content", kind: KindShellExec, dialect: DialectPowerShell,
			target: `Set-Content -Path C:\Users\u\.observer\security\osv-db-consent.json -Value '{}'`, wantRule: "R-165", wantEnforce: DecisionDeny,
		},
		{
			name: "Write tool on the database accept record", kind: KindFileAccess, actionType: "write_file",
			target: "/home/u/.observer/security/osv-db-consent.json", wantRule: "R-165", wantEnforce: DecisionDeny,
		},
		{
			name: "Edit tool on the disclosure record", kind: KindFileAccess, actionType: "edit_file",
			target: "/home/u/.observer/security/online-disclosure.json", wantRule: "R-165", wantEnforce: DecisionDeny,
		},
		sh("echo into the Opengrep install consent", `echo '{}' > ~/.observer/security/opengrep-install-consent.json`, "R-165", DecisionDeny),
		{
			name: "Write tool on the Opengrep install consent", kind: KindFileAccess, actionType: "write_file",
			target: "/home/u/.observer/security/opengrep-install-consent.json", wantRule: "R-165", wantEnforce: DecisionDeny,
		},
		sh("cat the database accept record is a read", `cat /home/u/.observer/security/osv-db-consent.json`, "", 0),
		sh("a project file of another name", `echo '{}' > /home/u/proj/security/consent.json`, "", 0),
		// Request row: recorded, never blocked.
		sh("request access", `observer request access "need to push" --rule R-110`, "R-165", DecisionFlag),
		sh("request budget is not a guard exception", `observer request budget "more"`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}

// TestSelfApprovalRuleIsIntegrity pins R-165 in the integrity set: a
// below-org disable or relaxation leaves the deny standing, because a layer
// that relaxed it would let an agent grant itself any exception.
func TestSelfApprovalRuleIsIntegrity(t *testing.T) {
	t.Parallel()
	if !IsIntegrityRuleID("R-165") {
		t.Fatal("integrity set: want R-165 in")
	}
	allow := DecisionAllow
	ev := Event{Kind: KindShellExec, Target: "observer guard approve R-101 --global", Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj"}
	for name, cfg := range map[string]Config{
		"disabled": {Mode: ModeEnforce, Home: "/home/u", Disabled: []string{"R-165"}},
		"relaxed":  {Mode: ModeEnforce, Home: "/home/u", Overrides: []Override{{RuleID: "R-165", Decision: &allow, Source: "user"}}},
		"capped":   {Mode: ModeEnforce, Home: "/home/u", Overrides: []Override{{RuleID: "R-165", EnforceOff: true, Source: "user"}}},
	} {
		e, err := New(cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if v := e.Evaluate(ev); v.RuleID != "R-165" || v.Decision != DecisionDeny {
			t.Errorf("%s: verdict %s/%s, want R-165/deny", name, v.RuleID, v.Decision)
		}
	}
}

// TestBoolFlagTrue is the parser table behind the R-165 preview rows (lane
// SEC-G4 audit finding 7): a value reads the way pflag reads a bool flag,
// strconv.ParseBool, so a real preview is never denied as a write, and an
// unreadable value stays not set.
func TestBoolFlagTrue(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"--dry-run"}, true},
		{[]string{"x", "--dry-run", "y"}, true},
		{nil, false},
		{[]string{"--dry-run-x"}, false},
		{[]string{"--dry-run=", "y"}, false},
		{[]string{"--dry-run", "--dry-run=false"}, false},
		{[]string{"--dry-run=false", "--dry-run"}, true},
		{[]string{"--config", "--dry-run"}, false},
		{[]string{"--", "--dry-run"}, false},
	}
	for _, v := range []string{"1", "t", "T", "TRUE", "true", "True"} {
		cases = append(cases, struct {
			args []string
			want bool
		}{[]string{"--dry-run=" + v}, true})
	}
	for _, v := range []string{"0", "f", "F", "FALSE", "false", "False", "yes", "on", "tRuE", "2", " true"} {
		cases = append(cases, struct {
			args []string
			want bool
		}{[]string{"--dry-run=" + v}, false})
	}
	for _, c := range cases {
		if got := boolFlagTrue(c.args, "--dry-run"); got != c.want {
			t.Errorf("boolFlagTrue(%q) = %v, want %v", c.args, got, c.want)
		}
	}
}
