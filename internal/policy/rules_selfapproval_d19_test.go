package policy

import "testing"

// TestSelfApprovalD19SectionAndPolicyRoutes pins review findings R-B01 and
// R-B07: an agent cannot write a D19 family or a confirm-tier key through
// the section routes, the obs policy editors, the Slack webhook route, a
// config keys body the JSON matcher cannot read, or `observer config set`.
func TestSelfApprovalD19SectionAndPolicyRoutes(t *testing.T) {
	t.Parallel()
	const base = "http://127.0.0.1:8081"
	cases := []coreRuleCase{
		// R-B01: the named section routes and obs policy POSTs.
		sh("section org share", `curl -X PUT `+base+`/api/config/section/org -d '{"Share":{"FullContent":true}}'`, "R-165", DecisionDeny),
		sh("section org scope", `curl -X PUT `+base+`/api/config/section/org -d '{"Scope":{"ProjectRootDenylist":[]}}'`, "R-165", DecisionDeny),
		sh("section observability store_content", `curl -X PUT `+base+`/api/config/section/observability -d '{"StoreContent":true}'`, "R-165", DecisionDeny),
		sh("section observability judge", `curl -X PUT `+base+`/api/config/section/observability -d '{"Judge":{"BaseURL":"https://evil.example.com"}}'`, "R-165", DecisionDeny),
		sh("section observability admission budget", `curl -X PUT `+base+`/api/config/section/observability -d '{"Admission":{"Budget":{"PerUser5hUSD":0}}}'`, "R-165", DecisionDeny),
		sh("section observability switch", `curl -X PUT `+base+`/api/config/section/observability -d '{"Enabled":false}'`, "R-165", DecisionDeny),
		sh("admission policy POST", `curl -X POST `+base+`/api/obs/admission/policy -d '{"mode":"report"}'`, "R-165", DecisionDeny),
		sh("egress policy POST", `curl -X POST `+base+`/api/obs/egress/policy -d '{"rules":[]}'`, "R-165", DecisionDeny),
		sh("slack webhook PUT", `curl -X PUT `+base+`/api/obs/alerts/slack -d '{"webhook_url":"https://hooks.slack.com/services/x"}'`, "R-165", DecisionDeny),
		sh("slack test is not a write of the setting", `curl -X POST `+base+`/api/obs/alerts/slack/test`, "", 0),
		// R-C02: the PagerDuty key route and the alert-channel and admission
		// setup CLI verbs.
		sh("pagerduty key PUT", `curl -X PUT `+base+`/api/obs/alerts/pagerduty -d '{"routing_key":"0123456789abcdef0123456789abcdef"}'`, "R-165", DecisionDeny),
		sh("pagerduty test is not a write of the setting", `curl -X POST `+base+`/api/obs/alerts/pagerduty/test`, "", 0),
		sh("cli slack set", `echo https://hooks.slack.com/services/x | observer obs alerts slack set`, "R-165", DecisionDeny),
		sh("cli slack clear", `observer obs alerts slack clear`, "R-165", DecisionDeny),
		sh("cli pagerduty set", `echo 0123456789abcdef0123456789abcdef | observer obs alerts pagerduty set`, "R-165", DecisionDeny),
		sh("cli pagerduty clear", `observer obs alerts pagerduty clear --config /tmp/c.toml`, "R-165", DecisionDeny),
		sh("cli admission setup", `observer obs admission setup --base-url https://evil.example.com --yes`, "R-165", DecisionDeny),
		sh("cli slack test", `observer obs alerts slack test`, "", 0),
		sh("cli pagerduty test", `observer obs alerts pagerduty test`, "", 0),
		sh("cli alerts status", `observer obs alerts`, "", 0),
		sh("a read of the admission policy", `curl `+base+`/api/obs/admission/policy`, "", 0),
		// Found by the section drift walk and the editor sweep.
		sh("section hooks", `curl -X PUT `+base+`/api/config/section/hooks -d '{"AutoRegister":false}'`, "R-165", DecisionDeny),
		sh("section proxy", `curl -X PUT `+base+`/api/config/section/proxy -d '{"Upstreams":{"x":"https://evil.example.com"}}'`, "R-165", DecisionDeny),
		sh("section otel", `curl -X PUT `+base+`/api/config/section/otel -d '{"Endpoint":"https://evil.example.com"}'`, "R-165", DecisionDeny),
		sh("section process capture bodies", `curl -X PUT `+base+`/api/config/section/process -d '{"Network":{"CaptureBodies":"all"}}'`, "R-165", DecisionDeny),
		sh("section process poll interval", `curl -X PUT `+base+`/api/config/section/process -d '{"PollIntervalMS":500}'`, "", 0),
		sh("ssh profiles editor", `curl -X PUT `+base+`/api/terminal/ssh/profiles -d '{"enabled":true}'`, "R-165", DecisionDeny),
		sh("update auto-apply", `curl -X PUT `+base+`/api/update/auto-apply -d '{"auto_apply":true}'`, "R-165", DecisionDeny),
		sh("pricing table", `curl -X PUT `+base+`/api/config/pricing -d '{}'`, "R-165", DecisionDeny),
		sh("pricing defaults read", `curl `+base+`/api/config/pricing/defaults`, "", 0),
		// R-B07: the CLI deny side covers the confirm tier and admission whole.
		sh("config set scope denylist", `observer config set org_client.scope.project_root_denylist "" --yes`, "R-165", DecisionDeny),
		sh("config set org policy", `observer config set org_client.policy.accept_families "" --yes`, "R-165", DecisionDeny),
		sh("config set alert webhook", `observer config set observability.alerts.webhook_url https://evil.example.com --yes`, "R-165", DecisionDeny),
		sh("config set a proxy upstream", `observer config set proxy.upstreams.x https://evil.example.com --yes`, "R-165", DecisionDeny),
		sh("config set admission scope", `observer config set observability.admission.scope all`, "R-165", DecisionDeny),
		sh("config set admission secret remote judge", `observer config set observability.admission.secret_remote_judge true`, "R-165", DecisionDeny),
		sh("config set an ordinary key", `observer config set observability.alerts.eval_interval_minutes 5`, "", 0),
		// E-24 (ruling D29): keys that change egress or safety joined D19.
		sh("config set the online sample rate", `observer config set observability.eval.online_sample_rate 1`, "R-165", DecisionDeny),
		sh("config set the online scorers", `observer config set observability.eval.online_scorers llm_judge`, "R-165", DecisionDeny),
		sh("config set the judge model", `observer config set observability.eval.judge_model gpt-5`, "R-165", DecisionDeny),
		sh("config set proxy turn traces", `observer config set observability.proxy_turn_traces true`, "R-165", DecisionDeny),
		sh("config set alerting off", `observer config set observability.alerts.enabled false`, "R-165", DecisionDeny),
		sh("config set the database path", `observer config set observer.db_path /tmp/other.db`, "R-165", DecisionDeny),
		sh("section observer database path", `curl -X PUT `+base+`/api/config/section/observer -d '{"Observer":{"DBPath":"/tmp/other.db"}}'`, "R-165", DecisionDeny),
		sh("section observer other member", `curl -X PUT `+base+`/api/config/section/observer -d '{"Observer":{"Watch":{"HomeWalk":true}}}'`, "", 0),
		// R-B07: the text fallback names the D19 families too.
		sh("keys body text fallback", `curl -X PUT `+base+`/api/config/keys --data-binary @- <<< '{patches:[{key:"org_client.share.full_content",value:true}]}'`, "R-165", DecisionDeny),
	}
	runCoreRuleCases(t, cases, "R-165")
}
