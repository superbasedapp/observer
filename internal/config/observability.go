package config

// This file holds the config types of [observability] (AI Apps on the
// machine) and [selfobs].

// SelfObsConfig is the [selfobs] surface (P1-10 production retrofit,
// docs/plans/plane-a-p1-10-production-retrofit-plan.md). LOCAL-ONLY.
// Default OFF — emission is a credential-bearing OTLP call to the org
// gateway and must never fire without operator consent + keys.
type SelfObsConfig struct {
	// Enabled gates sink construction. false ⇒ emit.Nop().
	Enabled bool `toml:"enabled"`
	// Endpoint is the OTLP/HTTP gateway endpoint (host:port or full URL).
	Endpoint string `toml:"endpoint"`
	// KeyID / Secret compose the ingest credential; Token (if set) wins.
	KeyID  string `toml:"key_id"`
	Secret string `toml:"secret"`
	Token  string `toml:"token"`
	// Insecure permits plaintext http:// (default requires https://).
	Insecure bool `toml:"insecure"`
	// ServiceName overrides the OTLP resource service.name.
	ServiceName string `toml:"service_name"`
	// RoutingSampleN controls routing Decide emission: 0 = off, 1 = every
	// decide, N = 1-of-N sample (plan fork 1; default 32).
	RoutingSampleN int `toml:"routing_sample_n"`
}

// ObservabilityConfig is the [observability] surface — the generalized
// observability subsystem (internal/obs; plan
// docs/plans/generalized-observability-custom-app-plan-2026-06-27.md). It is
// OPT-IN (default false): unlike CacheTrack/Guard/Advisor, the zero value is
// the intended default, so no partial-merge entry is required — an install
// with no [observability] section keeps the subsystem off and creates no
// obs_* tables. The subsystem is additionally compiled out by the no_obs
// build tag for minimal distributions (decision D2).
type ObservabilityConfig struct {
	// Enabled gates the whole subsystem: the OTLP /v1/traces receiver,
	// the obs_* schema (applied only when true), ingestion, the
	// trajectory API, and the eval plane. Default false.
	Enabled bool `toml:"enabled"`

	// Eval configures the minimal eval plane (plan §8). Zero value = the
	// `observer eval` CLI works on demand with code scorers; no online
	// sampling, no judge.
	Eval ObservabilityEvalConfig `toml:"eval"`

	// Judge is the SHARED judge binding (admission spec §14 Q4 decision,
	// 2026-07-05): a single [observability.judge] block that both the eval
	// plane and admission fall back to when they don't set their own judge
	// fields. Zero value = no shared judge; the pre-existing
	// [observability.eval] judge_* keys still win where set (no break).
	Judge ObservabilityJudgeConfig `toml:"judge"`

	// Admission configures the input-admission gate (admission spec) — an
	// LLM-as-judge that evaluates incoming user requests to a co-resident
	// agentic app against an admin policy. Zero value = admission off (no
	// schema cost beyond the shared obs migration). Engages only in the
	// co-resident-app posture; meaningless at the coding-agent node.
	Admission ObservabilityAdmissionConfig `toml:"admission"`

	// Alerts configures NODE-SIDE alert evaluation (general-observability
	// gap-audit item #9): threshold rules over this node's OWN local obs_*
	// data, so a node with org sharing off still gets error-rate / cost / p95
	// alerting (org-side alerting in internal/orgserver/obsalert only fires on
	// pushed summaries). Zero value = off. Default false because a fired alert
	// makes an outbound webhook call — explicit opt-in keeps the node
	// egress-free by default.
	Alerts ObservabilityAlertsConfig `toml:"alerts"`

	// Egress configures Plane-A policy egress routing (G22): after admission
	// judges a request, a policy layer may route it to an alternate declared
	// upstream, swap to a cheaper same-shape model, degrade effort, or deny —
	// composed on top of the admission verdict. LOCAL-ONLY, DEFAULT OFF (zero
	// value, same partial-merge rule as the other observability blocks). The
	// obs_egress_decisions audit table is node-local, never pushed.
	Egress ObservabilityEgressConfig `toml:"egress"`

	// ProxyTurnTraces is the "gateway rail" (docs/observability.md "proxy
	// turn (automatic)"): when true (and Enabled is true), a proxied LLM
	// turn that arrived on an explicit /up/<id> upstream lane — the lane a
	// co-resident hosted app is pointed at (e.g. Open WebUI via
	// /up/openrouter) — is synthesized into an obs_traces/obs_spans pair
	// (chat.turn/chat.completions) at insert time, so it appears in the org
	// Trajectory explorer without the app instrumenting anything.
	//
	// PLANE BOUNDARY: synthesis covers ONLY /up/<id> lane traffic. The
	// default provider lanes (ANTHROPIC_BASE_URL, codex base_url, gemini)
	// carry Plane-B coding agents, whose rail is api_turns → sessions → the
	// coding-agent org rollups; they must never appear in the Hosted Apps
	// (Plane A) Trajectory explorer. An earlier all-lanes default mixed the
	// two planes (operator-reported, 2026-08-13) and was reversed. Residual:
	// a coding agent deliberately routed through a /up/ lane (hermes →
	// OpenRouter) still synthesizes; disable this key or give that agent a
	// dedicated upstream id if that matters for your deployment.
	//
	// Default() seeds it true so the loader's partial-merge keeps it true
	// for an existing [observability] section that only sets `enabled` (the
	// CacheTrack partial-merge rule); it has no effect while Enabled is
	// false.
	ProxyTurnTraces bool `toml:"proxy_turn_traces"`

	// StoreContent is the node-local Plane A content key (D8, D17, F07):
	// when true, captured prompt, response and tool bodies of a hosted app's
	// spans (and the matching eval-dataset snapshots and admission excerpts)
	// are kept raw in this node's own obs_* tables, after mandatory secret
	// scrubbing. When false only their content hashes are kept, and span
	// events and links keep only their metadata attributes (names, ids,
	// types, models, usage counters).
	//
	// It governs storage ON THIS NODE ONLY: node-local data never leaves the
	// machine. Whether raw content is pushed to an org is a separate
	// decision that stays with the existing raw-content predicate
	// ([org_client.share] full_content / admin_managed or the signed
	// enterprise grant); this key never widens it. It is also separate from
	// those Plane B developer-privacy keys, which no longer decide whether a
	// hosted app's own content is stored locally.
	//
	// Default true (Default() seeds it, so an [observability] section that
	// only sets `enabled` keeps it on). No effect while Enabled is false.
	StoreContent bool `toml:"store_content"`

	// SDK is [observability.sdk]: where this machine tells the superbased
	// SDKs to send an app's data by default (D18; the contract is
	// docs/plans/plane-a-sdk-buildout/contracts/destination.md). Zero value =
	// the default: local when not signed in, both when signed in.
	SDK ObservabilitySDKConfig `toml:"sdk"`
}

// ObservabilityEgressConfig is the [observability.egress] surface (G22, design
// §5). LOCAL-ONLY, never distributed; gated under [observability] enabled.
// DEFAULT OFF (zero value Enabled=false). Translated into the pure
// internal/obs/egress engine's PolicyInput AT THE BOUNDARY (obs_wire), so the
// pure package never imports internal/config.
type ObservabilityEgressConfig struct {
	// Enabled gates the whole egress layer. Default false.
	Enabled bool `toml:"enabled"`
	// Mode is off | advise | enforce. advise evaluates + logs the directive but
	// never applies it; enforce applies it on the proxy path. Empty ⇒ off.
	Mode string `toml:"mode"`
	// CooldownSeconds is the hold window for a same-session budget-band model
	// switch (design §3.6 / finding 11) — a cost switch is held within this
	// window; verdict/locality switches never hold. 0 = the boundary default.
	CooldownSeconds int `toml:"cooldown_seconds"`
	// Rules is the first-match-wins rule table.
	Rules []EgressRuleConfig `toml:"rules"`
	// Targets is the typed upstream target table (id + url + shape). A declared
	// shape is REQUIRED for any enforce-mode route_to_upstream (design finding
	// 6) — [proxy.upstreams] entries carry only URLs.
	Targets []EgressTargetConfig `toml:"targets"`
	// Cohorts is an optional end-user → cohort map (LOCAL-ONLY).
	Cohorts map[string]string `toml:"cohorts"`
}

// EgressRuleConfig is one [[observability.egress.rules]] entry.
type EgressRuleConfig struct {
	Name          string             `toml:"name"`
	When          EgressWhenConfig   `toml:"when"`
	Action        EgressActionConfig `toml:"action"`
	OnUnavailable string             `toml:"on_unavailable"` // fail_open | deny
	Reason        string             `toml:"reason"`
	ReasonCode    string             `toml:"reason_code"`
}

// EgressWhenConfig is a rule's matcher set. BudgetBandAtLeast is a pointer so a
// rule can distinguish "0.0 (zero-spend)" from "unset".
type EgressWhenConfig struct {
	VerdictAtLeast    string   `toml:"verdict_at_least"`
	Criterion         string   `toml:"criterion"`
	SeverityAtLeast   string   `toml:"severity_at_least"`
	ContentClass      string   `toml:"content_class"`
	ModelGlob         string   `toml:"model_glob"`
	Provider          string   `toml:"provider"`
	User              string   `toml:"user"`
	UserCohort        string   `toml:"user_cohort"`
	BudgetBandAtLeast *float64 `toml:"budget_band_at_least"`
	MinPromptTokens   int      `toml:"min_prompt_tokens"`
}

// EgressActionConfig is a rule's action — exactly one primary must be set
// (lint/compile-enforced).
type EgressActionConfig struct {
	RouteToUpstream string `toml:"route_to_upstream"`
	RouteToModel    string `toml:"route_to_model"`
	SetEffort       string `toml:"set_effort"`
	Deny            bool   `toml:"deny"`
	NoRoute         bool   `toml:"no_route"`
}

// EgressTargetConfig is one [[observability.egress.targets]] entry.
type EgressTargetConfig struct {
	ID    string `toml:"id"`
	URL   string `toml:"url"`
	Shape string `toml:"shape"` // anthropic | openai
}

// ObservabilityAlertsConfig is the [observability.alerts] surface. LOCAL-ONLY,
// never distributed; gated under [observability] enabled. It reuses the org
// alert-rule dialect (internal/orgserver/obsalert): metric ∈ error_rate |
// cost_usd | latency_p95_ms, a gt/gte comparator, a threshold, and a window —
// but node windows are in MINUTES (finer than the org's day windows). The
// evaluator loop + webhook client live in cmd/observer; the pure evaluation is
// internal/obs/alert; fired events persist to the node-local obs_alert_events
// table. No node-dashboard surface (obs is Plane-A/web2-only) — the CLI
// (`observer obs alerts`) + the webhook are the node surfaces.
type ObservabilityAlertsConfig struct {
	// Enabled gates the evaluator loop. Default false — a fired alert POSTs to
	// WebhookURL (an outbound network call), so alerting is explicit opt-in.
	Enabled bool `toml:"enabled"`
	// WebhookURL receives the fired-alert JSON payload (one POST per crossing).
	// Empty = record fired events (visible via `observer obs alerts`) but send
	// no webhook — the node stays egress-free.
	WebhookURL string `toml:"webhook_url"`
	// Email, when true, ALSO delivers each fired alert as an email through the
	// shared [email] channel (which must itself be enabled). This is the
	// per-consumer opt-in mirroring WebhookURL — an ADDITIONAL delivery target,
	// not a replacement. Default false.
	Email bool `toml:"email"`
	// EmailTo overrides the [email].to default recipients for this node's alert
	// emails. Empty falls back to [email].to.
	EmailTo []string `toml:"email_to"`
	// EvalIntervalMinutes is how often the evaluator ticks. 0 defaults to 5.
	EvalIntervalMinutes int `toml:"eval_interval_minutes"`
	// SlackWebhookURL is a Slack incoming-webhook URL every fired alert is
	// also posted to (W3-5). A SECRET: never rendered or logged; written only
	// through PUT /api/obs/alerts/slack or `observer obs alerts slack set`.
	// Only https://hooks.slack.com/ and hooks.slack-gov.com URLs are
	// accepted. Empty = no Slack delivery.
	SlackWebhookURL string `toml:"slack_webhook_url"`
	// PagerDutyRoutingKey is a PagerDuty Events API v2 routing (integration)
	// key (W5-5): a fire triggers an incident and the rule's clear resolves
	// it. A SECRET: never rendered or logged; written only through
	// PUT /api/obs/alerts/pagerduty or `observer obs alerts pagerduty set`.
	// Empty = no PagerDuty delivery.
	PagerDutyRoutingKey string `toml:"pagerduty_routing_key"`
	// Rules is the locally-authored rule table.
	Rules []ObservabilityAlertRuleConfig `toml:"rules"`
}

// ObservabilityAlertRuleConfig is one node alert rule. Mirrors the org
// obs_alert_rules row shape (name / metric / comparator / threshold / window /
// cooldown), with the window/cooldown expressed in minutes.
type ObservabilityAlertRuleConfig struct {
	// Name identifies the rule in fired events + the CLI.
	Name string `toml:"name"`
	// Metric ∈ error_rate | cost_usd | latency_p95_ms.
	Metric string `toml:"metric"`
	// Comparator ∈ gt | gte. Empty defaults to gt.
	Comparator string `toml:"comparator"`
	// Threshold is the value the metric is tested against.
	Threshold float64 `toml:"threshold"`
	// WindowMinutes is the lookback the metric is computed over. 0 defaults to
	// 60 at evaluation.
	WindowMinutes int `toml:"window_minutes"`
	// CooldownMinutes is the minimum gap between fires of this rule (dedup). 0
	// defaults to WindowMinutes (a full window must elapse before re-firing).
	CooldownMinutes int `toml:"cooldown_minutes"`
	// Model, User, Tag and Service narrow the rule to one slice of traffic
	// (W3-5 dimensions, internal/alertspec): a span model, the app's end
	// user, one trace tag, the resource service. Empty = any.
	Model   string `toml:"model"`
	User    string `toml:"user"`
	Tag     string `toml:"tag"`
	Service string `toml:"service"`
}

// ObservabilityJudgeConfig is one OpenAI-compatible /chat/completions judge
// binding (the eval/admission shared shape, admission spec §5). LOCAL-ONLY.
// The key is NEVER written to disk: APIKeyEnv names the env var holding it
// (the pi/hermes launcher posture). Zero value = judge unbound (llm_judge
// scorer / admission judge criteria are simply unavailable; code / pre-filter
// layers still run offline).
type ObservabilityJudgeConfig struct {
	// Model names the judge model. Empty = judge disabled.
	Model string `toml:"model"`
	// BaseURL is the OpenAI-compatible chat-completions base URL. Empty
	// defaults to OpenRouter (https://openrouter.ai/api/v1) at the binding.
	BaseURL string `toml:"base_url"`
	// APIKeyEnv names the ENV VAR holding the judge API key — never the key
	// itself. Empty defaults to OPENROUTER_API_KEY. Loopback/local judges
	// need no key (the binding treats a loopback base_url as no-egress and
	// allows an empty/unset key).
	APIKeyEnv string `toml:"api_key_env"`
	// TimeoutMS bounds a single judge call. 0 = the default for where the
	// judge runs: 1500 ms for a loopback judge (the admission budget) and
	// 8000 ms for a hosted one, whose first call (TLS set-up plus a reasoning
	// model's thinking) outlasted 1.5 s live; an org-relay judge defaults to
	// 10000 ms.
	TimeoutMS int `toml:"timeout_ms"`
	// MaxTokens caps the judge REPLY length (the reply is only a short JSON
	// verdict). 0 = the binding's default. A tight cap bounds latency + cost
	// on a hosted judge and stops a chatty local model from streaming forever.
	MaxTokens int `toml:"max_tokens"`
	// NumCtx is an Ollama-style context-window hint passed through ONLY to a
	// loopback/local judge (a hosted OpenAI-compatible API rejects unknown
	// fields, so it is never sent remotely). 0 = omit. Its effect depends on
	// the local host honoring the field on its /v1/chat/completions endpoint.
	NumCtx int `toml:"num_ctx"`
	// RequestProfile is how the judge request is shaped: "auto" (or empty,
	// the default) picks from the model id (bare OpenAI GPT-5 and o-series
	// ids get "reasoning", everything else "chat"); "chat" sends max_tokens
	// and temperature 0 (OpenAI-compatible chat models, local servers);
	// "reasoning" sends max_completion_tokens, no temperature and a
	// reasoning effort, which OpenAI's reasoning models require (they refuse
	// max_tokens and temperature 0). Set it for a model id auto cannot
	// recognise, such as an Azure deployment name.
	RequestProfile string `toml:"request_profile"`
	// ReasoningEffort overrides the reasoning effort a "reasoning" request
	// sends (for example "minimal", "low"). Empty takes the model family's
	// default (minimal for gpt-5 / -mini / -nano, low for later GPT-5 and the
	// o-series). Ignored on the chat profile.
	ReasoningEffort string `toml:"reasoning_effort"`
	// UseOrgRelay routes the judge call through the org server's
	// POST /api/agent/judge instead of an OpenAI-compatible endpoint held
	// locally (C1 judge relay, docs/plans/c1-judge-relay-spec-2026-08-15.md
	// §3). The gateway never holds a judge-provider credential in this mode —
	// the org server resolves its own sealed provider credential. Model stays
	// optional under relay: it rides as an optional model_hint (recorded
	// only; the org's provider selection decides the actual model).
	// Validated mutually exclusive with a non-empty BaseURL/APIKeyEnv on the
	// same resolved block (ambiguous transport).
	UseOrgRelay bool `toml:"use_org_relay"`
}

// ObservabilityAdmissionConfig is the [observability.admission] surface
// (admission spec §4). LOCAL-ONLY, never distributed; gated under
// [observability] enabled. Observe-first: Mode defaults to "observe" only
// once Enabled is set — the zero value (Enabled=false) is fully off.
type ObservabilityAdmissionConfig struct {
	// Enabled gates admission WITHIN the obs subsystem. Default false.
	Enabled bool `toml:"enabled"`
	// Mode is off | observe | enforce. P1 ships observe only; enforce is P2.
	// Empty is treated as "observe" when Enabled.
	Mode string `toml:"mode"`
	// Strict = fail-closed on judge error/timeout (Deny). Default false =
	// fail-open (Allow + recorded admission_error). BACK-COMPAT ALIAS: prefer
	// OnJudgeError, which is the explicit posture enum. When OnJudgeError is
	// empty, Strict resolves the posture (strict=true → fail_closed); when
	// OnJudgeError is set, it wins and Strict is ignored.
	Strict bool `toml:"strict"`
	// OnJudgeError is the explicit judge-unavailable posture:
	// "fail_open" (Allow, today's default) or "fail_closed" (Deny). Empty =
	// resolve from Strict. This is the enum form of Strict; the invasive
	// request-queueing posture is deliberately NOT offered here (it would need
	// a new proxy admit-result shape). LOCAL-ONLY, never distributed.
	OnJudgeError string `toml:"on_judge_error"`
	// JudgeRetries is how many EXTRA bounded in-process attempts the admission
	// engine makes on a judge transport error before the posture fires. 0 =
	// no retry (today's behavior). A cheap reliability lever for a flaky or
	// cold-starting judge; it does not change the synchronous verdict contract.
	JudgeRetries int `toml:"judge_retries"`
	// Scope is last_user | conversation. P1 = last_user; conversation is P3.
	Scope string `toml:"scope"`
	// RetentionDays bounds the obs_admission_events audit table. 0 = keep.
	RetentionDays int `toml:"retention_days"`
	// Criterion is the admin's policy table (§4).
	Criterion []AdmissionCriterionConfig `toml:"criterion"`
	// Judge overrides the shared [observability.judge] for admission only.
	// Zero value = fall back to [observability.judge].
	Judge ObservabilityJudgeConfig `toml:"judge"`
	// Prefilter holds the deterministic allow/deny lists + size ceiling.
	Prefilter AdmissionPrefilterConfig `toml:"prefilter"`
	// SecretRemoteJudge is the local decision (allow|flag|ask|deny) applied
	// when the request carries a pattern-certain secret AND the judge is
	// REMOTE — the request is NOT egressed to the hosted judge; the configured
	// decision is returned locally instead (spec §3 layer 3). Empty/"allow" =
	// off (the request still goes to the — already secret-scrubbed, §item 8 —
	// remote judge). Inert for a local/off judge.
	SecretRemoteJudge string `toml:"secret_remote_judge"`
	// CacheTTLS is the verdict-cache TTL in seconds. 0 = the svc default.
	CacheTTLS int `toml:"cache_ttl_s"`
	// JudgeChunkBytes bounds a single judge call's content size: a request
	// longer than this is split into overlapping windows, each judged, and the
	// verdicts reduced strictest-wins (map-reduce, spec §4 — mirrors the demo's
	// app-layer chunking, now in-core). 0 = the engine default (3500).
	JudgeChunkBytes int `toml:"judge_chunk_bytes"`
	// JudgeChunkOverlapBytes is the overlap between adjacent judge windows so a
	// concern straddling a boundary is still seen whole by one chunk. 0 = the
	// engine default (200); clamped below JudgeChunkBytes.
	JudgeChunkOverlapBytes int `toml:"judge_chunk_overlap_bytes"`
	// IncludeReasoning asks the judge to explain (OpenAI's ~40% latency
	// finding — default false).
	IncludeReasoning bool `toml:"include_reasoning"`
	// Budget is the per-end-user spend guardrail evaluated at the admission
	// chokepoint (the org-hosted-app model: the budgeted subject is an
	// end-user of the hosted app, identified by the app-shared enduser.id /
	// the admission `user` field → obs_traces.user; spend is summed from
	// obs_spans.cost_usd). Off by default.
	Budget AdmissionBudgetConfig `toml:"budget"`
}

// AdmissionBudgetConfig is the per-end-user spend guardrail evaluated at the
// admission chokepoint (docs/guardrails.md; org-budget plan §1). A window
// breach yields a Deny verdict: in observe mode it is recorded as a shadow
// "would-deny"; enforce blocks (P2). It requires the app to share the end-user
// identity (enduser.id / the admission `user` field); an anonymous request is
// inert. A 0 cap disables that window; Enabled=false disables the gate.
//
// PLANE A budget (docs/deployment-models.md): caps a HOSTED-APP END-USER's
// spend at the admission chokepoint. Distinct from the two Plane-B budgets:
// [guard.budget] (GuardBudgetConfig — the DEVELOPER's own provider spend) and
// [routing.budget] (RoutingBudgetConfig — the routing spend-band downshift).
type AdmissionBudgetConfig struct {
	Enabled           bool    `toml:"enabled"`
	PerUser5hUSD      float64 `toml:"per_user_5h_usd"`
	PerUserWeeklyUSD  float64 `toml:"per_user_weekly_usd"`
	PerUserMonthlyUSD float64 `toml:"per_user_monthly_usd"`
	// UserHeader names the request header the proxy pre-forward backstop reads
	// the end-user identity from — the app shares it as an integration
	// requirement (the SDK path passes `user` directly and ignores this).
	// Empty → DefaultAdmissionUserHeader. Absent header ⇒ the per-end-user gate
	// is inert for that request (the app-wide policy still applies).
	UserHeader string `toml:"user_header"`
}

// DefaultAdmissionUserHeader is the request header the proxy admission backstop
// reads the end-user identity from when [observability.admission.budget]
// user_header is unset.
const DefaultAdmissionUserHeader = "X-Superbased-User"

// AdmissionCriterionConfig is one policy criterion (§4). type ∈
// valid_use_case | denied_topics | jailbreak | custom (the pure package
// resolves the vocabulary). Topics apply to denied_topics; Definition to the
// judged types.
type AdmissionCriterionConfig struct {
	ID         string   `toml:"id"`
	Type       string   `toml:"type"`
	Name       string   `toml:"name"`
	Definition string   `toml:"definition"`
	Topics     []string `toml:"topics"`
	Decision   string   `toml:"decision"`
	Severity   string   `toml:"severity"`
}

// AdmissionPrefilterConfig is the deterministic pre-filter layer (§3 layers
// 1-2). Allow/Deny are regex-or-prefix patterns; MaxMessageBytes caps length
// (0 = off).
type AdmissionPrefilterConfig struct {
	Allow           []string `toml:"allow"`
	Deny            []string `toml:"deny"`
	MaxMessageBytes int      `toml:"max_message_bytes"`
}

// ObservabilityEvalConfig configures the obs eval plane (plan §8). LOCAL-ONLY,
// never distributed. Online sampling is off by default (OnlineSampleRate 0).
type ObservabilityEvalConfig struct {
	// OnlineSampleRate, in (0,1], runs OnlineScorers over that fraction of
	// live LLM spans as they ingest (the Langfuse/Arize online-eval model).
	// 0 (default) disables online sampling entirely.
	OnlineSampleRate float64 `toml:"online_sample_rate"`
	// OnlineScorers are the scorer specs run during online sampling, each a
	// string "name" or "name:key=val,key2=val2". Only facts-based code
	// scorers make sense online (status_ok / latency_under / cost_under) —
	// content scorers need a stored body. Empty disables online sampling.
	OnlineScorers []string `toml:"online_scorers"`
	// JudgeModel names the model an llm_judge scorer uses by default (when a
	// scorer spec omits its own model=). Empty disables the LLM judge: the
	// host JudgeClient stays unbound, llm_judge errors clearly, and code
	// scorers run fully offline. The judge call is the ONLY outbound network
	// in the subsystem and runs ONLY for an explicitly-invoked `observer eval
	// run` (never the daemon/online-sampling path).
	JudgeModel string `toml:"judge_model"`
	// JudgeBaseURL is the OpenAI-compatible chat-completions base URL the
	// judge posts to. Empty defaults to OpenRouter (https://openrouter.ai/api/v1).
	JudgeBaseURL string `toml:"judge_base_url"`
	// JudgeAPIKeyEnv names the ENVIRONMENT VARIABLE holding the judge API key
	// — the key is never written to config or disk (the pi/hermes launcher
	// posture). Empty defaults to OPENROUTER_API_KEY.
	JudgeAPIKeyEnv string `toml:"judge_api_key_env"`
}
