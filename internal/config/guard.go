package config

// This file holds the config types of [guard]: the coding-agent tool-call
// guardrails.

// GuardConfig is the full [guard] surface (guard spec §16). Same
// partial-merge invariant as CacheTrackConfig: an install with no
// [guard] section gets Enabled=true + Mode="observe" from Default()
// — never a zero-valued false/"" (operator decision D2: fresh
// installs observe and alert; nothing blocks until the operator
// flips enforce).
//
// Sub-sections gate later G-commits (proxy G9, mcp G10, budget G12,
// dialects G11, cloud G15); they are declared now so the config
// vocabulary is stable and a forward-written config file round-trips.
type GuardConfig struct {
	// Enabled gates all guard wiring (ingest seam, hook seam, CLI
	// surfaces). When false, no policy engine is constructed and no
	// guard_events are written.
	Enabled bool `toml:"enabled"`
	// Mode is the global posture: "off" | "observe" | "enforce"
	// (default "observe", D2). In observe, deny/ask-class verdicts
	// are recorded + alerted but the action proceeds.
	Mode string `toml:"mode"`
	// Strict inverts the Q2 fail-open default: a guard internal
	// error then blocks instead of approving. Enterprise posture;
	// default false. It is NOT a strictness level (that is Level): the
	// dashboard labels it "Fail closed when the guard itself errors".
	Strict bool `toml:"strict"`
	// Level is the guard recipe level applied to the whole machine: one of
	// the catalog's level recipes ("none", "loose", "balanced", "strict",
	// "lockdown") or a user level recipe from the guard-recipes directory.
	// Empty (the default) means no level was applied: the built-in rules,
	// the mode and the policy files decide alone, exactly as before levels
	// existed. `observer guard recipe apply` and the Security page's
	// Recipes card write it together with mode and [guard.prompt] mode and
	// the recipe file beside the user policy (docs/guard-recipes.md);
	// remove clears it. The rows a level sets live in that recipe file,
	// not here, so a hand edit of this key changes no rule by itself
	// (`observer guard recipe list` reports the mismatch).
	Level string `toml:"level"`
	// RetentionDays is the guard_events / expired-approvals prune
	// horizon (spec §10.3). Default 365 — audit data wants ≥1y for
	// compliance buyers. ≤0 disables the guard prune.
	RetentionDays int `toml:"retention_days"`

	Rules    GuardRulesConfig    `toml:"rules"`
	Boundary GuardBoundaryConfig `toml:"boundary"`
	Database GuardDatabaseConfig `toml:"database"`
	Network  GuardNetworkConfig  `toml:"network"`
	Taint    GuardTaintConfig    `toml:"taint"`
	Proxy    GuardProxyConfig    `toml:"proxy"`
	MCP      GuardMCPConfig      `toml:"mcp"`
	Budget   GuardBudgetConfig   `toml:"budget"`
	Alerts   GuardAlertsConfig   `toml:"alerts"`
	Export   GuardExportConfig   `toml:"export"`
	Dialects GuardDialectsConfig `toml:"dialects"`
	Cloud    GuardCloudConfig    `toml:"cloud"`
	Prompt   GuardPromptConfig   `toml:"prompt"`

	// Lock is the runtime record of the managed-node org lock this Load
	// applied (guardfloor.go, T-839 / T-844). Never TOML, never JSON: it is
	// set by Load only, and the zero value (no lock) is every individual,
	// un-enrolled and pre-lock node.
	Lock GuardOrgLock `toml:"-" json:"-"`
}

// GuardRulesConfig is [guard.rules] (spec §16): rule disabling and
// the user/project policy-file locations.
type GuardRulesConfig struct {
	// Disable lists rule IDs turned off entirely.
	Disable []string `toml:"disable"`
	// EvasionWindowSeconds turns on rule A-613 (policy evasion, flag
	// only): after a deny, other differently shaped attempts that hit the
	// same rule within this many seconds in the same session are flagged.
	// 0, the default, leaves A-613 off.
	EvasionWindowSeconds int `toml:"evasion_window_seconds"`
	// UserPolicy is the user policy file location. Default
	// "~/.observer/guard-policy.toml".
	UserPolicy string `toml:"user_policy"`
	// ProjectPolicy is the project policy file location relative to
	// each project root. Default ".observer/guard-policy.toml".
	ProjectPolicy string `toml:"project_policy"`
	// TrustedProjectDir is the daemon-local directory holding the
	// dashboard-authored trusted per-project policy files (one file per
	// project root, named <sha256(canonical root) as 64 hex chars>.toml). Default
	// "~/.observer/guard-project-policies". Unlike ProjectPolicy (the
	// in-repo, agent-writable, escalate-only file), files under this
	// directory sit inside R-160's ~/.observer/** deny surface — the
	// agent cannot write them — so they carry user-level weaken/disable
	// semantics scoped to one project (never below the org floor). The
	// dashboard writes them directly; guard loads them in the per-project
	// engine build. Empty disables the trusted per-project layer.
	TrustedProjectDir string `toml:"trusted_project_dir"`
	// OrgBundle is the local cache location of the verified org
	// policy bundle envelope (guard spec §14.2). Default
	// "~/.observer/org-policy-bundle.json". Written ONLY by the org
	// client after full signature + key-pin verification; read by
	// every guard construction (daemon and hook processes alike) as
	// the org policy layer, with the signature re-checked at load.
	// The file is absent on non-enrolled installs — absence simply
	// means no org layer.
	OrgBundle string `toml:"org_bundle"`
	// CEL is the Q1 v2 gate for CEL-expression user rules. Parsed
	// but rejected by the loader until the v2 arc lands (decided:
	// matchers v1, CEL deferred).
	CEL bool `toml:"cel"`
}

// GuardBoundaryConfig is [guard.boundary] (spec §16). Nil slices mean
// "use the policy-engine defaults" (policy.DefaultAllowPaths /
// DefaultProtectedBranches); explicitly empty lists mean "none".
type GuardBoundaryConfig struct {
	AllowPaths        []string `toml:"allow_paths"`
	ProtectedBranches []string `toml:"protected_branches"`
	// ProtectedPathClasses makes these path classes read-only for agents
	// (rule R-166): "tests", "ci" and "coverage". Empty, the default,
	// leaves R-166 off, because ordinary test maintenance is common.
	ProtectedPathClasses []string `toml:"protected_path_classes"`
}

// GuardDatabaseConfig is [guard.database]: the inputs of the database rule
// family (R-120 to R-126, docs/guard.md "Database rules").
type GuardDatabaseConfig struct {
	// ProdPatterns names the production databases R-125 asks about: a
	// database command whose host, connection string, database name or
	// profile matches one of these. A pattern with no `*` or `?` matches
	// as a case-insensitive substring ("prod" matches db.prod.example.com);
	// one with them is a case-insensitive glob over the whole value
	// ("*.prod.internal"). Empty, the default, leaves R-125 inert.
	ProdPatterns []string `toml:"prod_patterns"`
}

// GuardNetworkConfig is [guard.network]: the host lists of the network rule
// family (R-174 to R-179, docs/guard.md "Network rules"). A host pattern is a
// host name ("example.com" also matches its subdomains, "*.example.com" only
// them), an IP address or a CIDR block ("10.0.0.0/8"). The rules judge the
// hosts a command names on its command line; they are not an egress
// firewall (the sandboxed terminal's egress gateway is).
type GuardNetworkConfig struct {
	// AllowHosts is the allow-list R-176 compares against: a network
	// command to a host not on it (loopback always passes) hits the rule.
	// R-176 is silent until a level or pack raises it (lockdown, the
	// networking pack); then an empty list means every non-loopback host.
	AllowHosts []string `toml:"allow_hosts"`
	// DenyHosts is the deny list of R-174 (the never-reach hosts, beside
	// the cloud metadata endpoints): a network command to a host on it is
	// flagged in observe and denied in enforce. Empty, the default, leaves
	// that row inert.
	DenyHosts []string `toml:"deny_hosts"`
}

// GuardTaintConfig is [guard.taint] (spec §4.5, §16).
type GuardTaintConfig struct {
	// Enabled gates taint tracking + the T-5xx rules' input (with
	// tracking off the snapshot is always empty, so taint rules
	// never fire).
	Enabled bool `toml:"enabled"`
	// DecayTurns is the mark lifetime in session turns. Default 10.
	DecayTurns int `toml:"decay_turns"`
}

// GuardProxyConfig is [guard.proxy] (spec §8, lands G9).
type GuardProxyConfig struct {
	// EgressScan gates the §8.2 typed secret scan over the final
	// outbound request body.
	EgressScan bool `toml:"egress_scan"`
	// EgressAction is the enforce-class action when the R-172
	// api_request verdict blocks: "flag" (record only), "mask"
	// (rewrite detector-certain values to [REDACTED:type] and
	// forward; entropy hits never mask), "deny" (synthetic 403,
	// §8.5). Default "mask" per §8.2 ("mask mode default-on in
	// enforce for detector-certain types") — inert in observe mode,
	// where every egress verdict is a flag (D2).
	EgressAction string `toml:"egress_action"` // flag | mask | deny
	// EgressAllow are regex patterns over the MATCHED VALUE: a
	// finding whose value matches is ignored entirely (test
	// fixtures, known-fake keys). Compiled by the guard layer;
	// invalid patterns degrade to load issues. Global in G9 —
	// per-project egress_allow joins when the project policy
	// vocabulary grows a proxy section (deferred, documented).
	EgressAllow []string `toml:"egress_allow"`
	// ResponseScan gates the §8.3 response-side tool_use inspection
	// (flag/alert only in v1).
	ResponseScan bool `toml:"response_scan"`
	// InjectionHeuristics gates the §8.4 prompt-injection heuristics
	// on inbound tool-result/web content (flag + taint, never deny).
	InjectionHeuristics bool `toml:"injection_heuristics"`
}

// GuardMCPConfig is [guard.mcp] (spec §9, lands G10).
type GuardMCPConfig struct {
	Pinning             bool `toml:"pinning"`
	PoisoningHeuristics bool `toml:"poisoning_heuristics"`
}

// GuardBudgetConfig is [guard.budget] (spec §12.1, lands G12). 0
// means off.
//
// PLANE B budget (docs/deployment-models.md): caps the DEVELOPER's OWN
// provider spend on their coding-agent turns. Distinct from [routing.budget]
// (RoutingBudgetConfig — the routing spend-band downshift, also Plane B) and
// from the Plane-A [observability.admission.budget] (AdmissionBudgetConfig —
// a hosted-app END-USER's spend at the admission chokepoint).
type GuardBudgetConfig struct {
	SessionUSD float64 `toml:"session_usd"`
	DailyUSD   float64 `toml:"daily_usd"`
	// WeeklyUSD / MonthlyUSD are $ ceilings over a rolling 7-day
	// window and the calendar month (rules B-604 / B-603), enforced
	// with the same deny-on-proxy discipline as SessionUSD/DailyUSD.
	// 0 disables the window.
	WeeklyUSD  float64 `toml:"weekly_usd"`
	MonthlyUSD float64 `toml:"monthly_usd"`
	// SessionTokens / DailyTokens / WeeklyTokens / MonthlyTokens are the
	// TOKEN-denominated siblings of the four $ ceilings above, one for one
	// (org-budget plan §3.3c, rules B-621..B-624). 0 disables the window,
	// exactly like the $ fields — 0 is "unset", never a cap of zero.
	//
	// They exist because a token cap is the denomination an org budget is
	// authored in (the plan's R3): tokens are the unit the org can enforce
	// without a rate card, and `int` is the only numeric kind the governance
	// pin vocabulary carries, so a token cap is expressible end to end where a
	// float USD cap is not.
	SessionTokens int64 `toml:"session_tokens"`
	DailyTokens   int64 `toml:"daily_tokens"`
	WeeklyTokens  int64 `toml:"weekly_tokens"`
	MonthlyTokens int64 `toml:"monthly_tokens"`
	Hard          bool  `toml:"hard"`
	// FromOrg opts this node into applying the ORGANIZATION's budget, fetched
	// per caller from GET /api/agent/budget (org-budget plan §3.3c). Default
	// TRUE (operator decision 2026-09-20): an enrolled node applies its org's
	// pricing/budget by default — the node-side companion to the default-on
	// pricing feed. Set it false to opt OUT, which makes the node behave
	// byte-identically to a build that never had this feature.
	//
	// With it on, the composition is capability-branched, never
	// source-branched: on an INDIVIDUAL node the org's numbers may only LOWER
	// the four thresholds above (govern.LowerFloat / LowerInt — min with the
	// "0 means unset" rule); on a MANAGED node whose grant carries
	// govern.AuthorityEnforceBudget the org's numbers and enforcement mode are
	// authoritative. Both this key and Hard are pinnable through node
	// governance (internal/policyfam/nodegov.PinnableKeys) so an org can set
	// the fleet's POSTURE; the NUMBERS never ride the pin rail, because a pin
	// is one value for a whole fleet and a cap is per developer.
	//
	// The node-side fetch/compose/enforce half is wave W3b; this key exists in
	// W3a because the governance vocabulary row must resolve against a real
	// config key (TestEveryPinnableKeyResolvesInConfig).
	FromOrg bool `toml:"from_org"`
	// FailClosed is the ORGANIZATION's explicit opt-in to refusing proxied
	// requests (rule B-625) while a managed node that holds enforce.budget has
	// no verified org budget in hand: before the first pull after an
	// enrolment, while the org server has never been reached, or when the
	// signed document did not verify. Default FALSE (operator ruling D-502,
	// 2026-10-09): such a node FAILS OPEN on its own [guard.budget] numbers and
	// says so loudly, because a requirement this node cannot currently satisfy
	// for reasons outside the request must never stop a developer's session.
	// A node with NO live enrolment never fails closed, whatever this says.
	//
	// It is pinnable through node governance (restrictive-only, Safe=true) so
	// the org opts a fleet in through its signed node.governance body; a
	// developer may also set it locally to be stricter. Unlike the other
	// pinned keys it is NOT restart-bound in the daemon: the org-budget
	// composition resolves it live on every cycle from the node's own value
	// and the CURRENT governance pin (REVIEW-4 P4-04), so a left
	// organization's pin does not outlive its governance. The launcher reads
	// it from the config it loads for each launch.
	FailClosed bool `toml:"fail_closed"`
	// MaxDocumentAge is the freshness window a SIGNED org budget document
	// must fall inside to be applied: the node refuses a 200 whose issued_at
	// is older than this, or in the future beyond a small clock skew. A Go
	// duration string ("1h", "30m"); empty means the 1h default, and an
	// unparsable value also falls back to the default rather than disabling
	// the check.
	//
	// It closes the REPLAY window the signature alone cannot (fundamentals
	// finding M3). Version monotonicity refuses an OLDER document, but an
	// EQUAL-version one is legitimately re-served on every poll — so an
	// intermediary holding yesterday's correctly signed explicit-none can
	// replay it against a node whose cache is cold (a restart, a fresh
	// install) and that node would run uncapped, believing the org said so.
	// A timestamp INSIDE the signed body is the only thing that dates the
	// document, and the org is the only party that can mint a fresh one.
	//
	// Tighter is safer but not free: the value must exceed the poll interval
	// or a node that misses one cycle starts refusing documents it should
	// accept.
	MaxDocumentAge string `toml:"max_document_age"`
	// Window gates on the provider's own 5h / weekly usage windows
	// (utilization 0..1, read from limit_snapshots) — distinct from
	// the $ caps above; the "limit" guardrails B-610..B-613.
	Window GuardBudgetWindowConfig `toml:"window"`
}

// GuardBudgetWindowConfig is [guard.budget.window] (spec §12.1) —
// utilization thresholds (0..1) over the provider's unified 5h and
// weekly usage windows. warn flags, deny blocks (proxy). 0 disables
// the threshold. deny must be >= warn when both are set.
type GuardBudgetWindowConfig struct {
	Util5hWarn     float64 `toml:"util_5h_warn"`
	Util5hDeny     float64 `toml:"util_5h_deny"`
	UtilWeeklyWarn float64 `toml:"util_weekly_warn"`
	UtilWeeklyDeny float64 `toml:"util_weekly_deny"`
}

// GuardAlertsConfig is [guard.alerts] (spec §16, lands G5).
type GuardAlertsConfig struct {
	// Desktop enables exec-based desktop notifications (Q3).
	Desktop bool `toml:"desktop"`
	// MinSeverity is the alert threshold: "info" | "warn" | "high" |
	// "critical". Default "high".
	MinSeverity string `toml:"min_severity"`
}

// GuardExportConfig is [guard.export] (spec §11.4, lands G16).
type GuardExportConfig struct {
	OTel bool `toml:"otel"`
}

// GuardDialectsConfig is [guard.dialects] (spec §13.2, lands G11).
type GuardDialectsConfig struct {
	Compile bool     `toml:"compile"`
	Targets []string `toml:"targets"`
}

// GuardCloudConfig is [guard.cloud] (spec §15, lands G15). EVERYTHING
// here requires explicit opt-in (operator decision D1); the master
// Enabled plus per-feature switches all default false.
type GuardCloudConfig struct {
	Enabled         bool                  `toml:"enabled"`
	LLMJudge        GuardLLMJudgeConfig   `toml:"llm_judge"`
	Reputation      GuardReputationConfig `toml:"reputation"`
	Webhooks        []GuardWebhookConfig  `toml:"webhooks"`
	PayloadMaxBytes int                   `toml:"payload_max_bytes"`
}

// GuardLLMJudgeConfig configures the §15.2 LLM-judge reviewer.
// Endpoint is an OpenAI-chat-completions-compatible URL (bring-your-
// own: a local gateway, litellm, or the user's own proxied provider
// session). APIKeyEnv names an ENVIRONMENT VARIABLE holding the
// bearer key — never the key itself (the no-secrets-in-config rule);
// empty means the endpoint authenticates locally or not at all.
type GuardLLMJudgeConfig struct {
	Enabled   bool   `toml:"enabled"`
	Endpoint  string `toml:"endpoint"`
	Model     string `toml:"model"`
	APIKeyEnv string `toml:"api_key_env"`
}

// GuardReputationConfig configures the §15.3 reputation lookups.
type GuardReputationConfig struct {
	Enabled bool `toml:"enabled"`
}

// GuardWebhookConfig is one [[guard.cloud.webhooks]] entry (§15.4).
// RoutingKey is PagerDuty's Events-API v2 routing key (kind =
// "pagerduty" only; URL then stays the standard events endpoint).
type GuardWebhookConfig struct {
	URL         string `toml:"url"`
	Kind        string `toml:"kind"` // generic | slack | discord | pagerduty
	MinSeverity string `toml:"min_severity"`
	RoutingKey  string `toml:"routing_key"`
}
