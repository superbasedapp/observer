package configschema

import (
	"sort"
	"strings"
)

// Tier is the security tier of a leaf (plan §4.1).
type Tier string

// Security tiers. The zero value is deliberately NOT a tier: a leaf the
// table does not classify fails TestEveryLeafKeyClassified.
const (
	// TierPlain — class L route, no confirm token.
	TierPlain Tier = "plain"
	// TierSensitive — class L + confirm token + audit row; every allow-list
	// and every consent / egress / exposure switch (§4.2).
	TierSensitive Tier = "sensitive"
	// TierSecret — never rendered, never writable (§4.3).
	TierSecret Tier = "secret"
	// TierOwnerElsewhere — read-only; OwnedBy names the owning command
	// or editor (§4.1 T3).
	TierOwnerElsewhere Tier = "owner_elsewhere"
)

// Restart is the restart class of a leaf (plan §3.1).
type Restart string

// Restart classes. The UI chip text is derived from these, never authored
// per form.
const (
	// RestartLive — an existing hot-reload seam re-points the running daemon.
	RestartLive Restart = "live"
	// RestartLivePersist — live-applied AND persisted on save.
	RestartLivePersist Restart = "live_persist"
	// RestartNextSpawn — binds in a child process (an MCP subprocess, a
	// launched terminal), not this daemon.
	RestartNextSpawn Restart = "next_spawn"
	// RestartRequired — bind-at-start; the running daemon keeps the old value.
	RestartRequired Restart = "restart"
)

// Prominence decides how a leaf is surfaced (plan §1.5).
type Prominence string

// Prominence levels.
const (
	ProminencePrimary  Prominence = "primary"
	ProminenceAdvanced Prominence = "advanced"
	ProminenceExpert   Prominence = "expert"
)

// rule is one row of the annotation table. A rule matches a leaf when the
// leaf's path equals prefix (always) or starts with prefix+"." (unless
// exact). Each classification attribute is resolved INDEPENDENTLY: for a
// given attribute the most specific matching rule that sets it wins
// (longest prefix; an exact rule beats a prefix rule of the same length),
// so a block-level tier can coexist with a key-level section override
// without either having to restate the other.
type rule struct {
	prefix string
	exact  bool

	tier       Tier
	restart    Restart
	section    string
	prominence Prominence
	secret     bool
	deprecated string
	ownedBy    string
	enum       []string
	min, max   *float64
}

func f(v float64) *float64 { return &v }

// Owning-command strings for T3 leaves. One constant per owner so the copy
// the UI renders is consistent.
const (
	ownerConfigMigrate = "`observer config migrate` (schema-version stamp; never hand-set)"
	ownerOrgEnroll     = "`observer org enroll` / `observer org unenroll` (enrolment identity)"
	ownerDeprecated    = "a deprecated alias — the loader honours it for one release; set the replacement key instead"
	ownerPricingEditor = "the Settings → Pricing editor (PUT /api/config/pricing)"
	ownerRoutingEditor = "the Settings → Routing rules editor / config.toml"
	ownerExperiments   = "`observer experiment` (the [[experiments]] list)"
	ownerGuardCloud    = "`observer guard cloud` / config.toml"
	ownerFileOnly      = "config.toml directly (a compound table the generic editor does not render)"
	ownerSSHProfiles   = "config.toml [[terminal.ssh.profiles]] (the dashboard profile editor is plan item P0-6, not yet shipped)"
	ownerLaunchTools   = "config.toml [launch.tools.<tool>] (per-tool launch overrides)"
)

// rules is THE annotation table. Ordered for reading, not for precedence —
// precedence is by specificity (see resolve). Add a config key by adding a
// data row here, never new control flow.
//
// Every top-level block MUST have a tier + restart + section rule (the
// block rules at the top of each group); TestEveryLeafKeyClassified fails
// the build otherwise.
var rules = []rule{
	// ---------------------------------------------------------------- observer
	{prefix: "observer", tier: TierPlain, restart: RestartRequired, section: "observer"},
	{prefix: "observer.log_level", exact: true, enum: []string{"debug", "info", "warn", "error"}},
	{prefix: "observer.config_version", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerConfigMigrate, prominence: ProminenceExpert},
	{prefix: "observer.watch", section: "watcher"},
	{prefix: "observer.freshness", section: "freshness"},
	{prefix: "observer.retention", section: "retention"},
	{prefix: "observer.retention.wal_alert_mb", exact: true, prominence: ProminenceAdvanced},
	{prefix: "observer.retention.wal_watch_minutes", exact: true, prominence: ProminenceAdvanced},
	// Per-table event horizons (internal/retention/events.go). Advanced, not
	// plain: they only matter to an operator who has looked at a per-table
	// storage breakdown and wants to trade history for disk.
	{prefix: "observer.retention.compaction_events_days", exact: true, prominence: ProminenceAdvanced},
	{prefix: "observer.retention.compression_events_days", exact: true, prominence: ProminenceAdvanced},
	{prefix: "observer.hooks", section: "hooks"},
	{prefix: "observer.antigravity", section: "antigravity"},
	{prefix: "observer.antigravity.dump_shape_mismatches_dir", exact: true, prominence: ProminenceExpert},
	// Secrets scrubbing changes what the daemon may store — capture
	// granularity (§4.2).
	{prefix: "observer.secrets", tier: TierSensitive, section: "secrets"},
	{prefix: "observer.db", section: "storage", prominence: ProminenceAdvanced},
	{prefix: "observer.db.hard_heap_limit_mb", exact: true, prominence: ProminenceExpert},
	// Process capture.
	{prefix: "observer.process", section: "process"},
	{prefix: "observer.process.backend", exact: true, enum: []string{"auto", "bridge", "both", "linux_ebpf", "etw", "endpointsecurity", "poll", "off"}},
	{prefix: "observer.process.queue_size", exact: true, prominence: ProminenceExpert},
	{prefix: "observer.process.batch_size", exact: true, prominence: ProminenceExpert},
	{prefix: "observer.process.correlate_interval_ms", exact: true, prominence: ProminenceExpert},
	{prefix: "observer.process.windows_binary_path", exact: true, prominence: ProminenceAdvanced},
	{prefix: "observer.process.argv", prominence: ProminenceAdvanced},
	{prefix: "observer.process.argv.mode", exact: true, enum: []string{"preview", "hash_only", "off"}},
	{prefix: "observer.process.executable", prominence: ProminenceAdvanced},
	{prefix: "observer.process.env", prominence: ProminenceAdvanced},
	{prefix: "observer.process.env.allowlist", exact: true, tier: TierSensitive},
	{prefix: "observer.process.network.capture_bodies", exact: true, tier: TierSensitive, enum: []string{"", "off", "proxied", "available"}},
	{prefix: "observer.process.network.max_request_bytes", exact: true, prominence: ProminenceAdvanced},
	{prefix: "observer.process.network.max_response_bytes", exact: true, prominence: ProminenceAdvanced},
	{prefix: "observer.process.network.process_bytes", exact: true, prominence: ProminenceAdvanced},
	{prefix: "observer.process.filesystem.mode", exact: true, enum: []string{"sensitive", "writes", "all_attributed_writes"}},
	{prefix: "observer.process.metrics", prominence: ProminenceAdvanced},
	// The ETW listener is a network exposure surface; its token is T2.
	{prefix: "observer.process.etw.listen_addr", exact: true, tier: TierSensitive},
	{prefix: "observer.process.etw.allow_non_loopback", exact: true, tier: TierSensitive},
	{prefix: "observer.process.etw.token", exact: true, tier: TierSecret, secret: true},
	{prefix: "observer.process.etw.token_path", exact: true, tier: TierSensitive},
	{prefix: "observer.process.etw.handshake_timeout_ms", exact: true, prominence: ProminenceAdvanced},

	// ------------------------------------------------------------------- proxy
	{prefix: "proxy", tier: TierPlain, restart: RestartRequired, section: "proxy"},
	// Upstreams redirect the node's API traffic (§4.2 "Upstreams").
	{prefix: "proxy.anthropic_upstream", exact: true, tier: TierSensitive},
	{prefix: "proxy.openai_upstream", exact: true, tier: TierSensitive},
	{prefix: "proxy.chatgpt_upstream", exact: true, tier: TierSensitive},
	{prefix: "proxy.gemini_upstream", exact: true, tier: TierSensitive},
	{prefix: "proxy.upstreams", tier: TierSensitive},
	{prefix: "proxy.auto_default_lane", exact: true, tier: TierSensitive, prominence: ProminenceAdvanced},
	{prefix: "proxy.org_route", tier: TierSensitive, prominence: ProminenceAdvanced},
	{prefix: "proxy.org_route.mode", exact: true, enum: []string{"", "gateway"}},
	{prefix: "proxy.force_chatgpt_http", exact: true, prominence: ProminenceAdvanced},
	{prefix: "proxy.prewarm_targets", exact: true, prominence: ProminenceAdvanced},

	// --------------------------------------------------------------- dashboard
	{prefix: "dashboard", tier: TierPlain, restart: RestartRequired, section: "dashboard"},
	// Network exposure (§4.2).
	{prefix: "dashboard.addr", exact: true, tier: TierSensitive},

	// ------------------------------------------------------------- compression
	{prefix: "compression", tier: TierPlain, restart: RestartRequired, section: "compression"},
	{prefix: "compression.code_graph", tier: TierOwnerElsewhere, ownedBy: ownerDeprecated, deprecated: "use codeintel.enabled / codeintel.index.on_start (see docs/codeintel/configuration.md); run `observer config migrate`", prominence: ProminenceExpert},
	{prefix: "compression.conversation.mode", exact: true, enum: []string{"token", "cache", "cache_aware"}},
	{prefix: "compression.conversation.target_ratio", exact: true, min: f(0), max: f(1)},
	{prefix: "compression.conversation.logs", prominence: ProminenceAdvanced},
	{prefix: "compression.conversation.stash", prominence: ProminenceAdvanced},
	{prefix: "compression.conversation.rolling", prominence: ProminenceAdvanced},
	{prefix: "compression.conversation.compaction", prominence: ProminenceAdvanced},
	{prefix: "compression.indexing", prominence: ProminenceAdvanced},

	// ------------------------------------------------------------ intelligence
	{prefix: "intelligence", tier: TierPlain, restart: RestartRequired, section: "intelligence"},
	// Pricing hot-reloads through cost.Engine.Reload (plan §3.2) and has its
	// own editor; the compound tables stay owned by it.
	{prefix: "intelligence.api_key_env", exact: true, tier: TierSensitive},
	{prefix: "intelligence.pricing", restart: RestartLive, section: "pricing"},
	{prefix: "intelligence.pricing.models", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerPricingEditor},
	{prefix: "intelligence.pricing.dated", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerPricingEditor},
	{prefix: "intelligence.project_budgets_usd", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerFileOnly},
	// Each AI session spawns a fresh `observer serve` that runs config.Load
	// itself — a restart chip would lie (plan §3.2).
	{prefix: "intelligence.mcp", restart: RestartNextSpawn, section: "mcp"},
	{prefix: "intelligence.code_graph", tier: TierOwnerElsewhere, ownedBy: ownerDeprecated, deprecated: "use codeintel.enabled (see docs/codeintel/configuration.md); run `observer config migrate`", prominence: ProminenceExpert},

	// -------------------------------------------------------------- org_client
	// Every share/scope switch is data egress consent (§4.2).
	{prefix: "org_client", tier: TierSensitive, restart: RestartRequired, section: "org"},
	{prefix: "org_client.enabled", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerOrgEnroll},
	{prefix: "org_client.org_server_url", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerOrgEnroll},
	{prefix: "org_client.keychain_id", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerOrgEnroll},
	{prefix: "org_client.push_interval_seconds", exact: true, tier: TierPlain, prominence: ProminenceAdvanced},
	{prefix: "org_client.snapshot_interval_seconds", exact: true, tier: TierPlain, prominence: ProminenceAdvanced},
	{prefix: "org_client.policy_poll_interval_seconds", exact: true, tier: TierPlain, prominence: ProminenceAdvanced},
	{prefix: "org_client.policy_state_heartbeat_seconds", exact: true, tier: TierPlain, prominence: ProminenceAdvanced},
	{prefix: "org_client.max_push_bytes", exact: true, tier: TierPlain, prominence: ProminenceAdvanced},
	{prefix: "org_client.policy", prominence: ProminenceAdvanced},
	{prefix: "org_client.share.obs_summary", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerDeprecated, deprecated: "use org_client.share.obs.summary; run `observer config migrate`", prominence: ProminenceExpert},
	{prefix: "org_client.share.obs_traces", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerDeprecated, deprecated: "use org_client.share.obs.traces; run `observer config migrate`", prominence: ProminenceExpert},
	{prefix: "org_client.share.obs_content", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerDeprecated, deprecated: "use org_client.share.obs.content; run `observer config migrate`", prominence: ProminenceExpert},
	{prefix: "org_client.share.obs_eval_summary", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerDeprecated, deprecated: "use org_client.share.obs.eval_summary; run `observer config migrate`", prominence: ProminenceExpert},

	// ------------------------------------------------------- exporter / ingest
	{prefix: "exporter", tier: TierSensitive, restart: RestartRequired, section: "otel"},
	{prefix: "ingest", tier: TierSensitive, restart: RestartRequired, section: "otel"},

	// ---------------------------------------------------- cachetrack / cachewarm
	{prefix: "cachetrack", tier: TierPlain, restart: RestartRequired, section: "cachetrack"},
	{prefix: "cachetrack.calibrate_log_path", exact: true, prominence: ProminenceAdvanced},
	{prefix: "cachewarm", tier: TierPlain, restart: RestartRequired, section: "cachetrack", prominence: ProminenceAdvanced},
	{prefix: "cachewarm.enabled", exact: true, prominence: ProminencePrimary},
	{prefix: "cachewarm.keepwarm.mode", exact: true, enum: []string{"", "off", "advise", "enforce"}},

	// ----------------------------------------------------------------- predict
	{prefix: "predict", tier: TierPlain, restart: RestartRequired, section: "intelligence", prominence: ProminenceAdvanced},
	{prefix: "predict.enabled", exact: true, prominence: ProminencePrimary},

	// ---------------------------------------------------------------- guidance
	// Agent-guidance-file inventory. Plain: the block holds only scan
	// bounds — no credential, no egress, no authority. Restart-required
	// because the scan loop is composed once at daemon start.
	{prefix: "guidance", tier: TierPlain, restart: RestartRequired, section: "intelligence", prominence: ProminenceAdvanced},
	{prefix: "guidance.enabled", exact: true, prominence: ProminencePrimary},

	// ------------------------------------------------------------ pricing feed
	// Standalone-node pricing feed client (docs/plans/pricing-sync-tokenomics-
	// to-platform-plan-2026-09-11.md §C.4). enabled/auto are egress consent —
	// the feed is the node's opt-in outbound call — so the block is sensitive.
	// The block-level rule every top-level block must carry (pinned by
	// TestEveryBlockHasABlockRule); [pricing] holds only the feed today, so it
	// inherits the feed's sensitivity.
	{prefix: "pricing", tier: TierSensitive, restart: RestartRequired, section: "pricing", prominence: ProminenceAdvanced},
	{prefix: "pricing.feed", tier: TierSensitive, restart: RestartRequired, section: "pricing", prominence: ProminenceAdvanced},
	{prefix: "pricing.feed.enabled", exact: true, prominence: ProminencePrimary},

	// --------------------------------------------------------------------- loc
	// Lines-of-code tracking. The block holds only the editor-endpoint
	// credential; it maps onto the intelligence Settings section because
	// that is where the LOC surfaces already live. editor_token_required
	// is SENSITIVE — it is an authentication switch, and clearing it is
	// the direction that loosens the endpoint.
	{prefix: "loc", tier: TierPlain, restart: RestartRequired, section: "intelligence", prominence: ProminenceAdvanced},
	{prefix: "loc.editor_token_required", exact: true, tier: TierSensitive},

	// ----------------------------------------------------------------- browser
	// [tasks] — session-level task/todo/plan checklist tracking
	// (docs/task-tracking.md; merged from origin/main 2026-09-10). Binds once at
	// daemon startup (SetTasksEnabled/SetTasksOptions), so a change needs a
	// restart. Renders under the Tasks settings section (sectionSpecs.ts
	// "tasks"), which the closed org-facing vocabulary
	// (nodegov.SettingsSectionIDs) also carries since the same merge.
	{prefix: "tasks", tier: TierPlain, restart: RestartRequired, section: "tasks"},
	{prefix: "browser", tier: TierPlain, restart: RestartRequired, section: "browser"},
	{prefix: "browser.listener", tier: TierSensitive},
	{prefix: "browser.listener.token", exact: true, tier: TierSecret, secret: true},
	{prefix: "browser.sites", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerFileOnly},
	{prefix: "browser.granularity_ceiling", exact: true, tier: TierSensitive, enum: []string{"", "usage_only", "redacted", "full"}},
	{prefix: "browser.ingest_timeout_ms", exact: true, prominence: ProminenceAdvanced},

	// ----------------------------------------------------------------- handoff
	{prefix: "handoff", tier: TierPlain, restart: RestartRequired, section: "terminal", prominence: ProminenceAdvanced},
	{prefix: "handoff.enabled", exact: true, prominence: ProminencePrimary},
	// Gates the dashboard terminal launcher — an execution capability.
	{prefix: "handoff.allow_dashboard_launch", exact: true, tier: TierSensitive, prominence: ProminencePrimary},

	// ---------------------------------------------------------------- terminal
	{prefix: "terminal", tier: TierPlain, restart: RestartRequired, section: "terminal"},
	// Live through terminalLimitsSetter (plan §3.2); the generic route
	// degrades to restart when the setter is not wired.
	{prefix: "terminal.max_concurrent", exact: true, restart: RestartLivePersist},
	{prefix: "terminal.idle_timeout", exact: true, restart: RestartLivePersist},
	{prefix: "terminal.ring_bytes", exact: true, prominence: ProminenceAdvanced},
	{prefix: "terminal.max_subscribers", exact: true, prominence: ProminenceAdvanced},
	{prefix: "terminal.ws_ping_interval_seconds", exact: true, prominence: ProminenceExpert},
	{prefix: "terminal.ws_ping_timeout_seconds", exact: true, prominence: ProminenceExpert},
	{prefix: "terminal.ws_ping_failures_allowed", exact: true, prominence: ProminenceExpert},
	{prefix: "terminal.status", prominence: ProminenceAdvanced},
	// Execution allow-lists (§4.2).
	{prefix: "terminal.launch", tier: TierSensitive},
	// Read per-launch by the CLI, not by this daemon (F6).
	{prefix: "terminal.attach.route_proxy", exact: true, restart: RestartNextSpawn},
	{prefix: "terminal.attach.default_on", exact: true, restart: RestartNextSpawn},
	{prefix: "terminal.attach.reclaim_on_input", exact: true, prominence: ProminenceAdvanced},
	{prefix: "terminal.attach.forward_auth_env", exact: true, tier: TierSensitive, prominence: ProminenceAdvanced},
	// Sandbox binds (§4.2).
	{prefix: "terminal.sandbox", tier: TierSensitive},
	{prefix: "terminal.sandbox.backend", exact: true, enum: []string{"", "bwrap"}},
	{prefix: "terminal.sandbox.home_mode", exact: true, enum: []string{"", "tmpfs", "readonly"}},
	{prefix: "terminal.sandbox.prep_timeout_seconds", exact: true, tier: TierPlain, prominence: ProminenceAdvanced},
	{prefix: "terminal.sandbox.workspace_retention_days", exact: true, tier: TierPlain},
	{prefix: "terminal.ssh", tier: TierSensitive},
	{prefix: "terminal.ssh.profiles", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerSSHProfiles},

	// ------------------------------------------------------------------ launch
	{prefix: "launch", tier: TierPlain, restart: RestartNextSpawn, section: "terminal", prominence: ProminenceAdvanced},
	{prefix: "launch.tools", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerLaunchTools},

	// --------------------------------------------------------------- codeintel
	{prefix: "codeintel", tier: TierPlain, restart: RestartRequired, section: "intelligence"},
	{prefix: "codeintel.index", prominence: ProminenceAdvanced},
	{prefix: "codeintel.index.on_start", exact: true, prominence: ProminencePrimary},
	{prefix: "codeintel.compression", prominence: ProminenceAdvanced},
	{prefix: "codeintel.semantic", prominence: ProminenceAdvanced},
	{prefix: "codeintel.max_file_bytes", exact: true, prominence: ProminenceAdvanced},
	{prefix: "codeintel.auto_index_limit", exact: true, prominence: ProminenceAdvanced},

	// ----------------------------------------------------------------- archive
	{prefix: "archive", tier: TierPlain, restart: RestartRequired, section: "storage"},
	{prefix: "archive.max_projects_per_pass", exact: true, prominence: ProminenceAdvanced},
	{prefix: "archive.batch_rows", exact: true, prominence: ProminenceAdvanced},

	// ----------------------------------------------------------------- advisor
	{prefix: "advisor", tier: TierPlain, restart: RestartRequired, section: "advisor"},
	{prefix: "advisor.min_confidence", exact: true, min: f(0), max: f(1)},
	{prefix: "advisor.digest_refresh_minutes", exact: true, prominence: ProminenceAdvanced},

	// ----------------------------------------------------------------- routing
	{prefix: "routing", tier: TierPlain, restart: RestartRequired, section: "routing"},
	{prefix: "routing.mode", exact: true, tier: TierSensitive, enum: []string{"off", "advise", "enforce"}},
	{prefix: "routing.enabled", exact: true, tier: TierSensitive},
	{prefix: "routing.key_pool", tier: TierSecret, secret: true},
	{prefix: "routing.tiers", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerRoutingEditor, prominence: ProminenceAdvanced},
	{prefix: "routing.path_classes", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerRoutingEditor, prominence: ProminenceAdvanced},
	{prefix: "routing.rules", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerRoutingEditor},
	{prefix: "routing.budget.scopes", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerRoutingEditor},
	{prefix: "routing.privacy.rules", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerRoutingEditor},
	{prefix: "routing.reliability", prominence: ProminenceAdvanced},
	{prefix: "routing.reliability.fallbacks", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerRoutingEditor},
	// A local upstream re-points model traffic (§4.2 "Upstreams").
	{prefix: "routing.local_upstreams", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerRoutingEditor},
	{prefix: "routing.stickiness", prominence: ProminenceAdvanced},
	{prefix: "routing.rate_limit_window", prominence: ProminenceAdvanced},
	{prefix: "routing.calibration", prominence: ProminenceAdvanced},
	{prefix: "routing.translation", prominence: ProminenceAdvanced},
	{prefix: "routing.benchmark_files", exact: true, prominence: ProminenceAdvanced},
	{prefix: "routing.decision_log_retention_days", exact: true, prominence: ProminenceAdvanced},

	// ------------------------------------------------------------------ update
	// [update] is the node side of enterprise update management
	// (docs/enterprise-updates.md): it only ever talks to the org server the
	// node is enrolled with, so it lives under the org Settings section. The
	// three keys that change WHICH BINARY RUNS are sensitive.
	{prefix: "update", tier: TierPlain, restart: RestartRequired, section: "org"},
	{prefix: "update.enabled", exact: true, tier: TierSensitive},
	{prefix: "update.auto_apply", exact: true, tier: TierSensitive},
	{prefix: "update.allow_downgrade", exact: true, tier: TierSensitive},
	{prefix: "update.channel", exact: true, enum: []string{"", "stable", "lts", "edge"}},
	{prefix: "update.state_dir", exact: true, prominence: ProminenceExpert},
	{prefix: "update.keep_previous_days", exact: true, prominence: ProminenceAdvanced},
	{prefix: "update.max_download_bytes", exact: true, prominence: ProminenceAdvanced},
	{prefix: "update.drain_timeout", exact: true, prominence: ProminenceAdvanced},
	{prefix: "update.handshake_timeout", exact: true, prominence: ProminenceAdvanced},

	// ------------------------------------------------------------------- guard
	{prefix: "guard", tier: TierPlain, restart: RestartRequired, section: "guard"},
	// Guard policy (§4.2).
	{prefix: "guard.enabled", exact: true, tier: TierSensitive},
	{prefix: "guard.mode", exact: true, tier: TierSensitive, enum: []string{"off", "observe", "enforce"}},
	{prefix: "guard.strict", exact: true, tier: TierSensitive},
	{prefix: "guard.rules", tier: TierSensitive},
	{prefix: "guard.boundary", tier: TierSensitive},
	{prefix: "guard.proxy.egress_action", exact: true, tier: TierSensitive, enum: []string{"", "flag", "mask", "deny"}},
	{prefix: "guard.proxy.egress_allow", exact: true, tier: TierSensitive},
	{prefix: "guard.alerts.min_severity", exact: true, enum: []string{"", "info", "warn", "high", "critical"}},
	{prefix: "guard.taint", prominence: ProminenceAdvanced},
	{prefix: "guard.dialects", prominence: ProminenceAdvanced},
	{prefix: "guard.export", prominence: ProminenceAdvanced},
	{prefix: "guard.budget.window", prominence: ProminenceAdvanced},
	{prefix: "guard.cloud", tier: TierOwnerElsewhere, ownedBy: ownerGuardCloud, prominence: ProminenceAdvanced},

	// ---------------------------------------------------------------- profiles
	// The OnConfigSaved hook re-points the proxy's profile router for new
	// sessions (plan §3.2).
	{prefix: "profiles", tier: TierPlain, restart: RestartLive, section: "profiles"},

	// --------------------------------------------------------------- benchmark
	{prefix: "benchmark", tier: TierPlain, restart: RestartRequired, section: "storage", prominence: ProminenceAdvanced},

	// ---------------------------------------------------------- email / digest
	// Outbound SMTP is data egress (§4.2).
	{prefix: "email", tier: TierSensitive, restart: RestartRequired, section: "observer"},
	{prefix: "email.password", exact: true, tier: TierSecret, secret: true},
	{prefix: "email.tls_mode", exact: true, enum: []string{"", "starttls", "tls", "none"}},
	{prefix: "email.auth", exact: true, enum: []string{"", "plain", "login"}},
	{prefix: "email.timeout_seconds", exact: true, prominence: ProminenceAdvanced},
	{prefix: "digest", tier: TierSensitive, restart: RestartRequired, section: "observer"},
	{prefix: "digest.frequency", exact: true, enum: []string{"", "weekly", "monthly"}},
	{prefix: "digest.send_hour", exact: true, min: f(0), max: f(23)},

	// ----------------------------------------------------------- observability
	{prefix: "observability", tier: TierPlain, restart: RestartRequired, section: "observability"},
	{prefix: "observability.judge", prominence: ProminenceAdvanced},
	{prefix: "observability.judge.model", exact: true, prominence: ProminencePrimary},
	{prefix: "observability.judge.base_url", exact: true, prominence: ProminencePrimary},
	{prefix: "observability.judge.api_key_env", exact: true, tier: TierSensitive, prominence: ProminencePrimary},
	{prefix: "observability.eval.judge_api_key_env", exact: true, tier: TierSensitive},
	{prefix: "observability.eval.online_sample_rate", exact: true, min: f(0), max: f(1)},
	{prefix: "observability.admission.on_judge_error", exact: true, enum: []string{"fail_open", "fail_closed"}},
	{prefix: "observability.admission.criterion", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerFileOnly},
	{prefix: "observability.admission.judge", prominence: ProminenceAdvanced},
	{prefix: "observability.admission.judge.api_key_env", exact: true, tier: TierSensitive},
	{prefix: "observability.admission.judge_chunk_bytes", exact: true, prominence: ProminenceAdvanced},
	{prefix: "observability.admission.judge_chunk_overlap_bytes", exact: true, prominence: ProminenceAdvanced},
	{prefix: "observability.admission.cache_ttl_s", exact: true, prominence: ProminenceAdvanced},
	{prefix: "observability.admission.judge_retries", exact: true, prominence: ProminenceAdvanced},
	{prefix: "observability.admission.prefilter", prominence: ProminenceAdvanced},
	{prefix: "observability.alerts.rules", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerFileOnly},
	{prefix: "observability.alerts.webhook_url", exact: true, tier: TierSensitive},
	{prefix: "observability.alerts.email", exact: true, tier: TierSensitive},
	{prefix: "observability.alerts.email_to", exact: true, tier: TierSensitive},
	// Egress routing (§4.2).
	{prefix: "observability.egress", tier: TierSensitive},
	{prefix: "observability.egress.rules", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerFileOnly},
	{prefix: "observability.egress.targets", exact: true, tier: TierOwnerElsewhere, ownedBy: ownerFileOnly},
	{prefix: "observability.proxy_turn_traces", exact: true, prominence: ProminenceAdvanced},

	// ----------------------------------------------------------------- selfobs
	{prefix: "selfobs", tier: TierSensitive, restart: RestartRequired, section: "observability", prominence: ProminenceAdvanced},
	{prefix: "selfobs.enabled", exact: true, prominence: ProminencePrimary},
	{prefix: "selfobs.endpoint", exact: true, prominence: ProminencePrimary},
	{prefix: "selfobs.secret", exact: true, tier: TierSecret, secret: true},
	{prefix: "selfobs.token", exact: true, tier: TierSecret, secret: true},

	// ---------------------------------------------------------- aggregate_share
	{prefix: "aggregate_share", tier: TierSensitive, restart: RestartRequired, section: "otel"},

	// ------------------------------------------------------------------ remote
	// Network exposure — all of [remote] (§4.2).
	{prefix: "remote", tier: TierSensitive, restart: RestartRequired, section: "dashboard"},
	{prefix: "remote.mode", exact: true, enum: []string{"", "off", "tailscale", "lan"}},
	{prefix: "remote.notify.kind", exact: true, enum: []string{"", "webhook", "ntfy"}},
	{prefix: "remote.writer_lease_idle_minutes", exact: true, prominence: ProminenceAdvanced},
	{prefix: "remote.writer_lease_max_minutes", exact: true, prominence: ProminenceAdvanced},
	{prefix: "remote.rate_limit_per_min", exact: true, prominence: ProminenceAdvanced},
	{prefix: "remote.capability_ttl_minutes", exact: true, prominence: ProminenceAdvanced},
	{prefix: "remote.session_ttl_minutes", exact: true, prominence: ProminenceAdvanced},
	{prefix: "remote.session_idle_minutes", exact: true, prominence: ProminenceAdvanced},
	{prefix: "remote.max_sessions", exact: true, prominence: ProminenceAdvanced},

	// ------------------------------------------------------------------- cloud
	// Read by each `observer cloud` invocation — except the background-sync
	// schedule, which the daemon binds at start.
	{prefix: "cloud", tier: TierPlain, restart: RestartNextSpawn, section: "cloud"},
	{prefix: "cloud.auto_sync", exact: true, restart: RestartRequired},
	{prefix: "cloud.auto_sync_interval_minutes", exact: true, restart: RestartRequired},
	// Deployment/infrastructure knobs, not user preferences: in a shipped
	// build these are compiled-in hosted-service defaults (or discovered),
	// exposed here only for staging/self-host. Expert prominence keeps them
	// reachable behind a disclosure rather than sitting in the user's face
	// next to the sign-in card (the Cloud Intelligence section renders them
	// under an "Advanced" fold; the account card owns the primary surface).
	{prefix: "cloud.workos_client_id", exact: true, prominence: ProminenceExpert},
	{prefix: "cloud.base_url", exact: true, prominence: ProminenceExpert},
	{prefix: "cloud.login_port", exact: true, prominence: ProminenceExpert},

	// ------------------------------------------------------------- experiments
	{prefix: "experiments", tier: TierOwnerElsewhere, restart: RestartLive, section: "profiles", ownedBy: ownerExperiments},
}

// sortedRules is rules ordered most-specific first, built once.
var sortedRules = func() []rule {
	out := append([]rule(nil), rules...)
	sort.SliceStable(out, func(i, j int) bool {
		li, lj := len(out[i].prefix), len(out[j].prefix)
		if li != lj {
			return li > lj
		}
		return out[i].exact && !out[j].exact
	})
	return out
}()

func (r rule) matches(path string) bool {
	if path == r.prefix {
		return true
	}
	return !r.exact && strings.HasPrefix(path, r.prefix+".")
}

// annotate resolves every classification attribute of leaf from the table,
// each attribute independently, most specific match first. Missing tier /
// restart / section stay zero — the classification gate catches them.
func annotate(leaf *Leaf) {
	leaf.Prominence = ProminencePrimary
	var gotProm bool
	for _, r := range sortedRules {
		if !r.matches(leaf.Path) {
			continue
		}
		if leaf.Tier == "" && r.tier != "" {
			leaf.Tier = r.tier
		}
		if leaf.Restart == "" && r.restart != "" {
			leaf.Restart = r.restart
		}
		if leaf.Section == "" && r.section != "" {
			leaf.Section = r.section
		}
		if !gotProm && r.prominence != "" {
			leaf.Prominence, gotProm = r.prominence, true
		}
		if r.secret {
			leaf.Secret = true
		}
		if leaf.Deprecated == "" && r.deprecated != "" {
			leaf.Deprecated = r.deprecated
		}
		if leaf.OwnedBy == "" && r.ownedBy != "" {
			leaf.OwnedBy = r.ownedBy
		}
		if leaf.Enum == nil && r.enum != nil {
			leaf.Enum = r.enum
		}
		if leaf.Min == nil && r.min != nil {
			leaf.Min = r.min
		}
		if leaf.Max == nil && r.max != nil {
			leaf.Max = r.max
		}
	}
	// A compound table the generic editor cannot express is owner-elsewhere
	// by construction, whatever the block rule says — never an editable
	// control that would fail on save.
	if leaf.Kind == KindTable && leaf.Tier != TierSecret && leaf.OwnedBy == "" {
		leaf.Tier = TierOwnerElsewhere
		leaf.OwnedBy = ownerFileOnly
	}
	if leaf.Kind == KindTable && leaf.Tier != TierSecret {
		leaf.Tier = TierOwnerElsewhere
	}
	// Secret implies the secret tier; the tier implies secret. Keep both
	// spellings consistent so a consumer may check either.
	if leaf.Secret {
		leaf.Tier = TierSecret
	}
	if leaf.Tier == TierSecret {
		leaf.Secret = true
	}
}

// SectionOf resolves the Settings section a dotted key belongs to. ok is
// false for an unknown key — callers gate on it (fail closed).
func SectionOf(dotted string) (section string, ok bool) {
	l, found := Lookup(dotted)
	if !found {
		return "", false
	}
	return l.Section, true
}
