package policy

// sensitiveConfigKeys are the config leaves configschema marks sensitive
// (TierSensitive: a write needs the person's confirm, the dashboard's confirm
// token or the CLI's --yes) that no selfLoweringSections or
// settingsApprovalPrefixes family already covers. An agent may not pass that
// confirm for the person: MCP set_setting files a proposal for every one of
// them (internal/settingsgate), so `observer config set <key> --yes` and a
// loopback PUT /api/config/keys of one are R-165 self-approvals too (Plane A
// review finding R-B07: D19 family OR sensitive tier, one predicate on both
// sides).
//
// A key matches the leaf itself or an entry under it (a map leaf's
// <leaf>.<id>). The list mirrors internal/configschema's sensitive leaves
// (this package stays import-free); settingsgate's
// TestPolicyCoversEverySensitiveLeaf fails when a sensitive leaf is missing
// here and when an entry here is no longer a sensitive leaf.
//
// One subtree is left out on purpose (sensitiveKeysOwnedElsewhere): R-167
// owns [terminal.sandbox] and denies the writes that loosen the sandbox
// while letting a tightening through, which a blanket R-165 row would
// override.
var sensitiveConfigKeys = []string{
	"browser.granularity_ceiling",
	"browser.listener.allow_non_loopback",
	"browser.listener.enabled",
	"browser.listener.listen_addr",
	"dashboard.addr",
	"digest.enabled",
	"digest.frequency",
	"digest.send_hour",
	"digest.to",
	"email.auth",
	"email.enabled",
	"email.from",
	"email.host",
	"email.password_env",
	"email.password_file",
	"email.port",
	"email.timeout_seconds",
	"email.tls_mode",
	"email.to",
	"email.username",
	"exporter.otel.emit_prompt_content",
	"exporter.otel.emit_user_email",
	"exporter.otel.enabled",
	"exporter.otel.endpoint",
	"exporter.otel.insecure",
	"exporter.otel.poll_interval_seconds",
	"exporter.otel.semconv_stability",
	"handoff.allow_dashboard_launch",
	"ingest.otel.allow_non_loopback",
	"ingest.otel.content_capture",
	"ingest.otel.content_max_bytes",
	"ingest.otel.enabled",
	"ingest.otel.grpc_addr",
	"ingest.otel.http_addr",
	"intelligence.api_key_env",
	"loc.editor_token_required",
	"mcp_relay.enabled",
	"messages.read_receipts",
	"observability.alerts.email",
	"observability.alerts.email_to",
	"observability.alerts.webhook_url",
	"observability.eval.judge_api_key_env",
	"observer.process.env.allowlist",
	"observer.process.etw.allow_non_loopback",
	"observer.process.etw.listen_addr",
	"observer.process.etw.token_path",
	"observer.secrets.enable_scrubbing",
	"observer.secrets.extra_patterns",
	"org_client.policy.accept_families",
	"org_client.policy.accept_module_families",
	"org_client.policy.node_environment",
	"org_client.policy.node_service",
	"org_client.policy.node_workspace",
	"org_client.policy.preauthorize_enforce",
	"org_client.policy.preauthorize_module_enforce",
	"org_client.scope.project_root_allowlist",
	"org_client.scope.project_root_denylist",
	"pricing.feed.auto",
	"pricing.feed.enabled",
	"pricing.feed.poll_interval_hours",
	"pricing.feed.url",
	"projects.alignment_judge",
	"proxy.anthropic_upstream",
	"proxy.auto_default_lane",
	"proxy.chatgpt_upstream",
	"proxy.client_auth_routes",
	"proxy.client_token_file",
	"proxy.gemini_upstream",
	"proxy.openai_upstream",
	"proxy.org_route.direct_fallback_custody_ack",
	"proxy.org_route.fallbacks",
	"proxy.org_route.mode",
	"proxy.org_route.primary",
	"proxy.org_route.terminal_policy",
	"proxy.require_client_auth",
	"proxy.upstreams",
	"remote.allow_remote_terminal_takeover",
	"remote.allow_standing_terminal_control",
	"remote.allow_terminal",
	"remote.allow_terminal_view",
	"remote.bind_addr",
	"remote.capability_ttl_minutes",
	"remote.enabled",
	"remote.max_sessions",
	"remote.mode",
	"remote.notify.enabled",
	"remote.notify.events",
	"remote.notify.kind",
	"remote.notify.url",
	"remote.rate_limit_per_min",
	"remote.require_tls",
	"remote.revoke_standing_on_takeover",
	"remote.session_idle_minutes",
	"remote.session_ttl_minutes",
	"remote.tailscale_backend_addr",
	"remote.trusted_hosts",
	"remote.writer_lease_idle_minutes",
	"remote.writer_lease_max_minutes",
	"routing.enabled",
	"routing.mode",
	"selfobs.enabled",
	"selfobs.endpoint",
	"selfobs.insecure",
	"selfobs.key_id",
	"selfobs.routing_sample_n",
	"selfobs.service_name",
	"terminal.attach.forward_auth_env",
	"terminal.ssh.connect_timeout_seconds",
	"terminal.ssh.enabled",
	"terminal.ssh.keepalive_seconds",
	"update.allow_downgrade",
	"update.enabled",
}

// sensitiveKeysOwnedElsewhere are sensitive subtrees another rule judges, so
// sensitiveConfigKeys leaves them out: the prefix and the rule that owns it.
var sensitiveKeysOwnedElsewhere = map[string]string{
	"terminal.sandbox": "R-167",
}

// SensitiveKeysOwnedElsewhere returns sensitiveKeysOwnedElsewhere's prefixes
// (for the settingsgate drift test).
func SensitiveKeysOwnedElsewhere() []string {
	out := make([]string, 0, len(sensitiveKeysOwnedElsewhere))
	for p := range sensitiveKeysOwnedElsewhere {
		out = append(out, p)
	}
	return out
}

// SensitiveConfigKeys returns a copy of sensitiveConfigKeys (for the
// settingsgate drift test).
func SensitiveConfigKeys() []string { return append([]string(nil), sensitiveConfigKeys...) }
