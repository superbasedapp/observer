package orgcontract

// PushEnvelope is the body of POST /api/agent/push (gzip-compressed on the
// wire). cursor_from/cursor_to bound the batch against the agent's local
// ingest cursor so the server can ACK a next_cursor and the agent can
// resume exactly once.
type PushEnvelope struct {
	AgentVersion string `json:"agent_version"`
	// MachineIdentity is the pushing node's org-salted machine fingerprint
	// (machineid.ForOrg — the SAME opaque value ManagedBindRequest and
	// PolicyStateReport carry), present ONLY for a node enrolled under
	// managed tenancy. It is ENVELOPE-level, not a per-row column: one push
	// comes from one machine, so repeating it on every session row would be
	// pure redundancy.
	//
	// The individual/BYO plane sends nothing here (orgclient's
	// ManagedMachineIdentity returns "" for an unmanaged enrolment, a host
	// with no stable machine id, or any load error), and omitempty keeps
	// those envelopes byte-identical to the pre-feature shape. The server
	// stamps it onto the sessions rows this push inserts, which is what
	// makes project_identity_signals.node_count a real count of MACHINES
	// rather than a copy of the developer count. Empty is "not tracked",
	// never "zero machines".
	MachineIdentity string `json:"machine_identity,omitempty"`
	// SourceNodeKey is the pushing DEVICE's stable identity for the managed-
	// node MCP relay ingest (doc3 §9.5, R8.28.g / R8.30.a): the lowercase hex
	// SHA-256 of the node's per-device agent-access public-key thumbprint
	// (SourceNodeKeyFromThumbprint). Distinct from the member-level agent
	// signing key push auth verifies and from MachineIdentity (managed-only,
	// org-salted). ENVELOPE-level like both: one push comes from one device.
	//
	// OPTIONAL both directions (the compat invariant): a pre-P4 agent sends
	// nothing and the server keys its relay rows 'member:' || member_id
	// (MemberSourceNodeKey); a pre-P4 server ignores the key. The server
	// accepts a supplied value ONLY when it matches an ACTIVE kind='node'
	// agent_credential of the authenticated member - a node cannot spoof
	// another device's key (400). omitempty keeps a node without an
	// agent-access key on a byte-identical envelope.
	SourceNodeKey string `json:"source_node_key,omitempty"`
	// UpdatePosture is the OPTIONAL self-reported update state of this node
	// (Enterprise Update Management §3.5): version / channel / os / arch /
	// state / target / manifest version / error CLASS / install method /
	// auto-apply / extension version. No hostname, no paths, no free text —
	// see UpdatePostureRow in update.go for the field-by-field rationale and
	// the structural pin that keeps it that way.
	//
	// ENVELOPE-level like MachineIdentity, and for the same reason: one push
	// comes from one node, so this is one fact about the pusher, not a
	// per-row column. It is composed by internal/store/updateposture.go and
	// called BY orgpush.go, so the privacy sentinel keeps forbidding the
	// node-local update_state / update_events table names inside that seam.
	//
	// omitempty keeps a pre-feature node's envelope BYTE-IDENTICAL to today's
	// accepted shape, and a pre-feature server ignores the unknown key — the
	// same compat invariant RoutingSummaries carries below.
	UpdatePosture *UpdatePostureRow `json:"update_posture,omitempty"`
	CursorFrom    int64             `json:"cursor_from"`
	CursorTo      int64             `json:"cursor_to"`
	Sessions      []SessionRow      `json:"sessions"`
	Actions       []ActionRow       `json:"actions"`
	APITurns      []APITurnRow      `json:"api_turns"`
	TokenUsage    []TokenUsageRow   `json:"token_usage"`
	// Deletions are the node's TOMBSTONES for cursor-wire rows it deleted as
	// a correction after pushing them (agent migration 141, lane R2-TOMB):
	// a dedup repair, a moved row, a retired identity. Node-local ageing
	// (retention) never produces one. The org deletes its copy only when the
	// copy's node_rev is OLDER than the tombstone's NodeRev (see
	// PushDeletion). OPTIONAL both directions: a pre-141 agent sends none, a
	// pre-R2-TOMB server ignores the key (and keeps the rows, exactly the old
	// behaviour); omitempty keeps an envelope without deletions
	// byte-identical to the previous shape.
	Deletions []PushDeletion `json:"deletions,omitempty"`
	// SessionManifests are the `observer org resync --deletions` HEAL for rows
	// deleted before tombstones existed: per session, a digest of every row
	// identity the node still holds, so the org removes the rows it holds for
	// that session that the node no longer does (see SessionManifest).
	// OPTIONAL both directions like Deletions.
	SessionManifests []SessionManifest `json:"session_manifests,omitempty"`
	// RoutingSummaries is the OPTIONAL §R19.4 aggregate (counts +
	// dollars by tier/reason only) — present only when the node
	// operator opted in via [org_client.share] routing_summary.
	// Optional both directions: v1.8.x servers ignore the key,
	// future servers tolerate its absence.
	RoutingSummaries []RoutingSummaryRow `json:"routing_summaries,omitempty"`

	// CacheSummaries is the OPTIONAL Arc 4 P5c cache-detail aggregate
	// (day × model × kind counts + tokens + cost delta only), present
	// only when the node ships the cache_detail tier (opt-in individual /
	// admin-raised managed). Optional both directions like RoutingSummaries.
	CacheSummaries []CacheSummaryRow `json:"cache_summaries,omitempty"`

	// CodeintelSummaries is the OPTIONAL Arc 4 P5f codeintel-detail aggregate
	// (per project-hash × language file/symbol/edge counts only), present only
	// when the node ships the codeintel_detail tier (opt-in individual /
	// admin-raised managed via the DISTINCT extract.codeintel authority). No
	// symbol name, fqn, signature, or raw path ever crosses. Optional both
	// directions like RoutingSummaries.
	CodeintelSummaries []CodeintelSummaryRow `json:"codeintel_summaries,omitempty"`

	// ProcessSummaries is the OPTIONAL Arc 4 P5g process-detail aggregate
	// (per day × tool run/exit/duration counts only), present only when the
	// node ships the process_detail tier (opt-in individual / admin-raised
	// managed via the DISTINCT extract.process authority). No exe path, argv,
	// cwd, network body, or hash ever crosses. Optional both directions like
	// RoutingSummaries.
	ProcessSummaries []ProcessSummaryRow `json:"process_summaries,omitempty"`

	// SessionVerbositySummaries carries the W3.1 output-composition summary,
	// one row per session (byte totals by category + language split, never
	// content) — session-scoped enterprise wire, present only under
	// shipsRawContent() (full_content / admin_managed). Optional both
	// directions like RoutingSummaries. See internal/orgcontract/verbosity.go.
	SessionVerbositySummaries []SessionVerbosityRow `json:"session_verbosity,omitempty"`

	// SessionLOC carries the Lines-of-Code per-session AGGREGATE (one row per
	// session × project root: line counts by actor, the classifier version and
	// the human-capture flag). Unlike the session-scoped wires around it, this
	// one rides the DEFAULT metadata-only posture — a count of lines written is
	// the same disclosure class as SessionRow.TotalActions. The one field
	// gated on shipsRawContent() is the row's own LanguageMixJSON. Composed by
	// store.SelectSessionLOCSummaries (internal/store/locsummary.go, a separate
	// file so orgpush.go never names file_changes). Optional both directions
	// like RoutingSummaries. See internal/orgcontract/loc.go.
	SessionLOC []SessionLOCRow `json:"session_loc,omitempty"`

	// LOCDays carries the day-bucketed (day, project root) line-count
	// aggregate — the carrier for editor-reported human work that happens
	// outside any session (plan §2). Same default posture as SessionLOC.
	LOCDays []LOCDayRow `json:"loc_days,omitempty"`

	// SessionQuality carries the per-session quality score (BL2-ORG), one row
	// per session the node's scorer has written, windowed on scored_at so a
	// score that lands after its sessions row already shipped still goes out.
	// Derived numbers only, so it rides the DEFAULT metadata posture like
	// SessionLOC. Composed by store.SelectSessionQualityRows
	// (internal/store/sessionqualitysummary.go). Optional both directions: an
	// older server ignores the key, an older agent omits it. See
	// internal/orgcontract/sessionquality.go.
	SessionQuality []SessionQualityRow `json:"session_quality,omitempty"`

	// CommitOwnership carries commit ownership (lane F-PROJ): one row per
	// (project root, commit) this node's AI sessions contributed to, with the
	// owning session, the ranked contributors and their shares, plus an
	// identity-only row for a commit that fell out of HEAD. Ids and counts
	// ride the DEFAULT metadata posture like SessionLOC; the commit Subject is
	// gated on shipsRawContent(); no author identity and no path ever ship.
	// Composed by store.SelectCommitOwnershipRows
	// (internal/store/commitownersummary.go), so orgpush.go never names the
	// node-local commit tables. Optional both directions: an older server
	// ignores the key, an older agent omits it. See
	// internal/orgcontract/commitowner.go.
	CommitOwnership []CommitOwnershipRow `json:"commit_ownership,omitempty"`

	// DeliveryDays carries the delivery (commit to PR to merge) daily counts
	// from every node; PullRequests carries PR identity rows ONLY under
	// ShareOptions.shipsRawContent(). Composed by
	// store.SelectDeliveryWireRows (internal/store/deliverysummary.go). An
	// older server ignores both keys, an older agent omits them. See
	// internal/orgcontract/delivery.go.
	DeliveryDays []DeliveryDayRow `json:"delivery_days,omitempty"`
	PullRequests []PullRequestRow `json:"pull_requests,omitempty"`

	// SessionCacheSummaries carries the W2.1 session-scoped cache summary
	// (per session × model × kind × cause counts + token sums, no content) —
	// present only under shipsRawContent() (full_content / admin_managed);
	// the fleet day-aggregate CacheSummaries above is the separate teams-tier
	// surface. Optional both directions. See internal/orgcontract/cachesession.go.
	SessionCacheSummaries []SessionCacheRow `json:"session_cache,omitempty"`

	// SessionCacheEvents carries the PER-EVENT cache timeline (one row per
	// node cache_events row, capped per session) — the substrate the org
	// drawer feeds to the SAME cachetrack.BuildTimeline the node uses, so the
	// two Cache tabs cannot drift. Present only under shipsRawContent()
	// (full_content / admin_managed / enterprise-granted), the SessionCache
	// posture and deliberately NOT the teams-tier cache_detail flag, which
	// gates the content-free FLEET aggregate above and stays orthogonal in
	// both directions. The node's `detail` diagnostic JSON, the cache scope /
	// prefix hashes and the node-local anchor ids are all excluded by
	// construction. Composed by store.SelectSessionCacheEvents, which owns the
	// node-local read — orgpush.go names no cache_* table. Optional both
	// directions. See internal/orgcontract/cacheeventsession.go.
	SessionCacheEvents []SessionCacheEventRow `json:"session_cache_events,omitempty"`

	// SessionProcesses is the W2.2 session-scoped RAW process-run wire (one
	// row per process run: exe/cwd/argv-preview/metrics, capped per session
	// at push time) — present only under shipsRawContent() (full_content /
	// admin_managed); the fleet ProcessSummaries above stays the content-free
	// teams tier. Optional both directions. See
	// internal/orgcontract/processsession.go.
	SessionProcesses []SessionProcessRow `json:"session_processes,omitempty"`

	// SessionProcessRollups / SessionProcessCaptureStats are the process
	// capture budget's org wire (docs/plans/process-capture-budget-plan-
	// 2026-11-04.md §4.8, layer O1): the per-bucket rollup groups of the runs
	// the node counted but did not keep as SessionProcesses rows, and one
	// counters row per session. Same shipsRawContent() tier as
	// SessionProcesses. Optional both directions: an older server ignores the
	// keys, and an older agent sends neither, which the server reads as "no
	// capture budget" (the drawer's legacy view), never as zero processes.
	// See internal/orgcontract/processrollup.go.
	SessionProcessRollups      []SessionProcessRollupRow       `json:"session_process_rollups,omitempty"`
	SessionProcessCaptureStats []SessionProcessCaptureStatsRow `json:"session_process_capture_stats,omitempty"`

	// SessionNetworkEvents is the W2.2b session-scoped RAW network-egress wire
	// (one row per process_events network row, joined to its optional
	// process_network_bodies excerpt when a plaintext capture source produced
	// one; capped per session at push time) — present only under
	// shipsRawContent() (full_content / admin_managed). Every network event
	// ships regardless of body availability — a non-proxied TLS connection is
	// metadata-only BY CAPTURE, never an omission. See
	// internal/orgcontract/networksession.go.
	SessionNetworkEvents []SessionNetworkEventRow `json:"session_network_events,omitempty"`

	// SessionTaskItems / SessionTaskTransitions are the W2 session task/todo
	// checklist wires (node session-detail trickle-up plan §2 "W2"), present
	// only when the node ships the task_detail tier (opt-in individual /
	// admin-raised managed via the DISTINCT extract.tasks authority). The
	// status vocabulary, counters and transitions ship under that tier alone;
	// each item's PROSE (content/active_form/owner) additionally requires the
	// node's raw-content posture. Composed by store.SelectSessionTaskItems /
	// SelectSessionTaskTransitions, which own the node-local read — orgpush.go
	// names the task_* tables nowhere. Optional both directions like
	// RoutingSummaries. See internal/orgcontract/taskflowsession.go.
	SessionTaskItems       []SessionTaskItemRow       `json:"session_task_items,omitempty"`
	SessionTaskTransitions []SessionTaskTransitionRow `json:"session_task_transitions,omitempty"`

	// SessionToolAccounts is the W3 vendor-login observation wire (§2 "W3"),
	// present only when the node ships the tool_account_detail tier (opt-in
	// individual / admin-raised managed via the DISTINCT extract.tool_accounts
	// authority). Binding enums + the opaque account_key ship under that tier
	// alone; the raw identity (email/name/account_id) additionally requires
	// the node's raw-content posture (decision D2). Composed by
	// store.SelectSessionToolAccounts, which owns the node-local read.
	// Optional both directions. See internal/orgcontract/toolaccountsession.go.
	SessionToolAccounts []SessionToolAccountRow `json:"session_tool_accounts,omitempty"`

	// SessionHookActivity is the per-session hook liveness wire (surface-gap
	// DEC-5), present only when the node ships the hook_activity tier (opt-in
	// individual / admin-raised managed via extract.hook_activity or the
	// umbrella). Counts and coarse env classes ship under that tier alone; a
	// content-level env class (the CLAUDE_CONFIG_DIR hash) additionally
	// requires the node's raw-content posture. Composed by
	// store.SelectSessionHookActivity. Optional both directions: an older
	// server ignores the key. See internal/orgcontract/hookactivity.go.
	SessionHookActivity []HookActivitySessionRow `json:"session_hook_activity,omitempty"`

	// --- Org-parity Wave-3 per-developer enterprise wires. All ride
	// shipsRawContent() (full_content / admin_managed) like the session-
	// scoped wires above; each row type documents its own posture. All
	// optional both directions (older servers ignore, older agents omit).
	// See docs/plans/org-parity-full-depth-plan-2026-08-24.md §4. ---

	// AdvisorSuggestions is the W3.2 Suggestions/Advisor wire: one row per
	// active suggestion in the node's advisor digest, enterprise-raw
	// (paths/commands/evidence verbatim). See advisor.go.
	AdvisorSuggestions []AdvisorSuggestionRow `json:"advisor_suggestions,omitempty"`
	// ProjectPatterns is the W3.3 Discovery/Patterns wire: one row per
	// project × pattern kind × value, raw paths/commands. See patterns.go.
	ProjectPatterns []ProjectPatternRow `json:"project_patterns,omitempty"`
	// BenchmarkRuns / BenchmarkAttempts are the W3.4 wire: per-(run,config)
	// aggregates + terminal attempts (task prompts / judge rationales /
	// answer excerpts raw). See benchmark.go.
	BenchmarkRuns     []BenchmarkRunRow     `json:"benchmark_runs,omitempty"`
	BenchmarkAttempts []BenchmarkAttemptRow `json:"benchmark_attempts,omitempty"`
	// CompressionStats is the W3.5 wire: day × mechanism honest byte deltas
	// (saved vs evicted kept structurally separate). See compression.go.
	CompressionStats []CompressionStatRow `json:"compression_stats,omitempty"`
	// RoutingDevRows / CodeintelDevRows are the W2.3/W2.4 per-developer
	// variants of the teams-tier fleet aggregates (which stay untouched).
	// See routingdev.go / codeinteldev.go.
	RoutingDevRows   []RoutingDevRow   `json:"routing_dev,omitempty"`
	CodeintelDevRows []CodeintelDevRow `json:"codeintel_dev,omitempty"`
	// TerminalRuns / TerminalCommands / RemoteAudit are the W2.6 per-dev
	// terminal + remote-access visibility wires (command identity is
	// hash-only BY CAPTURE — the node never stores raw command text; peer
	// addresses raw). See terminaldev.go.
	TerminalRuns     []TerminalRunRow     `json:"terminal_runs,omitempty"`
	TerminalCommands []TerminalCommandRow `json:"terminal_commands,omitempty"`
	RemoteAudit      []RemoteAuditRow     `json:"remote_audit,omitempty"`
	// GuardPins / GuardApprovals are the W5.2 guard pin + exception-approval
	// current-state snapshots. See guardpins.go.
	GuardPins      []GuardPinRow      `json:"guard_pins,omitempty"`
	GuardApprovals []GuardApprovalRow `json:"guard_approvals,omitempty"`

	// TerminalSummaries + RemoteAuditSummaries are the OPTIONAL Arc 4 P5h
	// terminal-detail aggregates (per day×tool×kind terminal run/command counts,
	// and per day×kind×decision×principal remote-audit event counts), present
	// only when the node ships the terminal_detail tier (opt-in individual /
	// admin-raised managed via the DISTINCT extract.terminal authority). No
	// command, hash, session id, peer address, or route ever crosses. The
	// terminal_* / remote_audit raw tables stay pinned out of the wire; only
	// these aggregates cross, under this explicit tier. Optional both directions
	// like RoutingSummaries.
	TerminalSummaries    []TerminalSummaryRow    `json:"terminal_summaries,omitempty"`
	RemoteAuditSummaries []RemoteAuditSummaryRow `json:"remote_audit_summaries,omitempty"`
	// SandboxPosture + SandboxCapability are the OPTIONAL sandbox posture
	// aggregate (sandbox plan v2 section 8.4): per-day run counts by the
	// closed isolation and capture enums, and the node's capability enums.
	// Shipped under the terminal_detail tier, and only while the Sandboxes and
	// VMs module is active on the node. See sandboxposture.go. Optional both
	// directions.
	SandboxPosture    []SandboxPostureRow   `json:"sandbox_posture,omitempty"`
	SandboxCapability *SandboxCapabilityRow `json:"sandbox_capability,omitempty"`
	// SandboxEgressRefusals is the OPTIONAL per-day egress refusal count by
	// tier and closed rule (audit CG-15, decision D-11), sent only by a
	// MANAGED node. Enums and counts only; no host, port, path or run. See
	// sandboxegress.go. Optional both directions: an old agent omits it, an
	// old server ignores the key.
	SandboxEgressRefusals []SandboxEgressRefusalDayRow `json:"sandbox_egress_refusals,omitempty"`
	// SecurityPosture / SecurityFindings / AIChangeRecords are the OPTIONAL
	// security pillar wire (security plan 7.4, lane SEC-E2), composed through
	// the SecurityOrgProviders seam only while the security module is active
	// and the share level allows (an individual node sends none until its
	// operator sets [org_client.share].security). Every field is tag-classed
	// and raw fields ship only under shipsRawContent(). See securityrows.go.
	// Optional both directions: an old server ignores the keys.
	SecurityPosture  []SecurityPostureRow `json:"security_posture,omitempty"`
	SecurityFindings []SecurityFindingRow `json:"security_findings,omitempty"`
	AIChangeRecords  []AIChangeRecordRow  `json:"ai_change_records,omitempty"`
	// MCPRelayActivity is the HMAC-only daily aggregate of this node's MCP
	// relay decisions (Agent Access P4 W4e, doc3 §9.5). An individual node
	// attaches it only under [org_client.share].mcp_activity (R8.30.b); an
	// enrolled teams/enterprise node attaches it by capture posture (R9.5).
	// Composed by internal/store/mcprelaysummary.go through the
	// internal/mcprelay/record seam - orgpush.go names no relay table.
	// Optional both directions like RoutingSummaries.
	MCPRelayActivity []MCPRelayActivityRow `json:"mcp_relay_activity,omitempty"`
	// MCPRelayEvents are the per-record relay events (decision / completion /
	// gap / gap_resolution, R14.5), attached ONLY under shipsRawContent() -
	// the enrolled teams/enterprise L2 posture - and never on an individual
	// node. A CURSOR wire (PushCursor.MCPRelay) like GuardEvents: the server
	// de-dupes on (source_node_key, local_record_seq, record_kind).
	MCPRelayEvents []MCPRelayEventRow `json:"mcp_relay_events,omitempty"`
	// MCPInventory is the node's configured-MCP-server inventory (Agent
	// Access P11 item (c), R12.10 / R13.8 / R14.6; mcpinventory.go): FULL
	// under shipsRawContent(), REDUCED (identity + metadata, no raw locator)
	// otherwise; an individual node attaches it only under
	// [org_client.share].mcp_activity. Composed by
	// internal/store/mcpinventory.go through the MCPInventoryProviders seam.
	// Optional both directions like RoutingSummaries.
	MCPInventory []MCPInventoryRow `json:"mcp_inventory,omitempty"`

	// RoutingDetails is the OPTIONAL Arc 4 P5d routing-detail aggregate
	// (model-id-bearing per-decision rollup), present only when the node
	// ships the routing_detail tier (opt-in individual / admin-raised
	// managed). Optional both directions like RoutingSummaries.
	RoutingDetails []RoutingDetailRow `json:"routing_details,omitempty"`

	// LimitGauges is the OPTIONAL Arc 4 P5e predictions aggregate (per day ×
	// provider rate-limit utilization), present only when the node ships the
	// limit_gauge tier (opt-in individual / admin-raised managed). Optional
	// both directions like RoutingSummaries.
	LimitGauges []LimitGaugeRow `json:"limit_gauges,omitempty"`

	// SessionLimitSnapshots is the OPTIONAL per-session rate-limit window wire
	// (lane F-WIRE): the newest proxy-captured 5h / 7d window observation per
	// (session, provider) above the node's limit-snapshot cursor, so the org
	// session drawer renders the node's "% of limit spent" gauge. Metadata
	// only; ships under the limit_gauge tier or on a full-capture node.
	// Composed by store.SelectSessionLimitSnapshots
	// (internal/store/limitgauge.go, so orgpush.go never names
	// limit_snapshots). Optional both directions like RoutingSummaries. See
	// internal/orgcontract/limitsnapshot.go.
	SessionLimitSnapshots []SessionLimitSnapshotRow `json:"session_limit_snapshots,omitempty"`

	// GuardEvents are guard-layer verdict rows (v1.8.3+, guard spec
	// §14.3). omitempty keeps pre-guard envelopes byte-identical and
	// lets pre-guard servers ignore the key entirely (the standard
	// additive-compat posture: no required new fields in either
	// direction). Server-side ingest + rollups land with the G14
	// teams arc; until then an old server ACKs the batch and the
	// guard rows are simply not retained centrally.
	GuardEvents []GuardEventRow `json:"guard_events,omitempty"`

	// OTelContent are native-OTel content bodies (native-console Phase 2b,
	// v1.8.x+). Same additive-compat posture as GuardEvents: omitempty so
	// pre-feature envelopes stay byte-identical and an older server ignores
	// the key (ACKs the batch; content simply isn't retained centrally).
	// Present only when the node shares full content (full_content /
	// admin_managed) for the raw body — the hash ships regardless.
	OTelContent []OTelContentRow `json:"otel_content,omitempty"`

	// Org-tier observability (internal/obs) — the tiered, independently
	// node-opt-in disclosure ladder (docs/plans/obs-org-tier-plan-2026-06-29.md
	// §1). Each slice is present only under its own [org_client.share] flag
	// (default false, never server-forced) and is composed via the obs
	// provider seam in orgpush.go (which names no obs_* table — the privacy
	// sentinel stays green, like routing_summaries). Same additive-compat
	// posture as the other optional slices: pre-feature servers ignore the
	// keys, future servers tolerate their absence.
	//
	// T1 — aggregate rollup (counts + token/cost/latency sums; content-free).
	ObsSummaries []ObsSummaryRow `json:"obs_summaries,omitempty"`
	// T2 — trace + span STRUCTURE (topology/kind/name/model/tokens/cost/
	// latency/status/request_id; hashes only, never bodies).
	ObsTraces     []ObsTraceRow     `json:"obs_traces,omitempty"`
	ObsSpans      []ObsSpanRow      `json:"obs_spans,omitempty"`
	ObsSpanEvents []ObsSpanEventRow `json:"obs_span_events,omitempty"`
	// T3 — raw span CONTENT bodies (prompt/response/tool_io); content present
	// only under shipsRawContent(), content_hash always.
	ObsContent []ObsContentRow `json:"obs_content,omitempty"`
	// T4 — eval run health (summaries + scores; content-free).
	ObsEvalRuns []ObsEvalRow `json:"obs_eval_runs,omitempty"`
	// T5 — per-END-USER spend (org-budget guardrails plan §2.1). End-user
	// PII: present ONLY under ObsSummary AND shipsRawContent(), off by
	// default, never server-forced (same additive-compat posture as the
	// other optional slices).
	ObsEndUserSpend []ObsEndUserSpendRow `json:"obs_enduser_spend,omitempty"`
	// T6 — input-admission verdicts + policy snapshots (Plane-A admission
	// org tier, gap-audit 2026-07-10 §2.1 / #1a). Present only under the
	// node's own [org_client.share.obs] admission opt-in (default false,
	// never server-forced). Same additive-compat posture as the other
	// optional slices: pre-feature servers ignore the keys, future servers
	// tolerate their absence. Verdict PII/prose (Tenant/EndUser/
	// ReasonExcerpt) is gated by shipsRawContent(); policy Body always ships.
	ObsAdmissionEvents   []ObsAdmissionRow       `json:"obs_admission_events,omitempty"`
	ObsAdmissionPolicies []ObsAdmissionPolicyRow `json:"obs_admission_policies,omitempty"`
	// T7 — per-item eval scores (Plane-A eval-run detail org tier, gap-audit
	// 2026-07-10 §1 / §2.2 / §6). Present only under the node's own
	// [org_client.share.obs] eval_items opt-in (default false, never
	// server-forced). Distinct from ObsEvalRuns (T4), which carries run/scorer
	// AGGREGATES only; this tier carries the per-item scores that let the org
	// Evals page drill into one run and diff two runs cell-for-cell. The
	// verdict METADATA is content-free and always ships; the item content
	// excerpts (input/expected/output/rationale) are gated by shipsRawContent().
	// Same additive-compat posture as the other optional slices.
	ObsEvalItems []ObsEvalItemRow `json:"obs_eval_items,omitempty"`
	// ObsEgressDecisions carries the T8 egress-routing decision feed (W5.3).
	// Populated only when the node has opted in via
	// [org_client.share.obs].egress (default false). Optional both directions.
	ObsEgressDecisions []ObsEgressRow `json:"obs_egress_decisions,omitempty"`

	// BudgetPosture is the OPTIONAL enum-only self-report of whether the org's
	// BUDGET is actually holding on this node (org-budget plan §3.3d): the
	// enforcement point, the guard's mode, where the effective numbers came
	// from, the last fetch's state, and the coverage limit. NO cap value and NO
	// resolved scope — see BudgetPostureRow in budgetposture.go for why.
	//
	// ENVELOPE-level like MachineIdentity and UpdatePosture, and for the same
	// reason: one push comes from one node, so this is one fact about the
	// pusher, not a per-row column. It is composed by
	// internal/store/budgetposture.go and called BY orgpush.go through a func
	// seam, the RoutingSummaries pattern.
	//
	// omitempty keeps a pre-feature node's envelope BYTE-IDENTICAL to today's
	// accepted shape, and a pre-feature server ignores the unknown key.
	BudgetPosture *BudgetPostureRow `json:"budget_posture,omitempty"`

	// ComponentPosture is the OPTIONAL enum-only component posture of this
	// node (modular packaging plan 6.4, T-682): distro, catalog version, the
	// compiled and active digests, the governance source, and the state and
	// reason of every component that is not active. See ComponentPostureRow
	// in componentposture.go. Envelope-level and composed through a store
	// func seam like BudgetPosture; omitempty keeps a pre-feature node's
	// envelope byte-identical, and a pre-feature server ignores the key.
	ComponentPosture *ComponentPostureRow `json:"component_posture,omitempty"`

	// AgentConfigState is a MANAGED node's applied state of the org's AI tool
	// settings policy (adapter config phase P7, agentconfigstate.go): one row
	// per setting and target file, closed enums plus value hashes. ENVELOPE-
	// level like BudgetPosture and composed the same way, through a func seam
	// (internal/store/agentconfigorgstate.go), so orgpush.go names no node
	// table. Nil on an individual node and on a managed node holding no
	// policy; omitempty keeps every other envelope byte-identical, and a
	// pre-feature server ignores the unknown key.
	AgentConfigState *AgentConfigStateReport `json:"agent_config_state,omitempty"`

	// AgentConfigInventory is a MANAGED node's whole AI tool configuration
	// (D-112, T-427, agentconfiginventory.go): every catalogued setting found
	// in its tools' settings files and every instruction-family file, values
	// and text scrubbed of secrets. Composed through a func seam
	// (internal/store/agentconfiginventory.go) like AgentConfigState, only
	// under raw content and only when it changed since the last accepted
	// push. omitempty keeps every other envelope byte-identical, and a
	// pre-feature server ignores the unknown key.
	AgentConfigInventory *AgentConfigInventoryReport `json:"agent_config_inventory,omitempty"`
}

// PushResponse is the 200 body of POST /api/agent/push.
type PushResponse struct {
	// QueuedRows is the total row count of the envelope the collector durably
	// queued onto the shared log (stateless-collectors-durable-log plan §4.3).
	// It is the honest answer a stateless collector CAN give: the collector
	// only enqueues, so it cannot yet know the true applied/deduped totals
	// (those move to ingest health, computed by the apply worker).
	//
	// Compat rule (plan §6 criterion 10): a pre-arc node ignores this unknown
	// key and reads accepted_rows, which the collector MIRRORS from
	// queued_rows so the node still advances its cursor exactly as before; a
	// post-arc node may prefer queued_rows. omitempty keeps a legacy
	// synchronous-ingest response (QueuedRows == 0) byte-identical to today's
	// shape, so no existing wire golden or client changes.
	QueuedRows   int64 `json:"queued_rows,omitempty"`
	AcceptedRows int64 `json:"accepted_rows"`
	DedupedRows  int64 `json:"deduped_rows"`
	NextCursor   int64 `json:"next_cursor"`

	// GrantReplacement is the OPTIONAL delivery seam for an out-of-band
	// authority change (Plane B dual-mode gateway/RBAC-IA design §5.3, Sol
	// S4). The push cycle is the ONLY node->server round trip that both
	// authenticates the calling node (claims.Sub) and always returns a body
	// (no 304), so it is the smallest existing seam to hand an already-
	// enrolled node its freshly-signed replacement. omitempty on both sides
	// of the compat invariant: a pre-P2b server never emits it (nothing to
	// accept); a pre-P2b agent ignores the unknown key. A P2b agent decodes it
	// from the RAW response body (the generated client's typed 200 struct does
	// not carry it, so no OpenAPI regeneration is needed) and feeds it to
	// orgclient.Client.AcceptGrantReplacement, which verifies and applies it.
	// The node reports adoption back via HeaderGrantReplacementAck on its next
	// push — the fleet-ACK signal the server's posture-activation gate reads.
	GrantReplacement *GrantReplacement `json:"grant_replacement,omitempty"`

	// Reconsent is the OPTIONAL advisory that this organization now offers
	// the calling node an enrolment it does not hold, which the developer
	// must accept on the machine before anything changes (budget enforce
	// consistency, 2026-11-19). Today it has one reason,
	// ReconsentOwnerManaged: a personal organization's machine that
	// enrolled as an individual before a personal org was managed by its
	// owner. It carries no authority and the node NEVER acts on it by itself:
	// it only shows the local dashboard's "Review and accept" prompt, whose
	// click runs an ordinary re-connect and consent screen. omitempty on both
	// sides of the compat invariant.
	Reconsent *ReconsentOffer `json:"reconsent,omitempty"`

	// BreakGlassLeases is the OPTIONAL delivery seam for approved break-glass
	// credential leases owed to THIS node (Plane B design §4.2 rung 3, operator
	// Q5, P6). It rides the same already-authenticated push round trip as
	// GrantReplacement, as an omitempty slice (a node may have one pending lease
	// per provider upstream). Same compat invariant: a pre-P6 server never emits
	// it; a pre-P6 node ignores the unknown key. Each lease is self-contained and
	// signed (see breakglass.go); the node verifies, opens the per-machine seal,
	// and reports adoption back via HeaderBreakGlassAck. Node-side redemption is
	// a separate lane; this field only freezes the delivery contract.
	BreakGlassLeases []BreakGlassLease `json:"break_glass_leases,omitempty"`

	// BreakGlassRevokedLeaseIDs lists lease ids this node previously ACKed that
	// the server has since REVOKED early (an admin revoke before TTL — G1-
	// BREAKGLASS). TTL expiry needs no signal (the node enforces ExpiresAt
	// itself); an explicit revoke does, or a pulled lease would stay usable on
	// the node until its TTL. Advisory and idempotent: the node drops any
	// matching local lease and forgets unknown ids. Same omitempty compat
	// invariant as BreakGlassLeases.
	BreakGlassRevokedLeaseIDs []string `json:"break_glass_revoked_lease_ids,omitempty"`

	// PolicyVersions is the OPTIONAL policy-propagation nudge (2026-09-01):
	// the latest published version per policy-resource family. A node compares
	// it against what it last saw and triggers an immediate policy-resource
	// fetch when the server is ahead, so a publish converges within one push
	// interval instead of the policy poll interval (default hourly). This is a
	// version-number HINT riding an already-authenticated response — it carries
	// no body and forces nothing: delivery, the signature/pin gates, and the
	// [org_client.policy] accept_families opt-in all stay node-owned exactly as
	// before. Same omitempty compat invariant as the seams above: a pre-nudge
	// server never emits it; a pre-nudge agent ignores the unknown key.
	PolicyVersions map[string]int64 `json:"policy_versions,omitempty"`

	// UpdateVersions is the OPTIONAL update nudge (Enterprise Update
	// Management §3.5): the latest PUBLISHED manifest version this node is
	// eligible for, per channel. A node compares it against its own
	// last-accepted manifest version and fetches the SIGNED manifest with a
	// separate authenticated GET when the server is ahead. It carries no
	// document and forces nothing.
	//
	// Deliberately the same shape as PolicyVersions above rather than the
	// manifest itself: it keeps the push response small, and it makes the
	// manifest fetch independently authenticated and independently verifiable
	// instead of something smuggled inside a batch ACK. (Announcements, which
	// this rail is modelled on, do not ride the response body either — they
	// are a separate GET on the same cycle.)
	//
	// Because the node only fetches when the nudge says the server is ahead,
	// the steady state adds ZERO extra requests: with [update].enabled and no
	// published manifest, a node makes exactly the same set of requests to
	// exactly the same hosts as it does today.
	//
	// Same omitempty compat invariant as the seams above: a pre-feature
	// server never emits it and the node stays inert; a pre-feature agent
	// ignores the unknown key.
	UpdateVersions map[string]int64 `json:"update_versions,omitempty"`

	// SecurityPurpose is the org's stated purpose for its Code security
	// views (security plan 7.12, lane SEC-E3): a closed id from
	// SecurityPurposes, or SecurityPurposeUnset, sent only while
	// org.security is configured on the server. The node shows it in its
	// affected-worker notice, rendered from its own label table (never text
	// the server wrote). Same omitempty compat invariant as the seams above.
	SecurityPurpose string `json:"security_purpose,omitempty"`

	// SecurityVisibility is what the org's Code security views show under
	// its current settings (operator ruling P-089): the minimum group, the
	// fields switched off and whether the optional purpose statement is
	// shown. Sent with SecurityPurpose, only while org.security is
	// configured; the node's notice renders it from its own label table.
	// Same omitempty compat invariant as the seams above.
	SecurityVisibility *SecurityVisibility `json:"security_visibility,omitempty"`

	// RailVersions is the OPTIONAL rail nudge (2026-10-02 budget-latency arc,
	// P2): the current version of every node-pulled rail that is NOT a
	// policy-resource family (RailBudget, RailPricing, RailBundle,
	// RailRouting, RailAnnouncement, RailDisplay). The SAME map GET /api/agent/policy-version
	// returns, riding the push acknowledgment so a push still converges. A
	// HINT only, exactly like PolicyVersions: it carries no document; the node
	// fetches through each rail's own signed, pinned, monotonic path. A
	// separate key from PolicyVersions on purpose: an older node treats every
	// policy_versions key as a policy-resource family and would wake that
	// loop for a budget edit.
	RailVersions map[string]int64 `json:"rail_versions,omitempty"`

	// OrgName is the organization's CURRENT display name (T-862). An admin
	// may rename the org after a node enrolled (Settings > Server, or
	// `observer-org org rename`); the node records the name it reads here in
	// place of the one its enrolment stored, so `observer org status` and
	// the node dashboard follow the rename without a re-enrolment. It rides
	// the already-authenticated push acknowledgment at the same trust level
	// as EnrollResponse.OrgName, and it is a label only: it changes no
	// identity, key pin, grant or policy. The node applies it only when it
	// passes OrgNameProblem. omitempty on both sides of the compat invariant:
	// an older server never sends it (the node keeps its enrolment name) and
	// an older node ignores the unknown key.
	OrgName string `json:"org_name,omitempty"`

	// OwnerManaged is whether this organization is the developer's own: its
	// only admin and its only developer are the same person (a personal
	// organization of one, orgkind's OwnerManaged row), the same fact as
	// EnrollResponse.OwnerManaged, restated on every accepted push so a node
	// that enrolled before it stored the fact (agent migration 261), or
	// whose organization's answer changed, records the current one
	// (store.SetEnrolmentOwnerManaged, bound to the enrolment's org id). It
	// grants no authority: on a managed enrolment it only picks the owner
	// audience of the managed-default visibility table (finding F12). A
	// POINTER so an explicit false can clear the node's record while an
	// absent key (an older server, or a push whose org-kind read failed)
	// changes nothing. omitempty on both sides of the compat invariant: an
	// older node ignores the unknown key.
	OwnerManaged *bool `json:"owner_managed,omitempty"`
}

// Rail keys of PushResponse.RailVersions / PolicyVersionsDoc.RailVersions.
const (
	RailBudget       = "budget"
	RailPricing      = "pricing"
	RailBundle       = "bundle"
	RailRouting      = "routing"
	RailAnnouncement = "announcement"
	// RailDisplay is the developer cost-display rail (GET
	// /api/agent/display-policy, DisplayPolicyDoc); its version is the
	// org_display_settings counter the signed document carries. An older node
	// ignores the unknown key; an older server never sends it.
	RailDisplay = "display"
	// RailGrants is the per-caller access-grant rail (GET /api/agent/grants,
	// AccessGrantDoc); its version is org_access_grant_epoch, bumped on every
	// issue, revoke, extend and scheduled-start. An older node ignores the
	// unknown key; an older server never sends it.
	RailGrants = "grants"
	// RailMessages is the per-caller admin message rail (GET
	// /api/agent/messages, OrgMessageDoc). Its version is computed PER
	// CALLER: the highest message id in the caller's own threads combined
	// with the org's message-settings version, so a message to one developer
	// wakes only that developer's node. An older node ignores the unknown
	// key; an older server never sends it.
	RailMessages = "messages"
)

// OrgMessagesPath is the node's pull path for admin messages.
const OrgMessagesPath = "/api/agent/messages"

// OrgMessageReceiptsPath is where the node posts read/acknowledge receipts.
const OrgMessageReceiptsPath = "/api/agent/messages/receipts"

// PolicyVersionsPath is the node's lightweight policy-freshness probe
// (GET, enrolment bearer; ETag / If-None-Match -> 304).
const PolicyVersionsPath = "/api/agent/policy-version"

// The HELD policy-version probe (T-474: an org change reaches an ACTIVE node
// within seconds). An active node adds ?wait=<seconds> to the probe together
// with its If-None-Match; a server that supports holding keeps the request
// open while the version vector still matches that ETag, answers 200 the
// moment it moves, and answers 304 when the hold ends. It marks every answer
// to a hold it granted with HeaderPolicyVersionsHold. Both halves are
// additive: an older server ignores the query parameter and answers at once
// without the header (the node then keeps its pre-hold cadence), and an older
// node never asks. The body and every signed rail are unchanged.
const (
	// PolicyVersionsHoldParam is the query parameter carrying the requested
	// hold in whole seconds.
	PolicyVersionsHoldParam = "wait"
	// HeaderPolicyVersionsHold is set by a server that granted the hold; its
	// value is the hold it applied, in whole seconds.
	HeaderPolicyVersionsHold = "X-SBO-Policy-Hold"
	// MaxPolicyVersionsHoldSeconds caps the hold a server applies, whatever
	// a node asks for. It stays under the node's 30 s HTTP client timeout and
	// the org server's 60 s write timeout.
	MaxPolicyVersionsHoldSeconds = 25
)

// HeaderPushMinInterval is the org's push BACKPRESSURE hint on an accepted
// push (2026-10-02 budget-latency arc, P3): the minimum number of whole
// seconds this node should leave between two pushes. It only ever slows a
// node's activity-driven pushes (the node's own 15 s floor still applies, and
// its ceiling is unaffected); an absent header means no hint. Older nodes
// ignore it.
const HeaderPushMinInterval = "X-SBO-Push-Min-Interval"

// PolicyVersionsDoc is the probe's response body: the version vector of every
// node-pulled policy, and NOTHING else - no caps, no prices, no rules. It is
// UNSIGNED by design: it can only make a node call the existing signed rails,
// never apply, lower, raise or clear anything itself (docs/security.md
// POLICY-PROBE-1).
type PolicyVersionsDoc struct {
	// PolicyVersions is the latest published version per policy-resource
	// family (the push-ack nudge's map).
	PolicyVersions map[string]int64 `json:"policy_versions,omitempty"`
	// RailVersions is the per-rail version (see PushResponse.RailVersions).
	RailVersions map[string]int64 `json:"rail_versions"`
	// The wire name "probe_after_seconds" is RESERVED (T-533): it was declared
	// here as a server-advised probe interval that no server ever sent and no
	// node ever read, so it was removed. Removal is compatible both ways: a
	// server never emitted it (it was omitempty and always zero), and the node
	// decodes this document leniently. The node's own pacing is
	// internal/policyfresh (activity, backstop, held-probe gap). Never reuse
	// the name with another meaning.
}

// HeaderGrantReplacementAck is the request header a node sets on POST
// /api/agent/push to report the highest grant-replacement generation it has
// adopted (its stored enrolment grant's ReplacementGeneration, 0 when none).
// It is advisory bookkeeping over an ALREADY-authenticated push (the Ed25519
// per-push proof is the sole authenticator); the header can only report the
// node's OWN adoption and never widens access, exactly like
// HeaderAgentKeyFingerprint. The server records it into
// org_grant_replacement_ack, the fleet-ACK registry its posture-activation
// gate reads.
const HeaderGrantReplacementAck = "X-SBO-Grant-Replacement-Ack"

// Product posture classes (design §5.2). The org's product posture is chosen
// at org creation and served to both the dashboard and the fleet.
//
//   - ProductPostureTeams keeps today's opt-in algebra: under the teams posture
//     sharing is node-side opt-in, never server-forced, and the privacy
//     sentinel holds byte-for-byte (the posture-conditional truth of §5.3).
//   - ProductPostureEnterprise inverts the default at the GRANT layer: under the
//     enterprise posture enrolment auto-issues the full extract.* set (managed-
//     consent class), so effective sharing is ALL by default with zero node-side
//     edits — raw content ships via store.ShareOptions.EnterpriseGranted, a
//     resolved enrolment grant, never a live remote command.
//
// The empty string is treated as ProductPostureTeams everywhere so a pre-P2b
// server (which stores no posture) and a pre-P2b node behave exactly as teams.
const (
	ProductPostureTeams      = "teams"
	ProductPostureEnterprise = "enterprise"
)

// PostureState is the 200 body of GET /api/agent/posture (node-facing) and the
// core of the dashboard's GET /api/org/posture. It is a READ of server state;
// it carries NO authority and grants nothing — the authority a node actually
// holds lives only in its signed EnrolmentGrant / GrantReplacement. It exists
// so a node (and the personal-plane data-authority classifier) has one honest,
// deterministic source for "what posture is this org, and what collection has
// the admin turned off".
type PostureState struct {
	// Posture is the ACTIVE posture (teams|enterprise).
	Posture string `json:"posture"`
	// PendingPosture is the target of an in-flight teams->enterprise flip that
	// has not yet cleared the fleet-ACK gate; empty when no flip is pending.
	PendingPosture string `json:"pending_posture,omitempty"`
	// ReplacementGeneration is the current fleet grant-replacement generation
	// (0 = none issued). A node compares it against its own adopted generation.
	ReplacementGeneration int64 `json:"replacement_generation"`
	// Collection is the org-side per-share-tier collection toggle map (design
	// §5.2 "org collection settings"): tier key -> enabled. Absent/true means
	// "collect"; false means the admin has LOWERED that tier fleet-wide. Only
	// tiers the admin has explicitly turned OFF are guaranteed present; a
	// missing key is enabled (the default-ALL-ON posture).
	Collection map[string]bool `json:"collection,omitempty"`
}

// PolicyBundle is the 200 body of GET /api/v1/policy-bundle (guard spec
// §14.2): one signed, versioned org guard-policy TOML rule set. The agent
// also persists the verified envelope verbatim as its local bundle cache
// (~/.observer/org-policy-bundle.json) so the guard's org layer loads with
// no network and re-checks the same signature at load time.
//
// Trust model: Signature covers PolicyBundleSigningMessage(Version,
// BundleTOML) under the org policy key. PublicKey rides along in EVERY
// envelope so verification is self-contained, but the key only counts as
// trusted when its PublicKeyPinHash matches the pin the agent recorded at
// enrolment (or on first fetch for pre-G13 enrolments). An envelope whose
// signature or pin check fails is REJECTED — the agent keeps its previous
// bundle and records an R-205 guard event.
//
// The bundle channel DISTRIBUTES policy (server → agent); it never widens
// content sharing (§14.1) — nothing in this type flows back to the server.
type PolicyBundle struct {
	// Version is the server-assigned monotonically increasing bundle
	// version. Agents reject a fetched version lower than the last one
	// they verified (downgrade protection); rolling back is done by
	// publishing the old content as a NEW version.
	Version int64 `json:"version"`
	// BundleTOML is the org guard-policy rule set in exactly the §4.4
	// user/project policy-file format ([[rule]] + [[override]] tables).
	BundleTOML string `json:"bundle_toml"`
	// Signature is base64url(Ed25519 signature) over
	// PolicyBundleSigningMessage(Version, BundleTOML).
	Signature string `json:"signature"`
	// PublicKey is the base64url Ed25519 public half of the signing key.
	PublicKey string `json:"public_key"`
	// SignedAt is the RFC3339 instant the bundle was signed (audit metadata;
	// not part of the signed message — Version is the integrity anchor).
	SignedAt string `json:"signed_at"`
	// Description is the operator's note for the version history.
	Description string `json:"description,omitempty"`
	// Binding is set on a v2 (bound) delivery only: the org and member the
	// signature also covers (policybinding.go). Absent on every v1 envelope,
	// so a released node, which never asks for v2, never sees it.
	Binding *PolicyBinding `json:"binding,omitempty"`
	// ProjectBinding is set on a v3 (project-audience) delivery only
	// (projectenvelope.go): the org, member, assignment epoch and, on the
	// composed bundle, the digest of the signed project mapping, or, on a
	// per-project envelope, the org project id. A v3 envelope carries no
	// Binding; a node never sees this field unless it asked for v3.
	ProjectBinding *ProjectBinding `json:"project_binding,omitempty"`
	// Projects rides the composed v3 bundle only: the signed project mapping
	// and one signed envelope per project whose sections reach the member.
	// It is NOT part of the composed bundle's own signature; the mapping is
	// bound by digest and epoch in ProjectBinding, and each envelope carries
	// its own v3 signature. The node strips it before caching the bundle.
	Projects *ProjectDelivery `json:"projects,omitempty"`
	// Families rides a per-project v3 envelope only, to a node that asked
	// for ProjectFamiliesCapability (projectfamilies.go, lane sec-p3): the
	// project's family sections, covered by the envelope's signature through
	// ProjectBinding.FamiliesDigest. Absent everywhere else.
	Families []ProjectFamilyMember `json:"families,omitempty"`
}

// SignedPolicyResource is the P0-5 unified, family-tagged, signed org
// policy resource (docs/plane-a/unified-policy-resource.md §6;
// docs/plans/plane-a-p0-5-unified-policy-resource-v1-plan.md §4.1). It
// generalizes PolicyBundle (guard, family-implicit) into a family-tagged
// shape any of the seven policy rails (§3 of the design doc) can eventually
// ride, while v1 ships exactly two: admission.input and
// egress.routing_guardrail.
//
// Distribution mirrors PolicyBundle: GET /api/agent/policy/{family}, strong
// ETag (over the SIGNING MESSAGE digest, not Body alone — §4.4), 304 on
// If-None-Match. Trust model: Signature covers
// PolicyResourceSigningMessage(ID, Version, Family, CompilerVersion,
// BodyHash, SelectorsJSON, RequiredCapabilities) under the org's dedicated
// policy-resource signing key (domain-separated from PolicyBundle's key use
// — signing.go's sbo-policy-resource-v1 domain — even when both rails share
// literal key bytes). PublicKey rides in every response so verification is
// self-contained; it counts as trusted only once TOFU-pinned (the guard
// model, unified-policy-resource.md §7 gate 2).
//
// v1 fields are a DELIBERATE SUBSET of the design doc's full §6 shape:
// Selectors ships pre-serialized as SelectorsJSON, now carrying a real
// (canonical, grammar-checked) targeting predicate — P0-10 Phase B, see
// selectors.go and SelectorsJSON's own comment below; Rollout/RollbackTarget/
// Provenance are not part of this milestone (residual R2, plan §10). Adding
// any of those later is additive (CLAUDE.md #6): new fields join the
// signing message under the SAME domain-separation discipline, never a
// silent Body reinterpretation.
type SignedPolicyResource struct {
	// ID is the immutable resource identity. v1 uses the literal "default"
	// (plan v8 fork 4) — one resource per family, no per-selector targeting
	// yet.
	ID string `json:"id"`
	// Version is monotonic per ID. Rollback = republish old content as a
	// new HIGHER version, never a decrement.
	Version int64 `json:"version"`
	// Family selects the compiler + eligible enforcement points (design
	// doc §3 closed enum). v1: "admission.input" | "egress.routing_guardrail".
	Family string `json:"family"`
	// CompilerVersion pins the family compiler that produced Body, so a
	// decision's engine version is provable in evidence later (design §8.6).
	CompilerVersion string `json:"compiler_version"`
	// Body is the family's native spec as CANONICAL JSON (policyfam's
	// CompileBody output) — never the publisher's raw submitted bytes.
	Body string `json:"body"`
	// BodyHash is hex(SHA-256(Body)) — the dedup + effective-hash
	// reconciliation identity (design §4.3).
	BodyHash string `json:"body_hash"`
	// RequiredCapabilities are the capability tokens an enforcement point
	// must advertise to accept this version (design §2 `required_capabilities`).
	// Normalized (sorted, deduped, grammar-checked) as part of the signing
	// message — see signing.go.
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
	// SelectorsJSON is the pre-serialized §2 targeting predicate over the
	// CLOSED workspace|environment|service vocabulary (selectors.go). The
	// match-all predicate is the literal "{}"; a targeted resource carries
	// the canonical encoding CanonicalSelectorsJSON produces (compact,
	// sorted keys, no empty values), bounded by
	// MaxPolicyResourceSelectorsBytes. It is part of the signing message, so
	// tampering with it invalidates the signature; the agent additionally
	// re-derives the canonical form and rejects any non-canonical spelling
	// (closed_envelope_violation) before evaluating it, keeping the field's
	// grammar closed even though its VALUE is now open (P0-10 Phase B;
	// docs/plans/policy-targeting-rollback-design-2026-08-13.md §2).
	SelectorsJSON string `json:"selectors_json"`
	// Signature is base64url(Ed25519 signature) over
	// PolicyResourceSigningMessage(...).
	Signature string `json:"signature"`
	// PublicKey is the base64url Ed25519 public half of the signing key.
	PublicKey string `json:"public_key"`
	// SignedAt is the RFC3339 instant the resource was signed — UNTRUSTED
	// display metadata, not part of the signed message (Version + BodyHash
	// are the integrity anchors).
	SignedAt string `json:"signed_at"`
	// Description is the operator's note for the version history.
	Description string `json:"description,omitempty"`
	// Binding is set on a v2 (bound) delivery only: the org, member and
	// projection target the signature also covers (policybinding.go). Absent
	// on every stored row and every v1 delivery.
	Binding *PolicyBinding `json:"binding,omitempty"`
}

// RoutingPolicyDoc is the §R19.1 org-distributed policy document. The
// body is a TOML fragment using the [routing] vocabulary; the agent
// composes it with hard-constraints-first semantics
// (routingconfig.ComposeOrgPolicy) and STRUCTURALLY ignores any
// enabled/mode keys — enforcement is node-side opt-in by design
// (§R23: no remote enforce toggle exists).
type RoutingPolicyDoc struct {
	Version int64 `json:"version"`
	// Body is the TOML policy fragment.
	Body string `json:"body"`
	// BodyHash is hex(SHA-256(body)).
	BodyHash string `json:"body_hash"`
	// Signature is base64(Ed25519 signature over body bytes) made with
	// the org server's policy signing key.
	//
	// This is the v1 rail and it is RELEASED, which is why it still
	// covers the bare body — see SignatureV2 below and docs/security.md
	// ledger row ROUTING-SIG-1.
	Signature string `json:"signature"`
	// SignatureV2 is base64(Ed25519 signature over
	// RoutingPolicySigningMessageV2(Version, Body)) — the
	// DOMAIN-SEPARATED, VERSION-BOUND signature that closes
	// ROUTING-SIG-1's version-replay and cross-rail confusion.
	//
	// ADDITIVE and omitempty on purpose, in BOTH compat directions: a
	// pre-v2 server's response is byte-identical (the field is simply
	// absent, and the agent falls back to verifying Signature), and a
	// pre-v2 agent ignores the extra key. An agent that RECEIVES a v2
	// signature verifies THAT and never falls back — the fallback is
	// for a document carrying no v2 at all, never for one whose v2
	// failed.
	SignatureV2 string `json:"signature_v2,omitempty"`
	// PublicKey is base64(Ed25519 public key) — TOFU-pinned by the
	// agent on first receipt (enrolment-channel trust, §R19.1).
	PublicKey string `json:"public_key"`
}

// OrgAnnouncementDoc is the rail-R3 org announcement document
// (docs/plans/dashboard-announcements-banner-plan-2026-07-31.md §4).
// It mirrors RoutingPolicyDoc field-for-field on purpose: the same
// versioned + signed + TOFU-pinned distribution mechanism carries it,
// and the agent verifies it with the same helper.
//
// The ONLY difference is what Body means. Here it is the plan §1
// announcement JSON — either one object or an array of them — and an
// EMPTY Body is the retraction: a published empty document is a valid,
// signed, version-bumped instruction to show nothing. (Retraction has
// to be a real published version, not a delete, because the agent's
// monotonic-version short-circuit is what makes the poll cheap.)
//
// Nothing about this document is a remote control: it can only ever
// put text in a dismissible banner. The node's [dashboard].
// org_announcements switch silences it locally, and there is no
// server-side toggle for that — same posture as share.full_content.
type OrgAnnouncementDoc struct {
	Version int64 `json:"version"`
	// Body is the announcement JSON (a §1 object or an array of them).
	// Empty means "retracted — show nothing".
	Body string `json:"body"`
	// BodyHash is hex(SHA-256(body)) — an integrity/dedup value for
	// display. It is NOT what authorizes the document; see Signature.
	BodyHash string `json:"body_hash"`
	// Signature is base64(Ed25519 signature over
	// AnnouncementSigningMessage(Version, Body)) made with the org
	// server's distribution signing key — the SAME key that signs
	// RoutingPolicyDoc, resolved through the one seam
	// orgserver/routingpolicy.SigningKeyWith: the configured
	// [policy].signing_key_path (the key the enrolment response delivers)
	// when the org has one, the routing_policy_keys row otherwise.
	//
	// The signed message is domain-separated and version-bound, NOT the
	// bare body: sharing one key across two rails is only safe if a
	// signature minted for one cannot verify on the other, and a
	// version-bumped replay of a captured document (an announcement, or
	// an old retraction) must not be accepted by a node.
	Signature string `json:"signature"`
	// PublicKey is base64(Ed25519 public key) — TOFU-pinned by the
	// agent on first receipt (enrolment-channel trust).
	PublicKey string `json:"public_key"`
}

// ReconsentOffer is PushResponse.Reconsent: an advisory, never authority.
type ReconsentOffer struct {
	// Reason is one of the Reconsent* constants; a node that does not know
	// the reason shows nothing.
	Reason string `json:"reason"`
}

// ReconsentOwnerManaged is the reason a personal organization's machine,
// enrolled as an individual, is offered a re-consent: its organization is
// managed by its owner, so an Enforce budget there can block only after the
// machine re-connects and the owner accepts the managed grant.
const ReconsentOwnerManaged = "owner_managed"
