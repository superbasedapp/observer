import * as I from "lucide-react";
import type { LucideIcon } from "lucide-react";

// vocabIcons — ONE table mapping every closed dashboard vocabulary value to a
// lucide glyph (CLAUDE.md #5: decision logic as data, never an if/else ladder
// in a component). Each vocabulary sits next to its existing metadata owner
// (the comment names it); components call vocabIcon(vocab, value) or render
// <VocabIcon>, and an unknown value falls back to CircleHelp rather than
// throwing, the same honesty rule as SurfaceBadge (unknown ≠ a guess).
//
// Source of the value lists: design-kit survey A (web/) section 5 and survey
// B (web2/), each value verified against lucide-react 0.469.0. IMPORTANT:
// fix the colour-map conflicts listed in the README (guard decision,
// severity, cache kind, cache severity) BEFORE adding icons, so glyph and
// colour agree everywhere.

export const VOCAB_ICONS = {
  // shared/lib/actiontax.gen.ts categories (colour: --act-*)
  actionCategory: {
    file: I.FileText, cmd: I.SquareTerminal, search: I.TextSearch, web: I.Globe, agent: I.Bot,
    skill: I.WandSparkles, mcp: I.Plug, user: I.UserRound, meta: I.Settings2, fail: I.OctagonX,
  },
  // shared/lib/actiontax.gen.json actionTypes (48)
  actionType: {
    read_file: I.FileText, edit_file: I.FilePen, write_file: I.FilePlus2, run_command: I.SquareTerminal,
    search_files: I.FileSearch, search_text: I.TextSearch, tool_search: I.SearchCode, web_fetch: I.CloudDownload,
    web_search: I.ScanSearch, browser_action: I.MousePointerClick, mcp_call: I.Plug, skill_invoke: I.WandSparkles,
    spawn_subagent: I.GitFork, subagent_start: I.Play, subagent_stop: I.Square, subagent_wait: I.Hourglass,
    agent_control: I.Bot, agent_message: I.BotMessageSquare, stdin_write: I.Keyboard, user_prompt: I.UserRound,
    user_prompt_expansion: I.TextCursorInput, ask_user: I.MessageCircleQuestion,
    assistant_message: I.MessageSquareText, system_prompt: I.ScrollText, instructions_loaded: I.BookOpen,
    prompt_context: I.FileStack, context_compacted: I.FoldVertical, config_change: I.FileCog,
    cwd_change: I.FolderOpen, harness_call: I.Workflow, notification: I.Bell,
    permission_request: I.ShieldQuestion, permission_mode: I.KeyRound, permission_denied: I.ShieldBan,
    post_tool_batch: I.Layers, rate_limit: I.Gauge, schedule: I.CalendarClock, session_start: I.CirclePlay,
    session_end: I.CircleStop, setup: I.Wrench, task_complete: I.CircleCheck, todo_update: I.ListTodo,
    tool_failure: I.OctagonX, api_error: I.CloudAlert, turn_aborted: I.Ban, worktree_create: I.FolderGit2,
    worktree_remove: I.FolderX, unknown: I.CircleHelp,
  },
  // shared/lib/actions.ts ACTION_SURFACES
  toolSurface: { builtin: I.Package, mcp: I.Plug, orchestration: I.Workflow, meta: I.Settings2, unresolved: I.CircleHelp },
  // shared/primitives/SurfaceBadge.tsx (the only vocabulary with icons today)
  captureSurface: { cli: I.SquareTerminal, ide: I.AppWindow, desktop: I.Monitor, sdk: I.Braces, web: I.Globe },
  // shared/lib/guardCatalog.ts
  guardDecision: { allow: I.ShieldCheck, flag: I.Flag, ask: I.ShieldQuestion, deny: I.ShieldBan },
  guardSeverity: { info: I.Info, warn: I.TriangleAlert, high: I.OctagonAlert, critical: I.Siren },
  guardMode: { observe: I.Eye, advise: I.Lightbulb, enforce: I.ShieldAlert, disabled: I.ShieldOff, off: I.ShieldOff },
  // web/src/pages/Security.tsx PromptGuardCard + components/PromptGuardLine.tsx
  // (the prompt-submit guard outcome; tone: web/src/lib/vocabTones.ts)
  promptGuardOutcome: {
    blocked: I.ShieldBan, confirmed: I.ShieldQuestion, warned: I.TriangleAlert, redacted: I.EyeOff,
    allowed: I.ShieldCheck, degraded: I.ShieldOff,
  },
  // web/src/lib/types.ts suggestions
  suggestionSeverity: { info: I.Info, advice: I.Lightbulb, warning: I.TriangleAlert },
  suggestionCategory: { cost: I.DollarSign, latency: I.Timer, quality: I.BadgeCheck, hygiene: I.Sparkles },
  suggestionScope: { session: I.MessagesSquare, project: I.FolderKanban, global: I.Globe },
  // cache (CacheExpiryCard / Cache.tsx / CacheTimelineList)
  cacheExpiry: { ok: I.Flame, soon: I.Timer, critical: I.AlarmClock, cold: I.Snowflake },
  keepWarmMode: { off: I.PowerOff, advise: I.Lightbulb, enforce: I.Flame },
  cacheEventKind: {
    hit: I.Zap, write: I.PenLine, reanchor: I.Anchor, mispredict: I.Crosshair, below_min: I.Minimize2,
    invalidation_rewrite: I.RefreshCcw, expiry_rewrite: I.TimerReset, model_switch_rewrite: I.ArrowLeftRight,
    compaction_reset: I.FoldVertical,
    // internal/cachetrack/attribute.go §15.3 implicit-cache kinds
    implicit_hit: I.Zap, implicit_miss: I.ZapOff, implicit_write: I.PenLine,
  },
  cacheCause: {
    // the internal/cachetrack/attribute.go Cause values (tone: shared/lib/cacheVocab.ts)
    suffix_growth: I.TrendingUp, tools_changed: I.Wrench, system_changed: I.ScrollText, reanchor: I.Anchor,
    handoff_rehydration: I.Handshake, model_changed: I.ArrowLeftRight, fast_toggle: I.Rabbit,
    tools_or_system_changed: I.SlidersHorizontal, context_compacted: I.FoldVertical, ttl_expired: I.TimerOff,
    lookback_window_missed: I.SearchX, block_diverged: I.Split, below_min_cacheable: I.Minimize2,
    parallel_cold_start: I.Snowflake, unknown: I.CircleHelp, implicit_hit: I.Zap, prefix_churn: I.Shuffle,
    prefix_shrink: I.Shrink, prompt_cache_key_overflow: I.KeyRound,
  },
  cacheEntryState: { live: I.Flame, unverified: I.CircleDashed, expired: I.TimerOff, invalidated: I.CircleSlash },
  // token source / tier + reliability
  sourceTier: { proxy: I.Network, jsonl: I.FileJson, transcript: I.FileJson, mixed: I.Merge, none: I.CircleSlash },
  reliability: { accurate: I.BadgeCheck, approximate: I.BadgeAlert, unreliable: I.BadgeX, unknown: I.CircleHelp },
  // Projects (internal/projectroi statuses)
  promptStatus: {
    committed: I.GitCommitHorizontal, partial: I.CircleDashed, uncommitted: I.FileDiff, superseded: I.History,
    no_edits: I.FileMinus,
  },
  commitCapture: { ok: I.GitCommitHorizontal, no_git: I.FolderX, never_scanned: I.ScanSearch, error: I.TriangleAlert },
  worktreeState: {
    modified: I.FilePen, added: I.FilePlus2, deleted: I.FileX2, renamed: I.ArrowRightLeft, untracked: I.FileQuestion,
    ignored: I.EyeOff, unmerged: I.GitMerge,
  },
  locCategory: { code: I.CodeXml, docs: I.BookText, config: I.FileCog, generated: I.Wand, vendored: I.Package, unknown: I.FileQuestion },
  patternType: {
    hot_file: I.Flame, co_change: I.GitCompare, edit_test_pair: I.FlaskConical, knowledge_snippet: I.Lightbulb,
    common_command: I.SquareTerminal,
    // internal/intelligence/patterns/patterns.go TypeOnboardingSeq / TypeCrossTool
    onboarding_sequence: I.ListOrdered, cross_tool_file: I.Files,
  },
  // terminals
  terminalAgentStatus: {
    working: I.LoaderCircle, "waiting-for-input": I.Keyboard, blocked: I.OctagonAlert, idle: I.CirclePause,
    exited: I.CircleStop, unknown: I.CircleHelp,
  },
  terminalTransport: { connecting: I.LoaderCircle, open: I.Wifi, reconnecting: I.RefreshCw, exited: I.PowerOff, error: I.WifiOff },
  // session detail
  taskStatus: {
    pending: I.Circle, in_progress: I.CircleDot, completed: I.CircleCheck, cancelled: I.CircleX, deleted: I.Trash2,
    vanished: I.Ghost, never_activated: I.CircleDashed, still_open: I.CircleEllipsis,
    // internal/taskflow/types.go StatusBlocked
    blocked: I.OctagonAlert,
  },
  messageRole: { user: I.UserRound, assistant: I.Sparkles, tool: I.Wrench, system: I.Settings2 },
  stopReason: {
    end_turn: I.Check, tool_use: I.Wrench, max_tokens: I.Scissors, refusal: I.Ban, pause_turn: I.Pause, stop_sequence: I.Square,
  },
  serviceTier: { fast: I.Rabbit, priority: I.Rabbit, standard: I.Turtle },
  qualityBand: { Strong: I.BadgeCheck, Fair: I.BadgeInfo, Weak: I.BadgeAlert },
  // web/src/lib/cloudProgress.ts
  cloudProgress: {
    idle: I.Sparkle, pending: I.Timer, sending: I.CloudUpload, sent: I.Hourglass, complete: I.Sparkles,
    failed_retryable: I.RefreshCw, failed_terminal: I.CloudOff, cancelled: I.Ban, reconfirmation_required: I.ShieldQuestion,
  },
  // Egress / policies
  egressOutcome: {
    applied: I.Route, fail_closed: I.Lock, breaker_open: I.Unplug, upstream_error: I.CloudAlert, fallback_open: I.LockOpen,
    splice_failed: I.Link2Off,
  },
  judgeHosting: { local: I.Laptop, aggregator: I.Network, provider: I.Cloud, private: I.Lock },
  governanceSource: { you: I.UserRound, org: I.Users, both: I.Users, org_raised: I.ShieldAlert },
  // Benchmarks
  benchmarkRun: { completed: I.CircleCheck, running: I.LoaderCircle, budget_stop: I.HandCoins, aborted: I.OctagonX, error: I.CircleX },
  benchmarkVerdict: {
    candidate_cheaper_noninferior: I.Trophy, candidate_worse: I.TrendingDown, no_detected_difference: I.Equal,
    inconclusive: I.CircleHelp, insufficient_distinct_tasks: I.Tally5,
  },
  // Settings / health
  healthCheck: { ok: I.CircleCheck, warn: I.TriangleAlert, fail: I.CircleX },
  auditChain: { intact: I.Link, broken: I.Link2Off },
  proxySetup: {
    oauth_ready: I.KeyRound, api_key_ready: I.KeyRound, claude_not_installed: I.PackageX, routed_to_observer: I.Route,
  },
  mcpToolVerdict: { active: I.Activity, low_use: I.TrendingDown, unused: I.CircleSlash, no_data: I.CircleDashed },
  // web/src/lib/tagTaxonomy.ts outcome tags
  outcomeTag: {
    shipped: I.Rocket, wip: I.Construction, blocked: I.Ban, junk: I.Trash2, success: I.CircleCheck, failed: I.CircleX,
    abandoned: I.Archive,
  },

  // ======================= ORG DASHBOARD (web2) =======================
  // internal/orgserver/rbac/roles.go + web2 Roles.tsx
  rbacRole: {
    admin: I.Crown, team_leader: I.UserCog, finance: I.Wallet, security_viewer: I.Shield,
    policy_admin: I.FileLock2, custom: I.Pencil, auditor: I.Eye, member: I.User, lead: I.UserCog,
  },
  permissionGroup: { read: I.Eye, write: I.Pencil, admin: I.Crown, agent_access: I.Bot, "scope:org": I.Globe },
  // web2/src/lib/authRails.ts
  signInRail: { local: I.KeyRound, saml: I.ShieldCheck, oidc: I.Fingerprint, dev: I.SquareTerminal },
  railHealth: { ok: I.CircleCheck, unknown: I.CircleDashed, degraded: I.TriangleAlert, disabled: I.CircleSlash },
  provenance: {
    dashboard: I.LayoutDashboard, scim: I.FolderSync, directory: I.FolderSync, "sign-in": I.KeyRound,
    mfa: I.ShieldCheck, single_factor: I.ShieldQuestion, active: I.UserCheck, inactive: I.UserX, enrolled: I.Laptop,
  },
  enrolmentClass: { managed: I.Building2, individual: I.Laptop },
  assuranceLevel: {
    hardware_bound: I.Fingerprint, node_enrolled: I.Monitor, workload_bound: I.Container, shared_secret: I.Key,
    user_session_only: I.User, claimed: I.CircleHelp,
  },
  // web2/src/pages/Audit.tsx (actor kind prefix: assistant_* → Bot, else User)
  auditAction: {
    view_team_developers: I.Users, view_org_developers: I.User, view_org_sessions: I.History,
    view_session_messages: I.MessageSquare, drill_down_developers: I.Search, revoke_bearer: I.Ban,
    set_team_role: I.UserCog, view_guard_agents: I.Shield, publish_policy_bundle: I.Upload,
    policy_evolution_config_upsert: I.Pencil, policy_evolution_run_now: I.Play,
    policy_evolution_config_delete: I.Trash2, policy_evolution_config_resume: I.RefreshCw,
    policy_evolution_auto_apply: I.Wand, chat_proposal_approve: I.Check, assistant_proposal_approved: I.Check,
    chat_proposal_reject: I.X, assistant_proposal_rejected: I.X, assistant_proposal_created: I.Bot,
    assistant_proposal_executed: I.CircleCheck, assistant_proposal_failed: I.CircleX,
    assistant_proposal_invalid: I.FileWarning, assistant_proposal_stale: I.ClockAlert,
    assistant_proposal_expired: I.TimerOff, assistant_proposal_unknown: I.CircleHelp,
    assistant_read_people: I.Users, assistant_read_pending_members: I.UserPlus, assistant_read_team: I.Users,
    assistant_read_security: I.ScrollText, assistant_read_credentials: I.KeyRound, assistant_read_roles: I.UserCog,
    assistant_read_trace_content: I.Eye, assistant_item_attempt: I.Zap, assistant_item_outcome: I.ListChecks,
    assistant_service_account_create: I.UserPlus, assistant_service_account_deactivate: I.UserX,
    assistant_ingest_credential_mint: I.Key, assistant_ingest_credential_rotate: I.RefreshCw,
    assistant_ingest_credential_revoke: I.Ban, archive_holds_replaced: I.Archive, resolve_projects: I.FolderGit2,
  },
  // alerts
  alertRuleKind: {
    threshold: I.Gauge, burn_rate: I.Flame, no_data: I.CircleSlash, fleet_authority_divergence: I.Split,
    fleet_integrity_risk: I.Fingerprint, fleet_no_contact: I.Unplug, fleet_governance_lapsed: I.FileWarning,
  },
  alertEvent: {
    firing: I.BellRing, fired: I.BellRing, ok: I.Check, resolved: I.Check, delivered: I.Send, attempted: I.Clock,
    failed: I.TriangleAlert, webhook: I.Webhook, email: I.Mail,
  },
  // the org's cross-page severity ladder (unify tones first, README §3.1)
  severity: {
    critical: I.OctagonAlert, high: I.TriangleAlert, medium: I.CircleAlert, med: I.CircleAlert,
    warn: I.TriangleAlert, notice: I.Megaphone, info: I.Info, low: I.Info, retracted: I.Undo2,
  },
  // docs/budgets.md
  budgetEnforcement: { report: I.Eye, soft: I.BellRing, hard: I.Lock, control_unavailable: I.ShieldOff },
  budgetBreach: { over: I.OctagonAlert, near: I.TriangleAlert, under: I.CircleCheck, rung_fired: I.BellRing, rung_pending: I.Circle },
  budgetScope: {
    org: I.Building2, team: I.Users, project: I.FolderGit2, member: I.User, model: I.Boxes, tool: I.Wrench,
    mcp_server: I.Server, mcp_tool: I.Plug, key: I.KeyRound,
  },
  budgetPeriod: { rolling_30d: I.RefreshCw, calendar_month: I.CalendarDays, calendar_day: I.CalendarClock },
  capUnit: { usd: I.Receipt, tokens: I.Coins, both: I.Layers },
  // docs/assistant.md — the 9 proposal statuses (unknown ≠ failed)
  proposalStatus: {
    pending: I.Hourglass, approved: I.Check, executed: I.CircleCheck, rejected: I.X, expired: I.TimerOff,
    invalid: I.FileWarning, stale: I.ClockAlert, failed: I.CircleX, unknown: I.CircleHelp,
  },
  policyEvolutionStatus: { pending: I.Hourglass, applied: I.CircleCheck, rejected: I.X, lint_failed: I.FileX, superseded: I.Replace },
  mcpApprovalStatus: {
    pending: I.Hourglass, approved: I.Check, denied: I.Ban, expired: I.TimerOff, consumed: I.CircleCheck,
    invalidated: I.CircleSlash,
  },
  requestKind: { enable_feature: I.ToggleRight, raise_budget: I.Wallet, allow_tool: I.Wrench, other: I.MessageSquare },
  requestStatus: { open: I.CircleDot, resolved: I.Check, other: I.Archive },
  breakGlass: { pending: I.Hourglass, approved: I.Check, denied: I.Ban, revoked: I.Undo2, expired: I.TimerOff, live: I.Siren },
  // fleet / nodes / updates (docs/enterprise-updates.md)
  nodeContact: { healthy: I.Activity, online: I.Activity, stale: I.Clock, offline: I.Unplug, unknown: I.CircleHelp },
  nodeUpdateState: {
    applied: I.CircleCheck, idle: I.CircleDot, available: I.Download, downloading: I.CloudDownload,
    verified: I.BadgeCheck, applying: I.RefreshCw, blocked: I.Ban, stale_manifest: I.FileClock, failed: I.CircleX,
    rolled_back: I.Undo2, not_reported: I.CircleHelp, below_minimum: I.TriangleAlert,
  },
  integrityCheck: {
    clear: I.ShieldCheck, unknown: I.ShieldQuestion, incomplete: I.ShieldEllipsis, risk: I.ShieldAlert,
    machine_unbound: I.Unlink, identity_conflict: I.Fingerprint, idp_enrolled: I.IdCard,
  },
  fleetFinding: {
    governance_lapsed: I.FileWarning, authority_divergence: I.Split, integrity_risk: I.Fingerprint,
    no_contact: I.Unplug, resolved: I.Check,
  },
  fleetPoint: {
    guard: I.Shield, router: I.Shuffle, "proxy-admitter": I.ShieldCheck, "proxy-egress": I.Route,
    "proxy-gateway": I.Cpu, "node-dashboard": I.Monitor, "node-features": I.ToggleRight, "node-mcp-relay": I.Plug,
  },
  fleetStatus: {
    effective: I.CircleCheck, delivered_unaccepted: I.CircleX, pending_restart: I.RefreshCw, stale_lkg: I.History,
    yes: I.Check, diverged: I.Split, unknown: I.CircleHelp, no_org_rail: I.CircleSlash,
  },
  posture: { teams: I.Users, enterprise: I.Building2, pending: I.Hourglass, excluded: I.CircleMinus },
  planeBMode: { node: I.Monitor, gateway: I.Cpu },
  preflightGate: { pending: I.CircleDashed, green: I.CircleCheck, failed: I.CircleX, acknowledged: I.Check, stale: I.ClockAlert, unacknowledged: I.Circle },
  updateChannel: { stable: I.ShieldCheck, lts: I.Anchor, edge: I.FlaskConical },
  rolloutStage: {
    draft: I.CircleDashed, pending: I.CircleDashed, staged: I.Layers, verify: I.SearchCheck, full: I.CircleCheck,
    halted: I.CirclePause, rolled_back: I.Undo2, approved: I.Check, promoted: I.ChevronsUp,
  },
  manifestState: { published: I.PackageCheck, draft: I.Package, signed: I.Signature, unsigned: I.TriangleAlert },
  setupStep: {
    welcome: I.Rocket, storage: I.Database, connectors: I.Plug, identity: I.Fingerprint, fleet: I.Network,
    policy: I.FileLock2, intelligence: I.Brain, review: I.ClipboardCheck,
  },
  topology: {
    sqlite: I.Database, sqlite_local: I.Database, clickhouse: I.Database, existing_analytical: I.HardDrive,
    custom_adapter: I.Plug, parquet_jsonl: I.Archive, saml_scim: I.Fingerprint, otlp_gateway: I.Filter,
  },
  // guard / admission / egress / routing / governance (org spelling)
  orgGuardDecision: {
    allow: I.Check, deny: I.Ban, ask: I.MessageCircleQuestion, flag: I.Flag, mask: I.VenetianMask,
    enforced: I.Lock, observed: I.Eye, prompt_guard: I.MessageSquare,
  },
  controlLever: {
    hook_block: I.ShieldX, sandbox_enforce: I.Box, org_disallow: I.Building2, recorded_acceptance: I.ScrollText,
    block_ask: I.MessageCircleQuestion, block_only: I.Ban, probe_required: I.ScanSearch, proxy_only: I.Route, none: I.CircleMinus,
  },
  admissionDecision: { allow: I.Check, flag: I.Flag, ask: I.MessageCircleQuestion, would_block: I.ShieldAlert, deny: I.Ban },
  admissionMode: { observe: I.Eye, enforce: I.Lock, judge: I.Gavel, degraded: I.ShieldOff },
  egressAction: { route_to_upstream: I.Route, route_to_model: I.Boxes, set_effort: I.Gauge, deny: I.Ban, no_route: I.CircleSlash },
  routingTier: { economy: I.Coins, standard: I.Box, premium: I.Award, flagship: I.Crown, local: I.Laptop },
  governanceSection: { visible: I.Eye, read_only: I.Lock, hidden: I.EyeOff },
  governanceShare: { unset: I.CircleMinus, pin: I.Pin, lower: I.TrendingDown },
  featureState: { unset: I.CircleMinus, on: I.ToggleRight, off: I.PowerOff },
  collectionTier: { metadata: I.Tags, prompts: I.MessageSquare, outputs: I.FileText, relay: I.Radio },
  telemetrySignal: { traces: I.Spline, logs: I.ScrollText, metrics: I.ChartColumn },
  telemetryCapture: { metadata_only: I.Tags, classified_safe: I.Filter, full_redacted: I.EyeOff },
  // Agent Access + MCP (docs/agent-access.md)
  agentKind: { coding_agent: I.SquareTerminal, hosted_agent: I.AppWindow, service: I.Server, system_agent: I.Cpu },
  agentLifecycle: { draft: I.PencilLine, active: I.CircleCheck, deprecated: I.TriangleAlert, retired: I.Archive, certified: I.BadgeCheck },
  credentialKind: { node: I.Monitor, private_key_jwt: I.KeyRound, mtls_client: I.LockKeyhole, client_secret: I.Key },
  credentialStatus: { active: I.CircleCheck, revoked: I.Ban, expired: I.TimerOff },
  signingKeyState: { active: I.KeyRound, pending: I.CircleDashed, retiring: I.Hourglass, retired: I.Archive },
  mcpTransport: { streamable_http: I.Globe, sse_legacy: I.Radio, node_local_stdio: I.SquareTerminal, openapi: I.Braces },
  mcpServerStatus: { draft: I.PencilLine, approved: I.BadgeCheck, relist_pending: I.Hourglass, quarantined: I.ShieldX, retired: I.Archive },
  mcpDrift: { none: I.Check, drifted: I.Diff, quarantined: I.ShieldX },
  mcpCredentialMode: {
    vault_user: I.LockKeyhole, service: I.Server, passthrough: I.ArrowRightLeft, forward_idp: I.Fingerprint,
    obo: I.UserCheck, none: I.CircleMinus,
  },
  mcpSource: { manual: I.Pencil, imported: I.Import, git_catalog: I.GitBranch, discovered: I.Radar },
  mcpGrantEffect: { allow: I.Check, deny: I.Ban, ask: I.MessageCircleQuestion, judge: I.Gavel },
  mcpSubjectKind: {
    any: I.Asterisk, user: I.User, product: I.Package, agent_def: I.Bot, agent_kind: I.Blocks, env: I.Layers,
    ws: I.LayoutDashboard, group: I.UsersRound, team: I.Users, project: I.FolderGit2,
  },
  mcpAction: {
    discover: I.Compass, list: I.ListChecks, call: I.Zap, read: I.Eye, subscribe: I.Radio, "tasks/get": I.ListTree,
    "tasks/update": I.Pencil, "tasks/cancel": I.X,
  },
  mcpPublication: { draft: I.PencilLine, pending_review: I.Hourglass, published: I.PackageCheck, rejected: I.X },
  shadowCandidate: { new: I.Sparkles, reviewed: I.Eye, adopted: I.CircleCheck, dismissed: I.X, shadow: I.Ghost },
  shadowSource: { guard_pin: I.Pin, mcp_inventory: I.ListChecks, proxy_tools: I.Route, hook: I.Webhook },
  connection: {
    connected: I.Plug, revoked: I.Unplug, refresh_failed: I.TriangleAlert, ok: I.Check,
    refresh_pending: I.RefreshCw, reauth_required: I.KeyRound,
  },
  oauthClient: { active: I.CircleCheck, pending: I.Hourglass, revoked: I.Ban, expired: I.TimerOff, disabled: I.CircleSlash },
  // Plane A (hosted-app observability)
  spanKind: { llm: I.Brain, tool: I.Wrench, agent: I.Bot, retriever: I.Search, chain: I.Link2, embedding: I.Layers, other: I.Circle },
  traceStatus: { ok: I.Check, error: I.CircleX },
  evalVerdict: {
    pass: I.Check, fail: I.X, neutral: I.Circle, reviewed: I.Eye, regression: I.TrendingDown, online: I.Radio,
    "org-run": I.Building2, scheduled: I.CalendarClock,
  },
  experimentVerdict: { similar: I.Equal, different: I.EqualNot, degraded: I.TrendingDown },
  // shared by eval runs, workflow jobs, session enrichment and webcloud IntelResultCard
  jobStatus: {
    queued: I.CircleDashed, pending: I.CircleDashed, running: I.LoaderCircle, done: I.CircleCheck,
    succeeded: I.CircleCheck, error: I.CircleX, failed: I.CircleX, partial: I.CircleGauge, capped: I.CircleGauge,
    parked: I.CirclePause,
  },
  insightOutcome: { finding: I.Radar, recommendation: I.Lightbulb, no_issue: I.CircleCheck, abstain: I.CircleMinus, error: I.CircleX },
  harness: { deterministic: I.ListChecks, llm_single: I.Brain, agentic: I.Bot, remote_ws: I.Globe },
  cacheCallVerdict: { first_call: I.Sparkles, hit: I.Zap, partial: I.CircleGauge, miss: I.RefreshCw },
  projectEvidence: {
    manual: I.Pencil, rule: I.ListChecks, auto_remote: I.GitBranch, auto_upstream: I.Building2,
    auto_root_commit: I.GitCommitHorizontal, auto_scm: I.FolderGit2, suggested_remote: I.Lightbulb,
  },
  pricingSource: { negotiated: I.Handshake, list: I.Tags, imported: I.Import },
  pricingDiff: { added: I.Plus, changed: I.Pencil, removed: I.CircleMinus },
  assistantRole: { user: I.User, assistant: I.Bot, proposal: I.ClipboardCheck, system_note: I.Info },
  captureTier: { proxy: I.ShieldCheck, estimated: I.Calculator },
  dataRail: { coding: I.Braces, hosted: I.AppWindow },

  // ===================== CLOUD PORTAL (webcloud) =====================
  // internal/cloudcontract/consent.go — 7 purposes, least → most disclosing
  consentPurpose: {
    account_device_operations: I.IdCard, structural_activity_insights: I.ChartColumn,
    bounded_context_enrichment: I.Quote, extended_evidence_deep_review: I.FileSearch,
    community_cohort_benchmarking: I.ChartNoAxesColumn, public_community_profile: I.Contact,
    research_model_improvement: I.FlaskConical,
  },
  // 6 field classes (first_user_prompt_excerpt ⊂ content_excerpts)
  fieldClass: {
    identity_linkage: I.Link, structural_metrics: I.ChartColumn, paths_project_identifiers: I.FolderTree,
    user_feedback: I.Star, content_excerpts: I.Quote, first_user_prompt_excerpt: I.MessageSquareQuote,
  },
  subscriptionStatus: {
    active: I.CircleCheck, trialing: I.Sparkles, canceled: I.CircleX, past_due: I.ClockAlert, paused: I.CirclePause,
    refunded: I.Undo2, charged_back: I.OctagonAlert,
  },
  planFeature: { included: I.Check, not_included: I.Minus },
} satisfies Record<string, Record<string, LucideIcon>>;

export type Vocab = keyof typeof VOCAB_ICONS;

/** The glyph for one vocabulary value; CircleHelp for an unknown value. */
export function vocabIcon(vocab: Vocab, value: string | null | undefined): LucideIcon {
  const table = VOCAB_ICONS[vocab] as Record<string, LucideIcon>;
  return (value != null && table[value]) || I.CircleHelp;
}
