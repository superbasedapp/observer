import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import clsx from "clsx";
import {
  Button,
  Card,
  ChartShell,
  Input,
  PageHeader,
  Pill,
  Select,
  SettingRow,
  SlideOver,
  Table,
  Textarea,
  Toggle,
  Tooltip,
} from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { BUILTIN_PROFILE_NAMES, SECTION_SPECS, type SectionSpec } from "./settings/sectionSpecs";
import { StructuredConfigSection } from "./settings/StructuredConfigSection";
import { SchemaSection } from "./settings/SchemaSection";
import { AntigravityHelperCard } from "./settings/AntigravityHelperCard";
import { ETWCapturerCard } from "./settings/ETWCapturerCard";
import { ConnectedToolsSection } from "./settings/ConnectedToolsSection";
import { CloudIntelligenceSection } from "./settings/CloudIntelligenceSection";
import { EnrolmentSection } from "./settings/EnrolmentSection";
import { HealthSection } from "./settings/HealthSection";
import { StorageSection } from "./settings/StorageSection";
import { ChartState } from "@/components/ChartState";
import { CommunityLinksMini } from "@/components/CommunityCard";
import {
  BoltIcon,
  CalendarIcon,
  ClockIcon,
  CoinsIcon,
  CompassIcon,
  CompressIcon,
  DatabaseIcon,
  DropletIcon,
  EyeIcon,
  LayersIcon,
  LightningIcon,
  ListIcon,
  SearchIcon,
  ShieldIcon,
  SparklesIcon,
  WrenchIcon,
} from "@/components/icons";

import { fetchJSON } from "@/lib/api";
import { markRestartPending } from "@/lib/restartPending";
import { useApi } from "@/lib/useApi";
import { useConfigSchema, type ConfigSchemaDescriptor } from "@/lib/configSchema";
import {
  isSettingsHidden,
  isSettingsReadOnly,
  useGovernance,
  type Governance,
} from "@/lib/governance";
import { fmtDateTime, fmtInt, fmtUSD } from "@/lib/format";
import type {
  BackfillJob,
  BackfillJobsListResponse,
  BackfillRunResponse,
  BackfillStatusResponse,
  ConfigResponse,
  CostPricing,
  DatedCostPricing,
  MCPValueResponse,
  ModelPricing,
  PeakRates,
  PeakSchedule,
  PricingDefaultsResponse,
  ProfileShowResponse,
  ToolsStatusResponse,
} from "@/lib/types";
import { costPricingToConfig } from "@/lib/types";

type SectionId =
  | "pricing"
  | "backfill"
  | "tools"
  | "health"
  | "storage"
  | "enrolment"
  | "cloud"
  | "observer"
  | "watcher"
  | "freshness"
  | "retention"
  | "hooks"
  | "proxy"
  | "dashboard"
  | "compression"
  | "profiles"
  | "intelligence"
  | "advisor"
  | "cachetrack"
  | "tasks"
  | "observability"
  | "secrets"
  | "mcp"
  | "org"
  | "otel"
  | "guard"
  | "routing"
  | "process"
  | "antigravity"
  | "browser"
  | "terminal";

type SectionDef = {
  id: SectionId;
  label: string;
  group: "edit" | "config";
  // Deployment plane (docs/deployment-models.md). Omitted (the default)
  // = Plane B: this node's OWN coding-agent usage, the developer-facing
  // subject of every other section. "admin" = Plane A: general
  // observability of an admin/org-hosted LLM app whose END-USER requests
  // route through Observer — a fundamentally different subject, surfaced
  // here only because the receiver + schema are configured node-side.
  // The nav renders these under a separate "Observability (admin plane)"
  // subgroup so an operator never mistakes it for a coding-agent feature.
  plane?: "admin";
  // hot = takes effect immediately on save (cost-engine reload).
  // soft = consumed lazily by the next job, no restart needed.
  // restart = daemon must restart to bind the new value.
  status: "hot" | "soft" | "restart";
  // Inline glyph rendered in the SectionNav row + page header to
  // match design/page-settings.jsx — every section carries a single
  // identifying icon so the nav reads at a glance.
  icon: ReactNode;
  about: {
    summary: string;
    whenModified: string;
    behavior: string;
  };
};

const SECTIONS: SectionDef[] = [
  {
    id: "pricing",
    label: "Pricing",
    group: "edit",
    status: "hot",
    icon: <CoinsIcon size={13} />,
    about: {
      summary:
        "Per-model pricing overrides. The cost engine ships with baked-in defaults for every common Anthropic / OpenAI / xAI model; overrides let you correct a contract rate or add a new SKU before observer's defaults catch up.",
      whenModified:
        "Custom contract rates, or a new SKU lands before observer's defaults catch up. Hot-reloaded - no restart needed.",
      behavior:
        "Save writes ~/.observer/config.toml + a .bak of the prior version. The cost engine swaps the active pricing table atomically on save - no restart, no daemon bounce.",
    },
  },
  {
    id: "backfill",
    label: "Backfill",
    group: "edit",
    status: "soft",
    icon: <DatabaseIcon size={13} />,
    about: {
      summary:
        "Run schema-fill jobs against your DB. Useful after a schema upgrade or when a new derived column lands and needs back-population.",
      whenModified:
        "After a schema migration, or when a v1.x.x release adds new derived columns.",
      behavior:
        "Spawns a subprocess that streams output back to the dashboard via 3-second polling. Idempotent; safe to re-run.",
    },
  },
  {
    id: "tools",
    label: "Connected tools",
    group: "edit",
    status: "soft",
    icon: <CompassIcon size={13} />,
    about: {
      summary:
        "Per-tool integration matrix: every AI tool observer supports, with live detected / capturing / hooks / MCP / proxied state. All probes are read-only - nothing on this panel writes AI-client config.",
      whenModified:
        "Checking why a tool isn't showing data, after installing a new AI tool, or before/after running `observer init`.",
      behavior:
        "Pure reads, computed per request: directory probes for detection, dry-run registry probes for hooks/MCP, routing-config reads for the proxy column. Refresh re-probes immediately.",
    },
  },
  {
    id: "health",
    label: "Health",
    group: "edit",
    status: "soft",
    icon: <BoltIcon size={13} />,
    about: {
      summary:
        "The `observer doctor` checks in the dashboard - database integrity, hook checksums and binary paths, MCP registrations, pidbridge, concurrent daemons, codex hook trust, proxy routing gap, org enrolment - plus the recent-failures card (failed commands grouped, recovered vs not, session deep-links).",
      whenModified:
        "Something looks off - missing capture, a tool that stopped reporting, a command that keeps failing, after an upgrade or a machine migration.",
      behavior:
        "Read-only. Checks run when the section opens and on Re-run - not on a poll loop (the DB integrity check is not free on a large database). The failures card reads the local failure_context table.",
    },
  },
  {
    id: "storage",
    label: "Storage",
    group: "edit",
    status: "soft",
    icon: <DatabaseIcon size={13} />,
    about: {
      summary:
        "Where the database's bytes live: per-table size breakdown (indexes and FTS shadow tables folded into their owners), vacuum, and one-click backup with restore instructions. Backups are consistent snapshots written next to the live DB via VACUUM INTO - capture keeps running while one is taken.",
      whenModified:
        "The DB feels large and you want to see why; before an upgrade or machine move (take a backup); after a big retention prune (vacuum returns the freed pages to the OS).",
      behavior:
        "The size report walks every page on demand - opened or refreshed explicitly, never polled. Vacuum and backup run as `observer db vacuum` / `observer db backup` subprocesses through the shared job runner with streamed output; the CLI commands are the identical code path.",
    },
  },
  {
    id: "enrolment",
    label: "Enrolment",
    group: "edit",
    status: "soft",
    icon: <OrgSectionIcon />,
    about: {
      summary:
        "Teams & Org Visibility. When enrolled, this agent shares content-free activity rollups (counts, costs, timings, paths - never prompt text or tool output) with your organisation's SuperBased server. View exactly what was last shared, or unenrol.",
      whenModified:
        "Joining or leaving an organisation. Enrol with `observer enroll <org-url> <token>`; unenrol from here or with `observer unenroll`.",
      behavior:
        "Unenrol deletes the local enrolment + keychain credentials immediately; a running daemon's push loop stops within one interval. Nothing already shared with the server is deleted.",
    },
  },
  {
    id: "cloud",
    label: "Cloud Intelligence",
    group: "edit",
    status: "soft",
    icon: <SparklesIcon size={13} />,
    about: {
      summary:
        "Optional signed-in personal enrichment (Signed-in Free). The Cloud account card at the top is where you sign in and out - the daemon itself never touches the network: Sign in runs the same consent-gated `observer cloud login` you would type, as a subprocess, and the credential stays in the local keychain. The card also carries the two egress preferences (auto-sync, auto-enrich). Below it: consent receipts, the send outbox by state, and any synced enrichment results. Deployment knobs (client id, base URL, callback port) live under an Advanced fold - most people never touch them.",
      whenModified:
        "Signing in for the first time, turning auto-sync or auto-enrich on, checking what's queued for the next `observer cloud sync`, why a job is awaiting reconfirmation, or whether results have been pulled. The Advanced fold is only for staging or self-hosting - pointing the node at a different hosted base URL or WorkOS client.",
      behavior:
        "Every local Observer feature works fully without this. Nothing is wired into the watcher or proxy - only an `observer cloud` command touches the network - typed, launched by a button here (Sign in, Sync now, Grant, Revoke, Delete account) or on a session card (Preview, Confirm and enrich, Sync now), or the scheduled `cloud sync` when you turn auto-sync on. Settings edits take effect on the next cloud command; turning auto-sync on/off needs a daemon restart to change the schedule.",
    },
  },
  {
    id: "intelligence",
    label: "Intelligence",
    group: "edit",
    status: "restart",
    icon: <SparklesIcon size={13} />,
    about: {
      summary:
        "Summary model, monthly budget cap, code-graph integration. These power the Analysis tab's headline KPIs and the MCP `get_session_summary` tool.",
      whenModified:
        "Switching to a cheaper Haiku for summaries, raising/lowering the budget cap, or enabling/disabling the code-graph backend.",
      behavior:
        "Save writes config.toml; consumers bind the value at daemon startup, so a `observer serve` restart is required for the new value to take effect.",
    },
  },
  {
    id: "observer",
    label: "Observer",
    group: "config",
    status: "restart",
    icon: <EyeIcon size={13} />,
    about: {
      summary: "Top-level observer settings (db path, log level) plus every [observer] key the sub-sections do not own, rendered from the config schema.",
      whenModified: "Adding/removing a watched root, tweaking retention, etc.",
      behavior: "Restart required - consumers bind at startup.",
    },
  },
  {
    id: "watcher",
    label: "Watcher",
    group: "config",
    status: "restart",
    icon: <SearchIcon size={13} />,
    about: {
      summary: "Filesystem watcher - watch_paths, ignore_globs. Defines what observer scans for new session files.",
      whenModified: "Onboarding a new AI client, or moving session files to a non-default location.",
      behavior: "Restart required.",
    },
  },
  {
    id: "freshness",
    label: "Freshness",
    group: "config",
    status: "restart",
    icon: <ClockIcon size={13} />,
    about: {
      summary: "Freshness classifier - how observer scores whether a file read is stale vs fresh.",
      whenModified: "Tuning the staleness threshold or hashing rules.",
      behavior: "Restart required.",
    },
  },
  {
    id: "retention",
    label: "Retention",
    group: "config",
    status: "restart",
    icon: <CalendarIcon size={13} />,
    about: {
      summary: "How long observer keeps each table's data. Trims the DB on schedule.",
      whenModified: "Disk pressure or compliance retention windows.",
      behavior: "Restart required.",
    },
  },
  {
    id: "hooks",
    label: "Hooks",
    group: "config",
    status: "restart",
    icon: <BoltIcon size={13} />,
    about: {
      summary: "Per-tool hook configuration (Claude Code, Codex, Cursor, etc).",
      whenModified: "Adding a new tool integration or fixing a broken envelope.",
      behavior: "Restart required.",
    },
  },
  {
    id: "proxy",
    label: "Proxy",
    group: "config",
    status: "restart",
    icon: <CompassIcon size={13} />,
    about: {
      summary: "API proxy port + compression knobs.",
      whenModified: "Changing the proxy port or compression toggles.",
      behavior: "Restart required - proxy is bound at startup.",
    },
  },
  {
    id: "dashboard",
    label: "Dashboard",
    group: "config",
    status: "restart",
    icon: <CompassIcon size={13} />,
    about: {
      summary: "Durable dashboard listen address.",
      whenModified: "Setting a fixed host:port for the dashboard listener.",
      behavior:
        "Restart required - the dashboard listener binds at daemon start. Precedence: --dashboard-addr flag > OBSERVER_DASHBOARD_ADDR env > this config value > default 127.0.0.1:8081.",
    },
  },
  {
    id: "compression",
    label: "Compression",
    group: "config",
    status: "restart",
    icon: <CompressIcon size={13} />,
    about: {
      summary: "Per-mechanism compression configuration - drop / dedup / stash thresholds.",
      whenModified: "Tuning the compression pipeline.",
      behavior: "Restart required.",
    },
  },
  {
    id: "profiles",
    label: "Profiles",
    group: "config",
    status: "hot",
    icon: <WrenchIcon size={13} />,
    about: {
      summary:
        "Which compression profile each traffic class runs. Profiles are named parameter sets (the embedded recipes + `default` = master config) resolved per request at the proxy, so Claude Code and codex each get their tuned parameters from one daemon. The master compression switch stays the only on/off gate - profiles never enable compression.",
      whenModified:
        "Pointing OpenAI traffic at codex-variant for a *-codex reasoning model, trying a different tuning, or pinning everything to your master parameters.",
      behavior:
        "Hot for new sessions: saving re-points the proxy's profile router immediately - the next session resolves the new assignment. Sessions already in flight keep the parameters they started with (deliberate: mid-session parameter flips would break rolling summaries and cache alignment). No restart, no banner.",
    },
  },
  {
    id: "org",
    label: "Org sharing",
    group: "config",
    status: "restart",
    icon: <EyeIcon size={13} />,
    about: {
      summary:
        "What this node shares with an org server when enrolled: share mode (metadata-only by default - hashes and counts, never raw content), per-action target exceptions, project scope lists, push cadence. Raw-content sharing (full_content/admin_managed) is node opt-in only, never server-forced; the reporting-tier shares (e.g. routing_summary, obs_summary) are node opt-in, or can be raised by the org on a managed node via node governance policy.",
      whenModified:
        "Opting into (or out of) full-content sharing, scoping which projects push, or tuning push cadence. Enrolment itself stays with `observer enroll` / the Enrolment section.",
      behavior:
        "Saves write this node's config.toml only - the enrolment identity (server URL, keychain) is deliberately untouchable from here. The push loop binds config at daemon start: restart to apply.",
    },
  },
  {
    id: "guard",
    label: "Guard",
    group: "config",
    status: "restart",
    icon: <ShieldIcon size={13} />,
    about: {
      summary:
        "The security guard layer - posture (enabled / observe vs enforce / strict), rule disables, boundary allowlists, taint tracking, proxy egress + response scans, MCP pinning, budget limits, alerts, and native-dialect compilation. Cloud features ([guard.cloud] - LLM judge, reputation, webhooks) are deliberately NOT editable here: network egress stays a hand-written config decision.",
      whenModified:
        "Silencing a noisy rule (rules.disable), tuning the egress action, moving observe → enforce (the Security page's mode control shows the evidence first), or setting session/daily budget limits.",
      behavior:
        "Restart required - the policy engine and proxy seams bind config at startup. Saves write config.toml + .bak; the boundary allowlists treat an empty list as 'keep engine defaults' (explicit 'none' is a config-file edit).",
    },
  },
  {
    id: "routing",
    label: "Routing",
    group: "config",
    status: "restart",
    icon: <CompassIcon size={13} />,
    about: {
      summary:
        "Model routing - the opt-in layer that picks (advise) or rewrites (enforce) the model per turn based on a policy template, with session stickiness, outcome calibration, and subscription-window headroom. Custom [[routing.rules]], tier overrides, budget scopes, privacy rules, key pools, and local upstreams are deliberately NOT editable here: complex shapes and secrets stay hand-written config decisions, preserved on every save.",
      whenModified:
        "Enabling routing for the first time (the Routing page's preview shows the value first), switching policy templates, tuning switch stickiness, or moving advise → enforce (the Shadow card's promote control shows the readiness evidence first).",
      behavior:
        "Restart required - the proxy's router binds config at startup. Saves write config.toml + .bak. Mode and policy validate at save against the closed vocabularies, so a bad value can never reach the file.",
    },
  },
  {
    id: "otel",
    label: "OTel export",
    group: "config",
    status: "restart",
    icon: <LightningIcon size={13} />,
    about: {
      summary:
        "Agent-side OpenTelemetry exporter - one gen_ai.client span per proxied API turn to your own OTLP/HTTP collector. Disabled by default; prompt content and user email are separate, off-by-default opt-ins.",
      whenModified:
        "Wiring observer spans into an existing observability stack (Grafana, Honeycomb, Jaeger…).",
      behavior:
        "The exporter goroutine starts with the daemon: restart to apply. OTEL_* environment variables override file values at construction time.",
    },
  },
  {
    id: "mcp",
    label: "MCP tools",
    group: "config",
    status: "soft",
    icon: <SearchIcon size={13} />,
    about: {
      summary:
        "The on-demand MCP retrieval tools (get_file / get_symbols / get_relations / retrieve_stashed), their shared audit log, and the value meter - what the tools actually got called vs their ~1,900-token-per-turn schema overhead.",
      whenModified:
        "Tightening the file-retrieval allow/deny lists, disabling individual tools, or deciding whether MCP registration is worth the per-turn tax (the meter below answers that with your own numbers).",
      behavior:
        "Soft: each AI session spawns a fresh observer MCP server that reads config at start, so saves bind on the next session - no daemon restart, no banner. Running MCP sessions keep the config they spawned with.",
    },
  },
  {
    id: "advisor",
    label: "Advisor",
    group: "config",
    status: "restart",
    icon: <LightningIcon size={13} />,
    about: {
      summary:
        "The suggestions engine - evidence window, confidence/savings visibility floors, and the opt-in session-start digest that injects top advisories into Claude Code.",
      whenModified:
        "Tuning how chatty the Suggestions tab is, or enabling the session-start digest (default off).",
      behavior:
        "Restart required - the daemon's digest refresher and the /api/suggestions floors bind at startup.",
    },
  },
  {
    id: "cachetrack",
    label: "Cache tracking",
    group: "config",
    status: "restart",
    icon: <LayersIcon size={13} />,
    about: {
      summary:
        "Anthropic prompt-cache observation + forecasting - the Cache tab's data source. Hash-only and node-local; cache rows never leave this machine.",
      whenModified:
        "Disabling the engine, bounding tracked sessions, tuning cache-row retention, or enabling the calibrate-log diagnostic sidecar.",
      behavior:
        "Restart required - the proxy constructs the engine at startup. Retrofit historical sessions with Backfill → cache-rescan.",
    },
  },
  {
    id: "tasks",
    label: "Task tracking",
    group: "config",
    status: "restart",
    icon: <ListIcon size={13} />,
    about: {
      summary:
        "Session-level todo/plan checklist tracking — decodes TaskCreate/TodoWrite/update_plan/manage_todo_list and similar tool calls already captured into a per-task lifecycle + cost report (the session detail Tasks tab, and Analysis's Tasks section).",
      whenModified:
        "Disabling the engine, switching how whole-list-rewrite tools are matched across snapshots, changing how concurrent in-progress tasks are attributed, folding sub-agent usage into the parent's open task, backfilling on start, or bounding retention.",
      behavior:
        "Restart required — SetTasksEnabled/SetTasksOptions bind once at daemon startup, same as every section except pricing/profiles. Retrofit historical sessions with `observer backfill --tasks` (also in the Backfill panel below).",
    },
  },
  {
    id: "observability",
    label: "Observability",
    group: "config",
    plane: "admin",
    status: "restart",
    icon: <EyeIcon size={13} />,
    about: {
      summary:
        "Generalized observability (admin plane) - the OTLP /v1/traces receiver, trajectory capture, and the eval plane for an admin/org-hosted LLM app whose END-USER requests route through SuperBased. This is NOT your own coding-agent usage (every other section is); the captured traces + evals are viewed on the admin/org dashboard, not this node dashboard. Opt-in and node-local: trace data never leaves this machine unless you opt into an obs share tier under Org sharing.",
      whenModified:
        "Turning the subsystem on or off. The judge model + online-sampling eval knobs ([observability.eval]) stay hand-edited config decisions.",
      behavior:
        "Restart required - the OTLP receiver and obs_* schema bind at `observer start`. The receiver is SHARED: it also binds whenever [ingest.otel] is enabled (for logs), so turning this toggle off does not stop the receiver if [ingest.otel] is on. Saves write config.toml + .bak.",
    },
  },
  {
    id: "secrets",
    label: "Secrets scrubbing",
    group: "config",
    status: "restart",
    icon: <DropletIcon size={13} />,
    about: {
      summary:
        "Regex scrubbing applied to captured tool output before anything is stored. Built-in patterns cover common API-key and token shapes; extra patterns append your own.",
      whenModified:
        "Adding org-specific credential shapes (internal token prefixes, hostnames) to the redaction set.",
      behavior: "Restart required - the scrubber is built at daemon startup.",
    },
  },
  {
    id: "antigravity",
    label: "Antigravity",
    group: "config",
    status: "restart",
    icon: <AntigravitySectionIcon />,
    about: {
      summary: "Antigravity (Google) adapter config - bridge ports, decrypt keys, etc.",
      whenModified: "Onboarding the Antigravity adapter.",
      behavior: "Restart required.",
    },
  },
  {
    id: "process",
    label: "Process capture",
    group: "config",
    status: "restart",
    icon: <LayersIcon size={13} />,
    about: {
      summary:
        "OS-level process observability - capture toggle, backend, and the poll rate that controls how often the process table is sampled.",
      whenModified:
        "Turning process capture on/off, or tuning the poll rate (lower = fresher capture + more CPU; higher = cheaper but misses short-lived commands).",
      behavior: "Restart required - the backend binds at daemon startup.",
    },
  },
  {
    id: "browser",
    label: "Browser capture",
    group: "config",
    status: "restart",
    icon: <EyeIcon size={13} />,
    about: {
      summary:
        "Browser-chat capture granularity ceiling - the daemon-side clamp on how much of a captured ChatGPT/Claude.ai/Perplexity/Gemini/Copilot web turn is stored (usage_only / redacted / full).",
      whenModified:
        "Tightening what browser-captured chats store: drop to usage_only to keep prompt/response text out of the DB while still tracking tokens and cost, or raise to full to keep the on-screen text.",
      behavior:
        "Restart required - the granularity ceiling is read when the browser-ingest listener starts. The extension must also be set at or above the level you want (effective = min(extension, ceiling)).",
    },
  },
  {
    id: "terminal",
    label: "Session attach",
    group: "config",
    status: "restart",
    icon: <LayersIcon size={13} />,
    about: {
      summary:
        "Session attach ([terminal.attach]) - serve the owner-only attach socket so `observer <tool> --attach` sessions become joinable from the dashboard, route attach sessions through the observer proxy, and control whether the launchers attach by default.",
      whenModified:
        "Turning the attach socket on/off, changing whether attach sessions route through the proxy by default, or toggling whether `observer claude`/`observer codex` attach by default (opt out per-launch with --no-attach).",
      behavior:
        "Serving the socket is start-time (restart required to bind/unbind). Route-through-proxy and attach-by-default are read per-launch by the CLI, so they take effect on the next launch with no restart.",
    },
  },
];

const STATUS_LABEL: Record<SectionDef["status"], string> = {
  hot: "hot",
  soft: "soft",
  restart: "restart",
};

const STATUS_CLASS: Record<SectionDef["status"], string> = {
  hot: "border-success/40 bg-success-soft text-success",
  soft: "border-line-3 bg-bg-3 text-fg-2",
  restart: "border-danger/40 bg-danger-soft text-danger",
};

function sectionAt(id: SectionId): SectionDef {
  return SECTIONS.find((s) => s.id === id)!;
}

// Small inline glyph for the Antigravity section — mirrors the
// per-tool antigravity ToolGlyph (upward triangle floating above a
// baseline) at the section-nav size. Sized to match the other 13px
// icon set rather than reach into ToolGlyph + its tinted frame.
function AntigravitySectionIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      stroke="currentColor"
      fill="none"
      aria-hidden
    >
      <path d="M12 5 L18 14 L6 14 Z" fill="currentColor" stroke="none" />
      <line
        x1="5"
        y1="18"
        x2="19"
        y2="18"
        strokeWidth="1.6"
        strokeLinecap="round"
        opacity="0.5"
      />
    </svg>
  );
}

// Small inline glyph for the Enrolment (Teams) section — two stacked
// people, sized to match the 13px section-nav icon set.
function OrgSectionIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" stroke="currentColor" fill="none" aria-hidden>
      <circle cx="6" cy="5" r="2.2" strokeWidth="1.3" />
      <path d="M2 13a4 4 0 0 1 8 0" strokeWidth="1.3" strokeLinecap="round" />
      <path d="M10.5 3.2a2.2 2.2 0 0 1 0 3.6M11 9.2a4 4 0 0 1 3 3.8" strokeWidth="1.3" strokeLinecap="round" />
    </svg>
  );
}

export function SettingsPage() {
  // The active section lives in the URL (`/settings?section=<id>`) so
  // other surfaces can deep-link straight to a section — the advisor's
  // compression_off remediation, the Cache empty-state, the Proxy
  // banner. Mirrors the sessions?session=<id> convention: URL is the
  // source of truth, local state derives from it.
  const [searchParams, setSearchParams] = useSearchParams();
  const requested = searchParams.get("section");
  // Governed nodes may have Settings sub-sections hidden or locked
  // read-only by their organization. gov.data is {active: false, ...}
  // (or null while loading) on an ordinary solo node, and every
  // isSettingsHidden/isSettingsReadOnly call below is a no-op in that
  // case — so visibleSections === SECTIONS and readOnly === false
  // everywhere, matching today's behavior exactly.
  const gov = useGovernance();
  const visibleSections = SECTIONS.filter(
    (s) => !isSettingsHidden(gov.data, s.id),
  );
  const fallback = visibleSections[0]?.id ?? "pricing";
  const active: SectionId = visibleSections.some((s) => s.id === requested)
    ? (requested as SectionId)
    : fallback;
  const setActive = (id: SectionId) => {
    setSearchParams(id === "pricing" ? {} : { section: id }, { replace: true });
  };
  const [helpOpen, setHelpOpen] = useState(true);
  const config = useApi<ConfigResponse>("/api/config");
  // The daemon's config schema drives every schema-rendered section
  // (owner-local route; null on a remote view, which the renderer says).
  const schema = useConfigSchema();
  const def = sectionAt(active);
  const readOnly = isSettingsReadOnly(gov.data, active);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <SettingsHeader
        configPath={config.data?.config_path ?? ""}
        helpOpen={helpOpen}
        onToggleHelp={() => setHelpOpen((o) => !o)}
      />
      <div
        className={clsx(
          "grid min-h-0 flex-1 gap-0",
          helpOpen
            ? "grid-cols-1 lg:grid-cols-[220px_minmax(0,1fr)_300px]"
            : "grid-cols-1 lg:grid-cols-[220px_minmax(0,1fr)]",
        )}
      >
        <aside className="border-r border-line-1 bg-bg-1 p-4">
          <SectionNav
            active={active}
            onChange={setActive}
            sections={visibleSections}
            gov={gov.data}
          />
          {config.data && (
            <div className="mt-6 rounded-2 border border-line-1 bg-bg-2 px-3 py-2 text-[10.5px] text-fg-3">
              <div className="mb-0.5 font-semibold uppercase tracking-[0.06em] text-fg-3">
                Config file
              </div>
              <Tooltip
                content={<span className="break-all font-mono">{config.data.config_path}</span>}
                maxWidth={420}
                disabled={!config.data.config_path}
              >
                <div
                  tabIndex={config.data.config_path ? 0 : undefined}
                  className="cursor-help break-all font-mono text-fg-2 focus:outline-none"
                >
                  {config.data.config_path || "(no file - ephemeral)"}
                </div>
              </Tooltip>
              <RestoreBackupControl onRestored={config.reload} />
            </div>
          )}
          <CommunityLinksMini />
        </aside>

        <main className="min-w-0 overflow-y-auto p-6">
          {active === "pricing" && (
            <PricingSection
              config={config.data}
              loading={config.loading}
              error={config.error}
              onReload={config.reload}
              readOnly={readOnly}
            />
          )}
          {active === "backfill" && <BackfillSection />}
          {active === "tools" && <ConnectedToolsSection />}
          {active === "health" && <HealthSection />}
          {active === "storage" && <StorageSection />}
          {active === "enrolment" && <EnrolmentSection />}
          {active === "cloud" && <CloudIntelligenceSection />}
          {active === "intelligence" && (
            <IntelligenceSection
              config={config.data}
              loading={config.loading}
              error={config.error}
              onReload={config.reload}
              readOnly={readOnly}
            />
          )}
          {active !== "pricing" &&
            active !== "backfill" &&
            active !== "tools" &&
            active !== "health" &&
            active !== "storage" &&
            active !== "enrolment" &&
            active !== "cloud" &&
            active !== "intelligence" && (
              <SectionView
                section={active}
                config={config.data}
                schema={schema.data}
                onReload={config.reload}
                readOnly={readOnly}
              />
            )}
        </main>

        {helpOpen && <AboutSectionRail def={def} />}
      </div>
    </div>
  );
}

function SettingsHeader({
  configPath,
  helpOpen,
  onToggleHelp,
}: {
  configPath: string;
  helpOpen: boolean;
  onToggleHelp: () => void;
}) {
  return (
    <div className="border-b border-line-1 bg-bg-1 px-6 py-4">
      <PageHeader
        title="Settings"
        helpId="tab.settings"
        sub={
          <>
            View and edit the live <code className="font-mono text-fg-2">config.toml</code>.
            Every key is editable here (except credentials, which stay
            file-only). Each key says whether it applies now, to new
            sessions, or on the next daemon restart; scalar edits keep your
            comments, and the prior file is preserved
            at <code className="font-mono text-fg-2">.bak</code>.
            {configPath && (
              <>
                {" · "}
                <Tooltip content={<span className="break-all font-mono">{configPath}</span>} maxWidth={420}>
                  <span tabIndex={0} className="cursor-help font-mono text-fg-2 focus:outline-none">
                    {configPath}
                  </span>
                </Tooltip>
              </>
            )}
          </>
        }
        right={
          <Button size="sm" onClick={onToggleHelp}>
            {helpOpen ? "Hide help" : "Show help"}
          </Button>
        }
      />
    </div>
  );
}

function AboutSectionRail({ def }: { def: SectionDef }) {
  return (
    <aside className="overflow-y-auto border-l border-line-1 bg-bg-1 px-4 py-5">
      <div className="mb-3 flex items-center gap-2">
        <h2 className="text-[12.5px] font-semibold text-fg-1">
          About this section
        </h2>
        <span
          className={clsx(
            "rounded-pill border px-1.5 py-px text-[9.5px] font-medium uppercase tracking-[0.04em]",
            STATUS_CLASS[def.status],
          )}
        >
          {STATUS_LABEL[def.status]}
        </span>
        {def.plane === "admin" && (
          <Tooltip
            content="Plane A - governs an admin/org-hosted app's end-users, not this node's own coding-agent. See docs/deployment-models.md."
            maxWidth={340}
          >
            <span
              tabIndex={0}
              className="cursor-help rounded-pill border border-accent/40 bg-accent-soft px-1.5 py-px text-[9.5px] font-medium uppercase tracking-[0.04em] text-accent focus:outline-none"
            >
              admin plane
            </span>
          </Tooltip>
        )}
      </div>
      <AboutBlock label={def.label.toUpperCase()} body={def.about.summary} />
      <AboutBlock label="WHEN MODIFIED" body={def.about.whenModified} />
      <AboutBlock label="HOT-RELOAD BEHAVIOR" body={def.about.behavior} />
    </aside>
  );
}

function AboutBlock({ label, body }: { label: string; body: string }) {
  return (
    <div className="mb-4">
      <div className="mb-1 text-[9.5px] font-semibold uppercase tracking-[0.08em] text-fg-3">
        {label}
      </div>
      <p className="text-[11.5px] leading-snug text-fg-2">{body}</p>
    </div>
  );
}

function SectionNav({
  active,
  onChange,
  sections,
  gov,
}: {
  active: SectionId;
  onChange: (s: SectionId) => void;
  // Pre-filtered by the caller (governance hidden_settings already
  // removed) — defaults to the full list so any other caller keeps
  // today's behavior.
  sections?: SectionDef[];
  gov?: Governance | null;
}) {
  const list = sections ?? SECTIONS;
  // Plane-A (admin) sections split out of the flat config list into
  // their own labeled subgroup so the operator sees at a glance that
  // they govern an admin-hosted app's end-users, not this node's own
  // coding-agent (docs/deployment-models.md; audit finding M2).
  const groups: { id: string; label: string; items: SectionDef[] }[] = [
    {
      id: "edit",
      label: "Edit",
      items: list.filter((s) => s.group === "edit"),
    },
    {
      id: "config",
      label: "Config",
      items: list.filter(
        (s) => s.group === "config" && s.plane !== "admin",
      ),
    },
    {
      id: "admin-plane",
      label: "Observability (admin plane)",
      items: list.filter((s) => s.plane === "admin"),
    },
  ].filter((g) => g.items.length > 0);
  return (
    <nav className="flex flex-col gap-4">
      {groups.map((g) => (
        <div key={g.id}>
          <div className="mb-1.5 px-1 text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
            {g.label}
          </div>
          <div className="flex flex-col gap-0.5">
            {g.items.map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() => onChange(s.id)}
                className={clsx(
                  "flex items-center gap-2 rounded-2 px-2 py-1.5 text-left text-[12px] transition-colors",
                  active === s.id
                    ? "bg-bg-3 text-fg-0"
                    : "text-fg-2 hover:bg-bg-2 hover:text-fg-1",
                )}
              >
                <span
                  className={clsx(
                    "grid h-5 w-5 shrink-0 place-items-center rounded-1",
                    active === s.id
                      ? "bg-bg-4 text-accent"
                      : "bg-bg-2 text-fg-3",
                  )}
                  aria-hidden
                >
                  {s.icon}
                </span>
                <span className="min-w-0 flex-1 truncate">{s.label}</span>
                {isSettingsReadOnly(gov, s.id) && (
                  <span
                    className="shrink-0 text-fg-3"
                    title="Managed by your organization"
                    aria-label="Managed by your organization"
                  >
                    <svg
                      width="11"
                      height="11"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      aria-hidden
                    >
                      <rect x="3" y="11" width="18" height="10" rx="2" />
                      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                  </span>
                )}
                <span
                  className={clsx(
                    "shrink-0 rounded-pill border px-1.5 py-px text-[9.5px] font-medium uppercase tracking-[0.04em]",
                    STATUS_CLASS[s.status],
                  )}
                >
                  {STATUS_LABEL[s.status]}
                </span>
              </button>
            ))}
          </div>
        </div>
      ))}
    </nav>
  );
}

// ============================================================ Pricing

function PricingSection({
  config,
  loading,
  error,
  onReload,
  readOnly,
}: {
  config: ConfigResponse | null;
  loading: boolean;
  error: Error | null;
  onReload: () => void;
  readOnly?: boolean;
}) {
  const defaults = useApi<PricingDefaultsResponse>(
    "/api/config/pricing/defaults",
  );
  const [overrides, setOverrides] = useState<
    Record<string, ModelPricing>
  >({});
  const [showDefaults, setShowDefaults] = useState(false);
  const [save, setSave] = useState<{
    state: "idle" | "saving" | "ok" | "err";
    message?: string;
    // Advisory problems the cost engine found while rebuilding the
    // dated-pricing table on this save — a malformed
    // [intelligence.pricing.dated] row that was skipped, or a dated
    // timeline whose newest entry disagrees with the flat rate just
    // saved. The save still succeeded (pricing never fails closed on
    // these); this is how the operator finds out an override was
    // silently ignored. See cost.Engine.PricingWarnings.
    warnings?: string[];
  }>({ state: "idle" });

  // Seed local edits from server config when it loads.
  useEffect(() => {
    if (config?.config?.Intelligence?.Pricing?.Models) {
      setOverrides(config.config.Intelligence.Pricing.Models);
    } else {
      setOverrides({});
    }
  }, [config]);

  const modelKeys = useMemo(
    () => Object.keys(overrides).sort(),
    [overrides],
  );
  const defaultKeys = useMemo(
    () => Object.keys(defaults.data?.defaults ?? {}).sort(),
    [defaults.data],
  );

  async function saveAll() {
    if (!config) return;
    setSave({ state: "saving" });
    try {
      const res = await fetchJSON<{ saved: boolean; warnings?: string[] }>(
        "/api/config/pricing",
        undefined,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ models: overrides }),
        },
      );
      if (!res.saved) throw new Error("server did not confirm save");
      setSave({
        state: "ok",
        message: "Saved · cost engine reloaded",
        warnings: res.warnings,
      });
      onReload();
    } catch (e) {
      setSave({
        state: "err",
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }

  function addOverride(modelKey: string) {
    setOverrides((prev) => {
      if (prev[modelKey]) return prev;
      const def = defaults.data?.defaults[modelKey];
      return {
        ...prev,
        [modelKey]: def ? costPricingToConfig(def) : blankPricing(),
      };
    });
  }

  function removeOverride(modelKey: string) {
    setOverrides((prev) => {
      const next = { ...prev };
      delete next[modelKey];
      return next;
    });
  }

  function updateRate(modelKey: string, field: keyof ModelPricing, val: string) {
    const n = Number(val);
    if (!Number.isFinite(n) || n < 0) return;
    setOverrides((prev) => ({
      ...prev,
      [modelKey]: { ...prev[modelKey], [field]: n },
    }));
  }

  return (
    <ChartShell
      title="Pricing overrides"
      sub="Per-million-token rates that shadow the baked-in defaults. Save triggers an in-place cost engine reload - Cost / Analysis / Session-detail pages reflect the new rates on next query (no daemon restart)."
      right={
        <div className="flex items-center gap-2 text-[11px]">
          {save.state === "ok" && (
            <span className="text-success">{save.message}</span>
          )}
          {save.state === "err" && (
            <Tooltip content={save.message} maxWidth={360}>
              <span tabIndex={0} className="cursor-help text-danger focus:outline-none">
                Save failed
              </span>
            </Tooltip>
          )}
          <Tooltip content="Jump to baked-in defaults">
            <Button
              size="sm"
              onClick={() => setShowDefaults((v) => !v)}
              className="!rounded-pill"
            >
              Baked-in defaults · {defaultKeys.length}
            </Button>
          </Tooltip>
          <Tooltip content="Pick a default model and add a pricing override">
            <Button size="sm" onClick={() => setShowDefaults(true)}>
              + Add override
            </Button>
          </Tooltip>
          <Button
            variant="soft"
            size="sm"
            onClick={saveAll}
            disabled={save.state === "saving" || loading || !config || readOnly}
            title={readOnly ? "Managed by your organization" : undefined}
          >
            {save.state === "saving" ? "Saving…" : "Save pricing"}
          </Button>
        </div>
      }
    >
      <ChartState
        loading={loading && !config}
        error={error}
        empty={false}
        height={120}
      >
        {save.warnings && save.warnings.length > 0 && (
          <PricingWarningsBanner warnings={save.warnings} />
        )}
        {modelKeys.length === 0 ? (
          <div className="rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-4 py-3 text-[12px] text-fg-3">
            No overrides defined. The cost engine is using its baked-in
            defaults (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowDefaults((v) => !v)}
              className="!inline-flex !gap-0 !border-0 !bg-transparent !p-0 !text-accent hover:!bg-transparent hover:!text-accent-strong"
            >
              {showDefaults ? "hide" : "show"} {defaultKeys.length} models
            </Button>
            ). Add an override below to shadow a default rate.
          </div>
        ) : (
          <PricingTable
            models={overrides}
            modelKeys={modelKeys}
            defaults={defaults.data?.defaults}
            onChange={updateRate}
            onRemove={removeOverride}
          />
        )}

        <details
          className="mt-4 rounded-2 border border-line-1 bg-bg-2"
          open={showDefaults}
          onToggle={(e) =>
            setShowDefaults((e.target as HTMLDetailsElement).open)
          }
        >
          <summary className="cursor-pointer px-3 py-2 text-[11.5px] text-fg-2">
            Baked-in defaults ·{" "}
            <span className="font-mono">{defaultKeys.length}</span> models
          </summary>
          <div className="border-t border-line-1 p-3">
            {defaults.loading && (
              <div className="text-[11px] text-fg-3">loading…</div>
            )}
            {defaults.data && (
              <DefaultsTable
                defaults={defaults.data.defaults}
                dated={defaults.data.dated_defaults}
                onAdd={addOverride}
                existing={new Set(modelKeys)}
              />
            )}
          </div>
        </details>
      </ChartState>
    </ChartShell>
  );
}

// PricingWarningsBanner surfaces advisory problems the cost engine found
// while rebuilding the dated-pricing table on the last save — pricing
// never fails closed on these, so the save above still succeeded; this
// is the only way the operator learns an override was silently ignored
// (a malformed [intelligence.pricing.dated] row, or a dated timeline
// whose newest entry no longer matches the flat rate they just saved).
function PricingWarningsBanner({ warnings }: { warnings: string[] }) {
  return (
    <div className="mb-4 flex items-start gap-3 rounded-3 border border-warn/30 bg-warn-soft/60 px-4 py-2.5 text-[11.5px]">
      <span className="mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded-full border border-warn/40 text-warn">
        !
      </span>
      <div className="min-w-0 flex-1 text-fg-2">
        <b className="text-fg-1">
          Saved, but the dated-rate table has {warnings.length === 1 ? "a problem" : `${warnings.length} problems`}.
        </b>{" "}
        Historical costs may be right while today&apos;s are wrong - check{" "}
        <code className="rounded-1 border border-line-3 bg-bg-3 px-1.5 py-0.5 font-mono text-[11px] text-fg-1">
          [intelligence.pricing.dated]
        </code>{" "}
        in config.toml.
        <ul className="mt-1.5 list-disc space-y-0.5 pl-4">
          {warnings.map((w, i) => (
            <li key={i} className="text-fg-3">
              {w}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function blankPricing(): ModelPricing {
  return {
    Input: 0,
    Output: 0,
    CacheRead: 0,
    CacheCreation: 0,
    CacheCreation1h: 0,
    LongContextThreshold: 0,
    LongContextInput: 0,
    LongContextOutput: 0,
    LongContextCacheRead: 0,
    LongContextCacheCreation: 0,
    LongContextCacheCreation1h: 0,
  };
}

const PRICING_FIELDS: { key: keyof ModelPricing; label: string }[] = [
  { key: "Input", label: "Input" },
  { key: "Output", label: "Output" },
  { key: "CacheRead", label: "Cache R" },
  { key: "CacheCreation", label: "Cache W (5m)" },
  { key: "CacheCreation1h", label: "Cache W (1h)" },
];

function PricingTable({
  models,
  modelKeys,
  defaults,
  onChange,
  onRemove,
}: {
  models: Record<string, ModelPricing>;
  modelKeys: string[];
  // Baked-in reference rates, keyed like `models` — consulted ONLY to
  // read a model's `peak` variant (peak scheduling isn't overridable in
  // this phase; the rates a developer edits below are always the
  // OFF-PEAK base). Absent while /api/config/pricing/defaults is still
  // loading, in which case no peak badge renders yet.
  defaults?: Record<string, CostPricing>;
  onChange: (key: string, field: keyof ModelPricing, val: string) => void;
  onRemove: (key: string) => void;
}) {
  return (
    <Table
      minWidth={820}
      head={
        <tr className="border-b border-line-2">
          <th className="py-1.5 pl-2 font-medium">Model</th>
          {PRICING_FIELDS.map((f) => (
            <Tooltip key={f.key} content="$ per million tokens">
              <th tabIndex={0} className="cursor-help py-1.5 text-right font-medium focus:outline-none">
                {f.label}
              </th>
            </Tooltip>
          ))}
          <th className="py-1.5 pl-3 font-medium" />
        </tr>
      }
    >
      {modelKeys.map((k) => {
        const def = defaults?.[k];
        return (
            <tr
              key={k}
              className="border-b border-line-1 last:border-b-0 hover:bg-bg-3/40"
            >
              <td className="py-1.5 pl-2 font-mono text-fg-1">
                <span className="inline-flex items-center gap-1.5">
                  {k}
                  {def?.peak && <PeakBadge base={def} peak={def.peak} />}
                </span>
              </td>
              {PRICING_FIELDS.map((f) => (
                <td key={f.key} className="py-1.5">
                  <Input
                    mono
                    type="number"
                    step="0.01"
                    min="0"
                    value={models[k][f.key]}
                    onChange={(e) => onChange(k, f.key, e.target.value)}
                    className="ml-auto h-7 w-[88px] !rounded-1 !px-2 !text-[11px] text-right"
                  />
                </td>
              ))}
              <td className="py-1.5 pl-3">
                <Tooltip content="Remove override (revert to default)">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => onRemove(k)}
                    className="!p-0 !border-0 !bg-transparent !text-[10.5px] !text-fg-3 hover:!bg-transparent hover:!text-danger"
                  >
                    Reset
                  </Button>
                </Tooltip>
              </td>
            </tr>
        );
      })}
    </Table>
  );
}

function DefaultsTable({
  defaults,
  dated,
  existing,
  onAdd,
}: {
  defaults: Record<string, CostPricing>;
  // Baked-in historical rate timelines, keyed like `defaults`. Only
  // models whose price actually changed appear here — most models
  // have no entry, meaning "this rate has been flat since forever."
  dated?: Record<string, DatedCostPricing[]>;
  existing: Set<string>;
  onAdd: (key: string) => void;
}) {
  const [query, setQuery] = useState("");
  const keys = useMemo(() => {
    const q = query.trim().toLowerCase();
    const all = Object.keys(defaults).sort();
    return q ? all.filter((k) => k.toLowerCase().includes(q)) : all;
  }, [defaults, query]);
  return (
    <>
      <Input
        type="search"
        placeholder={`Filter ${Object.keys(defaults).length} models…`}
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        className="mb-2"
      />
      <Table
        maxHeight={300}
        stickyHead
        size="sm"
        head={
          <tr className="border-b border-line-2">
            <th className="py-1 pl-2 font-medium">Model</th>
            <th className="py-1 text-right font-medium">Input</th>
            <th className="py-1 text-right font-medium">Output</th>
            <th className="py-1 text-right font-medium">Cache R</th>
            <th className="py-1 text-right font-medium">Cache W</th>
            <th className="py-1 pl-3 font-medium" />
          </tr>
        }
      >
        {keys.map((k) => {
              const p = defaults[k];
              const exists = existing.has(k);
              return (
                <tr
                  key={k}
                  className="border-b border-line-1 last:border-b-0"
                >
                  <td className="py-1 pl-2 font-mono text-fg-1">
                    <span className="inline-flex items-center gap-1.5">
                      {k}
                      {dated?.[k] && dated[k].length > 0 && (
                        <RateHistoryBadge periods={dated[k]} />
                      )}
                      {p.peak && <PeakBadge base={p} peak={p.peak} />}
                    </span>
                  </td>
                  <td className="py-1 text-right font-mono text-fg-2 tabular-nums">
                    {fmtUSD(p.input, true)}
                  </td>
                  <td className="py-1 text-right font-mono text-fg-2 tabular-nums">
                    {fmtUSD(p.output, true)}
                  </td>
                  <td className="py-1 text-right font-mono text-fg-2 tabular-nums">
                    {fmtUSD(p.cache_read, true)}
                  </td>
                  <td className="py-1 text-right font-mono text-fg-2 tabular-nums">
                    {fmtUSD(p.cache_creation, true)}
                  </td>
                  <td className="py-1 pl-3">
                    <Button
                      size="sm"
                      onClick={() => onAdd(k)}
                      disabled={exists}
                    >
                      {exists ? "Already overridden" : "Override"}
                    </Button>
                  </td>
                </tr>
              );
            })}
      </Table>
    </>
  );
}

// RateHistoryBadge marks a baked-in default whose price actually changed
// over time (a `dated_defaults` entry) so the defaults table never
// implies a flat single rate for a model the cost engine is in fact
// pricing on a timeline. Hover/focus shows every period, oldest first.
function RateHistoryBadge({ periods }: { periods: DatedCostPricing[] }) {
  const sorted = useMemo(
    () =>
      [...periods].sort((a, b) =>
        a.effective_from.localeCompare(b.effective_from),
      ),
    [periods],
  );
  const content = (
    <div className="max-w-[280px] text-left">
      <div className="mb-1 font-medium text-fg-1">
        Rate changed over time
      </div>
      <div className="space-y-1">
        {sorted.map((p, i) => (
          <div
            key={i}
            className="flex items-baseline justify-between gap-3 font-mono text-[10.5px]"
          >
            <span className="text-fg-3">{fmtEffectiveFrom(p.effective_from)}</span>
            <span className="text-fg-1 tabular-nums">
              {fmtUSD(p.input, true)} in / {fmtUSD(p.output, true)} out
            </span>
          </div>
        ))}
      </div>
    </div>
  );
  return (
    <Tooltip content={content} maxWidth={320}>
      <span
        tabIndex={0}
        aria-label={`Rate history - ${sorted.length} period${sorted.length === 1 ? "" : "s"}`}
        className="inline-grid h-4 w-4 shrink-0 cursor-help place-items-center rounded-full border border-line-3 text-fg-3 hover:border-accent/50 hover:text-accent focus:outline-none"
      >
        <ClockIcon size={9} />
      </span>
    </Tooltip>
  );
}

// fmtEffectiveFrom renders a DatedCostPricing.effective_from instant as
// a short date, or "since forever" for Go's time.Time zero value
// ("0001-01-01T00:00:00Z") — the idiomatic way the cost engine spells
// the oldest, open-ended period of a rate timeline.
function fmtEffectiveFrom(iso: string): string {
  if (!iso || iso.startsWith("0001-01-01")) return "since forever";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

// WEEKDAY_ABBR indexes like Go's time.Weekday (0=Sun..6=Sat) — the same
// numbering PeakWindow.days uses on the wire.
const WEEKDAY_ABBR = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

// formatWeekdays collapses a set of weekday numbers into contiguous
// range labels, e.g. [1,2,3,4,5] -> "Mon-Fri", [0,6] -> "Sun, Sat",
// and all seven -> "every day". Does not handle a range that wraps
// past Saturday into Sunday (v1 schedules don't author one).
function formatWeekdays(days: number[]): string {
  const sorted = [...new Set(days)].sort((a, b) => a - b);
  if (sorted.length === 0) return "";
  if (sorted.length === 7) return "every day";
  const labels: string[] = [];
  let start = sorted[0];
  let prev = sorted[0];
  for (let i = 1; i <= sorted.length; i++) {
    const d = sorted[i];
    if (d === prev + 1) {
      prev = d;
      continue;
    }
    labels.push(
      start === prev
        ? WEEKDAY_ABBR[start]
        : `${WEEKDAY_ABBR[start]}–${WEEKDAY_ABBR[prev]}`,
    );
    start = d;
    prev = d;
  }
  return labels.join(", ");
}

// formatPeakSchedule renders a PeakSchedule as one compact human-
// readable clause, e.g. "Mon-Fri 01:00-04:00, 06:00-10:00 UTC" for
// deepseek-v4-pro's two same-weekday windows. Windows that share an
// identical weekday set are grouped onto one line so the schedule
// doesn't repeat the day range per window; windows on different
// weekday sets are joined with "; ".
function formatPeakSchedule(schedule: PeakSchedule): string {
  const windows = schedule?.windows ?? [];
  if (windows.length === 0) return "no active window";
  const order: string[] = [];
  const groups = new Map<string, { days: number[]; times: string[] }>();
  for (const w of windows) {
    const key = [...new Set(w.days)].sort((a, b) => a - b).join(",");
    let g = groups.get(key);
    if (!g) {
      g = { days: w.days, times: [] };
      groups.set(key, g);
      order.push(key);
    }
    g.times.push(`${w.start_utc}–${w.end_utc}`);
  }
  return order
    .map((key) => {
      const g = groups.get(key)!;
      return `${formatWeekdays(g.days)} ${g.times.join(", ")} UTC`;
    })
    .join("; ");
}

// PeakBadge marks a model that bills at a higher rate during recurring
// UTC windows (`cost.Pricing.Peak`) — today only deepseek-v4-pro. `base`
// is the OFF-PEAK rate the surrounding row already shows; the badge's
// tooltip is the only place the peak rates and the window are spelled
// out, mirroring RateHistoryBadge's hover-for-detail idiom so the table
// itself stays exactly as compact as it is for every non-peak model.
function PeakBadge({
  base,
  peak,
}: {
  base: Pick<CostPricing, "input" | "output" | "cache_read">;
  peak: PeakRates;
}) {
  const windowLabel = useMemo(() => formatPeakSchedule(peak.schedule), [peak.schedule]);
  const content = (
    <div className="max-w-[280px] text-left">
      <div className="mb-1 font-medium text-fg-1">Peak-hours pricing</div>
      <div className="space-y-1">
        <div className="flex items-baseline justify-between gap-3 font-mono text-[10.5px]">
          <span className="text-fg-3">Off-peak</span>
          <span className="text-fg-1 tabular-nums">
            {fmtUSD(base.input, true)} in / {fmtUSD(base.output, true)} out
          </span>
        </div>
        <div className="flex items-baseline justify-between gap-3 font-mono text-[10.5px]">
          <span className="text-fg-3">Peak</span>
          <span className="text-fg-1 tabular-nums">
            {fmtUSD(peak.input, true)} in / {fmtUSD(peak.output, true)} out
          </span>
        </div>
      </div>
      <div className="mt-1.5 border-t border-line-2 pt-1 text-[10.5px] text-fg-3">
        {windowLabel}
      </div>
    </div>
  );
  return (
    <Pill variant="accent" title={content}>
      <LightningIcon size={9} />
      peak
    </Pill>
  );
}

// ============================================================ Backfill

function BackfillSection() {
  const status = useApi<BackfillStatusResponse>("/api/backfill/status");
  const [jobs, setJobs] = useState<Record<string, BackfillJob>>({});
  // trackerOpen drives the progress dialog. Auto-opens on Run / Run All so
  // the operator sees live output instead of guessing from per-row pills;
  // closing it doesn't cancel the jobs (they run in the observer process
  // and continue accumulating output for the next reopen).
  const [trackerOpen, setTrackerOpen] = useState(false);

  // Restore jobs on mount: the registry is process-local in the
  // observer, so navigating away from Settings then back lost the
  // running indicator pre-fix even though the subprocess was still
  // alive. /api/backfill/jobs returns every job newest-first; collapse
  // to one per mode (the freshest) to match the UI's single-job-per-mode
  // model. The poll useEffect below picks up any restored status="running"
  // entries automatically.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await fetchJSON<BackfillJobsListResponse>(
          "/api/backfill/jobs",
        );
        if (cancelled || !list?.jobs?.length) return;
        const byMode: Record<string, BackfillJob> = {};
        for (const j of list.jobs) {
          if (!byMode[j.mode]) byMode[j.mode] = j;
        }
        setJobs((prev) => ({ ...byMode, ...prev }));
      } catch {
        // soft-fail — list is best-effort UX restoration
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function run(mode: string) {
    setTrackerOpen(true);
    try {
      const res = await fetchJSON<BackfillRunResponse>(
        "/api/backfill/run",
        undefined,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mode }),
        },
      );
      setJobs((prev) => ({
        ...prev,
        [mode]: {
          id: res.job_id,
          mode: res.mode,
          status: res.status,
          started_at: res.started_at,
          output: "",
        },
      }));
    } catch (e) {
      setJobs((prev) => ({
        ...prev,
        [mode]: {
          id: "",
          mode,
          status: "failed",
          started_at: new Date().toISOString(),
          output: "",
          error: e instanceof Error ? e.message : String(e),
        },
      }));
    }
  }

  // Poll every running job every 3s.
  useEffect(() => {
    const running = Object.values(jobs).filter(
      (j) => j.status === "running" && j.id,
    );
    if (running.length === 0) return;
    const id = setInterval(async () => {
      for (const j of running) {
        try {
          const fresh = await fetchJSON<BackfillJob>(
            `/api/backfill/jobs/${j.id}`,
          );
          setJobs((prev) => ({ ...prev, [j.mode]: fresh }));
        } catch {
          // ignore — next tick retries
        }
      }
    }, 3000);
    return () => clearInterval(id);
  }, [jobs]);

  const anyRunning = Object.values(jobs).some((j) => j.status === "running");

  async function runAll() {
    if (!status.data) return;
    setTrackerOpen(true);
    for (const m of status.data.modes) {
      const j = jobs[m.mode];
      if (j?.status === "running") continue;
      await run(m.mode);
    }
  }

  const jobList = Object.values(jobs);
  const runningCount = jobList.filter((j) => j.status === "running").length;
  const doneCount = jobList.filter((j) => j.status === "done").length;
  const failedCount = jobList.filter((j) => j.status === "failed").length;

  // Full rescan (P4.13/E2): `observer scan --force [--adapter]`
  // through the same job registry. The adapter list comes from the
  // tools-status catalog; the server re-validates against its own
  // injected catalog regardless.
  const toolsStatus = useApi<ToolsStatusResponse>("/api/tools/status");
  const [scanAdapter, setScanAdapter] = useState("");
  async function runScan() {
    setTrackerOpen(true);
    const mode = scanAdapter ? `scan:${scanAdapter}` : "scan";
    try {
      const res = await fetchJSON<BackfillRunResponse>("/api/scan/run", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adapter: scanAdapter }),
      });
      setJobs((prev) => ({
        ...prev,
        [mode]: {
          id: res.job_id,
          mode: res.mode,
          status: res.status,
          started_at: res.started_at,
          output: "",
        },
      }));
    } catch (e) {
      setJobs((prev) => ({
        ...prev,
        [mode]: {
          id: "",
          mode,
          status: "failed",
          started_at: new Date().toISOString(),
          output: "",
          error: e instanceof Error ? e.message : String(e),
        },
      }));
    }
  }

  return (
    <ChartShell
      title="Backfill jobs"
      sub="Each mode re-fills a column or row class added in a later migration. SQL-checkable modes show a candidate count; file-walking modes mark `-1` (only the run itself can count). Jobs spawn the observer CLI subprocess with the current config path."
      right={
        status.data && status.data.modes.length > 0 ? (
          <Tooltip content="Fire every mode in sequence">
            <Button variant="soft" size="sm" onClick={runAll} disabled={anyRunning}>
              {anyRunning ? "Running…" : "Run all"}
            </Button>
          </Tooltip>
        ) : null
      }
    >
      {jobList.length > 0 && !trackerOpen && (
        <div className="mb-3 flex items-center gap-2 rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-[11.5px]">
          <span className="text-fg-2">
            {runningCount > 0 && (
              <>
                <b className="text-accent">{runningCount} running</b>
                {(doneCount > 0 || failedCount > 0) && " · "}
              </>
            )}
            {doneCount > 0 && (
              <>
                <span className="text-success">{doneCount} done</span>
                {failedCount > 0 && " · "}
              </>
            )}
            {failedCount > 0 && (
              <span className="text-danger">{failedCount} failed</span>
            )}
          </span>
          <Button size="sm" onClick={() => setTrackerOpen(true)} className="ml-auto">
            View progress
          </Button>
        </div>
      )}

      <div className="mb-3 rounded-2 border border-line-2 bg-bg-2 px-3 py-2">
        <div className="flex flex-wrap items-center gap-2 text-[11.5px]">
          <span className="font-semibold text-fg-1">Full rescan</span>
          <span className="text-fg-3">
            re-walks session files from offset 0 (idempotent; the recovery
            path for watcher gaps) -
          </span>
          <Select
            value={scanAdapter}
            onChange={(e) => setScanAdapter(e.target.value)}
            className="!w-auto"
            options={[
              { value: "", label: "all adapters" },
              ...(toolsStatus.data?.tools ?? []).map((t) => ({
                value: t.tool,
                label: t.tool,
              })),
            ]}
          />
          <Button
            variant="soft"
            size="sm"
            onClick={runScan}
            disabled={
              jobs[scanAdapter ? `scan:${scanAdapter}` : "scan"]?.status ===
              "running"
            }
          >
            {jobs[scanAdapter ? `scan:${scanAdapter}` : "scan"]?.status ===
            "running"
              ? "Rescanning…"
              : "Rescan"}
          </Button>
        </div>
      </div>

      <ChartState
        loading={status.loading && !status.data}
        error={status.error}
        empty={!status.data?.modes.length}
        emptyHint="No backfill modes registered."
        height={160}
      >
        {status.data && (
          <ul className="space-y-2">
            {status.data.modes.map((m) => {
              const job = jobs[m.mode];
              return (
                <li
                  key={m.mode}
                  className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[12px] text-fg-1">
                          {m.mode}
                        </span>
                        <span className="font-mono text-[10.5px] text-fg-3">
                          {m.flag}
                        </span>
                        <CandidatesPill
                          count={m.candidates}
                          note={m.candidates_note}
                        />
                        {job && <JobStatusPill status={job.status} />}
                      </div>
                      <p className="mt-0.5 text-[11px] text-fg-2">
                        {m.description}
                      </p>
                    </div>
                    <Button
                      variant="soft"
                      size="sm"
                      onClick={() => run(m.mode)}
                      disabled={job?.status === "running"}
                    >
                      {job?.status === "running" ? "Running…" : "Run"}
                    </Button>
                  </div>

                  {job && (job.status === "done" || job.status === "failed") && (
                    <details className="mt-2 rounded-1 border border-line-1 bg-bg-1">
                      <summary className="cursor-pointer px-2 py-1 text-[11px] text-fg-3">
                        Output · exit {job.exit_code ?? "?"} ·{" "}
                        {job.output.length.toLocaleString()}B
                        {job.error && (
                          <span className="ml-2 text-danger">{job.error}</span>
                        )}
                      </summary>
                      <pre className="m-0 max-h-[200px] overflow-auto whitespace-pre-wrap break-all px-2 py-1.5 font-mono text-[11px] text-fg-2">
                        {job.output || "(no output captured)"}
                      </pre>
                    </details>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </ChartState>
      <BackfillTrackerDialog
        open={trackerOpen}
        onClose={() => setTrackerOpen(false)}
        jobs={jobList}
        runningCount={runningCount}
        doneCount={doneCount}
        failedCount={failedCount}
      />
    </ChartShell>
  );
}

// BackfillTrackerDialog — progress surface that auto-opens on Run / Run
// All. Lists every job (running + done + failed) with streaming output
// for running jobs (polled by the parent every 3s; the job's Output
// field accumulates chunks as the subprocess writes them). Closing the
// dialog does NOT cancel jobs — they continue in the observer process
// and the banner reopens it on demand.
function BackfillTrackerDialog({
  open,
  onClose,
  jobs,
  runningCount,
  doneCount,
  failedCount,
}: {
  open: boolean;
  onClose: () => void;
  jobs: BackfillJob[];
  runningCount: number;
  doneCount: number;
  failedCount: number;
}) {
  return (
    <SlideOver
      open={open}
      onClose={onClose}
      title="Backfill progress"
      subtitle={
        <span>
          {runningCount > 0 && (
            <>
              <b className="text-accent">{runningCount} running</b>
              {(doneCount > 0 || failedCount > 0) && " · "}
            </>
          )}
          {doneCount > 0 && (
            <>
              <span className="text-success">{doneCount} done</span>
              {failedCount > 0 && " · "}
            </>
          )}
          {failedCount > 0 && (
            <span className="text-danger">{failedCount} failed</span>
          )}
          {jobs.length === 0 && "no jobs yet - click Run to kick one off"}
        </span>
      }
      width={720}
    >
      <div className="p-4">
        {jobs.length === 0 ? (
          <div className="rounded-2 border border-dashed border-line-2 px-4 py-6 text-center text-[12px] text-fg-3">
            No backfill jobs have been started in this session.
          </div>
        ) : (
          <ul className="space-y-3">
            {jobs.map((j) => (
              <BackfillTrackerRow key={j.mode + ":" + j.id} job={j} />
            ))}
          </ul>
        )}
      </div>
    </SlideOver>
  );
}

function BackfillTrackerRow({ job }: { job: BackfillJob }) {
  // Pin the scrollable output to the bottom on each render while the
  // job is running so the operator sees the latest chunks land
  // without manually scrolling. Stops once the job finishes so they
  // can scroll up to inspect.
  const preRef = useRef<HTMLPreElement>(null);
  useEffect(() => {
    if (job.status !== "running") return;
    const el = preRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [job.output, job.status]);

  return (
    <li className="rounded-2 border border-line-1 bg-bg-2">
      <div className="flex items-center justify-between gap-3 border-b border-line-1 px-3 py-2">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[12px] text-fg-1">{job.mode}</span>
          <JobStatusPill status={job.status} />
          {job.exit_code != null && job.status !== "running" && (
            <span className="font-mono text-[10.5px] text-fg-3">
              exit {job.exit_code}
            </span>
          )}
        </div>
        <span className="font-mono text-[10.5px] text-fg-3">
          {job.output.length.toLocaleString()}B
        </span>
      </div>
      {job.error && (
        <div className="border-b border-line-1 px-3 py-1.5 text-[11px] text-danger">
          {job.error}
        </div>
      )}
      <pre
        ref={preRef}
        className="m-0 max-h-[280px] overflow-auto whitespace-pre-wrap break-all px-3 py-2 font-mono text-[11px] text-fg-2"
      >
        {job.output || (job.status === "running" ? "(starting…)" : "(no output)")}
      </pre>
    </li>
  );
}

function CandidatesPill({
  count,
  note,
}: {
  count: number;
  note?: string;
}) {
  if (count < 0) {
    return (
      <Pill title={note}>
        scan needed
      </Pill>
    );
  }
  if (count === 0) {
    return <Pill variant="success">all filled</Pill>;
  }
  return (
    <Pill variant={count > 1000 ? "warn" : "info"}>
      {fmtInt(count)} candidates
    </Pill>
  );
}

function JobStatusPill({ status }: { status: string }) {
  switch (status) {
    case "running":
      return <Pill variant="accent">running</Pill>;
    case "done":
      return <Pill variant="success">done</Pill>;
    case "failed":
      return <Pill variant="danger">failed</Pill>;
    default:
      return <Pill>{status}</Pill>;
  }
}

// ============================================================ Intelligence

function IntelligenceSection({
  config,
  loading,
  error,
  onReload,
  readOnly,
}: {
  config: ConfigResponse | null;
  loading: boolean;
  error: Error | null;
  onReload: () => void;
  readOnly?: boolean;
}) {
  const intel = config?.config?.Intelligence;
  const [summaryModel, setSummaryModel] = useState("");
  const [apiKeyEnv, setApiKeyEnv] = useState("");
  const [monthlyBudget, setMonthlyBudget] = useState(0);
  const [codeGraphEnabled, setCodeGraphEnabled] = useState(false);
  const [save, setSave] = useState<{
    state: "idle" | "saving" | "ok" | "err";
    message?: string;
  }>({ state: "idle" });

  useEffect(() => {
    if (!intel) return;
    setSummaryModel(intel.SummaryModel ?? "");
    setApiKeyEnv(intel.APIKeyEnv ?? "");
    setMonthlyBudget(intel.MonthlyBudgetUSD ?? 0);
    setCodeGraphEnabled(intel.CodeGraph?.Enabled ?? false);
  }, [intel]);

  async function saveSection() {
    setSave({ state: "saving" });
    try {
      const res = await fetchJSON<{ saved: boolean; restart_required: boolean }>(
        "/api/config/section/intelligence",
        undefined,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            SummaryModel: summaryModel,
            APIKeyEnv: apiKeyEnv,
            MonthlyBudgetUSD: monthlyBudget,
            CodeGraph: { Enabled: codeGraphEnabled },
          }),
        },
      );
      if (!res.saved) throw new Error("server did not confirm save");
      if (res.restart_required) markRestartPending("intelligence");
      setSave({
        state: "ok",
        message: res.restart_required
          ? "Saved · restart daemon to apply"
          : "Saved",
      });
      onReload();
    } catch (e) {
      setSave({
        state: "err",
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }

  return (
    <ChartShell
      title="Intelligence"
      sub="Summary model + monthly budget + code-graph toggle. Saving writes config.toml and surfaces a Restart-required banner - these consumers bind config at startup, unlike pricing."
      right={
        <div className="flex items-center gap-2 text-[11px]">
          {save.state === "ok" && (
            <span className="text-success">{save.message}</span>
          )}
          {save.state === "err" && (
            <Tooltip content={save.message} maxWidth={360}>
              <span tabIndex={0} className="cursor-help text-danger focus:outline-none">
                Save failed
              </span>
            </Tooltip>
          )}
          <Button
            variant="soft"
            size="sm"
            onClick={saveSection}
            disabled={save.state === "saving" || loading || !intel || readOnly}
            title={readOnly ? "Managed by your organization" : undefined}
          >
            {save.state === "saving" ? "Saving…" : "Save section"}
          </Button>
        </div>
      }
    >
      <ChartState
        loading={loading && !config}
        error={error}
        empty={!intel}
        emptyHint="Intelligence section unavailable."
        height={200}
      >
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Field label="Summary model" hint="Used by `observer summarize` for session summaries.">
            <Input
              mono
              type="text"
              value={summaryModel}
              onChange={(e) => setSummaryModel(e.target.value)}
              placeholder="claude-haiku-4-5-20251001"
              className="h-8"
            />
          </Field>
          <Field label="API key env" hint="Env var name to read the summary API key from.">
            <Input
              mono
              type="text"
              value={apiKeyEnv}
              onChange={(e) => setApiKeyEnv(e.target.value)}
              placeholder="ANTHROPIC_API_KEY"
              className="h-8"
            />
          </Field>
          <Field label="Monthly budget (USD)" hint="Drives the MTD budget bar on the Analysis tab.">
            <Input
              mono
              type="number"
              min="0"
              step="10"
              value={monthlyBudget}
              onChange={(e) => setMonthlyBudget(Number(e.target.value) || 0)}
              className="h-8"
            />
            <div className="mt-1 text-[11px] text-fg-3">
              Current: <strong>{fmtUSD(monthlyBudget)}</strong>
            </div>
          </Field>
          <Field
            label="Code graph"
            hint="Enable codebase-memory-mcp queries for richer MCP responses."
          >
            <Toggle
              on={codeGraphEnabled}
              onChange={setCodeGraphEnabled}
              label={codeGraphEnabled ? "Enabled" : "Disabled"}
            />
          </Field>
        </div>
      </ChartState>
    </ChartShell>
  );
}

// Field is this page's local name for the shared SettingRow in its
// stacked layout (label above the control, hint below). Kept as a shim so
// the existing call sites are untouched.
function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <SettingRow layout="stack" label={label} help={hint}>
      {children}
    </SettingRow>
  );
}

// ============================================================ SectionView
//
// Per-section router. Sections with a registered structured spec
// (`./settings/sectionSpecs`) render that hand-written form first, then a
// schema-driven "More settings" card for every key of the section the spec
// does not cover; every other section renders entirely from the schema
// (dashboard-config-management plan P1-7). Nothing is read-only any more
// except what the schema says is: secrets, owner-elsewhere keys and
// deprecated aliases.

function SectionView({
  section,
  config,
  schema,
  onReload,
  readOnly,
}: {
  section: SectionId;
  config: ConfigResponse | null;
  schema: ConfigSchemaDescriptor | null;
  onReload: () => void;
  readOnly?: boolean;
}) {
  const spec = SECTION_SPECS[section];
  if (spec) {
    return (
      <StructuredConfigSection
        spec={spec}
        config={config}
        readOnly={readOnly}
        footer={
          <>
            {section === "antigravity" ? (
              <AntigravityHelperCard />
            ) : section === "process" ? (
              <ETWCapturerCard />
            ) : section === "retention" ? (
              <PruneNowCard />
            ) : section === "profiles" ? (
              <>
                <CustomProfilesCard config={config} onChanged={onReload} />
                <ProfilesReferenceCard />
              </>
            ) : section === "mcp" ? (
              <MCPValueMeterCard />
            ) : section === "routing" ? (
              <RoutingRulesEditorCard readOnly={readOnly} />
            ) : null}
            <div className="mt-4">
              <SchemaSection
                section={section}
                config={config}
                schema={schema}
                readOnly={readOnly}
                excludeFieldPaths={specFieldPaths(spec)}
                onSaved={onReload}
                compact
              />
            </div>
          </>
        }
      />
    );
  }
  return (
    <SchemaSection
      section={section}
      title={SECTIONS.find((s) => s.id === section)?.label ?? section}
      config={config}
      schema={schema}
      readOnly={readOnly}
      onSaved={onReload}
    />
  );
}

// specFieldPaths lists the JSON field paths a hand-written spec already
// edits, so the schema card below it never renders the same key twice.
function specFieldPaths(spec: SectionSpec): Set<string> {
  const out = new Set<string>();
  for (const f of spec.fields ?? []) out.add([...spec.path, f.id].join("."));
  for (const g of spec.groups ?? []) {
    for (const f of g.fields) out.add([...g.path, f.id].join("."));
  }
  return out;
}

// RoutingRulesEditorCard — the R2.2 [[routing.rules]] fragment editor
// under Settings → Routing (operator checkpoint Q3 FULL). Reads the
// current rules as TOML from /api/routing/policy (the encoder dialect
// — exactly what config.toml holds), validates via
// /api/routing/policy/lint, and saves through the ONE config seam:
// PUT /api/config/section/routing with RulesTOML. The server re-runs
// the same gate (parse + config.Load shape checks + error-severity
// compiler lint), so a malformed fragment is refused with the file
// untouched. Restart-honest like every routing config write.

type RoutingLintFinding = {
  check: string;
  rule?: string;
  severity: string;
  message: string;
};
type RoutingPolicyView = {
  rules_toml: string;
  rules: number;
  policy: string;
  policy_hash: string;
  lint: RoutingLintFinding[] | null;
  config_path: string;
  note: string;
};
type RoutingRulesLintResult = {
  ok: boolean;
  problems: string[];
  lint: RoutingLintFinding[] | null;
  rules: number;
};

const ROUTING_RULES_PLACEHOLDER = `# No custom rules yet. Example - route read-only turns to haiku-class:
#
# [[routing.rules]]
# name = "cheap-reads"
# when.turn_kind = "read_only"
# action.route_to_tier = "haiku-class"
# action.reason = "overpowered_read"
#
# Recipes: docs/model-routing.md (recipe gallery)`;

function RoutingRulesEditorCard({ readOnly }: { readOnly?: boolean }) {
  const policy = useApi<RoutingPolicyView>("/api/routing/policy");
  const [draft, setDraft] = useState<string | null>(null);
  const [lint, setLint] = useState<RoutingRulesLintResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  const text = draft ?? policy.data?.rules_toml ?? "";

  const validate = async (): Promise<RoutingRulesLintResult | null> => {
    setBusy(true);
    setError("");
    try {
      const res = await fetchJSON<RoutingRulesLintResult>("/api/routing/policy/lint", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules_toml: text }),
      });
      setLint(res);
      return res;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return null;
    } finally {
      setBusy(false);
    }
  };

  const save = async () => {
    // Lint-first save: the Validate check runs before the write, and
    // the server runs the same gate again at the PUT.
    const res = await validate();
    if (!res || !res.ok) return;
    setBusy(true);
    setError("");
    try {
      const cfg = await fetchJSON<{ config: { Routing: Record<string, unknown> } }>("/api/config");
      const sec = { ...cfg.config.Routing, RulesTOML: text };
      await fetchJSON("/api/config/section/routing", undefined, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(sec),
      });
      markRestartPending("routing");
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const findings = lint?.lint ?? [];
  return (
    <Card className="mt-4 text-[11.5px]">
      <div className="text-[12px] font-semibold text-fg-1">
        Custom rules - [[routing.rules]]
        <HelpInd id="card.settings_routing_rules" />
      </div>
      <p className="m-0 mt-0.5 text-fg-3">
        Custom rows append AFTER the template's rules and are walked top-down, first match wins. Saving replaces ALL
        custom rules (an empty editor clears them); the save is lint-gated - a fragment that would fail the next
        daemon start is refused with the file untouched. Worked examples:{" "}
        <code className="rounded-1 bg-bg-1 px-1 font-mono text-[10.5px]">docs/model-routing.md</code> (recipe
        gallery). Tiers, budgets, privacy rules, key pools and local upstreams stay config-file-only.
      </p>
      {policy.error && <p className="m-0 mt-2 text-danger">{String(policy.error)}</p>}
      <Textarea
        mono
        className="mt-3 h-56 leading-relaxed"
        value={text}
        onChange={(e) => {
          setDraft(e.target.value);
          setLint(null);
          setSaved(false);
        }}
        placeholder={ROUTING_RULES_PLACEHOLDER}
        spellCheck={false}
        disabled={policy.loading}
      />

      {lint && lint.ok && (
        <div className="mt-2 text-success">
          Lints clean - {lint.rules} rule(s).
          {findings.length > 0 && " Warnings below (non-blocking):"}
        </div>
      )}
      {lint && !lint.ok && (
        <div className="mt-2 space-y-0.5 text-danger">
          {lint.problems.map((p, i) => (
            <div key={i}>{p}</div>
          ))}
        </div>
      )}
      {findings.length > 0 && (
        <div className="mt-1 space-y-0.5 text-fg-3">
          {findings.map((f, i) => (
            <div key={i}>
              [{f.severity}] {f.check}
              {f.rule ? ` rule=${f.rule}` : ""}: {f.message}
            </div>
          ))}
        </div>
      )}
      {error && <p className="m-0 mt-2 text-danger">{error}</p>}
      <div className="mt-3 flex items-center gap-2">
        <Button
          onClick={validate}
          disabled={busy || policy.loading}
          loading={busy}
        >
          {busy ? "Working…" : "Validate"}
        </Button>
        <Button
          variant="primary"
          onClick={save}
          disabled={busy || policy.loading || readOnly}
          title={readOnly ? "Managed by your organization" : undefined}
        >
          Save rules
        </Button>
        {saved && <Pill variant="warn">saved - restart the daemon to apply</Pill>}
        {policy.data && !saved && (
          <span className="text-fg-3">
            {policy.data.rules} rule(s) on disk · policy {policy.data.policy} @{" "}
            <code className="font-mono text-[10.5px]">{policy.data.policy_hash}</code>
          </span>
        )}
      </div>
    </Card>
  );
}

// MCPValueMeterCard - the P4.10 value meter under the MCP section:
// what the retrieval tools actually got called vs the per-turn schema
// overhead MCP registration costs. Same numbers as the advisor's
// mcp_overhead detector, standing instead of one-off. Honesty rules:
// audit-off renders as "no usage data", never "unused".
function MCPValueMeterCard() {
  const meter = useApi<MCPValueResponse>("/api/mcp/value");
  const m = meter.data;
  const verdictPill = (v: MCPValueResponse["verdict"]) => {
    switch (v) {
      case "active":
        return <Pill variant="success">earning its overhead</Pill>;
      case "low_use":
        return <Pill variant="warn">low use for the tax</Pill>;
      case "unused":
        return <Pill variant="warn">paying tax, zero calls</Pill>;
      default:
        return <Pill variant="neutral">no usage data</Pill>;
    }
  };
  return (
    <ChartShell
      title="Value meter"
      sub="Are the MCP tools worth their per-turn schema overhead? Computed from your own last 30 days."
    >
      <ChartState
        loading={meter.loading}
        error={meter.error}
        empty={!meter.loading && !m}
        emptyHint="No data."
      >
        {m && (
          <div className="space-y-3 text-[11.5px]">
            <div className="flex flex-wrap items-center gap-2">
              {verdictPill(m.verdict)}
              <span className="text-fg-3">
                {m.calls > 0 ? (
                  <>
                    {fmtInt(m.calls)} retrieval-tool calls across ~
                    {fmtInt(m.turns_estimate)} turns (
                    {m.calls_per_100_turns.toFixed(1)} per 100; the worth-it
                    line is {m.threshold_calls_per_100}).
                  </>
                ) : m.verdict === "no_data" && !m.audit_enabled ? (
                  <>
                    The MCP audit log is disabled - usage is invisible, so
                    this meter can't judge. Re-enable it above to measure.
                  </>
                ) : m.verdict === "no_data" ? (
                  <>No turns captured in the window yet.</>
                ) : (
                  <>
                    Zero retrieval-tool calls across ~
                    {fmtInt(m.turns_estimate)} turns.
                  </>
                )}
              </span>
            </div>
            {m.turns_estimate > 0 && (
              <p className="text-fg-3">
                Registration overhead: every turn of an MCP-registered tool
                carries ~{fmtInt(m.schema_tokens_per_turn)} tokens of tool
                schemas - roughly{" "}
                <strong className="font-semibold text-fg-2">
                  {fmtInt(m.overhead_tokens_estimate)} tokens
                </strong>{" "}
                across this window's turns. If you rarely query observer
                mid-session, <code className="font-mono">observer init
                --skip-mcp</code> (or removing the MCP entries via the
                Connected-tools wizard) drops the tax; capture is unaffected.
              </p>
            )}
            {m.by_tool.length > 0 && (
              <Table
                fit
                head={
                  <tr>
                    <th className="pb-1 pr-4 font-semibold">Tool</th>
                    <th className="pb-1 pr-4 font-semibold">Calls</th>
                    <th className="pb-1 font-semibold">Bytes returned</th>
                  </tr>
                }
              >
                {m.by_tool.map((t) => (
                  <tr key={t.tool} className="border-t border-line-1">
                    <td className="py-1 pr-4 font-mono text-fg-2">{t.tool}</td>
                    <td className="py-1 pr-4 text-fg-2">{fmtInt(t.calls)}</td>
                    <td className="py-1 text-fg-2">{fmtInt(t.bytes)}</td>
                  </tr>
                ))}
              </Table>
            )}
            {m.denied_calls > 0 && (
              <p className="text-fg-3">
                {fmtInt(m.denied_calls)} call(s) were denied by the
                allow/deny rules above - denials are audit rows too.
              </p>
            )}
          </div>
        )}
      </ChartState>
    </ChartShell>
  );
}

// CustomProfilesCard — the editable half of the Profiles panel
// (P3.4/D11): create, edit, and delete USER profiles. Backed by the
// /api/config/profiles CRUD endpoints, which drive the same
// config.ProfileStore as `observer profile create|set|delete`. Edits
// apply to NEW sessions automatically (profile-content stamps ride
// the proxy router's instance key) — no restart, no reload.
function CustomProfilesCard({
  config,
  onChanged,
}: {
  config: ConfigResponse | null;
  onChanged: () => void;
}) {
  const names = config?.profile_names ?? [];
  const userProfiles = names.filter(
    (n) => !BUILTIN_PROFILE_NAMES.includes(n),
  );
  const [newName, setNewName] = useState("");
  const [newFrom, setNewFrom] = useState("claude-code");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const validName = /^[a-z0-9][a-z0-9-]{0,63}$/.test(newName);

  async function create() {
    setBusy(true);
    setErr(null);
    try {
      await fetchJSON("/api/config/profiles", undefined, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: newName, from: newFrom }),
      });
      setNewName("");
      onChanged();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove(name: string) {
    if (confirmDelete !== name) {
      setConfirmDelete(name);
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await fetchJSON(`/api/config/profiles/${name}`, undefined, {
        method: "DELETE",
      });
      setConfirmDelete(null);
      if (open === name) setOpen(null);
      onChanged();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-4 rounded-3 border border-line-2 bg-bg-2 p-4">
      <h4 className="mb-1 text-[12px] font-semibold uppercase tracking-[0.06em] text-fg-1">
        Custom profiles
      </h4>
      <p className="mb-3 text-[11px] leading-snug text-fg-3">
        Your own named parameter sets, stored as TOML files next to the
        config (one per profile). Start from a built-in, adjust the keys
        that matter, then assign it above (or per tool / per project via
        the CLI). Edits apply to new sessions automatically. Deleting a
        profile that is still assigned falls back to your master
        parameters with a daemon warning.
      </p>

      {userProfiles.length > 0 && (
        <div className="mb-3 space-y-2">
          {userProfiles.map((name) => (
            <div
              key={name}
              className="rounded-2 border border-line-1 bg-bg-3 px-3 py-2"
            >
              <div className="flex items-center gap-3">
                <span className="flex-1 font-mono text-[12px] text-fg-1">
                  {name}
                </span>
                <Button
                  size="sm"
                  onClick={() => {
                    setOpen(open === name ? null : name);
                    setConfirmDelete(null);
                  }}
                >
                  {open === name ? "Close" : "Edit"}
                </Button>
                <Button
                  size="sm"
                  variant={confirmDelete === name ? "danger" : "secondary"}
                  onClick={() => remove(name)}
                  disabled={busy}
                >
                  {confirmDelete === name ? "Confirm delete" : "Delete"}
                </Button>
              </div>
              {open === name && <ProfileEditor name={name} />}
            </div>
          ))}
        </div>
      )}
      {userProfiles.length === 0 && (
        <p className="mb-3 rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-3 py-2 text-[11.5px] text-fg-3">
          No custom profiles yet.
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-line-1 pt-3">
        <Input
          mono
          type="text"
          value={newName}
          onChange={(e) => {
            setNewName(e.target.value);
            setErr(null);
          }}
          placeholder="profile-name"
          className="w-44"
        />
        <span className="text-[11px] text-fg-3">from</span>
        <Select
          mono
          value={newFrom}
          onChange={(e) => setNewFrom(e.target.value)}
          className="!w-auto"
          options={names}
        />
        <Button variant="primary" onClick={create} disabled={!validName || busy}>
          Create
        </Button>
        {newName && !validName && (
          <span className="text-[11px] text-fg-3">
            lowercase letters, digits, dashes; max 64
          </span>
        )}
        {err && <span className="text-[11.5px] text-danger">{err}</span>}
      </div>
    </div>
  );
}

// The dotted compression keys the profile editor exposes — the
// headline conversation parameters. Anything else stays reachable via
// `observer profile set <name> <key> <value>` (same backend seam).
const PROFILE_EDIT_KEYS: {
  key: string;
  label: string;
  kind: "select" | "number" | "text";
  options?: string[];
  pick: (r: ProfileShowResponse) => string;
}[] = [
  {
    key: "compression.conversation.mode",
    label: "Mode",
    kind: "select",
    options: ["token", "cache", "cache_aware"],
    pick: (r) => r.resolved.Conversation?.Mode ?? "",
  },
  {
    key: "compression.conversation.target_ratio",
    label: "Target ratio",
    kind: "number",
    pick: (r) => String(r.resolved.Conversation?.TargetRatio ?? ""),
  },
  {
    key: "compression.conversation.preserve_last_n",
    label: "Preserve last N",
    kind: "number",
    pick: (r) => String(r.resolved.Conversation?.PreserveLastN ?? ""),
  },
  {
    key: "compression.conversation.compress_types",
    label: "Compress types",
    kind: "text",
    pick: (r) => (r.resolved.Conversation?.CompressTypes ?? []).join(", "),
  },
  {
    key: "compression.conversation.logs.max_lines",
    label: "Logs max lines",
    kind: "number",
    pick: (r) => String(r.resolved.Conversation?.Logs?.MaxLines ?? ""),
  },
];

// ProfileEditor — per-profile parameter editor. Loads the profile
// resolved against the master config, lets the user adjust the
// headline keys, and applies changed keys one PATCH each (the
// `observer profile set` seam — same validation, same allow-list).
function ProfileEditor({ name }: { name: string }) {
  const [data, setData] = useState<ProfileShowResponse | null>(null);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);

  async function load() {
    try {
      const r = await fetchJSON<ProfileShowResponse>(
        `/api/config/profiles/${name}`,
      );
      setData(r);
      const d: Record<string, string> = {};
      for (const k of PROFILE_EDIT_KEYS) d[k.key] = k.pick(r);
      setDraft(d);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name]);

  const baseline = useMemo(() => {
    if (!data) return {} as Record<string, string>;
    const d: Record<string, string> = {};
    for (const k of PROFILE_EDIT_KEYS) d[k.key] = k.pick(data);
    return d;
  }, [data]);

  const changedKeys = PROFILE_EDIT_KEYS.map((k) => k.key).filter(
    (k) => draft[k] !== baseline[k],
  );

  async function apply() {
    setBusy(true);
    setErr(null);
    setSavedMsg(null);
    try {
      for (const key of changedKeys) {
        await fetchJSON(`/api/config/profiles/${name}`, undefined, {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ key, value: draft[key] }),
        });
      }
      setSavedMsg("Applied - new sessions pick this up automatically.");
      await load();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!data) {
    return (
      <p className="mt-2 text-[11px] text-fg-3">{err ?? "Loading…"}</p>
    );
  }
  return (
    <div className="mt-2 border-t border-line-1 pt-2">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {PROFILE_EDIT_KEYS.map((k) => (
          <div key={k.key}>
            <div className="mb-0.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
              {k.label}
            </div>
            {k.kind === "select" ? (
              <Select
                mono
                value={draft[k.key] ?? ""}
                onChange={(e) =>
                  setDraft((d) => ({ ...d, [k.key]: e.target.value }))
                }
                options={k.options ?? []}
              />
            ) : (
              <Input
                mono
                type="text"
                value={draft[k.key] ?? ""}
                onChange={(e) =>
                  setDraft((d) => ({ ...d, [k.key]: e.target.value }))
                }
              />
            )}
          </div>
        ))}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-3">
        <Button
          variant="primary"
          size="sm"
          onClick={apply}
          disabled={changedKeys.length === 0 || busy}
        >
          {busy ? "Applying…" : "Apply changes"}
        </Button>
        <span className="text-[10.5px] text-fg-4">
          Values shown resolved against your master config. Other keys:{" "}
          <code className="font-mono">
            observer profile set {name} &lt;key&gt; &lt;value&gt;
          </code>
        </span>
        {savedMsg && (
          <span className="text-[11px] text-success">{savedMsg}</span>
        )}
        {err && <span className="text-[11px] text-danger">{err}</span>}
      </div>
    </div>
  );
}

// ProfilesReferenceCard — the read-only half of the Profiles panel
// (P2.7): what each built-in profile is tuned for and its headline
// parameters, so picking from the selects above doesn't require
// leaving the page. Values mirror the embedded recipes (byte-pinned
// by recipes_test.go); `observer profile show <name>` prints the full
// resolved parameter set.
function ProfilesReferenceCard() {
  const rows = [
    {
      name: "claude-code",
      tunedFor: "Anthropic models (Claude Code)",
      headline: "cache_aware · ratio 0.85 · keep last 5 · types json+logs+code+tools",
    },
    {
      name: "codex-safe",
      tunedFor: "plain OpenAI GPT under codex",
      headline: "token · ratio 0.95 · keep last 15 · logs + tools trim",
    },
    {
      name: "codex-variant",
      tunedFor: "*-codex reasoning models",
      headline: "token · ratio 0.99 · keep last 50 · no per-type compression",
    },
    {
      name: "default",
      tunedFor: "your master config",
      headline: "exactly the Compression section's parameters",
    },
  ];
  return (
    <Card title="Built-in profiles" className="mt-4">
      <Table
        minWidth={520}
        head={
          <tr>
            <th className="pb-1.5 pr-3 font-semibold">Profile</th>
            <th className="pb-1.5 pr-3 font-semibold">Tuned for</th>
            <th className="pb-1.5 font-semibold">Headline parameters</th>
          </tr>
        }
      >
        {rows.map((r) => (
          <tr key={r.name} className="border-t border-line-1">
            <td className="py-1.5 pr-3 font-mono text-fg-1">{r.name}</td>
            <td className="py-1.5 pr-3 text-fg-2">{r.tunedFor}</td>
            <td className="py-1.5 font-mono text-[11px] text-fg-3">{r.headline}</td>
          </tr>
        ))}
      </Table>
      <p className="mt-2 text-[11px] leading-snug text-fg-3">
        Full resolved parameters: <code className="font-mono text-fg-2">observer profile show &lt;name&gt;</code>.
        Assignments apply to new sessions immediately; the wrong pairing can
        break provider caching - the per-provider defaults are the measured
        safe choices.
      </p>
    </Card>
  );
}

// RestoreBackupControl — the config-undo safety net (usability arc
// P1.15). Every dashboard save copies the prior config.toml to
// config.toml.bak; this control restores it (a SWAP, so restoring
// twice round-trips). Lives under the config-file card in the
// Settings left rail.
function RestoreBackupControl({ onRestored }: { onRestored: () => void }) {
  const backup = useApi<{ exists: boolean; backup_path: string; modified_at?: string }>(
    "/api/config/backup",
  );
  const [phase, setPhase] = useState<"idle" | "confirm" | "working">("idle");
  const [msg, setMsg] = useState<string | null>(null);
  if (!backup.data?.exists) return null;

  async function restore() {
    setPhase("working");
    setMsg(null);
    try {
      await fetchJSON("/api/config/backup", undefined, { method: "POST" });
      markRestartPending("restored-backup");
      setMsg("Restored. The previous save is now the backup.");
      onRestored();
      backup.reload();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setPhase("idle");
    }
  }

  return (
    <div className="mt-2 border-t border-line-1 pt-2">
      {phase !== "confirm" ? (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setPhase("confirm")}
          disabled={phase === "working"}
          className="!p-0 !border-0 !bg-transparent !text-[10.5px] !text-accent hover:!bg-transparent hover:underline"
        >
          {phase === "working" ? "Restoring…" : "Restore previous version…"}
        </Button>
      ) : (
        <div className="space-y-1.5">
          <p className="m-0 text-fg-3">
            Swap config.toml with the backup
            {backup.data.modified_at
              ? ` from ${fmtDateTime(backup.data.modified_at)}`
              : ""}
            ? Restoring again undoes this.
          </p>
          <div className="flex gap-2">
            <Button variant="primary" size="sm" onClick={restore}>
              Restore
            </Button>
            <Button size="sm" onClick={() => setPhase("idle")}>
              Cancel
            </Button>
          </div>
        </div>
      )}
      {msg && <p className="m-0 mt-1 text-[10.5px] text-fg-3">{msg}</p>}
    </div>
  );
}

// PruneNowCard — on-demand retention sweep from the Retention section
// (usability arc P1.10). POSTs /api/prune/run (the `observer prune`
// equivalent), then polls the shared jobs endpoint for streamed
// output. The sweep uses the [observer.retention] thresholds saved
// above — save first if you just changed them (and note those need a
// daemon restart to affect the BACKGROUND prune cycle; the on-demand
// run reads the file fresh).
function PruneNowCard() {
  const [job, setJob] = useState<Pick<BackfillJob, "id" | "status" | "output" | "error"> | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!job || job.status !== "running") return;
    const t = window.setInterval(() => {
      fetchJSON<BackfillJob>(`/api/backfill/jobs/${job.id}`)
        .then((j) => setJob({ id: j.id, status: j.status, output: j.output, error: j.error }))
        .catch(() => {
          // transient poll failure — keep trying until the interval is
          // torn down by a terminal status.
        });
    }, 2000);
    return () => window.clearInterval(t);
  }, [job?.id, job?.status]);

  async function run() {
    setBusy(true);
    setErr(null);
    try {
      const res = await fetchJSON<BackfillRunResponse>("/api/prune/run", undefined, {
        method: "POST",
      });
      setJob({ id: res.job_id, status: "running", output: "", error: undefined });
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const outputTail = job?.output ? job.output.split("\n").slice(-8).join("\n").trim() : "";
  return (
    <div className="mt-4 rounded-3 border border-line-2 bg-bg-2 p-4 text-[11.5px]">
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-[12px] font-semibold text-fg-1">Run retention now</div>
          <p className="m-0 mt-0.5 text-fg-3">
            Sweep old rows immediately using the thresholds above - the
            same pass the daemon runs on its schedule. Deletion is
            permanent; the thresholds decide what counts as old.
          </p>
        </div>
        <Button
          variant="primary"
          className="shrink-0"
          onClick={run}
          disabled={busy || job?.status === "running"}
        >
          {job?.status === "running" ? "Pruning…" : "Run retention now"}
        </Button>
      </div>
      {err && <p className="m-0 mt-2 text-danger">{err}</p>}
      {job && job.status !== "running" && (
        <p className={clsx("m-0 mt-2", job.status === "done" ? "text-success" : "text-danger")}>
          {job.status === "done" ? "Done." : `Failed${job.error ? `: ${job.error}` : "."}`}
        </p>
      )}
      {outputTail && (
        <pre className="m-0 mt-2 max-h-40 overflow-auto whitespace-pre-wrap rounded-2 border border-line-1 bg-bg-1 px-3 py-2 font-mono text-[11px] text-fg-3">
          {outputTail}
        </pre>
      )}
    </div>
  );
}

