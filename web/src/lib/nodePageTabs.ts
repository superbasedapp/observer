// Page-tab models for the node dashboard pages restructured by the platform
// tabs plan (docs/audits/platform-ia-tabs-audit-2026-10-02.md §2.2, lane N).
//
// One table per page: the `?tab=` ids in strip order (the FIRST id is the
// default, written as the param's absence by useUrlTab) and the visible
// labels. Pure data plus a few tiny mappings, no React, no imports, so
// nodePageTabs.test.ts runs under plain `node --test` and pins the ids every
// deep link, help entry and redirect relies on.
//
// Node data is the developer's own (no audit-on-read), so none of these tabs
// carries an `audited` marker: tabs here are pure information architecture
// (lazy per tab, kept mounted once visited, `?tab=` + Back/Forward).

/** A page's tab table: ids in strip order and their labels. */
export type PageTabs<T extends string> = {
  /** Ids in strip order; ids[0] is the default tab. */
  ids: readonly T[];
  /** Visible label per id (at most about 14 characters). */
  labels: Readonly<Record<T, string>>;
};

function pageTabs<T extends string>(ids: readonly T[], labels: Record<T, string>): PageTabs<T> {
  return { ids, labels };
}

/** defaultTab is a page's default tab (the first id). */
export function defaultTab<T extends string>(p: PageTabs<T>): T {
  return p.ids[0];
}

// ---------- Security (N1, plan P1, mockup M4) ----------

export const SECURITY_TABS = pageTabs(
  ["overview", "verdicts", "rules", "budgets", "prompt-guard", "mcp", "coverage"] as const,
  {
    overview: "Overview",
    verdicts: "Verdicts",
    rules: "Rules",
    budgets: "Budgets",
    "prompt-guard": "Prompt guard",
    mcp: "MCP",
    coverage: "Coverage & evidence",
  },
);
export type SecurityTab = (typeof SECURITY_TABS.ids)[number];

/** How many verdicts the Overview tab previews before "See all in Verdicts". */
export const SECURITY_RECENT_VERDICTS = 5;

// ---------- Code security (security pillar plan sections 4.10 and 6.3) ----------

// Findings is the Phase A shell; Exceptions and Baselines arrive with lane
// sec-c3 (local exceptions and the baseline commit). The Trust, Scanners and
// Evidence tabs join with the phases that build them.
export const CODE_SECURITY_TABS = pageTabs(["findings", "exceptions", "baselines"] as const, {
  findings: "Findings",
  exceptions: "Exceptions",
  baselines: "Baselines",
});
export type CodeSecurityTab = (typeof CODE_SECURITY_TABS.ids)[number];

// ---------- Cost (plan P2; absorbs /report as Statement, §3 row 9) ----------

export const COST_TABS = pageTabs(
  ["overview", "by-model", "budgets", "statement", "reconciliation"] as const,
  {
    overview: "Overview",
    "by-model": "By model",
    budgets: "Budgets",
    statement: "Statement",
    reconciliation: "Reconciliation",
  },
);
export type CostTab = (typeof COST_TABS.ids)[number];

// ---------- Tools (T-935: the always-available capture coverage list) ----------
// Activity is the page as it was (per-tool aggregates over the window);
// Coverage lists every supported AI tool with whether it was found here and
// how it is captured. Not windowed, so it does not follow the filter bar.

export const TOOLS_TABS = pageTabs(["activity", "coverage"] as const, {
  activity: "Activity",
  coverage: "Coverage",
});
export type ToolsTab = (typeof TOOLS_TABS.ids)[number];

// ---------- Compression (plan P2) ----------

export const COMPRESSION_TABS = pageTabs(
  ["savings", "events", "experiments", "advanced"] as const,
  {
    savings: "Savings",
    events: "Events",
    experiments: "Experiments",
    advanced: "Advanced",
  },
);
export type CompressionTab = (typeof COMPRESSION_TABS.ids)[number];

// ---------- Cache (plan P2) ----------

export const CACHE_TABS = pageTabs(["overview", "events"] as const, {
  overview: "Overview",
  events: "Events",
});
export type CacheTab = (typeof CACHE_TABS.ids)[number];

// ---------- Routing (plan P2) ----------
// The Decisions tab keeps its feed filters in `?reason=&applied=` beside
// `?tab=decisions` (they survive tab switches, so Back restores both).

export const ROUTING_TABS = pageTabs(["overview", "decisions", "policy", "shadow"] as const, {
  overview: "Overview",
  decisions: "Decisions",
  policy: "Policy",
  shadow: "Shadow & apply",
});
export type RoutingTab = (typeof ROUTING_TABS.ids)[number];

// ---------- Remote access (plan P2) ----------

export const REMOTE_TABS = pageTabs(["pairing", "terminal-control", "tailscale", "audit"] as const, {
  pairing: "Pairing",
  "terminal-control": "Terminal control",
  tailscale: "Tailscale",
  audit: "Access audit",
});
export type RemoteTab = (typeof REMOTE_TABS.ids)[number];

// ---------- Terminals (plan P2: SegmentedControl -> TabStrip) ----------

export const TERMINALS_TABS = pageTabs(["workspace", "settings", "arena"] as const, {
  workspace: "Workspace",
  settings: "Settings",
  arena: "Arena",
});
export type TerminalsTab = (typeof TERMINALS_TABS.ids)[number];

// ---------- Policies (plan P3: tab moved from local state to `?tab=`) ----------

export const POLICIES_TABS = pageTabs(
  ["overview", "templates", "guardrails", "routing", "test", "activity"] as const,
  {
    overview: "Overview",
    templates: "Templates",
    guardrails: "Guardrails",
    routing: "Routing",
    test: "Test",
    activity: "Activity",
  },
);
export type PoliciesTab = (typeof POLICIES_TABS.ids)[number];

// ---------- AI tool settings (adapter config editor, backlog items 2 and 7) ----------

export const AGENT_CONFIG_TABS = pageTabs(
  ["tools", "projects", "common", "instructions", "organization", "coverage", "history"] as const,
  {
    tools: "By tool",
    projects: "Projects",
    common: "All AI tools",
    instructions: "Instructions",
    organization: "Organization",
    coverage: "Coverage",
    history: "History",
  },
);
export type AgentConfigTab = (typeof AGENT_CONFIG_TABS.ids)[number];

/** The in-page anchor on the Terminals Settings tab that other pages link to. */
export const TERMINALS_LAUNCH_POLICY_HASH = "#launch-policy";
/** The Folder Selection card (the allowed project roots), T-489. */
export const TERMINALS_FOLDERS_HASH = "#folder-selection";
/** The Remote systems card (the SSH profile editor), T-488. */
export const TERMINALS_REMOTE_SYSTEMS_HASH = "#remote-systems";

/** Every in-page anchor on the Terminals Settings tab. The hash minus its
 *  "#" is the card's element id, which the page scrolls to. */
export const TERMINALS_SETTINGS_ANCHORS: readonly string[] = [
  TERMINALS_LAUNCH_POLICY_HASH,
  TERMINALS_FOLDERS_HASH,
  TERMINALS_REMOTE_SYSTEMS_HASH,
];

/**
 * terminalsHashTab names the tab an old in-page anchor lives on, or null.
 * `/terminals#launch-policy` (the New Terminal dialog's picker legend)
 * must open Settings, where the launch-policy card is.
 */
export function terminalsHashTab(hash: string): TerminalsTab | null {
  return TERMINALS_SETTINGS_ANCHORS.includes(hash) ? "settings" : null;
}

/**
 * reportToCostSearch maps an old `/report?month=&project=` query string to
 * the Cost page's Statement tab (`/cost?tab=statement&month=&project=`),
 * keeping every param. For lane R's redirect of the retired /report route.
 */
export function reportToCostSearch(search: string): string {
  const p = new URLSearchParams(search);
  p.delete("tab");
  const rest = p.toString();
  return `?tab=statement${rest ? `&${rest}` : ""}`;
}
