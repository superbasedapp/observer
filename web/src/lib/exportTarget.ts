// exportTarget - what the TopBar's Export button downloads for the page in
// view. Before this table the button fell back to /api/status on every route
// it had no mapping for, so "Export" on Routing, Security, Projects and a
// dozen other pages silently downloaded the daemon status snapshot.
//
// EXPORT_ROUTES is the ONE table (walked top-down, first match wins): a page
// either names the endpoint whose JSON IS its data, with the global filters
// that endpoint honours, or says in one sentence why there is nothing to
// export. A route with no row gets the honest "nothing to export" state, and
// exportTarget.test.ts fails when a nav page has no row at all.
//
// A TABBED page (TABBED_PAGES) exports per tab (REVIEW-3 P3-24): every tab
// has its own row, naming the endpoint whose JSON is that tab's data or the
// sentence saying the tab has nothing to export, so a tab never downloads a
// different dataset than it shows. The default tab is the absence of
// `?tab=`, resolved to the page's first tab id before the walk.
//
// Pure (no React, no router, no DOM) so it runs under node --test.

import {
  AGENT_CONFIG_TABS,
  CACHE_TABS,
  COMPRESSION_TABS,
  COST_TABS,
  REMOTE_TABS,
  ROUTING_TABS,
  SECURITY_TABS,
  TERMINALS_TABS,
} from "./nodePageTabs.ts";

/** TABBED_PAGES maps each tabbed page to its tab ids (ids[0] is the default). */
export const TABBED_PAGES: Readonly<Record<string, readonly string[]>> = {
  "/security": SECURITY_TABS.ids,
  "/cost": COST_TABS.ids,
  "/compression": COMPRESSION_TABS.ids,
  "/cache": CACHE_TABS.ids,
  "/routing": ROUTING_TABS.ids,
  "/remote": REMOTE_TABS.ids,
  "/terminals": TERMINALS_TABS.ids,
  "/agent-config": AGENT_CONFIG_TABS.ids,
};

const CONFIG_TAB = "Nothing to export here: this tab is configuration, edited and shown on the tab itself.";

/** ExportFilter names a global filter an export endpoint honours. */
export type ExportFilter = "window" | "tool" | "project" | "model";

type ExportRow =
  | {
      path: string;
      /** Match only this `?tab=` value of the page (rows are walked in order). */
      tab?: string;
      endpoint: string;
      /** Fixed query params (limits). */
      base?: Record<string, string | number>;
      /** The global filters the endpoint honours. */
      filters?: readonly ExportFilter[];
      /** Page params copied through verbatim when present (e.g. ?q=, ?month=). */
      pageParams?: readonly string[];
      /** A page param the endpoint cannot run without; absent = nothing to export. */
      requires?: string;
      /** The reason shown when `requires` is absent. */
      requiresNote?: string;
    }
  | { path: string; tab?: string; none: string };

const ALL: readonly ExportFilter[] = ["window", "tool", "project", "model"];

export const EXPORT_ROUTES: readonly ExportRow[] = [
  { path: "/", endpoint: "/api/status/scoped", filters: ALL },
  { path: "/live", endpoint: "/api/live", base: { window_minutes: 15 }, filters: ["model"] },
  { path: "/sessions", endpoint: "/api/sessions", base: { limit: 200 }, filters: ALL },
  { path: "/actions", endpoint: "/api/actions", base: { limit: 500 }, filters: ALL },
  { path: "/projects", endpoint: "/api/projects", filters: ALL },
  { path: "/security", tab: "overview", endpoint: "/api/guard/summary" },
  { path: "/security", tab: "verdicts", endpoint: "/api/guard/events", base: { limit: 500 } },
  { path: "/security", tab: "rules", endpoint: "/api/guard/rules" },
  { path: "/security", tab: "budgets", endpoint: "/api/guard/budget" },
  { path: "/security", tab: "prompt-guard", endpoint: "/api/guard/prompt/events" },
  { path: "/security", tab: "mcp", endpoint: "/api/guard/mcp" },
  { path: "/security", tab: "coverage", endpoint: "/api/guard/conformance" },
  { path: "/code-security", endpoint: "/api/security/findings", base: { status: "open", limit: 1000 } },
  {
    path: "/egress",
    none: "Nothing to export here: egress decisions stream on the page and the policy is exported from its own editor.",
  },
  {
    path: "/search",
    endpoint: "/api/search",
    base: { limit: 50 },
    pageParams: ["q"],
    requires: "q",
    requiresNote: "Nothing to export yet: run a search first.",
  },
  {
    path: "/cost",
    tab: "statement",
    endpoint: "/api/report/monthly",
    filters: ["model"],
    pageParams: ["month", "project"],
  },
  { path: "/cost", tab: "overview", endpoint: "/api/models", filters: ALL },
  { path: "/cost", tab: "by-model", endpoint: "/api/models", filters: ALL },
  { path: "/cost", tab: "budgets", endpoint: "/api/budget" },
  { path: "/cost", tab: "reconciliation", endpoint: "/api/cowork/reconcile" },
  {
    path: "/plans",
    none: "Nothing to export here: plan readings change every few minutes and stay on this machine.",
  },
  { path: "/analysis", endpoint: "/api/analysis/headline", filters: ALL },
  { path: "/tools", endpoint: "/api/tools", filters: ["window", "project", "model"] },
  { path: "/compression", tab: "savings", endpoint: "/api/compression/timeseries", filters: ALL },
  { path: "/compression", tab: "events", endpoint: "/api/compression/events", base: { limit: 500 }, filters: ALL },
  { path: "/compression", tab: "experiments", endpoint: "/api/experiments" },
  {
    path: "/compression",
    tab: "advanced",
    none: "Nothing to export here: the advanced tab is beta surfaces and their settings, shown on the tab itself.",
  },
  { path: "/cache", tab: "overview", endpoint: "/api/cache/overview", filters: ALL },
  { path: "/cache", tab: "events", endpoint: "/api/cache/events", filters: ALL },
  { path: "/suggestions", endpoint: "/api/suggestions", filters: ALL },
  { path: "/routing", tab: "overview", endpoint: "/api/routing/status" },
  { path: "/routing", tab: "decisions", endpoint: "/api/routing/decisions", base: { limit: 1000 }, filters: ["window", "model"] },
  { path: "/routing", tab: "policy", none: CONFIG_TAB },
  { path: "/routing", tab: "shadow", endpoint: "/api/routing/shadow", filters: ["window", "model"] },
  { path: "/benchmarks", endpoint: "/api/benchmarks", base: { limit: 500 }, filters: ["model"] },
  { path: "/discovery", endpoint: "/api/discover", filters: ALL },
  { path: "/patterns", endpoint: "/api/patterns", base: { limit: 200 }, filters: ["tool", "project", "model"] },
  {
    path: "/policies",
    none: "Nothing to export here: policies are configuration, exported from each policy's own editor.",
  },
  { path: "/agent-config", tab: "tools", endpoint: "/api/agent-config/tools" },
  { path: "/agent-config", tab: "projects", none: CONFIG_TAB },
  { path: "/agent-config", tab: "common", none: CONFIG_TAB },
  { path: "/agent-config", tab: "instructions", none: CONFIG_TAB },
  { path: "/agent-config", tab: "organization", none: CONFIG_TAB },
  { path: "/agent-config", tab: "coverage", endpoint: "/api/agent-config/coverage" },
  { path: "/agent-config", tab: "history", endpoint: "/api/agent-config/history" },
  {
    path: "/privacy",
    none: "Nothing to export here: this page explains what leaves this machine; the last shipped payload is shown on the page.",
  },
  { path: "/terminals", tab: "workspace", endpoint: "/api/terminal/runs" },
  { path: "/terminals", tab: "settings", none: CONFIG_TAB },
  { path: "/terminals", tab: "arena", endpoint: "/api/arena/runs" },
  { path: "/remote", tab: "pairing", none: CONFIG_TAB },
  { path: "/remote", tab: "terminal-control", endpoint: "/api/remote/sessions" },
  { path: "/remote", tab: "tailscale", none: CONFIG_TAB },
  { path: "/remote", tab: "audit", endpoint: "/api/remote/audit" },
  { path: "/messages", endpoint: "/api/messages" },
  { path: "/requests", endpoint: "/api/requests" },
  { path: "/settings", endpoint: "/api/config" },
];

/** NO_EXPORT_NOTE is the state for a route with no row. */
export const NO_EXPORT_NOTE = "Nothing to export on this page.";

/** ExportFilterValues is the bar's state; "all" (or "") means unfiltered. */
export type ExportFilterValues = {
  /** The window as query params (lib/filters windowParams), precomputed by the caller. */
  window: Record<string, string | number | undefined>;
  tool: string;
  project: string;
  model: string;
};

export type ExportTarget = { url: string } | { none: string };

function isSet(v: string): boolean {
  return v !== "" && v !== "all";
}

/**
 * exportTargetFor resolves the page at (pathname, search) to the URL its
 * Export downloads (with the global filters its endpoint honours), or the
 * sentence saying there is nothing to export.
 */
export function exportTargetFor(pathname: string, search: string, f: ExportFilterValues): ExportTarget {
  const path = pathname === "" ? "/" : pathname.replace(/\/+$/, "") || "/";
  const page = new URLSearchParams(search);
  // A tabbed page's default tab is the absence of ?tab= (useUrlTab).
  const tab = page.get("tab") || (TABBED_PAGES[path]?.[0] ?? "");
  const row = EXPORT_ROUTES.find((r) => r.path === path && (r.tab == null || r.tab === tab));
  if (!row) return { none: NO_EXPORT_NOTE };
  if ("none" in row) return { none: row.none };
  if (row.requires && !(page.get(row.requires) ?? "").trim()) {
    return { none: row.requiresNote ?? NO_EXPORT_NOTE };
  }
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(row.base ?? {})) q.set(k, String(v));
  for (const k of row.pageParams ?? []) {
    const v = page.get(k);
    if (v) q.set(k, v);
  }
  const filters = row.filters ?? [];
  if (filters.includes("window")) {
    for (const [k, v] of Object.entries(f.window)) {
      if (v !== undefined && v !== "") q.set(k, String(v));
    }
  }
  if (filters.includes("tool") && isSet(f.tool)) q.set("tool", f.tool);
  if (filters.includes("project") && isSet(f.project)) q.set("project", f.project);
  if (filters.includes("model") && isSet(f.model)) q.set("model", f.model);
  const qs = q.toString();
  return { url: qs ? `${row.endpoint}?${qs}` : row.endpoint };
}
