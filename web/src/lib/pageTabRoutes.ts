// pageTabRoutes.ts - every node-dashboard page with page tabs, as ONE table
// built from lib/nodePageTabs.ts (the tab ids and labels the pages read).
// Two readers: the command palette ("Security › Prompt guard" jumps, never
// hand-listed in CommandPalette.tsx) and the TopBar breadcrumb (the open tab
// as its last segment). The node's own sibling of web2's pageTabRoutes.ts.
//
// Pure: no React, no router. Importable under `node --test`.

import {
  AGENT_CONFIG_TABS,
  CACHE_TABS,
  CODE_SECURITY_TABS,
  COMPRESSION_TABS,
  COST_TABS,
  POLICIES_TABS,
  REMOTE_TABS,
  ROUTING_TABS,
  SECURITY_TABS,
  TERMINALS_TABS,
  TOOLS_TABS,
  type PageTabs,
} from "./nodePageTabs.ts";

/** One tabbed page: its nav id (lib/nav.ts) and path, and its tab table. */
export type NodeTabRoute = {
  /** The nav item id (lib/nav.ts): its label and icon name the page. */
  navId: string;
  path: string;
  tabs: PageTabs<string>;
};

/** NODE_TAB_ROUTES: every tabbed node page, in sidebar order. */
export const NODE_TAB_ROUTES: readonly NodeTabRoute[] = [
  { navId: "security", path: "/security", tabs: SECURITY_TABS },
  { navId: "code-security", path: "/code-security", tabs: CODE_SECURITY_TABS },
  { navId: "cost", path: "/cost", tabs: COST_TABS },
  { navId: "tools", path: "/tools", tabs: TOOLS_TABS },
  { navId: "compression", path: "/compression", tabs: COMPRESSION_TABS },
  { navId: "cache", path: "/cache", tabs: CACHE_TABS },
  { navId: "routing", path: "/routing", tabs: ROUTING_TABS },
  { navId: "policies", path: "/policies", tabs: POLICIES_TABS },
  { navId: "agent-config", path: "/agent-config", tabs: AGENT_CONFIG_TABS },
  { navId: "terminals", path: "/terminals", tabs: TERMINALS_TABS },
  { navId: "remote", path: "/remote", tabs: REMOTE_TABS },
];

/** Old names a palette search should also find a tab by. */
const TAB_ALIASES: Record<string, readonly string[]> = {
  "/cost?tab=statement": ["Monthly statement", "Report"],
  "/tools?tab=coverage": ["Detected tools", "Tool coverage", "Capture status"],
};

/** One palette jump to a tab. */
export type NodeTabJump = {
  /** The address, e.g. `/security?tab=prompt-guard`. */
  to: string;
  /** The page's nav id (its icon). */
  navId: string;
  /** The tab's label (the palette prefixes the page label). */
  tabLabel: string;
  aliases: readonly string[];
};

/**
 * nodeTabJumps is one jump per non-default tab of every tabbed page (the
 * default tab is the page's own palette entry).
 */
export function nodeTabJumps(routes: readonly NodeTabRoute[] = NODE_TAB_ROUTES): NodeTabJump[] {
  const out: NodeTabJump[] = [];
  for (const r of routes) {
    r.tabs.ids.forEach((id, i) => {
      if (i === 0) return;
      const to = `${r.path}?tab=${encodeURIComponent(id)}`;
      out.push({ to, navId: r.navId, tabLabel: r.tabs.labels[id]!, aliases: TAB_ALIASES[to] ?? [] });
    });
  }
  return out;
}

/**
 * nodeTabCrumb is the breadcrumb's tab segment: the open tab's label when the
 * URL names a non-default tab of a tabbed page, else null. The session and
 * project drawers keep their tab in `?dtab=`, so they never collide with it.
 */
export function nodeTabCrumb(pathname: string, search: string): string | null {
  const r = NODE_TAB_ROUTES.find((x) => x.path === pathname);
  if (!r) return null;
  const v = new URLSearchParams(search).get("tab");
  if (!v) return null;
  const i = r.tabs.ids.indexOf(v);
  return i > 0 ? r.tabs.labels[v]! : null;
}
