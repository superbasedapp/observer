// filterScope - which of the global FilterBar controls a route actually
// reads. The bar used to show window / tool / project everywhere, including
// Settings, Terminals and Remote where they did nothing; a control that
// changes nothing on the page in front of you is a lie. This table is the one
// owner of that mapping: a page that starts reading a filter adds its row.
//
// Pure (no React, no router) so it runs under node --test.

/** FilterScope names the global filters a route consumes. */
export type FilterScope = { window: boolean; tool: boolean; project: boolean };

const ALL: FilterScope = { window: true, tool: true, project: true };
const NONE: FilterScope = { window: false, tool: false, project: false };

// First path segment -> the filters that page reads (grounded in each
// page's useFilters() destructure). Anything unlisted reads none.
const ROUTE_SCOPES: Record<string, FilterScope> = {
  "": ALL, // Overview
  actions: ALL,
  analysis: ALL,
  cache: ALL,
  compression: ALL,
  cost: ALL,
  discovery: ALL,
  sessions: ALL,
  suggestions: ALL,
  tools: ALL,
  patterns: { window: false, tool: true, project: true },
  routing: { window: true, tool: false, project: false },
};

/** filterScopeFor returns the filters the page at `pathname` reads. */
export function filterScopeFor(pathname: string): FilterScope {
  const seg = pathname.replace(/^\/+/, "").split("/")[0] ?? "";
  return ROUTE_SCOPES[seg] ?? NONE;
}

// A tool / project filter is "set" when it narrows to something: the
// FilterProvider's unfiltered value is "all" (lib/filters.tsx).
function isSet(v: string): boolean {
  return v !== "" && v !== "all";
}

/**
 * ignoredFilters lists the filters that are SET (narrowed, not "all") but not
 * read by this page, so the bar can say so instead of silently dropping them.
 */
export function ignoredFilters(
  scope: FilterScope,
  values: { tool: string; project: string },
): Array<"tool" | "project"> {
  const out: Array<"tool" | "project"> = [];
  if (!scope.tool && isSet(values.tool)) out.push("tool");
  if (!scope.project && isSet(values.project)) out.push("project");
  return out;
}
