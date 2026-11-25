// settingsPlaces: the web counterpart of internal/settingslink's two closed
// tables, for status texts the dashboard computes itself (not an API
// refusal, which carries its own link). Same ids, same paths, same labels:
// the Go test TestWebPlacesMirrorTheTable reads this file and fails when a
// row here differs from the Go table, so a route is still spelled once in
// effect.
//
//   PLACES      places in this dashboard, where the person changes a setting
//               on this machine
//   ORG_PLACES  places in the TEAM dashboard (the org server's own dashboard)
//               where only the organization's admins change a setting. The
//               node links there or names the place; it never offers a
//               toggle of its own.
//
// Pure (no React, no imports): needsSetting.test.ts covers it.

/** One place: its in-app path and its plain name. */
export type PlaceRow = { href: string; label: string };

// One line per row; the Go drift test parses exactly this shape.
export const PLACES = {
  components: { href: "/settings/components", label: "Settings > Components" },
  terminal_launch_policy: { href: "/terminals?tab=settings#launch-policy", label: "Terminals > Settings > Fresh-agent launch policy" },
  session_attach: { href: "/settings?section=terminal", label: "Settings > Session attach" },
  otel_export: { href: "/settings?section=otel", label: "Settings > OTel export" },
  remote_access: { href: "/remote", label: "Remote" },
  account: { href: "/settings?section=enrolment", label: "Settings > Account" },
  process_capture: { href: "/settings?section=process", label: "Settings > Process capture" },
  guard_network: { href: "/security?tab=mcp", label: "Security > MCP > Network features" },
  terminal_sandbox: { href: "/terminals?tab=settings#sandbox-backends", label: "Terminals > Settings > Sandbox isolation" },
  terminal_sandbox_hosted: { href: "/terminals?tab=settings#hosted-sandboxes", label: "Terminals > Settings > Hosted sandboxes" },
  team_summaries: { href: "/settings?section=intel", label: "Settings > Team AI summaries" },
  terminal_remote_systems: { href: "/terminals?tab=settings#remote-systems", label: "Terminals > Settings > Remote systems (SSH)" },
  connected_tools: { href: "/settings?section=tools", label: "Settings > Connected tools" },
  routing_settings: { href: "/settings?section=routing", label: "Settings > Routing" },
  guard_settings: { href: "/settings?section=guard", label: "Settings > Guard" },
  observability_settings: { href: "/settings?section=observability", label: "Settings > AI Apps" },
  intelligence_settings: { href: "/settings?section=intelligence", label: "Settings > Intelligence" },
  security_mode: { href: "/security?tab=overview", label: "Security > Overview > Mode" },
} as const satisfies Record<string, PlaceRow>;

export const ORG_PLACES = {
  org_session_enrichment: { href: "/intelligence?tab=session-enrichment", label: "Intelligence > Session enrichment" },
  org_developer_dashboards: { href: "/settings?section=developer-dashboards", label: "Settings > Developer dashboards" },
} as const satisfies Record<string, PlaceRow>;

export type Place = keyof typeof PLACES;
export type OrgPlace = keyof typeof ORG_PLACES;

/** The link of a local place, in the shape the notice renders. */
export function placeLink(p: Place): { href: string; label: string; command: null; component: null; componentState: null } {
  const r = PLACES[p];
  return { href: r.href, label: r.label, command: null, component: null, componentState: null };
}

/**
 * orgDashboardBase is the team dashboard's origin for an org server address
 * (internal/settingslink.OrgDashboardBase): https, or http on a loopback
 * host, with no credentials. Anything else yields null, so no button opens
 * it and the surface names the place in words.
 */
export function orgDashboardBase(serverURL: string | null | undefined): string | null {
  if (!serverURL) return null;
  try {
    const u = new URL(serverURL.trim());
    if (u.username || u.password || !u.host) return null;
    if (u.protocol === "https:") return `${u.protocol}//${u.host}`;
    if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]")) {
      return `${u.protocol}//${u.host}`;
    }
  } catch {
    // Not a URL.
  }
  return null;
}

/** orgDashboardURL keeps an absolute team-dashboard URL a button may open
 *  (the same rule as orgDashboardBase, path and query kept), else null. */
export function orgDashboardURL(raw: string | null | undefined): string | null {
  const base = orgDashboardBase(raw);
  if (!base || !raw) return null;
  const u = new URL(raw.trim());
  return base + u.pathname + u.search + u.hash;
}

/** The "ask your organization" link of a team-dashboard place: its
 *  absolute URL when the base is safe (else null) and its plain name. */
export function orgPlaceLink(
  serverURL: string | null | undefined,
  p: OrgPlace,
  kind?: string | null,
): { href: string | null; label: string; personal: boolean } {
  const r = ORG_PLACES[p];
  const base = orgDashboardBase(serverURL);
  return { href: base ? base + r.href : null, label: r.label, personal: kind === "personal" };
}
