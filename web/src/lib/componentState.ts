// componentState: the SPA's reading of which components run on this machine
// (modular packaging plan section 7, lane MP-DASH). Pure (no React, no app
// path aliases) so componentState.test.ts runs under `node --test`.
//
// Two daemon reads feed it: GET /api/components (the catalog: titles,
// surfaces, distros) and GET /api/components/state (this node's resolved
// state: componentstate.View plus the routes of inactive components). The
// nav filter, the NotInstalled route guard, useApi's fetch skip and the
// Settings > Components page all read them through the functions here, so
// they cannot disagree about what "not installed" means.

import { routeMatches } from "./concealedRoutes.ts";

/** Resolver state of one component (internal/components State). */
export type ComponentStateName = "active" | "available" | "absent" | "blocked";

/** One row of componentstate.View. */
export type ComponentRowState = {
  id: string;
  state: ComponentStateName;
  reason: string;
  because?: string;
  compiled: boolean;
  selected: boolean;
  in_base: boolean;
};

/** componentstate.View. */
export type ComponentsView = {
  configured: boolean;
  base: string;
  add: string[];
  remove: string[];
  binary_distro: string;
  components_digest: string;
  compiled_count: number;
  active_count: number;
  components: ComponentRowState[];
  issues: string[];
  restart_note: string;
  /** True when an organization governs this machine's components (lane MP-GOV, ruling D-434). */
  org_managed?: boolean;
  org_name?: string;
  governance_source?: string;
  /** Parts of the local block a managed machine ignores. */
  ignored?: string[];
};

/** GET /api/components/state. */
export type ComponentsStateResponse = {
  wired: boolean;
  view: ComponentsView;
  started_active: string[] | null;
  pending: { id: string; change: "activate" | "deactivate" }[];
  inactive_routes: string[];
  purgeable: string[];
  /**
   * One verdict per component from the node feasibility seam
   * (internal/feasibility/nodefeas.ComponentVerdicts, D-514): the reason, the
   * fix and the step for an option that cannot be chosen here. Optional and
   * additive: a daemon that does not send it falls back to stateCopy.
   */
  feasibility?: ComponentVerdict[];
  /**
   * The security components the daemon's opt-in rule selects
   * (cmd/observer securitySelected): an opt-in child is listed only when a
   * [components] block names it. Absent from an older daemon.
   */
  security_selected?: string[];
};

/** One feasibility.Verdict for a component option. */
export type ComponentVerdict = {
  id: string;
  option: string;
  configured: boolean;
  feasible: boolean;
  effect?: string;
  reason?: string;
  fix?: string;
  fix_step?: string;
};

/** verdictCopy is the one sentence an infeasible component shows, or null. */
export function verdictCopy(v: ComponentVerdict | undefined): string | null {
  if (!v || v.feasible || !v.reason) return null;
  const why = v.reason.trim().replace(/\.$/, "");
  return v.fix ? `${why}. ${v.fix}` : `${why}.`;
}

/** One catalog listener / egress row (components.ListenerView / EgressView). */
export type CatalogListener = { proto: string; addr: string; loopback: boolean; auth: string; trigger: string };
export type CatalogEgress = { host: string; purpose: string; gate: string; trigger: string };

/** One catalog row (components.ComponentView), the fields the page reads. */
export type CatalogComponent = {
  id: string;
  class: "core" | "feature" | "adapter" | "integration" | "server";
  title: string;
  about: string;
  stability: string;
  compiled: boolean;
  distros?: Record<string, "on" | "off" | "cond" | "out">;
  requires: string[];
  direct_modules: string[];
  surface: {
    listeners: CatalogListener[];
    egress: CatalogEgress[];
    files_written: string[];
    vendor_configs: string[];
    os_integration: string[];
    processes: string[];
    credentials: string[];
  };
  tables: string[];
  routes: string[];
  verbs: string[];
  teardown: { owner: string; what: string }[];
  ledger: string[];
  restart_class?: string;
  note?: string;
};

/** The closed observed-state vocabulary of a separately installed artifact
 * (internal/artifactstate State). */
export type ArtifactState =
  | "not_detected"
  | "connected"
  | "stale"
  | "incompatible"
  | "host_removed"
  | "policy_blocked"
  | "installed"
  | "absent"
  | "not_applicable";

/** One observed artifact (internal/artifactstate Status; item paths are
 * not served to the dashboard). */
export type ArtifactStatus = {
  id: string;
  state: ArtifactState;
  version?: string;
  detail: string;
  remedy?: string;
  leftover: boolean;
  rule: string;
  items?: { name: string; state: string; version?: string; detail?: string }[];
};

/** GET /api/components. artifact_states is present when the daemon observes
 * the separately installed artifacts (T-707). */
export type CatalogReport = {
  catalog_version: number;
  binary: string;
  distro: string;
  components_digest: string;
  compiled_count: number;
  components: CatalogComponent[];
  artifact_states?: ArtifactStatus[];
};

/** ARTIFACT_STATE_LABEL is the one-liner per observed state. */
export const ARTIFACT_STATE_LABEL: Readonly<Record<ArtifactState, string>> = {
  not_detected: "Not detected",
  connected: "Connected",
  stale: "Older than this Observer",
  incompatible: "Incompatible",
  host_removed: "Host removed",
  policy_blocked: "Blocked by policy",
  installed: "Installed",
  absent: "Not installed",
  not_applicable: "Not applicable here",
};

/**
 * artifactWarns mirrors cmd/observer artifactWarns (the doctor warning rule):
 * a stale, incompatible or host-removed artifact, or any leftover, deserves
 * attention; everything else is informational.
 */
export function artifactWarns(s: ArtifactStatus): boolean {
  return s.leftover || s.state === "stale" || s.state === "incompatible" || s.state === "host_removed";
}

/** The closed level-badge vocabulary of a Components row (plan 7.2). */
export type ComponentBadge =
  | "not_in_build"
  | "inactive"
  | "active"
  | "blocked"
  | "removal_pending"
  | "activation_pending";

/** BADGE_LABEL is the honest one-liner per badge (L2 is never "removed"). */
export const BADGE_LABEL: Readonly<Record<ComponentBadge, string>> = {
  not_in_build: "Not in this build",
  inactive: "Installed, inactive",
  active: "Active",
  blocked: "Blocked",
  removal_pending: "Removal pending restart",
  activation_pending: "Active after restart",
};

/** BADGE_TONE maps a badge onto a shared Pill tone. */
export const BADGE_TONE: Readonly<Record<ComponentBadge, "success" | "neutral" | "warn" | "danger" | "accent">> = {
  not_in_build: "neutral",
  inactive: "neutral",
  active: "success",
  blocked: "danger",
  removal_pending: "warn",
  activation_pending: "accent",
};

/**
 * badgeFor reads one row's badge. Ordered rules, first match wins: absent
 * beats everything (nothing can run it), then blocked, then a change that
 * waits for the daemon's restart, then the live state.
 */
export function badgeFor(
  row: Pick<ComponentRowState, "id" | "state">,
  pending: ComponentsStateResponse["pending"] = [],
): ComponentBadge {
  if (row.state === "absent") return "not_in_build";
  if (row.state === "blocked") return "blocked";
  const p = pending.find((x) => x.id === row.id);
  if (p?.change === "deactivate") return "removal_pending";
  if (p?.change === "activate") return "activation_pending";
  return row.state === "active" ? "active" : "inactive";
}

/** stateCopy is the honest sentence for a non-active state (plan 7.5). */
export function stateCopy(state: ComponentStateName, title: string, distros: string[] = []): string {
  switch (state) {
    case "absent":
      return `Not in this build. This binary was built without ${title.toLowerCase()}, so its code is absent.${
        distros.length ? ` Builds that include it: ${distros.join(", ")}.` : ""
      }`;
    case "blocked":
      return "Blocked on this machine. Settings > Components explains why.";
    case "available":
      return "Installed, inactive. The code is in this build but nothing runs: no listener, no network, no changes to your tools.";
    default:
      return "Active.";
  }
}

/** distrosWith lists the prebuilt distros that compile a catalog row. */
export function distrosWith(c: Pick<CatalogComponent, "distros"> | undefined): string[] {
  if (!c?.distros) return [];
  return Object.entries(c.distros)
    .filter(([, d]) => d === "on" || d === "off" || d === "cond")
    .map(([name]) => name)
    .sort();
}

/**
 * isComponentActive reports whether id is active in a view. Unknown ids and
 * core answer true, and so does a missing view: a gate must fail open to
 * today's behaviour, never hide a page because a read is slow or failed.
 */
export function isComponentActive(view: ComponentsView | null | undefined, id: string | undefined): boolean {
  if (!view || !id || id === "core") return true;
  const row = view.components.find((c) => c.id === id);
  return row ? row.state === "active" : true;
}

/**
 * SETTINGS_SECTION_COMPONENTS maps a Settings section to the component whose
 * config it edits, for the sections that leave with a compiled-out
 * component (T-681): [observability] with obs, [observer.process] with
 * processobs, [exporter.otel] with export.otel. Every other section edits
 * core config and always shows.
 */
export const SETTINGS_SECTION_COMPONENTS: Readonly<Record<string, string>> = {
  observability: "obs",
  process: "processobs",
  otel: "export.otel",
};

/**
 * absentSettingsSections lists the Settings sections whose component is not
 * in this build (state "absent", L1): the config they edit would only ever
 * be reported, never obeyed, so the rail hides them. An installed but
 * inactive component (L2) keeps its section, so it can be set up before it
 * is added. Empty while the state is unknown (fail open).
 */
export function absentSettingsSections(
  view: ComponentsView | null | undefined,
  sections: Readonly<Record<string, string>> = SETTINGS_SECTION_COMPONENTS,
): string[] {
  if (!view) return [];
  return Object.entries(sections)
    .filter(([, comp]) => view.components.find((c) => c.id === comp)?.state === "absent")
    .map(([section]) => section)
    .sort();
}

/** inactiveNavIds lists the nav ids whose page component is not active. */
export function inactiveNavIds(
  view: ComponentsView | null | undefined,
  navComponents: Readonly<Record<string, string>>,
): string[] {
  if (!view) return [];
  return Object.entries(navComponents)
    .filter(([, comp]) => !isComponentActive(view, comp))
    .map(([nav]) => nav)
    .sort();
}

/** filterNavByComponents drops the nav items of inactive components. */
export function filterNavByComponents<G extends { items: { id: string }[] }>(
  groups: G[],
  inactive: readonly string[],
): G[] {
  if (inactive.length === 0) return groups;
  const hidden = new Set(inactive);
  return groups
    .map((g) => ({ ...g, items: g.items.filter((it) => !hidden.has(it.id)) }))
    .filter((g) => g.items.length > 0);
}

/** The body a route of an inactive component answers (404). */
export type NotInstalledBody = {
  error: "component_not_installed";
  component: string;
  state: ComponentStateName;
  reason?: string;
  message?: string;
};

/** parseNotInstalled reads a 404 body, or null when it is not that class. */
export function parseNotInstalled(body: string | null | undefined): NotInstalledBody | null {
  if (!body) return null;
  try {
    const v = JSON.parse(body) as Partial<NotInstalledBody>;
    if (v && v.error === "component_not_installed" && typeof v.component === "string") {
      return v as NotInstalledBody;
    }
  } catch {
    // Not JSON: not this class.
  }
  return null;
}

// The fetch-skip store: the inactive routes from the last state read. Same
// shape as concealedRoutes (one module-level list, subscribers re-render on
// a change), kept separate because the two lists have different owners.
let inactiveRoutes: readonly string[] = [];
let inactiveKey = "";
const listeners = new Set<() => void>();

/** NEVER_SKIPPED are the reads that must answer even when everything is off. */
const NEVER_SKIPPED = ["/api/components", "/api/components/state", "/api/governance"];

/** setInactiveRoutes records the list from a state read. */
export function setInactiveRoutes(list: readonly string[] | undefined): void {
  const next = [...(list ?? [])].sort();
  const key = next.join("\n");
  if (key === inactiveKey) return;
  inactiveRoutes = next;
  inactiveKey = key;
  for (const fn of listeners) fn();
}

/** isRouteInactive reports whether a fetch of path must be skipped now. */
export function isRouteInactive(path: string): boolean {
  if (inactiveRoutes.length === 0) return false;
  const pathname = path.split(/[?#]/, 1)[0] || "/";
  if (NEVER_SKIPPED.includes(pathname)) return false;
  return inactiveRoutes.some((p) => routeMatches(pathname, p.replace(/^[A-Z]+ /, "")));
}

/** subscribeInactiveRoutes is the useSyncExternalStore subscribe. */
export function subscribeInactiveRoutes(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/** inactiveRoutesSnapshot is the useSyncExternalStore snapshot. */
export function inactiveRoutesSnapshot(): string {
  return inactiveKey;
}

/** The Settings > Components row groups (plan 7.2), in display order. */
export const COMPONENT_GROUPS: readonly { id: string; label: string; match: (c: CatalogComponent) => boolean }[] = [
  { id: "adapters", label: "Capture adapters", match: (c) => c.class === "adapter" },
  { id: "integrations", label: "Integrations (writes to other tools)", match: (c) => c.class === "integration" },
  { id: "telemetry", label: "Telemetry and export", match: (c) => /^(ingest\.|export\.|obs$|processobs$|egress\.)/.test(c.id) },
  { id: "org", label: "Org and updates", match: (c) => /^(org\.|agentaccess\.|cloud\.)/.test(c.id) },
  { id: "helpers", label: "Helpers", match: (c) => /^(demo|archive|notify\.)/.test(c.id) },
  { id: "features", label: "Features", match: (c) => c.class === "feature" || c.class === "core" },
];

/** groupOf returns the first COMPONENT_GROUPS id a row matches. */
export function groupOf(c: CatalogComponent): string {
  return COMPONENT_GROUPS.find((g) => g.match(c))?.id ?? "features";
}

/** manifestFor renders the "Download component manifest" body: the
 *  effective set as a custom distro manifest (plan 7.2 Export). */
export function manifestFor(view: ComponentsView): string {
  const active = view.components.filter((c) => c.state === "active").map((c) => c.id).sort();
  return `${JSON.stringify(
    {
      kind: "observer-components-manifest",
      version: 1,
      base: view.base,
      add: view.add,
      remove: view.remove,
      binary_distro: view.binary_distro,
      components_digest: view.components_digest,
      active,
    },
    null,
    2,
  )}\n`;
}

/**
 * TileOwner is what a dashboard tile needs to be meaningful (T-670): the data
 * route it reads, and/or the catalog component that produces its numbers when
 * that data rides on a core route (for example proxy turns counted inside
 * /api/status). A component id, never a tool name.
 */
export type TileOwner = { route?: string; component?: string };

/**
 * tileVisible reports whether a tile renders: hidden when its data route
 * belongs to a component that is not active (the same inactive-route list
 * the fetch skip reads) or when its producing component is not active.
 * Fails open like every gate here: no view and no list means visible.
 */
export function tileVisible(view: ComponentsView | null | undefined, owner: TileOwner): boolean {
  if (owner.route && isRouteInactive(owner.route)) return false;
  if (owner.component && !isComponentActive(view, owner.component)) return false;
  return true;
}
