// Dashboard visibility: the SPA half of the managed-node visibility arc
// (docs/audits/managed-node-visibility-2026-10-03.md, docs/managed-node-visibility.md).
//
// The daemon resolves, per page and per Settings section, whether it is
// hidden, read-only or visible ON THIS MACHINE (govern.Effective.
// DashboardVisibility: the org's applied node.governance directives composed
// with the managed-node defaults) and serves it as GET /api/governance's
// `visibility` block. Every surface below filters on THAT answer, so the nav,
// the route guard, the command palette, the tour, the help drawer and the
// Settings rail can never disagree with the API, which refuses the same ids.
//
// Pure: no React, no fetch, so visibility.test.ts runs under `node --test`.
// On an ungoverned individual node every list is empty and every helper is
// the identity, which IS the individual-node guarantee. The helpers read a
// null posture as "nothing hidden", so a filtering surface must never hand
// them an UNRESOLVED read: it reads governancePosture first and, until
// "ready", filters on failClosedLists (Sol A4-05; useGovernanceVisibility
// in ./governance does both).

export type VisibilityLevel = "hidden" | "read_only" | "visible";
/** "grant": a page-access grant shows a hidden page or tab read-only (T-435). */
export type VisibilitySource = "floor" | "org" | "default" | "none" | "grant";

export type VisibilityEntry = { level: VisibilityLevel; source: VisibilitySource };

export type DashboardVisibility = {
  /** True on a managed machine whose grant is live: the defaults apply. */
  managed_defaults: boolean;
  hidden_sections: string[];
  read_only_sections: string[];
  hidden_settings: string[];
  read_only_settings: string[];
  sections?: Record<string, VisibilityEntry>;
  settings?: Record<string, VisibilityEntry>;
  /**
   * Page tabs ("<page>/<tab>") the org hid on a page that is itself shown
   * (per-tab visibility, T-132; lib/tabVisibility.ts). Absent on a daemon
   * that predates per-tab visibility, which hides no tab.
   */
  hidden_tabs?: string[];
  tabs?: Record<string, VisibilityEntry>;
};

// The organization display name lives in ./orgName (its one owner, T-160);
// re-exported here so the governance surfaces' existing imports keep working.
export { orgDisplayLabel, orgDisplayLabelSentence } from "./orgName.ts";

/**
 * The subset of the /api/governance response these helpers read. `visibility`
 * is absent on a daemon that predates the arc; the legacy lists (the org's
 * applied directives, honoured only while `active`) are the fallback, which is
 * exactly what that daemon's API enforces.
 */
export type GovernanceLists = {
  active: boolean;
  hidden_sections: string[];
  read_only_sections: string[];
  hidden_settings: string[];
  read_only_settings: string[];
  visibility?: DashboardVisibility;
};

type Gov = GovernanceLists | null | undefined;

const EMPTY: readonly string[] = [];

/**
 * The pages and Settings sections no posture can hide: the T8 floor
 * (nodegov.UnhideableNavSectionIDs / UnhideableSettingsSectionIDs). They stay
 * reachable even while the posture is unknown, so a developer can always see
 * what their organization configured and manage their enrolment.
 */
export const FLOOR_NAV_IDS: readonly string[] = ["settings", "privacy", "requests", "messages"];
export const FLOOR_SETTINGS_IDS: readonly string[] = ["enrolment", "org"];

/**
 * Whether this machine's visibility posture is known yet (Sol A4-05).
 *
 * "ready" once GET /api/governance has answered (a later refresh error keeps
 * the last answer, which is what the daemon still enforces), "pending" while
 * the first read is in flight, "unavailable" when it failed. Only "ready" may
 * be treated as an ungoverned node: a null posture must never mean "nothing is
 * hidden", or a slow or failing read would mount every managed-hidden page.
 */
export type GovernancePosture = "pending" | "ready" | "unavailable";

export function governancePosture(state: { data: unknown; error: unknown }): GovernancePosture {
  if (state.data != null) return "ready";
  return state.error != null ? "unavailable" : "pending";
}

/**
 * The FAIL-CLOSED lists every filtering surface uses until the posture is
 * "ready": every nav page except the floor counts as hidden. Settings
 * sections are not listed (the Settings page and the help drawer, the two
 * surfaces that know the section ids, gate on the posture themselves).
 */
export function failClosedLists(navIds: readonly string[]): GovernanceLists {
  const floor = new Set(FLOOR_NAV_IDS);
  const hidden = navIds.filter((id) => !floor.has(id));
  return {
    active: false,
    hidden_sections: [],
    read_only_sections: [],
    hidden_settings: [],
    read_only_settings: [],
    visibility: {
      managed_defaults: false,
      hidden_sections: hidden,
      read_only_sections: [],
      hidden_settings: [],
      read_only_settings: [],
    },
  };
}

/** Whether a Settings section stays offered while the posture is not ready. */
export function settingsOfferedWhileUnresolved(id: string): boolean {
  return FLOOR_SETTINGS_IDS.includes(id);
}

function pick(
  gov: Gov,
  resolved: (v: DashboardVisibility) => string[],
  legacy: (g: GovernanceLists) => string[],
): readonly string[] {
  if (!gov) return EMPTY;
  if (gov.visibility) return resolved(gov.visibility) ?? EMPTY;
  return gov.active ? legacy(gov) ?? EMPTY : EMPTY;
}

/** Nav page ids hidden on this machine. */
export function hiddenNavIds(gov: Gov): readonly string[] {
  return pick(gov, (v) => v.hidden_sections, (g) => g.hidden_sections);
}

/** Nav page ids locked read-only on this machine. */
export function readOnlyNavIds(gov: Gov): readonly string[] {
  return pick(gov, (v) => v.read_only_sections, (g) => g.read_only_sections);
}

/** Settings sub-section ids hidden on this machine. */
export function hiddenSettingsIds(gov: Gov): readonly string[] {
  return pick(gov, (v) => v.hidden_settings, (g) => g.hidden_settings);
}

/** Settings sub-section ids locked read-only on this machine. */
export function readOnlySettingsIds(gov: Gov): readonly string[] {
  return pick(gov, (v) => v.read_only_settings, (g) => g.read_only_settings);
}

/** Whether a nav page's level was decided by the managed default. */
export function navSource(gov: Gov, id: string): VisibilitySource {
  return gov?.visibility?.sections?.[id]?.source ?? "none";
}

/**
 * pathNavId maps a SPA path (optionally with a query string, e.g. a palette
 * tab jump "/security?tab=rules") onto its nav id, using the nav table's own
 * paths. Unknown paths map to null and are never filtered.
 */
export function pathNavId(
  path: string,
  navPaths: ReadonlyArray<{ id: string; path: string }>,
): string | null {
  const pathname = path.split(/[?#]/, 1)[0] || "/";
  return navPaths.find((n) => n.path === pathname)?.id ?? null;
}

/** Drop the items whose path lands on a hidden page (palette jumps, tour steps). */
export function withoutHiddenPaths<T>(
  items: readonly T[],
  pathOf: (item: T) => string | undefined,
  hidden: readonly string[],
  navPaths: ReadonlyArray<{ id: string; path: string }>,
): T[] {
  if (hidden.length === 0) return items.slice();
  const set = new Set(hidden);
  return items.filter((it) => {
    const p = pathOf(it);
    if (!p) return true;
    const id = pathNavId(p, navPaths);
    return id == null || !set.has(id);
  });
}

/**
 * helpEntryHidden reports whether a help-registry entry documents a hidden
 * page or Settings section. Help ids are `<category>.<subject>` where the
 * subject is a page id ("tab.security"), a page-prefixed name
 * ("card.security_mode", "chart.routing_decisions") or a Settings-prefixed
 * one ("glossary.settings_guard"). Entries about anything else stay.
 */
export function helpEntryHidden(
  helpId: string,
  hiddenNav: readonly string[],
  hiddenSettings: readonly string[],
  /** Posture not ready: every non-floor Settings section counts as hidden. */
  allSettingsUnresolved = false,
): boolean {
  const dot = helpId.indexOf(".");
  if (dot < 0) return false;
  const subject = helpId.slice(dot + 1);
  for (const id of hiddenNav) {
    if (subject === id || subject.startsWith(`${id}_`)) return true;
  }
  if (allSettingsUnresolved && subject.startsWith("settings_")) {
    const rest = subject.slice("settings_".length);
    return !FLOOR_SETTINGS_IDS.some((id) => rest === id || rest.startsWith(`${id}_`));
  }
  for (const id of hiddenSettings) {
    if (subject === `settings_${id}` || subject.startsWith(`settings_${id}_`)) return true;
  }
  return false;
}
