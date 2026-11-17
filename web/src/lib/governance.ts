// Governance — the node's read of GET /api/governance, mirroring
// internal/govern.Effective (internal/govern/types.go). On an ordinary
// solo node the daemon returns {active: false, ...} with empty arrays,
// and every helper below is a no-op / identity function in that case —
// that property IS the solo-node guarantee: nothing in this file may
// change behavior unless a node has actually been enrolled and granted
// dashboard.visibility authority.
import { useCallback, useEffect, useMemo } from "react";
import { useApi, type ApiState } from "./useApi";
import { setConcealedRoutes } from "./concealedRoutes";
import { NAV_ITEMS, type NavGroup } from "./nav";
import type { PageTabs } from "./nodePageTabs";
import { NODE_TAB_ROUTES } from "./pageTabRoutes";
import { hiddenTabIds, withVisibleTabs } from "./tabVisibility";
import type { VocabEntry } from "@shared/lib/vocabEntry";
import {
  failClosedLists,
  governancePosture,
  hiddenNavIds,
  hiddenSettingsIds,
  hrefGate,
  readOnlyNavIds,
  orgDisplayLabel,
  readOnlySettingsIds,
  type DashboardVisibility,
  type GovernancePosture,
  type HrefGateTables,
  type LinkGate,
} from "./visibility";

export type GovernanceState =
  | "no_grant"
  | "grant_expired"
  | "identity_changed"
  | "key_pin_mismatch"
  | "no_policy"
  | "inert"
  | "applied";

export type GovernanceDropped = {
  directive: string;
  reason: string;
};

export type GovernanceNotice = {
  org_display_name?: string;
  contact?: string;
  policy_url?: string;
};

// GovernanceShareSource is the four-value enum the Privacy page's Source
// column renders. It is resolved AT THE BOUNDARY (GET /api/governance,
// govern.SourceForBool) and never composed in the SPA.
//
//   "you"        - the organization published nothing for this key, or what
//                  it published is inert on this machine
//   "org"        - the organization LOWERED this key below your setting
//   "both"       - the organization pinned this key at the value you had set
//   "org_raised" - the organization RAISED this key above your setting. Only
//                  reachable on a MANAGED machine (Enterprise-Managed
//                  Tenancy); on an individual / BYO machine the raise is
//                  structurally inert and the source stays "you".
export type GovernanceShareSource = "you" | "org" | "both" | "org_raised";

// GOVERNANCE_SOURCE - the tone of a governed share row's source pill. A raise
// is the one direction that shares MORE than the operator asked for, so it
// is warn rather than routine-policy info. Glyph: VOCAB_ICONS.governanceSource.
export const GOVERNANCE_SOURCE: Readonly<Record<GovernanceShareSource, VocabEntry>> = {
  you: { tone: "info" },
  org: { tone: "info" },
  both: { tone: "info" },
  org_raised: { tone: "warn" },
};

// GovernanceShareKey is one row of the /api/governance `share` block: the
// value in force, the value this machine's own config asks for, and which of
// the two decided it.
// local is null for a key this daemon build has no local counterpart for -
// structurally unreachable today (the org's share vocabulary is compiled into
// the same binary), kept in the type so a drift renders rather than throws.
export type GovernanceShareKey = {
  effective: boolean | string[];
  local: boolean | string[] | null;
  source: GovernanceShareSource;
  policy_version?: number;
};

export type Governance = {
  active: boolean;
  state: GovernanceState;
  version: number;
  org_name?: string;
  // managed is true when this machine enrolled under Enterprise-Managed
  // Tenancy. It drives the unhideable "this machine is managed by <org>"
  // transparency banner (T8). Absent on a pre-managed build, which reads as
  // false — the individual / BYO default.
  managed?: boolean;
  hidden_sections: string[];
  read_only_sections: string[];
  hidden_settings: string[];
  read_only_settings: string[];
  // The org's applied schema-3 EXPOSE lists (shown on a managed machine
  // despite the managed default). Absent on a pre-arc daemon.
  visible_sections?: string[];
  visible_settings?: string[];
  // visibility is the RESOLVED per-page answer on this machine: the org's
  // directives above composed with the managed-node defaults. Every helper
  // below filters on it; absent on a pre-arc daemon, where the legacy lists
  // are the fallback (lib/visibility.ts).
  visibility?: DashboardVisibility;
  notice: GovernanceNotice;
  authority?: string[];
  unknown_authority?: string[];
  dropped?: GovernanceDropped[];
  expires_at?: string;
  hash?: string;
  // share is the Phase-1b sharing block: one entry per [org_client.share]
  // key the organization published a directive for.
  //
  // SEAM: the endpoint does not emit it on every build yet. Absent means
  // "no org sharing directives", which resolves every key to source "you" -
  // the honest default, and the same answer a solo node gives forever.
  share?: Record<string, GovernanceShareKey>;
  // pricing is the node's price-table posture (enterprise-pricing plan §3.3).
  //
  // SEAM: absent on a build with no cost engine wired, and absent on every
  // pre-arc daemon. Absent means "not reported" and the card renders nothing
  // - never "seed", which would be a claim about rates nobody was asked
  // about.
  pricing?: GovernancePricing;
  // concealed_routes lists the API routes whose read the daemon refuses as
  // hidden on this machine right now (T-401). useGovernance hands it to
  // lib/concealedRoutes, the shared guard useApi consults so a hidden
  // section's API is never fetched. Absent when nothing is concealed, and on
  // an older daemon.
  concealed_routes?: string[];
};

// GovernancePricingSource is the three-value enum the Privacy page's pricing
// row renders.
//
//   "local"             - this machine's own table: the compiled defaults plus
//                         any [intelligence.pricing] override you set.
//   "org"               - your organization's signed rates are applied, with
//                         any override you set still winning above them.
//   "org_authoritative" - a MANAGED machine holding enforce.budget: the
//                         organization's rates sit ABOVE your own overrides,
//                         so a budget cannot be evaded by re-pricing.
//   "feed"              - a STANDALONE (non-enrolled) machine applying the
//                         public Tokenomics pricing feed (market LIST prices),
//                         below any rate you set yourself. An enrolled machine
//                         never consults the public feed.
export type GovernancePricingSource =
  | "local"
  | "org"
  | "org_authoritative"
  | "feed";

// GovernancePricing is the /api/governance `pricing` block: which price table
// is in force on this machine, at which document version, and anything the
// engine refused.
export type GovernancePricing = {
  source: GovernancePricingSource;
  org_version?: number;
  org_authoritative?: boolean;
  has_org_pricing?: boolean;
  // feed_version / feed_fetched_at are set only when source === "feed": the
  // applied public-feed version and when it was pulled.
  feed_version?: number;
  feed_fetched_at?: string;
  // warnings are organization rows this machine REFUSED. An admin who typed a
  // rate and saw nothing change finds out here, on the machine where it did
  // not apply.
  warnings?: string[];
};

// shareSourceOf resolves one sharing key's Source column. Absent governance,
// an inactive grant, or a key the organization published nothing for all
// resolve to "you" - never to a claim that the organization touched it.
export function shareSourceOf(
  gov: Governance | null | undefined,
  key: string,
): GovernanceShareKey | null {
  if (!gov?.active) return null;
  return gov.share?.[key] ?? null;
}

// SHARE_SOURCE_LABEL is the column copy, in plain hyphens, as a function of
// the org label so the policy version lands in the right clause.
//
// The "increased" label exists because increasing exists. This table used to
// say one deliberately did not, on the grounds that an organization
// "structurally cannot" raise sharing - true on the individual plane, and
// false since Enterprise-Managed Tenancy shipped the managed raise. Omitting
// the string never prevented the raise; it only meant a raised row was
// labelled "You", crediting the developer with their employer's decision.
export const SHARE_SOURCE_LABEL: Record<
  GovernanceShareSource,
  (version: string) => string
> = {
  you: () => "You",
  org: (v) => `Your organization${v} - reduced`,
  both: (v) => `You, locked by your organization${v}`,
  org_raised: (v) => `Your organization${v} - increased`,
};

// shareSourceLabel renders the column, naming the policy version whenever
// the organization is a source.
//
// The lookup is defensive: a daemon newer than this bundle can answer with a
// source this table has never heard of, and an unlabelled row must degrade to
// "set by your organization" - never to a TypeError that takes the whole
// Privacy page down with it.
export function shareSourceLabel(row: GovernanceShareKey | null): string {
  if (!row) return SHARE_SOURCE_LABEL.you("");
  const version = row.policy_version ? ` (policy v${row.policy_version})` : "";
  const label = SHARE_SOURCE_LABEL[row.source];
  if (!label) return `Your organization${version}`;
  return label(version);
}

// GOVERNANCE_REFRESH_MS: how often an open dashboard re-reads its posture.
// The node pulls a changed node.governance body within seconds (the
// policy-version probe), so an admin exposing a page should see it appear on
// an open dashboard without a reload. Every caller shares one cached read
// (useApi's query cache), so this is one small loopback GET per interval.
export const GOVERNANCE_REFRESH_MS = 15_000;

// useGovernance reads the node's resolved governance posture, refreshed every
// GOVERNANCE_REFRESH_MS while the tab is visible. An enrol/leave from
// Settings > Enrolment also invalidates this key itself, so the posture
// follows an enrolment change immediately rather than on the next tick.
export function useGovernance(): ApiState<Governance> {
  const st = useApi<Governance>("/api/governance", undefined, [], {
    refreshMs: GOVERNANCE_REFRESH_MS,
  });
  // Every answered read updates the shared fetch guard (T-401); a failed
  // read keeps the last list, since the daemon still enforces it.
  const routes = st.data ? (st.data.concealed_routes ?? []).join("\n") : null;
  useEffect(() => {
    if (routes != null) setConcealedRoutes(routes ? routes.split("\n") : []);
  }, [routes]);
  return st;
}

// FAIL_CLOSED_GOVERNANCE is what every FILTERING surface sees until the
// posture is known (Sol A4-05): every nav page but the floor hidden. One
// module-level value, so memoized consumers keep a stable identity.
const FAIL_CLOSED_GOVERNANCE: Governance = {
  ...failClosedLists(NAV_ITEMS.map((i) => i.id)),
  state: "no_grant",
  version: 0,
  notice: {},
};

// GovernanceVisibility is the posture the filtering surfaces (route guard,
// nav, command palette, tour, help, Settings rail) read. `gov` is the real
// posture once it is "ready" and FAIL_CLOSED_GOVERNANCE before that, so a
// slow or failing /api/governance never mounts a page the organization hid.
// Transparency surfaces (Privacy, the banner) keep reading useGovernance().
export type GovernanceVisibility = {
  gov: Governance;
  posture: GovernancePosture;
  reload: () => void;
};

export function useGovernanceVisibility(): GovernanceVisibility {
  const st = useGovernance();
  const posture = governancePosture(st);
  return {
    gov: posture === "ready" && st.data ? st.data : FAIL_CLOSED_GOVERNANCE,
    posture,
    reload: st.reload,
  };
}

// HREF_GATE_TABLES: the nav and tabbed-page tables useHrefGate maps an
// address with. Module-level so the hook's callback identity follows only
// the posture.
const HREF_GATE_TABLES: HrefGateTables = { navPaths: NAV_ITEMS, tabRoutes: NODE_TAB_ROUTES };

/**
 * useHrefGate returns how a link to an address renders on this machine
 * (lib/visibility.ts hrefGate: "shown", "managed" or "unresolved"), over the
 * same filtering posture the route guard, nav and Settings rail read. Every
 * link to a page, Settings section or tab an organization may hide goes
 * through it (components/GatedLink.tsx), so a link is never offered to a
 * place this machine does not show (CG-20/CG-21).
 */
export function useHrefGate(): (href: string) => LinkGate {
  const { gov, posture } = useGovernanceVisibility();
  return useCallback((href: string) => hrefGate(href, gov, posture, HREF_GATE_TABLES), [gov, posture]);
}

// usePageTabs is a tabbed page's tab table on THIS machine: `tabs` without the
// tabs the organization hid (per-tab visibility, T-132; lib/tabVisibility.ts).
// Every tabbed page reads its strip, its useUrlTab allow-list and its default
// tab from this, so a hidden tab is neither shown nor reachable by `?tab=`.
// Identity when nothing on the page is hidden.
export function usePageTabs<T extends string>(navId: string, tabs: PageTabs<T>): PageTabs<T> {
  const { gov } = useGovernanceVisibility();
  const hidden = hiddenTabIds(gov);
  const key = hidden.join(",");
  // `key` is the content of `hidden`, so the memo follows the posture, not
  // the array identity of each refresh.
  return useMemo(() => withVisibleTabs(navId, tabs, key ? key.split(",") : []), [navId, tabs, key]);
}

// filterNavGroups drops hidden nav items (and any group left with zero
// items) from NAV_GROUPS. Identity when nothing is hidden on this machine,
// the common case, so this never allocates on a solo node.
export function filterNavGroups(
  groups: NavGroup[],
  gov: Governance | null | undefined,
): NavGroup[] {
  const ids = hiddenNavIds(gov);
  if (ids.length === 0) return groups;
  const hidden = new Set(ids);
  return groups
    .map((g) => ({ ...g, items: g.items.filter((it) => !hidden.has(it.id)) }))
    .filter((g) => g.items.length > 0);
}

export function isSectionHidden(
  gov: Governance | null | undefined,
  id: string,
): boolean {
  return hiddenNavIds(gov).includes(id);
}

export function isSectionReadOnly(
  gov: Governance | null | undefined,
  id: string,
): boolean {
  return readOnlyNavIds(gov).includes(id);
}

export function isSettingsHidden(
  gov: Governance | null | undefined,
  id: string,
): boolean {
  return hiddenSettingsIds(gov).includes(id);
}

export function isSettingsReadOnly(
  gov: Governance | null | undefined,
  id: string,
): boolean {
  return readOnlySettingsIds(gov).includes(id);
}

// governedOrgLabel is the best available name for the governing
// organization, falling back through notice.org_display_name →
// org_name → a generic label so copy never renders an empty string, and
// never renders an org id (orgDisplayLabel skips id-shaped values).
export function governedOrgLabel(gov: Governance | null | undefined): string {
  return orgDisplayLabel(gov?.notice?.org_display_name, gov?.org_name);
}

// isManaged reports whether this machine enrolled under Enterprise-Managed
// Tenancy. It is the single predicate the transparency banner (T8) reads;
// false for every individual / BYO node, which is the default.
export function isManaged(gov: Governance | null | undefined): boolean {
  return !!gov?.managed;
}
