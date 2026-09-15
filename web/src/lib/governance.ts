// Governance — the node's read of GET /api/governance, mirroring
// internal/govern.Effective (internal/govern/types.go). On an ordinary
// solo node the daemon returns {active: false, ...} with empty arrays,
// and every helper below is a no-op / identity function in that case —
// that property IS the solo-node guarantee: nothing in this file may
// change behavior unless a node has actually been enrolled and granted
// dashboard.visibility authority.
import { useApi, type ApiState } from "./useApi";
import type { NavGroup } from "./nav";

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
//   "you"        - the organisation published nothing for this key, or what
//                  it published is inert on this machine
//   "org"        - the organisation LOWERED this key below your setting
//   "both"       - the organisation pinned this key at the value you had set
//   "org_raised" - the organisation RAISED this key above your setting. Only
//                  reachable on a MANAGED machine (Enterprise-Managed
//                  Tenancy); on an individual / BYO machine the raise is
//                  structurally inert and the source stays "you".
export type GovernanceShareSource = "you" | "org" | "both" | "org_raised";

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
  notice: GovernanceNotice;
  authority?: string[];
  unknown_authority?: string[];
  dropped?: GovernanceDropped[];
  expires_at?: string;
  hash?: string;
  // share is the Phase-1b sharing block: one entry per [org_client.share]
  // key the organisation published a directive for.
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
};

// GovernancePricingSource is the three-value enum the Privacy page's pricing
// row renders.
//
//   "local"             - this machine's own table: the compiled defaults plus
//                         any [intelligence.pricing] override you set.
//   "org"               - your organisation's signed rates are applied, with
//                         any override you set still winning above them.
//   "org_authoritative" - a MANAGED machine holding enforce.budget: the
//                         organisation's rates sit ABOVE your own overrides,
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
  // warnings are organisation rows this machine REFUSED. An admin who typed a
  // rate and saw nothing change finds out here, on the machine where it did
  // not apply.
  warnings?: string[];
};

// shareSourceOf resolves one sharing key's Source column. Absent governance,
// an inactive grant, or a key the organisation published nothing for all
// resolve to "you" - never to a claim that the organisation touched it.
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
// say one deliberately did not, on the grounds that an organisation
// "structurally cannot" raise sharing - true on the individual plane, and
// false since Enterprise-Managed Tenancy shipped the managed raise. Omitting
// the string never prevented the raise; it only meant a raised row was
// labelled "You", crediting the developer with their employer's decision.
export const SHARE_SOURCE_LABEL: Record<
  GovernanceShareSource,
  (version: string) => string
> = {
  you: () => "You",
  org: (v) => `Your organisation${v} - reduced`,
  both: (v) => `You, locked by your organisation${v}`,
  org_raised: (v) => `Your organisation${v} - increased`,
};

// shareSourceLabel renders the column, naming the policy version whenever
// the organisation is a source.
//
// The lookup is defensive: a daemon newer than this bundle can answer with a
// source this table has never heard of, and an unlabelled row must degrade to
// "set by your organisation" - never to a TypeError that takes the whole
// Privacy page down with it.
export function shareSourceLabel(row: GovernanceShareKey | null): string {
  if (!row) return SHARE_SOURCE_LABEL.you("");
  const version = row.policy_version ? ` (policy v${row.policy_version})` : "";
  const label = SHARE_SOURCE_LABEL[row.source];
  if (!label) return `Your organisation${version}`;
  return label(version);
}

// useGovernance fetches the node's resolved governance posture once
// per mount (no polling — the posture only changes on daemon restart
// or a fresh policy pull, neither of which happens mid-session).
export function useGovernance(): ApiState<Governance> {
  return useApi<Governance>("/api/governance");
}

// filterNavGroups drops hidden nav items (and any group left with zero
// items) from NAV_GROUPS. Identity when gov is null/inactive or
// hidden_sections is empty — the common case, so this never allocates
// on a solo node.
export function filterNavGroups(
  groups: NavGroup[],
  gov: Governance | null | undefined,
): NavGroup[] {
  if (!gov?.active || gov.hidden_sections.length === 0) return groups;
  const hidden = new Set(gov.hidden_sections);
  return groups
    .map((g) => ({ ...g, items: g.items.filter((it) => !hidden.has(it.id)) }))
    .filter((g) => g.items.length > 0);
}

export function isSectionHidden(
  gov: Governance | null | undefined,
  id: string,
): boolean {
  return !!gov?.active && gov.hidden_sections.includes(id);
}

export function isSectionReadOnly(
  gov: Governance | null | undefined,
  id: string,
): boolean {
  return !!gov?.active && gov.read_only_sections.includes(id);
}

export function isSettingsHidden(
  gov: Governance | null | undefined,
  id: string,
): boolean {
  return !!gov?.active && gov.hidden_settings.includes(id);
}

export function isSettingsReadOnly(
  gov: Governance | null | undefined,
  id: string,
): boolean {
  return !!gov?.active && gov.read_only_settings.includes(id);
}

// governedOrgLabel is the best available name for the governing
// organization, falling back through notice.org_display_name →
// org_name → a generic label so copy never renders an empty string.
export function governedOrgLabel(gov: Governance | null | undefined): string {
  return gov?.notice?.org_display_name || gov?.org_name || "your organization";
}

// isManaged reports whether this machine enrolled under Enterprise-Managed
// Tenancy. It is the single predicate the transparency banner (T8) reads;
// false for every individual / BYO node, which is the default.
export function isManaged(gov: Governance | null | undefined): boolean {
  return !!gov?.managed;
}
