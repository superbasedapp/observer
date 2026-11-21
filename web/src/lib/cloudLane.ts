// cloudLane: the display rules of the Projects detail "Where it ran" lane
// (cloud-agents lane CA-B5), kept out of the component so they are tested as
// data. The wire is GET /api/project/<id>/cloud (internal/cloudlane on the
// daemon). A missing figure is never shown as zero: each label below says
// "not reported" instead, and the coverage badge says how complete a shown
// figure is.

import type { CloudLaneBucket, CloudLaneCoverage, CloudLaneLedgerFigure, CloudLaneResponse, ProjectSpendLocations } from "./types";

/** laneShown: the lane renders only when something on the project ran off
 * this machine, a synthetic cloud project folds in, the project itself is
 * folded, or a cloud connector is linked. A node that never touched a cloud
 * agent sees the page exactly as before. */
export function laneShown(d: CloudLaneResponse | null | undefined): boolean {
  if (!d) return false;
  return (
    d.off_machine_sessions > 0 ||
    d.projects.length > 1 ||
    d.folded_into != null ||
    (d.accounts?.length ?? 0) > 0
  );
}

/** A coverage badge's label and detail for one figure. */
export type CoverageLabel = { status: CloudLaneCoverage; label: string; detail: string };

// TOKEN_COVERAGE / COST_COVERAGE: one row per coverage state (CLAUDE.md #5).
const TOKEN_COVERAGE: Record<CloudLaneCoverage, (b: CloudLaneBucket) => Omit<CoverageLabel, "status">> = {
  full: () => ({ label: "Reported", detail: "Every session here reported its tokens." }),
  partial: (b) => ({
    label: `${b.sessions_with_tokens} of ${b.sessions} sessions`,
    detail: `Only ${b.sessions_with_tokens} of ${b.sessions} sessions reported tokens. The total covers those sessions only; the rest are unknown, not zero.`,
  }),
  none: () => ({ label: "Not reported", detail: "No session here reported tokens." }),
  unknown: () => ({
    label: "Not reported",
    detail: "No session here reported tokens. The figure is unknown, not zero: the capture rail for these sessions carries no token counts.",
  }),
};

const COST_COVERAGE: Record<CloudLaneCoverage, (b: CloudLaneBucket) => Omit<CoverageLabel, "status">> = {
  full: () => ({ label: "Priced", detail: "Every turn here was priced." }),
  // Partial has two causes, both floors: unpriced turns (unknown model) and
  // sessions that reported no turns at all. Unpriced turns are named first.
  partial: (b) =>
    (b.unpriced_turns ?? 0) > 0
      ? {
          label: `${b.unpriced_turns} unpriced`,
          detail: `${b.unpriced_turns} of ${b.turns} turns have no price (unknown model), so the dollar figure is a floor.`,
        }
      : {
          label: `${b.sessions_with_turns} of ${b.sessions} sessions`,
          detail: `Only ${b.sessions_with_turns} of ${b.sessions} sessions reported turns. The figure covers those sessions only; the rest are unknown, not zero.`,
        },
  none: () => ({ label: "Not priced", detail: "No turn here could be priced." }),
  unknown: (b) =>
    b.turns > 0
      ? { label: "Not priced", detail: "No turn here could be priced (unknown model). The figure is unknown, not zero." }
      : { label: "Not reported", detail: "No turns were reported for these sessions. The figure is unknown, not zero." },
};

export function tokenCoverageLabel(b: CloudLaneBucket): CoverageLabel {
  return { status: b.token_coverage, ...TOKEN_COVERAGE[b.token_coverage](b) };
}

export function costCoverageLabel(b: CloudLaneBucket): CoverageLabel {
  return { status: b.cost_coverage, ...COST_COVERAGE[b.cost_coverage](b) };
}

/** ledgerCoverageLabel: how many of the bucket's sessions the provider figure covers. */
export function ledgerCoverageLabel(f: CloudLaneLedgerFigure, b: CloudLaneBucket): CoverageLabel {
  if (f.coverage === "full") return { status: "full", label: "All sessions", detail: "The provider reported this figure for every session here." };
  return {
    status: f.coverage,
    label: `${f.sessions} of ${b.sessions} sessions`,
    detail: `The provider reported this figure for ${f.sessions} of ${b.sessions} sessions here; the others are unknown, not zero.`,
  };
}

// MEASUREMENT_SOURCE_LABEL / ROLLUP_LABEL / MONETARY_LABEL: plain words for
// the ledger's closed vocabularies (internal/models cloudusage.go). An
// unlisted token renders verbatim rather than being guessed at.
const MEASUREMENT_SOURCE_LABEL: Record<string, string> = {
  exporter: "telemetry exporter",
  provider_run_total: "provider run total",
  org_report: "organization report",
  invoice: "invoice",
};

const ROLLUP_LABEL: Record<string, string> = {
  sum: "summed",
  latest_per_session: "latest per session",
  latest: "latest reading",
};

const MONETARY_LABEL: Record<string, string> = {
  not_monetary: "",
  reported_charge: "charged",
  estimated_charge: "estimated charge",
  quota_allocation: "quota",
  api_equivalent: "API-equivalent",
};

/** ledgerProvenance: one line naming where a provider figure came from. */
export function ledgerProvenance(f: CloudLaneLedgerFigure): string {
  return [
    f.connector,
    MEASUREMENT_SOURCE_LABEL[f.measurement_source] ?? f.measurement_source,
    ROLLUP_LABEL[f.rollup] ?? f.rollup,
    MONETARY_LABEL[f.monetary_status] ?? f.monetary_status,
  ]
    .filter(Boolean)
    .join(" · ");
}

/** ledgerValue: the figure in its OWN unit. Never converted, never summed with another unit. */
export function ledgerValue(f: CloudLaneLedgerFigure): string {
  const v = Number.isInteger(f.value) ? f.value.toLocaleString("en-US") : f.value.toLocaleString("en-US", { maximumFractionDigits: 2 });
  return `${v} ${f.unit}`;
}

// PROVENANCE_LABEL: the token capture path each turn came through.
const PROVENANCE_LABEL: Record<string, string> = {
  proxy: "proxy",
  jsonl: "transcript",
  unknown: "unknown path",
};

/** tokenProvenance: "via proxy 3, transcript 2", or "" when no turn reported. */
export function tokenProvenance(b: CloudLaneBucket): string {
  const parts = (b.provenance ?? []).map((p) => `${PROVENANCE_LABEL[p.source] ?? p.source} ${p.turns}`);
  return parts.length ? `via ${parts.join(", ")}` : "";
}

// ACCOUNT_COVERAGE: the connector coverage states of the cloud-agents plan
// (section 8). The vocabulary is owned by the connector lane; a token not
// listed renders with its underscores spaced out rather than being dropped.
const ACCOUNT_COVERAGE: Record<string, { label: string; status: CloudLaneCoverage }> = {
  verified: { label: "Verified", status: "full" },
  available_to_configure: { label: "Available to configure", status: "unknown" },
  permission_required: { label: "Permission required", status: "none" },
  partial_history: { label: "Partial history", status: "partial" },
  delayed_reporting: { label: "Delayed reporting", status: "partial" },
  not_established: { label: "Not established", status: "unknown" },
  disconnected: { label: "Disconnected", status: "none" },
};

export function accountCoverage(state: string | undefined): { label: string; status: CloudLaneCoverage } {
  if (!state) return { label: "Not assessed", status: "unknown" };
  const row = ACCOUNT_COVERAGE[state];
  if (row) return row;
  const spaced = state.replace(/_/g, " ");
  return { label: spaced.charAt(0).toUpperCase() + spaced.slice(1), status: "unknown" };
}

// ---------- Projects list: grouping a synthetic cloud project ----------

/** The slice of a /api/projects row the grouping reads. */
export type TwinRow = { id: number; cloud_twin_of?: number };

/**
 * groupCloudTwins puts each synthetic cloud project ("cloud:<remote>") right
 * after the local project it now groups under (the daemon's
 * store.CloudProjectTwins rule, carried as cloud_twin_of). A twin whose local
 * project is not in the list (filtered out) keeps its own place. Everything
 * else keeps the server's order. Pure: returns a new array.
 */
export function groupCloudTwins<T extends TwinRow>(rows: readonly T[]): T[] {
  const present = new Set(rows.map((r) => r.id));
  const twinsOf = new Map<number, T[]>();
  for (const r of rows) {
    if (r.cloud_twin_of != null && present.has(r.cloud_twin_of)) {
      const list = twinsOf.get(r.cloud_twin_of) ?? [];
      list.push(r);
      twinsOf.set(r.cloud_twin_of, list);
    }
  }
  const out: T[] = [];
  for (const r of rows) {
    if (r.cloud_twin_of != null && present.has(r.cloud_twin_of)) continue;
    out.push(r);
    for (const t of twinsOf.get(r.id) ?? []) out.push(t);
  }
  return out;
}

/** offMachineSessions: a project's all-time sessions that ran in a vendor cloud or on a worker. */
export function offMachineSessions(mix: Partial<Record<string, number>> | undefined): number {
  if (!mix) return 0;
  return (mix.vendor_cloud ?? 0) + (mix.customer_worker ?? 0);
}

// ---------- Spend split: the folded total by where it ran (lane CA-C1) ----------

/** One location's share of a folded Spend total. */
export type SpendSplitPart = {
  location: CloudLaneBucket["location"];
  /** Dollars, absent when nothing in the bucket was priced (never 0). */
  cost_usd?: number;
  /** Tokens, absent when nothing in the bucket reported them (never 0). */
  tokens?: number;
  /** How complete the dollar figure is, with the lane's own wording. */
  cost: CoverageLabel;
};

/** A provider usage figure in its own unit, tagged with where it ran. */
export type SpendSplitUsage = { location: CloudLaneBucket["location"]; figure: CloudLaneLedgerFigure };

export type SpendSplit = {
  parts: SpendSplitPart[];
  /** Native-unit figures (ACUs, credits, premium requests): never converted, never in the dollar total. */
  usage: SpendSplitUsage[];
  /** True when any location's dollars are a floor or missing: the total is partial. */
  partial: boolean;
  /** The folded "cloud:<remote>" projects the total includes. */
  folded: string[];
  superseded_turns: number;
};

/**
 * spendSplit turns the detail payload's spend.locations into the Overview
 * Spend tile's and the Spend tab's split (decision CA-D21). The buckets were
 * built from the same rows as total_usd, so their dollars add up to it. A
 * location whose dollars are missing or partial marks the whole total
 * partial: the tile then says so instead of passing a floor off as complete.
 * Null when the payload carries no split (a project that only ran here).
 */
export function spendSplit(loc: ProjectSpendLocations | null | undefined): SpendSplit | null {
  if (!loc || loc.buckets.length === 0) return null;
  const parts: SpendSplitPart[] = [];
  const usage: SpendSplitUsage[] = [];
  let partial = false;
  for (const b of loc.buckets) {
    parts.push({ location: b.location, cost_usd: b.cost_usd ?? undefined, tokens: b.tokens?.total, cost: costCoverageLabel(b) });
    if (b.cost_coverage !== "full") partial = true;
    for (const f of b.ledger ?? []) usage.push({ location: b.location, figure: f });
  }
  return {
    parts,
    usage,
    partial,
    folded: (loc.folded ?? []).map((p) => p.root_path),
    superseded_turns: loc.superseded_turns ?? 0,
  };
}

/**
 * laneSplit is spendSplit over a GET /api/project/<id>/cloud payload: the
 * same folded rows as the detail's spend.locations, for the Spend tab, which
 * already reads the lane. Null when the lane would not render.
 */
export function laneSplit(d: CloudLaneResponse | null | undefined): SpendSplit | null {
  if (!d || !laneShown(d)) return null;
  const own = d.projects[0]?.id;
  return spendSplit({
    buckets: d.buckets,
    folded: d.projects.filter((p) => p.synthetic && p.id !== own),
    superseded_turns: d.superseded_turns,
    ledger_truncated: d.ledger_truncated,
  });
}
