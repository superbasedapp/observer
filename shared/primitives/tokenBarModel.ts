// tokenBarModel - the pure half of <TokenBar>: the four token buckets in
// their one fixed order with their labels and --tok-* colours, and the
// segment arithmetic. Decision logic as data (CLAUDE.md #5). Pure, no React
// and no DOM, so web/src/lib/tokenBar.test.ts runs it under plain node.
//
// Honesty rules (unknown means unknown):
//   - a null / undefined / non-finite / negative bucket is UNKNOWN: it gets no
//     segment and no row, never a zero;
//   - a known zero is a fact: it gets a row (0 tokens) but no segment;
//   - when every bucket is unknown there is nothing to draw (`known` empty);
//   - when the known buckets sum to zero the track renders empty.

/** The four token buckets, keyed the way every token chart names them. */
export type TokenBucketKey = "netInput" | "cacheRead" | "cacheWrite" | "output";

/** One bucket's presentation row. */
export type TokenBucketMeta = {
  key: TokenBucketKey;
  label: string;
  /** CSS colour: the shared --tok-* token (shared/styles/tokens.css). */
  color: string;
};

// TOKEN_BUCKETS - the fixed order and colours, matching ModelsUsedPanel and
// TokensByDayChart (net input, cache read, cache write, output).
export const TOKEN_BUCKETS: readonly TokenBucketMeta[] = [
  { key: "netInput", label: "Net input", color: "var(--tok-net)" },
  { key: "cacheRead", label: "Cache read", color: "var(--tok-read)" },
  { key: "cacheWrite", label: "Cache write", color: "var(--tok-write)" },
  { key: "output", label: "Output", color: "var(--tok-out)" },
];

/** The counts a TokenBar draws; a missing / null bucket is unknown. */
export type TokenBuckets = Partial<Record<TokenBucketKey, number | null>>;

/** One known bucket: its count and its share of the known total (0..1). */
export type TokenBarRow = TokenBucketMeta & { value: number; share: number };

export type TokenBarModel = {
  /** Every KNOWN bucket, in TOKEN_BUCKETS order (zeros included). */
  known: TokenBarRow[];
  /** The known buckets with a positive count: the drawn segments. */
  segments: TokenBarRow[];
  /** Sum of the known buckets. */
  total: number;
};

function knownCount(v: number | null | undefined): number | null {
  return v != null && Number.isFinite(v) && v >= 0 ? v : null;
}

/** tokenBarModel folds four bucket counts into rows and drawn segments. */
export function tokenBarModel(b: TokenBuckets): TokenBarModel {
  const vals: { meta: TokenBucketMeta; value: number }[] = [];
  for (const meta of TOKEN_BUCKETS) {
    const v = knownCount(b[meta.key]);
    if (v != null) vals.push({ meta, value: v });
  }
  const total = vals.reduce((s, x) => s + x.value, 0);
  const known = vals.map(({ meta, value }) => ({
    ...meta,
    value,
    share: total > 0 ? value / total : 0,
  }));
  return { known, segments: known.filter((r) => r.value > 0), total };
}

/** tokenShareText renders a share as a whole percentage, "<1%" for a sliver. */
export function tokenShareText(share: number): string {
  if (!Number.isFinite(share) || share <= 0) return "0%";
  const pct = share * 100;
  return pct < 1 ? "<1%" : `${Math.round(pct)}%`;
}
