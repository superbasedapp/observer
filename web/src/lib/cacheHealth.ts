// cacheHealth: the Cache page's one engine-health alarm rule. Pure, so the
// node test runner covers it.

/** The fields of /api/cache/health the alarm rule reads. */
export type GradingGate = {
  graded_events: number;
  min_events_threshold: number;
  gate_passed: boolean;
};

/**
 * gradingGateFailed is the one alarm condition, read straight off the
 * server's verdict (gate_passed uses the same thresholds as
 * `observer cache-health`): enough graded events AND the gate failed.
 * Below the grading minimum there is nothing to judge yet, so nothing
 * alarms. The engine's labelling diagnostics (inconsistent rewrites,
 * bucket mismatches, a dominant cause) never alarm on their own: they grow
 * with history on every install.
 */
export function gradingGateFailed(health: GradingGate | null | undefined): boolean {
  if (!health) return false;
  return health.graded_events >= health.min_events_threshold && !health.gate_passed;
}

// ---------------------------------------------------------------------------
// The Full report (lane L5 B-R1): GET /api/cache/health?full=1, the
// per-session and per-event detail `observer cache-health` prints, with the
// command's four thresholds as inputs.

/** CacheHealthInputs are the four thresholds as the form holds them:
 *  rates and shares as percentages, the way the page shows them. */
export type CacheHealthInputs = {
  minEvents: number;
  maxRatePct: number;
  maxRewriteReadRatio: number;
  maxCauseSharePct: number;
};

/** The command's defaults (the P0 gate: 200 events, 5%; 3x; 80%). */
export const CACHE_HEALTH_DEFAULTS: CacheHealthInputs = {
  minEvents: 200,
  maxRatePct: 5,
  maxRewriteReadRatio: 3,
  maxCauseSharePct: 80,
};

type InputRule = {
  key: keyof CacheHealthInputs;
  label: string;
  lo: number;
  hi: number;
  integer?: boolean;
};

// One row per input: the same ranges the server clamps to
// (internal/intelligence/dashboard/cache_healthfull.go), so the form
// refuses what the server would silently clamp.
const INPUT_RULES: InputRule[] = [
  { key: "minEvents", label: "Minimum graded events", lo: 1, hi: 1_000_000, integer: true },
  { key: "maxRatePct", label: "Maximum mispredict rate", lo: 0, hi: 100 },
  { key: "maxRewriteReadRatio", label: "Rewrite read:write ratio", lo: 0.1, hi: 1000 },
  { key: "maxCauseSharePct", label: "Dominant cause share", lo: 0, hi: 100 },
];

/** cacheHealthInputErrors lists what is wrong with the inputs, one line
 *  per bad field, empty when the report can load. */
export function cacheHealthInputErrors(v: CacheHealthInputs): string[] {
  const out: string[] = [];
  for (const r of INPUT_RULES) {
    const n = v[r.key];
    if (!Number.isFinite(n) || n < r.lo || n > r.hi || (r.integer && !Number.isInteger(n))) {
      out.push(`${r.label}: use ${r.integer ? "a whole number " : ""}from ${r.lo} to ${r.hi}.`);
    }
  }
  return out;
}

/** cacheHealthFullParams is the query for the Full report: full=1 plus
 *  only the thresholds that differ from the command's defaults. */
export function cacheHealthFullParams(v: CacheHealthInputs): Record<string, string> {
  const p: Record<string, string> = { full: "1" };
  const d = CACHE_HEALTH_DEFAULTS;
  if (v.minEvents !== d.minEvents) p.min_events = String(v.minEvents);
  if (v.maxRatePct !== d.maxRatePct) p.max_rate = String(v.maxRatePct / 100);
  if (v.maxRewriteReadRatio !== d.maxRewriteReadRatio) p.max_rewrite_read_ratio = String(v.maxRewriteReadRatio);
  if (v.maxCauseSharePct !== d.maxCauseSharePct) p.max_cause_share = String(v.maxCauseSharePct / 100);
  return p;
}

/** CacheHealthFull mirrors the server's CacheHealthFull. */
export type CacheHealthFull = {
  per_session: { session_id: string; graded_events: number; mispredicts: number; mispredict_rate: number }[];
  per_session_total: number;
  cause_breakdown: { cause: string; count: number }[];
  mispredict_events: {
    session_id: string;
    timestamp: string;
    model: string;
    cause: string;
    predicted_kind: string;
    zero_usage?: boolean;
  }[];
  mispredict_events_total: number;
  inconsistent_rewrite_events: {
    session_id: string;
    timestamp: string;
    model: string;
    kind: string;
    cause: string;
    tokens_read: number;
    tokens_written: number;
    ratio: number;
  }[];
  inconsistent_rewrite_events_total: number;
  bucket_mispredicts_per_session: { session_id: string; bucket_mispredicts: number }[];
  max_rewrite_read_ratio_threshold: number;
  max_cause_share_threshold: number;
};

/** CacheHealthFullResponse is the summary fields the report reads, plus
 *  the full block. */
export type CacheHealthFullResponse = GradingGate & {
  mispredicts: number;
  mispredict_rate: number;
  max_rate_threshold: number;
  dominant_cause?: { cause: string; count: number; share: number };
  full?: CacheHealthFull;
};

/** cacheHealthVerdict is the report's one-line gate result, the way the
 *  command prints it: PASS, FAIL, or not enough events to judge. */
export function cacheHealthVerdict(r: CacheHealthFullResponse): { tone: "success" | "danger" | "neutral"; text: string } {
  const rate = `${(r.mispredict_rate * 100).toFixed(1)}%`;
  const limit = `${(r.max_rate_threshold * 100).toFixed(1)}%`;
  if (r.graded_events < r.min_events_threshold) {
    return {
      tone: "neutral",
      text: `Not enough to judge: ${r.graded_events} graded events, the gate needs ${r.min_events_threshold}. Rate so far ${rate}.`,
    };
  }
  if (r.gate_passed) {
    return { tone: "success", text: `Gate passes: ${r.mispredicts} mispredicts in ${r.graded_events} graded events (${rate}, limit ${limit}).` };
  }
  return { tone: "danger", text: `Gate fails: ${r.mispredicts} mispredicts in ${r.graded_events} graded events (${rate}, limit ${limit}).` };
}
