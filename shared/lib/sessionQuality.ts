// Session quality score (spec §15.2) - the pure wording + arithmetic behind
// the shared QualityPanel. The node drawer renders it over
// GET /api/session/<id>/quality; the org drawer renders the same panel over
// GET /api/org/sessions/<id>/quality (BL2-ORG), which carries the same shape
// minus `auto` (the org cannot see a node's scoring config). No imports on
// purpose: this file is unit-tested directly under `node --test`.
//
// Honesty rules:
//   - `scored: false` means the scorer never ran for this session. Nothing is
//     rendered as a number then - not scored is not zero.
//   - a component whose column is absent (a score written before the
//     breakdown was persisted) shows as "not recorded", never as 0.
//   - a score taken before newer activity says so.

export type SessionQualityWeightsLike = {
  redundancy: number;
  error: number;
  exploration: number;
  continuity: number;
};

export type SessionQualityLike = {
  session_id: string;
  scored: boolean;
  quality_score?: number;
  redundancy_ratio?: number;
  error_rate?: number;
  exploration_efficiency?: number;
  continuity_score?: number;
  onboarding_cost?: number;
  turns_to_first_edit?: number;
  retry_cost_tokens?: number;
  stale_reads_wasteful?: number;
  stale_reads_necessary?: number;
  redundancy_ratio_wasteful?: number;
  scored_at?: string;
  scored_action_count?: number;
  current_action_count: number;
  weights: SessionQualityWeightsLike;
  // The node's automatic-scoring posture. Absent on the org drawer, where the
  // scorer runs on the developer's machine and its config is not visible.
  auto?: { enabled: boolean; idle_minutes: number };
};

export type QualityTone = "success" | "warn" | "danger";

// Bands, walked top-down: the first row whose floor the score reaches wins.
const QUALITY_BANDS: { min: number; label: string; tone: QualityTone }[] = [
  { min: 0.8, label: "Strong", tone: "success" },
  { min: 0.6, label: "Fair", tone: "warn" },
  { min: Number.NEGATIVE_INFINITY, label: "Weak", tone: "danger" },
];

// qualityBand labels a 0-1 quality score.
export function qualityBand(score: number): { label: string; tone: QualityTone } {
  for (const b of QUALITY_BANDS) {
    if (score >= b.min) return { label: b.label, tone: b.tone };
  }
  return { label: "Weak", tone: "danger" };
}

export type QualityComponent = {
  key: keyof SessionQualityWeightsLike;
  label: string;
  // What the raw figure measures, for the row's secondary line.
  hint: string;
  weight: number;
  // goodness is the 0-1 term the formula multiplies by the weight (already
  // inverted for redundancy / errors). undefined = not recorded.
  goodness?: number;
  // points = weight * goodness, the component's share of the 0-1 score.
  points?: number;
};

// The four formula rows, in the spec's order. `invert` marks a raw figure
// where lower is better (the formula uses 1 - x).
const COMPONENT_ROWS: {
  key: keyof SessionQualityWeightsLike;
  field: keyof SessionQualityLike;
  label: string;
  hint: string;
  invert: boolean;
}[] = [
  { key: "redundancy", field: "redundancy_ratio", label: "Low redundancy", hint: "1 - stale re-reads per read or command", invert: true },
  { key: "error", field: "error_rate", label: "Tool success", hint: "1 - failed tool calls per call", invert: true },
  { key: "exploration", field: "exploration_efficiency", label: "Exploration efficiency", hint: "files edited / files touched", invert: false },
  { key: "continuity", field: "continuity_score", label: "Continuity", hint: "grows with session length (1 - e^(-actions/20))", invert: false },
];

// qualityComponents breaks a scored session into the four weighted terms.
export function qualityComponents(q: SessionQualityLike): QualityComponent[] {
  return COMPONENT_ROWS.map((row) => {
    const weight = q.weights[row.key];
    const raw = q[row.field];
    if (typeof raw !== "number" || !Number.isFinite(raw)) {
      return { key: row.key, label: row.label, hint: row.hint, weight };
    }
    const goodness = clamp01(row.invert ? 1 - raw : raw);
    return { key: row.key, label: row.label, hint: row.hint, weight, goodness, points: weight * goodness };
  });
}

// unscoredMessage is the empty-state sentence for a session with no score.
export function unscoredMessage(q: SessionQualityLike): string {
  if (q.current_action_count <= 0) {
    return "This session has no tool actions, so there is nothing to score.";
  }
  if (!q.auto) {
    return "Not scored yet. The developer's machine scores a session once it has gone idle; the score appears here after its next push.";
  }
  if (q.auto.enabled) {
    const m = q.auto.idle_minutes;
    return `Not scored yet. Sessions are scored automatically once they have been idle for ${m} minute${m === 1 ? "" : "s"}.`;
  }
  return "Not scored yet. Automatic scoring is off ([intelligence.scoring] auto = false); score it now or run `observer score`.";
}

// freshnessNote says when a stored score no longer covers the whole session,
// or predates the recorded breakdown. null = the score is current.
export function freshnessNote(q: SessionQualityLike): string | null {
  if (!q.scored) return null;
  if (q.scored_action_count == null) {
    return "Scored by an earlier version that did not record the full breakdown or the time it ran. Re-score to fill them in.";
  }
  const newer = q.current_action_count - q.scored_action_count;
  if (newer > 0) {
    const refresh = q.auto?.enabled ?" It refreshes automatically once the session goes idle." : "";
    return `Scored before ${newer} newer action${newer === 1 ? "" : "s"}.${refresh}`;
  }
  return null;
}

function clamp01(n: number): number {
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}
