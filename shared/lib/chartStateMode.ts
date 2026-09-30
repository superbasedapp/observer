// chartStateMode: the ONE precedence of the shared ChartState's slot states,
// as an ordered rule table walked top-down (pinned row by row in
// web2/src/lib/chartStateMode.test.ts). Pure (no React) so a test can load it.
//
// Order: an RBAC denial (HTTP 403) wins over everything - it is a distinct
// state, not an error, and retrying or waiting cannot change it. Below it the
// pre-existing ladder is kept exactly (loading, then error, then empty), so a
// caller that never passes `denied` renders byte-for-byte what it did before.

/** Which state a chart slot renders. */
export type ChartStateMode = "denied" | "loading" | "error" | "empty" | "content";

/** The inputs ChartState decides on (its own props). */
export interface ChartStateInput {
  denied?: boolean;
  loading: boolean;
  error: unknown;
  empty: boolean;
}

/** CHART_STATE_RULES: ordered, first match wins; no match renders content. */
export const CHART_STATE_RULES: ReadonlyArray<{
  mode: Exclude<ChartStateMode, "content">;
  when: (s: ChartStateInput) => boolean;
}> = [
  { mode: "denied", when: (s) => s.denied === true },
  { mode: "loading", when: (s) => s.loading },
  { mode: "error", when: (s) => Boolean(s.error) },
  { mode: "empty", when: (s) => s.empty },
];

/** chartStateMode walks CHART_STATE_RULES top-down. */
export function chartStateMode(s: ChartStateInput): ChartStateMode {
  return CHART_STATE_RULES.find((r) => r.when(s))?.mode ?? "content";
}

/** How a denial is drawn inside a slot of a given height. */
export type ChartDenialLayout = "illustrated" | "compact";

/** CHART_DENIAL_LAYOUT: ordered by minHeight, first match wins. A slot tall
 *  enough to hold the locked illustration plus two lines of copy gets the
 *  shared PermissionDenied; a shorter one gets a one-row lock + sentence. */
export const CHART_DENIAL_LAYOUT: ReadonlyArray<{ minHeight: number; layout: ChartDenialLayout }> = [
  { minHeight: 200, layout: "illustrated" },
  { minHeight: 0, layout: "compact" },
];

/** chartDenialLayout picks the denial layout for a slot height. */
export function chartDenialLayout(height: number): ChartDenialLayout {
  const h = Number.isFinite(height) ? height : 0;
  return CHART_DENIAL_LAYOUT.find((r) => h >= r.minHeight)?.layout ?? "compact";
}
