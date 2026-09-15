// Shared Recharts axis/grid styling so every chart in the app looks
// identical. Adjustments here propagate site-wide.

export const CHART_AXIS = {
  stroke: "var(--line-3)",
  tick: { fill: "var(--fg-3)", fontSize: 10 },
  tickLine: false,
  axisLine: false,
} as const;

export const CHART_GRID = {
  stroke: "var(--line-1)",
  vertical: false,
} as const;
