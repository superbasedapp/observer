import { BookCopy, Hourglass, List, ListTree, Play, Spline, Timer, TriangleAlert, UsersRound, type LucideIcon } from "lucide-react";

// APPS_METRIC_ICONS: the node's "Your AI apps" KPI tiles whose metric is not
// in the shared METRIC_ICONS table (traces, spans, duration, error rate,
// latency, end users, eval datasets / runs / items). The org dashboard
// already draws the same metrics from web2/src/lib/orgMetricIcons.ts; a
// glyph here is the org's glyph for the same key (pinned by
// appsMetricIcons.test.ts), so a tile looks the same on both dashboards.
// Rules as for the org table: a key never shadows a METRIC_ICONS key, and
// two different metrics never share a glyph.
//
// Both apps now draw these metrics, so they belong in the shared table: when
// they move there, this file becomes a re-export and the pages keep working.
export const APPS_METRIC_ICONS = {
  traces: Spline,
  spans: ListTree,
  duration: Hourglass,
  errorRate: TriangleAlert,
  latency: Timer,
  endUsers: UsersRound,
  runs: Play,
  items: List,
  datasets: BookCopy,
} as const satisfies Record<string, LucideIcon>;

/** AppsMetricKey names one AI apps KPI metric in {@link APPS_METRIC_ICONS}. */
export type AppsMetricKey = keyof typeof APPS_METRIC_ICONS;
