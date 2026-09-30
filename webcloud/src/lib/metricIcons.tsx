import {
  Award,
  CalendarCheck,
  CalendarClock,
  CalendarFold,
  Columns3,
  ListChecks,
  Target,
  type LucideIcon,
} from "lucide-react";
import { Icon } from "@shared/primitives/Icon";

// PORTAL_METRIC_ICONS: the portal's metric -> glyph table for KPI tiles whose
// metric does NOT exist in the ONE shared table `shared/lib/metricIcons.ts`
// (METRIC_ICONS). The rule is the dashboards' rule:
//
//   - A tile whose metric IS in METRIC_ICONS renders <MetricIcon metric=...>
//     (so "sessions" has one glyph on the node dashboard, the org dashboard
//     and the portal). A key here must never shadow a METRIC_ICONS key.
//   - A tile whose metric is portal-only renders <PortalMetricIcon metric=...>.
//   - A page never picks a glyph inline, and two metrics never share a glyph
//     (none of these glyphs is used in METRIC_ICONS; mind lucide aliases:
//     Layers3 IS Layers, the shared contextWindow glyph, so concurrency is
//     Columns3).
//
// Append keys; do not repurpose one.
export const PORTAL_METRIC_ICONS = {
  // Evidence coverage.
  activeDays: CalendarCheck,
  verificationCoverage: ListChecks,
  outcomeEvidence: Target,
  // Plan and enrichment allowances.
  plan: Award,
  dailyAllowance: CalendarClock,
  monthlyAllowance: CalendarFold,
  concurrency: Columns3,
} as const satisfies Record<string, LucideIcon>;

/** PortalMetricKey names one portal-only KPI metric. */
export type PortalMetricKey = keyof typeof PORTAL_METRIC_ICONS;

/**
 * PortalMetricIcon renders a portal-only KPI metric's glyph, sized for the
 * StatCard / HeroStat `icon` slot (the portal twin of the shared
 * <MetricIcon>).
 */
export function PortalMetricIcon({ metric }: { metric: PortalMetricKey }) {
  return <Icon icon={PORTAL_METRIC_ICONS[metric]} size="sm" />;
}
