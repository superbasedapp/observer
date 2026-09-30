import { Icon } from "./Icon";
import { metricIcon, type MetricKey } from "../lib/metricIcons";

/**
 * MetricIcon renders a KPI metric's glyph from the one METRIC_ICONS table
 * (shared/lib/metricIcons.ts), sized for the StatCard / HeroStat / BigStat
 * `icon` slot. Pass it as `icon={<MetricIcon metric="sessions" />}`; a page
 * never picks the glyph itself.
 */
export function MetricIcon({ metric }: { metric: MetricKey }) {
  return <Icon icon={metricIcon(metric)} size="sm" />;
}
