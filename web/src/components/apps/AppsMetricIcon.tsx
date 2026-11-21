import { Icon } from "@/components/primitives";
import { APPS_METRIC_ICONS, type AppsMetricKey } from "@/lib/appsMetricIcons";

/**
 * AppsMetricIcon renders an AI apps KPI glyph from APPS_METRIC_ICONS, sized
 * for the StatCard / HeroStat `icon` slot (the twin of the shared
 * <MetricIcon>, which stays the choice for spend, tokens and sessions). A
 * page never picks a glyph itself.
 */
export function AppsMetricIcon({ metric }: { metric: AppsMetricKey }) {
  return <Icon icon={APPS_METRIC_ICONS[metric]} size="sm" />;
}
