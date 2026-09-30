import type { ReactNode } from "react";
import { ModelMark } from "../primitives/ModelMark";
import { modelSeriesColors } from "../lib/models";

// Model-keyed chart helpers shared by every chart whose series are model ids
// (TokensByModelChart, TrendByKeyChart in "model" mode). Pure: no fetch, no
// state. The collapsed-tail bucket is named OTHER_SERIES_KEY and is never a
// model id, so it keeps the neutral colour and no family mark.

/** The series key a chart uses for its collapsed "rest of the models" tail. */
export const OTHER_SERIES_KEY = "other";

const OTHER_COLOR = "var(--tool-other)";

/**
 * modelSeriesColorMap - series key -> CSS colour for model-keyed series:
 * each model takes its FAMILY colour (modelSeriesColors: extra models of one
 * family are shades of it), and the "other" tail stays neutral.
 */
export function modelSeriesColorMap(keys: ReadonlyArray<string>): Map<string, string> {
  const models = keys.filter((k) => k !== OTHER_SERIES_KEY);
  const colors = modelSeriesColors(models);
  const out = new Map<string, string>();
  models.forEach((k, i) => out.set(k, colors[i]));
  if (keys.includes(OTHER_SERIES_KEY)) out.set(OTHER_SERIES_KEY, OTHER_COLOR);
  return out;
}

/**
 * modelLegendLabel - ChartLegend `renderLabel` for model-keyed series: the
 * family mark before the model id. The "other" tail renders as plain text.
 */
export function modelLegendLabel(name: string): ReactNode {
  if (name === OTHER_SERIES_KEY) return name;
  return (
    <span className="inline-flex items-center gap-1">
      <ModelMark model={name} size={11} tooltip={false} />
      <span>{name}</span>
    </span>
  );
}
