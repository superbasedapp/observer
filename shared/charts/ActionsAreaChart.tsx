import { memo, useMemo } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartTooltip } from "./ChartTooltip";
import { ChartLegendFrame } from "./ChartLegend";
import { fmtCompact } from "../lib/format";
import type { Granularity } from "../lib/granularity";
import type { ActionsPoint } from "../lib/types";
import { toolMeta } from "../lib/tools";
import { bucketTooltipLabel, CHART_AXIS, CHART_GRID, timeAxis } from "./common";
import { useChartMotion } from "./useChartMotion";

// Stacked-area chart of action counts by tool over time. Tool order
// is derived from total volume in the window so the densest tool sits
// at the bottom of the stack (most visually stable).
export const ActionsAreaChart = memo(function ActionsAreaChart({
  data,
  granularity = "1d",
}: {
  data: ActionsPoint[];
  /** Bucket granularity the rows were served at (the response `bucket`); drives the axis/tooltip labels. */
  granularity?: Granularity;
}) {
  const { rows, toolKeys } = useMemo(() => flattenByTool(data), [data]);
  // The legend lists every tool in the window, so it wraps onto several rows
  // on a busy install or a phone; it renders in normal flow above the plot
  // (ChartLegendFrame) so the plot always starts below its last row.
  const legend = useMemo(
    () =>
      toolKeys.map((tool) => ({
        id: tool,
        value: toolMeta(tool).label,
        color: toolMeta(tool).colorVar,
      })),
    [toolKeys],
  );

  const motion = useChartMotion(rows, "bucket");
  return (
    <ChartLegendFrame height={250} items={legend}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={rows} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
          <defs>
            {toolKeys.map((tool) => (
              <linearGradient
                key={tool}
                id={`actions-grad-${slugify(tool)}`}
                x1="0"
                y1="0"
                x2="0"
                y2="1"
              >
                <stop
                  offset="0%"
                  stopColor={toolMeta(tool).colorVar}
                  stopOpacity="0.6"
                />
                <stop
                  offset="100%"
                  stopColor={toolMeta(tool).colorVar}
                  stopOpacity="0.05"
                />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid {...CHART_GRID} />
          <XAxis {...CHART_AXIS} {...timeAxis(rows, granularity)} />
          <YAxis {...CHART_AXIS} tickFormatter={fmtCompact} />
          <Tooltip
            content={
              <ChartTooltip
                labelKey="bucket"
                labelFormatter={bucketTooltipLabel(granularity)}
                formatItem={(name, value) => `${name}: ${fmtCompact(value)}`}
                extra={(row) =>
                  row.total != null
                    ? `${fmtCompact(Number(row.total))} total`
                    : null
                }
              />
            }
            cursor={{ stroke: "var(--line-3)" }}
          />
          {toolKeys.map((tool) => (
            <Area
              {...motion}
              key={tool}
              type="monotone"
              dataKey={tool}
              name={toolMeta(tool).label}
              stroke={toolMeta(tool).colorVar}
              fill={`url(#actions-grad-${slugify(tool)})`}
              strokeWidth={1.4}
              stackId="1"
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </ChartLegendFrame>
  );
});

// slugify — converts tool keys like "claude-code" / "antigravity" into
// safe SVG <linearGradient id="..."> values (no slashes / spaces).
function slugify(s: string): string {
  return s.replace(/[^a-zA-Z0-9]+/g, "-").toLowerCase();
}

function flattenByTool(data: ActionsPoint[]) {
  const totals: Record<string, number> = {};
  for (const p of data) {
    for (const [tool, n] of Object.entries(p.by_tool || {})) {
      totals[tool] = (totals[tool] ?? 0) + n;
    }
  }
  // Stacking from bottom: densest tool first (most visually stable).
  const toolKeys = Object.keys(totals).sort((a, b) => totals[b] - totals[a]);
  const rows = data.map((p) => {
    const row: Record<string, number | string> = {
      bucket: p.bucket,
      total: p.total,
    };
    if (p.t != null) row.t = p.t;
    for (const tool of toolKeys) row[tool] = p.by_tool?.[tool] ?? 0;
    return row;
  });
  return { rows, toolKeys };
}
