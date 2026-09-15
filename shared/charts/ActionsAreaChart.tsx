import { useMemo } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartTooltip } from "./ChartTooltip";
import { ChartLegend } from "./ChartLegend";
import { fmtCompact } from "../lib/format";
import type { ActionsPoint } from "../lib/types";
import { toolMeta } from "../lib/tools";
import { CHART_AXIS, CHART_GRID } from "./common";

// Stacked-area chart of action counts by tool over time. Tool order
// is derived from total volume in the window so the densest tool sits
// at the bottom of the stack (most visually stable).
export function ActionsAreaChart({ data }: { data: ActionsPoint[] }) {
  const { rows, toolKeys } = useMemo(() => flattenByTool(data), [data]);

  return (
    <ResponsiveContainer width="100%" height={250}>
      <AreaChart data={rows} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <Legend
          verticalAlign="top"
          align="left"
          height={28}
          content={<ChartLegend />}
        />
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
        <XAxis dataKey="bucket" {...CHART_AXIS} tickFormatter={shortDate} />
        <YAxis {...CHART_AXIS} tickFormatter={fmtCompact} />
        <Tooltip
          content={
            <ChartTooltip
              labelKey="bucket"
              labelFormatter={shortDate}
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
  );
}

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
    for (const tool of toolKeys) row[tool] = p.by_tool?.[tool] ?? 0;
    return row;
  });
  return { rows, toolKeys };
}

function shortDate(s: string): string {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}
