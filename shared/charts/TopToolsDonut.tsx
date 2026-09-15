import { useId, useMemo } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { fmtCompact, fmtPct } from "../lib/format";
import { toolMeta } from "../lib/tools";
import type { ToolsResponse } from "../lib/types";

// TopToolsDonut — replaces the per-tool vertical bar list with the
// design's donut + side legend layout. Center text shows total
// actions; legend on the right shows per-tool count + success rate
// + a tiny share bar.
export function TopToolsDonut({
  tools,
}: {
  tools: ToolsResponse["tools"];
}) {
  const id = useId();
  const top = useMemo(() => tools.slice(0, 8), [tools]);
  const total = useMemo(
    () => top.reduce((a, t) => a + t.action_count, 0),
    [top],
  );
  // Recharts needs each datum to have a name + value; merge into a
  // single shape and read color off toolMeta.
  const data = useMemo(
    () =>
      top.map((t) => ({
        tool: t.tool,
        name: toolMeta(t.tool).label,
        value: t.action_count,
        success_rate: t.success_rate,
        color: toolMeta(t.tool).colorVar,
      })),
    [top],
  );

  if (!total) {
    return (
      <div className="grid h-[220px] place-items-center text-[12px] text-fg-3">
        No tools active in window.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-[180px_1fr] items-center gap-4">
      <div className="relative h-[180px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius="65%"
              outerRadius="92%"
              paddingAngle={1.5}
              stroke="var(--bg-1)"
              strokeWidth={2}
              isAnimationActive={false}
            >
              {data.map((d, i) => (
                <Cell key={`${id}-${i}`} fill={d.color} />
              ))}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (!active || !payload?.length) return null;
                const p = payload[0].payload as (typeof data)[number];
                return (
                  <div className="rounded-2 border border-line-3 bg-bg-3/95 px-3 py-2 text-[11px] shadow-2 backdrop-blur">
                    <div className="font-mono text-fg-1">{p.name}</div>
                    <div className="mt-0.5 text-fg-3">
                      {fmtCompact(p.value)} actions ·{" "}
                      {fmtPct(p.value / total)} of total ·{" "}
                      <span
                        className={
                          p.success_rate < 0.95
                            ? "text-warn"
                            : "text-fg-2"
                        }
                      >
                        {fmtPct(p.success_rate)}
                      </span>
                    </div>
                  </div>
                );
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 grid place-items-center">
          <div className="text-center">
            <div className="text-[20px] font-semibold leading-none tracking-tight text-fg-0">
              {fmtCompact(total)}
            </div>
            <div className="mt-1 text-[10px] uppercase tracking-[0.06em] text-fg-3">
              actions
            </div>
          </div>
        </div>
      </div>
      <ul className="space-y-1">
        {data.map((d) => {
          const share = d.value / total;
          return (
            <li
              key={d.tool}
              className="grid grid-cols-[8px_1fr_auto] items-baseline gap-2 text-[11.5px]"
            >
              <span
                className="block h-2 w-2 self-center rounded-pill"
                style={{ background: d.color }}
              />
              <div className="min-w-0">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="truncate text-fg-1">{d.name}</span>
                  <span className="shrink-0 tabular-nums text-fg-3">
                    {fmtCompact(d.value)} ·{" "}
                    <span
                      className={
                        d.success_rate < 0.95
                          ? "text-warn"
                          : "text-fg-2"
                      }
                    >
                      {fmtPct(d.success_rate)}
                    </span>
                  </span>
                </div>
                <div className="mt-0.5 h-1 w-full overflow-hidden rounded-pill bg-bg-3">
                  <span
                    className="block h-full"
                    style={{
                      width: `${share * 100}%`,
                      background: d.color,
                      opacity: 0.7,
                    }}
                  />
                </div>
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
