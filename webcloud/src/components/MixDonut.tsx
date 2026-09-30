import { useId, useMemo, type ReactNode } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip as ChartHover } from "recharts";
import { ChartTooltip } from "@shared/charts/ChartTooltip";
import { EmptyState } from "@shared/primitives/EmptyState";
import { Icon } from "@shared/primitives/Icon";
import { ModelMark } from "@shared/primitives/ModelMark";
import { ToolGlyphFrame } from "@shared/primitives/ToolBadge";
import { chartMotion } from "@shared/lib/motion";
import { fmtCompact, fmtPct } from "@shared/lib/format";
import { modelSeriesColors } from "@shared/lib/models";
import { toolMeta } from "@shared/lib/tools";
import type { MixEntry } from "../api";
import { jobStateSlices } from "../lib/vocab";
import { RawIdHint } from "./RawIdHint";

// MixDonut is the portal's ONE small donut + legend (Overview's tool, model
// family and jobs-by-state mixes, Usage's jobs-by-state). None of the shared
// donuts fits the portal's {key,count} shape: TopToolsDonut needs a per-tool
// success rate and ActionBreakdownDonut is keyed on the action taxonomy. So
// this stays local, but there is exactly one copy, and every slice arrives
// already coloured by MEANING from one of the builders below (a tool's
// --tool-* colour, a model family's colour, a job state's tone), never by its
// rank in the chart.

/** MixSlice is one donut slice: the wire key, the human label, its count, its
 *  colour and an optional leading mark (a tool logo, a model mark, a state
 *  glyph). */
export type MixSlice = {
  key: string;
  label: string;
  count: number;
  color: string;
  mark?: ReactNode;
};

const TOP_N = 6;

/** byCount orders entries largest first (stable, so ties keep wire order). */
function byCount<T extends { count: number }>(entries: readonly T[]): T[] {
  return entries.slice().sort((a, b) => b.count - a.count);
}

/** toolMixSlices: a tool id's registry label, --tool-* colour and logo. An id
 *  the registry does not know keeps its raw id, the --tool-other colour and
 *  the monogram fallback (toolMeta / ToolGlyph), never a guessed tool. */
export function toolMixSlices(mix: readonly MixEntry[]): MixSlice[] {
  return mix.map((e) => {
    const meta = toolMeta(e.key);
    return {
      key: e.key,
      label: meta.label,
      count: e.count,
      color: meta.colorVar,
      mark: <ToolGlyphFrame tool={e.key} size={14} pip={false} />,
    };
  });
}

/** modelFamilySlices: each family takes its family colour (a second family
 *  of the same vendor a shade of it, modelSeriesColors); an unmatched family
 *  keeps the neutral colour and the plain dot mark. */
export function modelFamilySlices(mix: readonly MixEntry[]): MixSlice[] {
  const ordered = byCount(mix);
  const colors = modelSeriesColors(ordered.map((e) => e.key));
  return ordered.map((e, i) => ({
    key: e.key,
    label: e.key,
    count: e.count,
    color: colors[i],
    mark: <ModelMark model={e.key} size={12} tooltip={false} />,
  }));
}

/** jobMixSlices: enrichment-job states coloured by the shared JOB_STATUS
 *  tones (lib/vocab.ts jobStateSlices); an in-flight state's glyph spins. */
export function jobMixSlices(byState: Readonly<Record<string, number>>): MixSlice[] {
  return jobStateSlices(byState).map((s) => ({
    key: s.key,
    label: s.key,
    count: s.count,
    color: s.color,
    mark: (
      <Icon
        icon={s.icon}
        size="xs"
        className={s.spin ? "shrink-0 animate-spin text-fg-3" : "shrink-0 text-fg-3"}
      />
    ),
  }));
}

export function MixDonut({
  slices,
  totalLabel,
}: {
  slices: readonly MixSlice[];
  totalLabel: string;
}) {
  const id = useId();
  const top = useMemo(() => byCount(slices).slice(0, TOP_N), [slices]);
  const total = useMemo(() => top.reduce((a, e) => a + e.count, 0), [top]);
  // The chart gets plain data only (no React node in a recharts datum).
  const pieData = useMemo(() => top.map(({ mark: _mark, ...d }) => d), [top]);

  if (total === 0) {
    return (
      <div className="grid min-h-[160px] place-items-center">
        <EmptyState variant="inline" illustration="chart" illustrationSize={80} title="No data yet" />
      </div>
    );
  }

  return (
    <div className="grid grid-cols-[140px_1fr] items-center gap-4">
      <div className="relative h-[140px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={pieData}
              dataKey="count"
              nameKey="label"
              innerRadius="65%"
              outerRadius="92%"
              paddingAngle={1.5}
              stroke="var(--bg-2)"
              strokeWidth={2}
              {...chartMotion()}
            >
              {top.map((d, i) => (
                <Cell key={`${id}-${i}`} fill={d.color} />
              ))}
            </Pie>
            <ChartHover
              content={(props) => {
                // A pie's tooltip payload carries neither the slice colour
                // nor a category label, so both are restated from the slice
                // before the shared ChartTooltip draws it.
                const slice = props.payload?.[0]?.payload as Omit<MixSlice, "mark"> | undefined;
                if (!slice) return null;
                return (
                  <ChartTooltip
                    active={props.active}
                    label={slice.label}
                    payload={props.payload?.map((p) => ({ ...p, color: slice.color }))}
                    formatItem={(_name, value) =>
                      `${fmtCompact(value)} · ${fmtPct(value / total)} of shown`
                    }
                  />
                );
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 grid place-items-center">
          <div className="text-center">
            <div className="text-[16px] font-semibold leading-none tracking-tight text-fg-0">
              {fmtCompact(total)}
            </div>
            <div className="mt-1 text-micro uppercase tracking-[0.06em] text-fg-3">{totalLabel}</div>
          </div>
        </div>
      </div>
      <ul className="space-y-1">
        {top.map((d) => (
          <li key={d.key} className="grid grid-cols-[8px_1fr_auto] items-baseline gap-2 text-[11.5px]">
            <span className="block h-2 w-2 self-center rounded-pill" style={{ background: d.color }} />
            <span className="flex min-w-0 items-center gap-1.5 text-fg-1">
              {d.mark}
              {d.label === d.key ? (
                <span className="truncate">{d.label}</span>
              ) : (
                // The raw wire id stays reachable behind its human label.
                <RawIdHint id={d.key} className="truncate">
                  {d.label}
                </RawIdHint>
              )}
            </span>
            <span className="shrink-0 tabular-nums text-fg-3">
              {fmtCompact(d.count)} · {fmtPct(d.count / total)}
            </span>
          </li>
        ))}
      </ul>
      {slices.length > top.length && (
        <p className="col-span-2 text-[10.5px] text-fg-3">
          Showing the top {top.length} of {slices.length}.
        </p>
      )}
    </div>
  );
}
