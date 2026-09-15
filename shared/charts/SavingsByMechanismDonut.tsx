import { useMemo } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { fmtBytes, fmtCompact, fmtPct, fmtUSD } from "../lib/format";
import type { CompressionTimeseries } from "../lib/types";
import type { SavingsUnit } from "./CompressionSavingsChart";

// SavingsByMechanismDonut — design's standalone donut sibling of the
// per-day savings chart. Rolls all per-day by_mechanism numbers into
// a single dataset for the active unit toggle.
//
// Mechanism colors mirror the per-day chart's palette so a viewer
// can flick between donut and area without re-learning the legend.
const MECH_COLOR: Record<string, string> = {
  drop: "var(--danger)",
  text: "var(--warn)",
  json: "var(--info)",
  logs: "var(--accent)",
  code: "var(--success)",
  diff: "var(--tok-out)",
  html: "var(--tok-write)",
  tools: "var(--tok-net)",
  stash: "var(--tok-read)",
  read_cache: "var(--tool-other)",
  rolling_summary: "var(--brand-from)",
  compaction: "var(--brand-to)",
};

const MECH_LABEL: Record<string, string> = {
  drop: "drop · low-importance",
  text: "text · trim",
  json: "json · token erasure",
  logs: "logs · dedup",
  code: "code · whitespace",
  diff: "diff · patch only",
  html: "html · strip",
  tools: "tools · summary",
  stash: "stash · SROD offload",
  read_cache: "read_cache",
  rolling_summary: "rolling summary",
  compaction: "compaction",
};

export function SavingsByMechanismDonut({
  data,
  unit,
  height = 240,
}: {
  data: CompressionTimeseries;
  unit: SavingsUnit;
  height?: number;
}) {
  const rolled = useMemo(() => rollByMechanism(data, unit), [data, unit]);
  const total = rolled.reduce((a, r) => a + r.value, 0);

  if (!total) {
    return (
      <div className="grid h-[200px] place-items-center text-[12px] text-fg-3">
        No compression activity in window.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-[180px_1fr] items-center gap-4">
      <div className="relative" style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={rolled}
              dataKey="value"
              nameKey="name"
              innerRadius="65%"
              outerRadius="92%"
              paddingAngle={1.5}
              stroke="var(--bg-1)"
              strokeWidth={2}
              isAnimationActive={false}
            >
              {rolled.map((r) => (
                <Cell key={r.mech} fill={r.color} />
              ))}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (!active || !payload?.length) return null;
                const p = payload[0].payload as (typeof rolled)[number];
                return (
                  <div className="rounded-2 border border-line-3 bg-bg-3/95 px-3 py-2 text-[11px] shadow-2 backdrop-blur">
                    <div className="font-mono text-fg-1">{p.name}</div>
                    <div className="mt-0.5 text-fg-3">
                      {formatValue(p.value, unit)} ·{" "}
                      {fmtPct(p.value / total)} of total
                    </div>
                  </div>
                );
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 grid place-items-center">
          <div className="text-center">
            <div className="text-[18px] font-semibold leading-none tracking-tight text-fg-0">
              {formatValue(total, unit)}
            </div>
            <div className="mt-1 text-[10px] uppercase tracking-[0.06em] text-fg-3">
              {unitLabel(unit)}
            </div>
          </div>
        </div>
      </div>
      <ul className="space-y-1">
        {rolled.map((r) => (
          <li
            key={r.mech}
            className="grid grid-cols-[8px_1fr_auto] items-baseline gap-2 text-[11px]"
          >
            <span
              className="block h-2 w-2 self-center rounded-pill"
              style={{ background: r.color }}
            />
            <span className="truncate text-fg-1">{r.name}</span>
            <span className="shrink-0 tabular-nums text-fg-3">
              {fmtPct(r.value / total)}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

type RolledRow = {
  mech: string;
  name: string;
  value: number;
  color: string;
};

function rollByMechanism(
  ts: CompressionTimeseries,
  unit: SavingsUnit,
): RolledRow[] {
  const totals: Record<string, number> = {};
  for (const p of ts.series) {
    for (const [mech, s] of Object.entries(p.by_mechanism)) {
      const v =
        unit === "usd"
          ? s.saved_usd_est
          : unit === "tokens"
            ? s.saved_bytes / 4 // tokens ≈ bytes ÷ 4 — same convention as
            : // CompressionSavingsChart
              s.saved_bytes;
      totals[mech] = (totals[mech] ?? 0) + v;
    }
  }
  return Object.entries(totals)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([mech, value]) => ({
      mech,
      name: MECH_LABEL[mech] ?? mech,
      value,
      color: MECH_COLOR[mech] ?? "var(--tool-other)",
    }));
}

function formatValue(v: number, unit: SavingsUnit): string {
  if (unit === "usd") return fmtUSD(v);
  if (unit === "tokens") return fmtCompact(v);
  return fmtBytes(v);
}

function unitLabel(unit: SavingsUnit): string {
  if (unit === "usd") return "saved";
  if (unit === "tokens") return "tokens saved";
  return "bytes saved";
}
