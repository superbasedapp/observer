import { useMemo, useState } from "react";
import { fmtUSD } from "../lib/format";
import type { AnalysisCostByDowHour } from "../lib/types";
import { Tooltip } from "../primitives";

// DowHourHeatmap — 7×24 grid showing cost concentration across
// day-of-week (rows) × hour-of-day (cols), matching the design's
// "When you spend" panel (`design/page-analysis.jsx`). Replaces the
// older 1D HourHeatmap once /api/analysis/cost-by-dow-hour is wired.
//
// Cells render with intensity = log(cost) / log(max) so a hot
// hour-cluster (e.g. Tue/Wed 14:00–17:00) reads at-a-glance while
// quieter cells stay visible rather than collapsing to bg.
export function DowHourHeatmap({
  cells,
  timezone,
}: {
  cells: AnalysisCostByDowHour["cells"];
  timezone?: string;
}) {
  const max = useMemo(() => {
    let m = 0;
    for (const c of cells) if (c.cost_usd > m) m = c.cost_usd;
    return Math.max(1, m);
  }, [cells]);

  const [hovered, setHovered] = useState<{ dow: number; hour: number } | null>(
    null,
  );

  // Day labels — Go's time.Weekday() encodes Sun=0..Sat=6; the design
  // mockup leads with Mon, so render in that order while preserving
  // the raw dow integer for cell lookup.
  const DAYS: { label: string; dow: number }[] = [
    { label: "Mon", dow: 1 },
    { label: "Tue", dow: 2 },
    { label: "Wed", dow: 3 },
    { label: "Thu", dow: 4 },
    { label: "Fri", dow: 5 },
    { label: "Sat", dow: 6 },
    { label: "Sun", dow: 0 },
  ];

  const lookup = useMemo(() => {
    const m = new Map<number, (typeof cells)[number]>();
    for (const c of cells) m.set(c.dow * 24 + c.hour, c);
    return m;
  }, [cells]);

  const sel =
    hovered != null
      ? lookup.get(hovered.dow * 24 + hovered.hour) ?? null
      : null;

  return (
    <div className="flex flex-col gap-2">
      <div className="overflow-x-auto">
        <div className="inline-grid min-w-full grid-cols-[36px_minmax(0,1fr)] items-center gap-y-px">
          {DAYS.map(({ label, dow }) => (
            <Row
              key={dow}
              label={label}
              dow={dow}
              lookup={lookup}
              max={max}
              hovered={hovered}
              onHover={setHovered}
            />
          ))}
        </div>
      </div>

      <div className="grid grid-cols-[36px_minmax(0,1fr)] gap-2 text-[9.5px] text-fg-4">
        <span />
        <div className="grid grid-cols-24 gap-px">
          {Array.from({ length: 24 }).map((_, hour) => (
            <span
              key={hour}
              className="text-center font-mono tabular-nums"
              style={{ visibility: hour % 3 === 0 ? "visible" : "hidden" }}
            >
              {pad(hour)}
            </span>
          ))}
        </div>
      </div>

      <div className="flex items-center justify-between gap-3 text-[10.5px] text-fg-3">
        <div className="flex items-center gap-2">
          <span className="font-mono uppercase tracking-[0.06em]">
            cost by hour of day × day of week · {timezone ?? "UTC"}
          </span>
        </div>
        <ScaleLegend max={max} />
      </div>

      {/* Fixed-height readout slot — operator complaint: the prior
          implementation toggled between a paragraph and a panel,
          which jumped the surrounding block's height as the cursor
          moved in / out. Reserved a constant 32px row with default
          "hover a cell" copy that swaps in-place to the data row.
          Same surface dims either way. */}
      <div className="flex h-[32px] items-center rounded-2 border border-line-1 bg-bg-3/40 px-3 text-[11px]">
        {sel ? (
          <>
            <span className="font-mono text-fg-3">
              From: {dayName(sel.dow)} {pad(sel.hour)}:00–{pad(sel.hour + 1)}:00{" "}
              {timezone ?? "UTC"}
            </span>
            <span className="px-1 text-fg-4">·</span>
            <span className="font-semibold tabular-nums text-fg-0">
              {fmtUSD(sel.cost_usd)}
            </span>
            {sel.turn_count > 0 && (
              <span className="ml-2 text-fg-3">
                · {sel.turn_count} turn{sel.turn_count === 1 ? "" : "s"}
              </span>
            )}
          </>
        ) : (
          <span className="text-fg-4">Hover a cell for the hour breakdown.</span>
        )}
      </div>
    </div>
  );
}

function Row({
  label,
  dow,
  lookup,
  max,
  hovered,
  onHover,
}: {
  label: string;
  dow: number;
  lookup: Map<number, { cost_usd: number; turn_count: number }>;
  max: number;
  hovered: { dow: number; hour: number } | null;
  onHover: (h: { dow: number; hour: number } | null) => void;
}) {
  return (
    <>
      <span className="pr-2 text-right font-mono text-[9.5px] uppercase tracking-[0.06em] text-fg-3">
        {label}
      </span>
      <div className="grid grid-cols-24 gap-px">
        {Array.from({ length: 24 }).map((_, hour) => {
          const cell = lookup.get(dow * 24 + hour);
          const value = cell?.cost_usd ?? 0;
          // Log scale — linear scale washes out off-peak hours in a
          // window dominated by one heavy day. log1p keeps the tail
          // visible while still letting the peak stand out.
          const intensity =
            value > 0 ? Math.min(1, Math.log1p(value) / Math.log1p(max)) : 0;
          const isHovered = hovered?.dow === dow && hovered?.hour === hour;
          return (
            <Tooltip
              key={hour}
              content={`${dayName(dow)} ${pad(hour)}:00 — ${fmtUSD(value)}${
                cell?.turn_count ? ` · ${cell.turn_count} turns` : ""
              }`}
            >
              <button
                type="button"
                onMouseEnter={() => onHover({ dow, hour })}
                onMouseLeave={() => onHover(null)}
                onFocus={() => onHover({ dow, hour })}
                onBlur={() => onHover(null)}
                className="aspect-square w-full rounded-[2px] transition-all"
                style={{
                  background:
                    intensity > 0
                      ? `color-mix(in srgb, var(--accent) ${(
                          14 +
                          intensity * 76
                        ).toFixed(0)}%, var(--bg-3))`
                      : "var(--bg-3)",
                  outline: isHovered ? "1px solid var(--accent)" : "none",
                  outlineOffset: isHovered ? "1px" : undefined,
                }}
              />
            </Tooltip>
          );
        })}
      </div>
    </>
  );
}

function ScaleLegend({ max }: { max: number }) {
  // 5-step gradient legend mirroring the cell color ramp so the user
  // can map a cell shade back to a dollar magnitude at a glance.
  const stops = [0, 0.25, 0.5, 0.75, 1];
  return (
    <div className="flex items-center gap-1">
      <span className="text-[9.5px] text-fg-4">$0</span>
      <div className="flex h-2.5 items-stretch gap-px">
        {stops.map((s, i) => (
          <span
            key={i}
            className="w-3 rounded-[1px]"
            style={{
              background:
                s > 0
                  ? `color-mix(in srgb, var(--accent) ${(14 + s * 76).toFixed(0)}%, var(--bg-3))`
                  : "var(--bg-3)",
            }}
          />
        ))}
      </div>
      <span className="font-mono text-[9.5px] tabular-nums text-fg-4">
        {fmtUSD(max)}
      </span>
    </div>
  );
}

function pad(n: number): string {
  return n.toString().padStart(2, "0");
}

function dayName(dow: number): string {
  switch (dow) {
    case 0:
      return "Sun";
    case 1:
      return "Mon";
    case 2:
      return "Tue";
    case 3:
      return "Wed";
    case 4:
      return "Thu";
    case 5:
      return "Fri";
    case 6:
      return "Sat";
    default:
      return String(dow);
  }
}
