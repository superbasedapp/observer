import { useMemo, useState } from "react";
import { fmtUSD } from "../lib/format";
import type { AnalysisCostByHour } from "../lib/types";
import { Tooltip } from "../primitives";

// HourHeatmap — single-row colour-intensity heatmap (24 cells × 1
// row) replacing the prior HourBars. The design intent is a 2D
// day-of-week × hour matrix; until /api/analysis/cost-by-hour
// exposes a DOW dimension this component stays 1D. The data
// contract + visual layout already match the 2D plan, so the
// upgrade is additive (extend rows from 1 → 7 when DOW lands).
//
// Cells are colour-mapped against the max bucket using `--accent`
// as the high end. Hovering or selecting a cell publishes a
// readout below the grid (mirrors the design's hover state).
export function HourHeatmap({
  buckets,
  timezone,
}: {
  buckets: AnalysisCostByHour["buckets"];
  timezone?: string;
}) {
  const max = useMemo(
    () => Math.max(1, ...buckets.map((b) => b.cost_usd)),
    [buckets],
  );
  const [selected, setSelected] = useState<number | null>(null);
  const sel = selected != null ? buckets.find((b) => b.hour === selected) : null;

  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-[36px_minmax(0,1fr)] items-center gap-2">
        <span className="text-[9.5px] font-mono uppercase tracking-[0.06em] text-fg-3">
          all
        </span>
        <div className="grid grid-cols-24 gap-px">
          {Array.from({ length: 24 }).map((_, hour) => {
            const b = buckets.find((bb) => bb.hour === hour);
            const value = b?.cost_usd ?? 0;
            const intensity = Math.min(1, value / max);
            return (
              <Tooltip
                key={hour}
                content={`${pad(hour)}:00 — ${fmtUSD(value)}${b?.turn_count ? ` · ${b.turn_count} turns` : ""}`}
              >
                <button
                  type="button"
                  onMouseEnter={() => setSelected(hour)}
                  onMouseLeave={() => setSelected(null)}
                  onClick={() => setSelected(hour)}
                  className="aspect-square w-full rounded-[2px] transition-opacity hover:opacity-80"
                  style={{
                    background:
                      intensity > 0
                        ? `color-mix(in srgb, var(--accent) ${(
                            12 +
                            intensity * 78
                          ).toFixed(0)}%, var(--bg-3))`
                        : "var(--bg-3)",
                    border:
                      selected === hour
                        ? "1px solid var(--accent)"
                        : "1px solid transparent",
                  }}
                />
              </Tooltip>
            );
          })}
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

      <div className="flex items-center justify-between gap-2 text-[11px] text-fg-3">
        <span>
          {sel
            ? `${pad(sel.hour)}:00–${pad((sel.hour + 1) % 24)}:00${
                timezone ? ` ${timezone}` : ""
              } · `
            : "Hover to inspect · "}
          {sel ? (
            <span className="font-mono text-fg-1">{fmtUSD(sel.cost_usd)}</span>
          ) : (
            <span className="text-fg-4">click a cell to pin</span>
          )}
          {sel?.turn_count != null && sel.turn_count > 0 && (
            <span className="ml-1 text-fg-3">· {sel.turn_count} turns</span>
          )}
        </span>
        <span className="flex items-center gap-1.5 text-[10px] text-fg-4">
          low
          <span className="flex h-2 w-24 overflow-hidden rounded-pill">
            {Array.from({ length: 6 }).map((_, i) => (
              <span
                key={i}
                className="block h-full flex-1"
                style={{
                  background: `color-mix(in srgb, var(--accent) ${
                    12 + i * 16
                  }%, var(--bg-3))`,
                }}
              />
            ))}
          </span>
          high
        </span>
      </div>
    </div>
  );
}

function pad(n: number): string {
  return n.toString().padStart(2, "0");
}
