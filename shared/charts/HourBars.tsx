import { memo } from "react";
import { fmtUSD } from "../lib/format";
import type { HourBucket } from "../lib/types";
import { Tooltip } from "../primitives";
import { ScaleLegend } from "./ScaleLegend";

// 24-bar "when you spend" chart. Hand-rolled so each bar can render
// its hour label + value tooltip without Recharts overhead.
// Color intensity scales with cost: hotter hours get warmer tones, and the
// scale legend under the bars (on by default; `legend={false}` for a caller
// that explains the ramp itself) maps a tint back to a dollar range.
export const HourBars = memo(function HourBars({
  buckets,
  legend = true,
}: {
  buckets: HourBucket[];
  legend?: boolean;
}) {
  // Recharts could do this but it's a perfect case for a tight
  // hand-rolled grid: 24 fixed columns + per-bar gradient.
  const filled = Array.from({ length: 24 }, (_, h) =>
    buckets.find((b) => b.hour === h) ?? { hour: h, cost_usd: 0, turn_count: 0 },
  );
  // peak is the real top hour (the legend's honest high end); max floors
  // it at 1 only as the intensity divisor.
  const peak = Math.max(0, ...filled.map((b) => b.cost_usd));
  const max = Math.max(1, peak);

  const bars = (
    <div className="flex h-[200px] items-end gap-[2px] px-1">
      {filled.map((b) => {
        const intensity = b.cost_usd / max;
        const h = Math.max(2, intensity * 170);
        return (
          <div
            key={b.hour}
            className="group flex flex-1 flex-col items-center gap-1"
          >
            <Tooltip
              content={`${pad(b.hour)}:00 UTC · ${fmtUSD(b.cost_usd)} · ${b.turn_count} turns`}
            >
              <div
                tabIndex={0}
                className="w-full cursor-help rounded-t-[2px] transition-opacity group-hover:opacity-90 focus:outline-none"
                style={{
                  height: `${h}px`,
                  background: hourTint(intensity),
                }}
              />
            </Tooltip>
            <span className="text-[9px] tabular-nums text-fg-3">
              {pad(b.hour)}
            </span>
          </div>
        );
      })}
    </div>
  );
  if (!legend) return bars;
  return (
    <div className="flex flex-col gap-2">
      {bars}
      <ScaleLegend
        className="self-end px-1"
        colorAt={hourTint}
        stops={[0.1, 0.3, 0.5, 0.7, 0.9]}
        low={fmtUSD(0)}
        high={fmtUSD(peak)}
        label="Cost colour scale"
      />
    </div>
  );
});

// TINT_STEPS: the bar colour for an intensity below each `upTo`, walked
// top-down (cool blue to warm orange; the same hues as --tok-net to
// --tok-write). A zero hour renders as the empty track.
const TINT_STEPS: readonly { upTo: number; color: string }[] = [
  { upTo: 0.2, color: "color-mix(in srgb, var(--tok-net) 35%, var(--bg-4))" },
  { upTo: 0.4, color: "color-mix(in srgb, var(--tok-net) 60%, transparent)" },
  { upTo: 0.6, color: "color-mix(in srgb, var(--accent) 70%, transparent)" },
  { upTo: 0.8, color: "color-mix(in srgb, var(--warn) 75%, transparent)" },
  { upTo: Infinity, color: "var(--warn)" },
];

function hourTint(t: number): string {
  if (t <= 0) return "var(--bg-4)";
  return TINT_STEPS.find((s) => t < s.upTo)?.color ?? "var(--warn)";
}

function pad(n: number): string {
  return String(n).padStart(2, "0");
}
