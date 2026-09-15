import { fmtUSD } from "../lib/format";
import type { HourBucket } from "../lib/types";
import { Tooltip } from "../primitives";

// 24-bar "when you spend" chart. Hand-rolled so each bar can render
// its hour label + value tooltip without Recharts overhead.
// Color intensity scales with cost — hotter hours get warmer tones.
export function HourBars({ buckets }: { buckets: HourBucket[] }) {
  // Recharts could do this but it's a perfect case for a tight
  // hand-rolled grid: 24 fixed columns + per-bar gradient.
  const filled = Array.from({ length: 24 }, (_, h) =>
    buckets.find((b) => b.hour === h) ?? { hour: h, cost_usd: 0, turn_count: 0 },
  );
  const max = Math.max(1, ...filled.map((b) => b.cost_usd));

  return (
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
                className="w-full cursor-help rounded-sm transition-opacity group-hover:opacity-90 focus:outline-none"
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
}

function hourTint(t: number): string {
  // Cool blue → warm orange. Same hues as --tok-net → --tok-write.
  if (t <= 0) return "var(--bg-4)";
  if (t < 0.2) return "color-mix(in srgb, var(--tok-net) 35%, var(--bg-4))";
  if (t < 0.4) return "color-mix(in srgb, var(--tok-net) 60%, transparent)";
  if (t < 0.6) return "color-mix(in srgb, var(--accent) 70%, transparent)";
  if (t < 0.8) return "color-mix(in srgb, var(--warn) 75%, transparent)";
  return "var(--warn)";
}

function pad(n: number): string {
  return String(n).padStart(2, "0");
}
