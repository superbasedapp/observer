import type { LegendProps } from "recharts";

// ChartLegend — shared Recharts <Legend content={...} /> renderer.
// Renders a horizontal row of [color-dot] [label] pills. Used by
// every stacked area / multi-series chart so the legend style is
// consistent across the dashboard.
export function ChartLegend(props: LegendProps) {
  const payload = props.payload ?? [];
  if (!payload.length) return null;
  return (
    <ul className="flex flex-wrap items-center gap-x-3 gap-y-1 px-1 pb-1 text-[10.5px] text-fg-2">
      {payload.map((p, i) => (
        <li key={`${p.value}-${i}`} className="flex items-center gap-1.5">
          <span
            aria-hidden
            className="h-2 w-2 rounded-pill"
            style={{ background: p.color ?? "var(--fg-3)" }}
          />
          <span>{p.value}</span>
        </li>
      ))}
    </ul>
  );
}
