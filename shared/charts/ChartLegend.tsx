import type { ReactNode } from "react";
import type { LegendProps } from "recharts";

// ChartLegend — shared Recharts <Legend content={...} /> renderer.
// Renders a horizontal row of [color-dot] [label] pills. Used by
// every stacked area / multi-series chart so the legend style is
// consistent across the dashboard.
//
// A series filled with a gradient reports `url(#id)` as its color, which is
// not a valid CSS background, so its swatch rendered empty. Such charts pass
// `colors` (series name -> CSS color) and any remaining url() falls back to a
// neutral swatch instead of nothing.
//
// Never give the host <Legend> a fixed `height`: Recharts then clamps the
// measured legend box to it, so a legend that wraps onto a second row (many
// series, or a narrow card) spills over the plot and the top y-axis tick.
// Leaving height unset lets Recharts measure the real box and push the plot
// down by it.
//
// Two more ways a top legend crowds the plot, both fixed here:
//  - the top y-axis tick label is centred on the top grid line, so about
//    half its height (~6px at the 10px axis font) sits ABOVE the plot, inside
//    the legend's measured box. The bottom padding (pb-3.5) is sized so that
//    overhang never reaches the last legend row.
//  - Recharts measures the legend box only when the <Legend> re-renders. A
//    legend that re-wraps later without a re-render (a web font finishing
//    its load, a card resizing) keeps the stale height until the next hover,
//    and a new second row then lands on the top tick. A chart whose legend
//    can wrap (many series) should render it OUTSIDE Recharts in normal flow
//    through `ChartLegendFrame` below, which needs no measurement at all.
//
// `renderLabel` (optional) replaces the plain series-name text, e.g. to put
// a model-family mark before a model id (./modelLegend.tsx). Default: the
// series name as text.
export function ChartLegend(
  props: LegendProps & {
    colors?: Record<string, string>;
    renderLabel?: (name: string) => ReactNode;
  },
) {
  const payload = props.payload ?? [];
  const swatch = (name: unknown, color: string | undefined): string => {
    const explicit = props.colors?.[String(name)];
    if (explicit) return explicit;
    if (!color || color.startsWith("url(")) return "var(--fg-3)";
    return color;
  };
  if (!payload.length) return null;
  return (
    <ul className="flex flex-wrap items-center gap-x-3 gap-y-1 px-1 pb-3.5 text-[10.5px] text-fg-2">
      {payload.map((p, i) => (
        <li key={`${p.value}-${i}`} className="flex items-center gap-1.5">
          <span
            aria-hidden
            className="h-2 w-2 rounded-pill"
            style={{ background: swatch(p.value, p.color) }}
          />
          <span>{props.renderLabel ? props.renderLabel(String(p.value)) : p.value}</span>
        </li>
      ))}
    </ul>
  );
}

// ChartLegendItem is one legend entry for `ChartLegendFrame` (the same shape
// Recharts hands a <Legend content> renderer).
export type ChartLegendItem = { value: string; color: string; id?: string };

// ChartLegendFrame lays a chart out as [legend][plot] inside a fixed total
// `height`: the legend is ordinary flow content, so however many rows it
// wraps to, the plot below gets exactly the remaining height (the child
// ResponsiveContainer must use height="100%", and re-measures itself when the
// legend grows). This is the measurement-free alternative to a Recharts
// <Legend verticalAlign="top">.
export function ChartLegendFrame({
  height,
  items,
  colors,
  renderLabel,
  children,
}: {
  height: number;
  items: ChartLegendItem[];
  colors?: Record<string, string>;
  renderLabel?: (name: string) => ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col" style={{ height }}>
      <ChartLegend
        payload={items.map((it) => ({ ...it, type: "circle" as const }))}
        colors={colors}
        renderLabel={renderLabel}
      />
      <div className="min-h-0 flex-1">{children}</div>
    </div>
  );
}
