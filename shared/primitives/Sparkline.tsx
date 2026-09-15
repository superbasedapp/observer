// Sparkline — tiny inline SVG. No tooltip / axis / legend; that's
// what ChartShell + Recharts are for. Use for at-a-glance trend
// indicators in StatCard.

export function Sparkline({
  data,
  width = 80,
  height = 28,
  color = "var(--accent)",
  fill = true,
  strokeWidth = 1.4,
}: {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
  fill?: boolean;
  strokeWidth?: number;
}) {
  if (!data || data.length < 2) {
    return <svg width={width} height={height} />;
  }
  const min = Math.min(...data);
  const max = Math.max(...data);
  // When every datapoint is identical (e.g. all zeros, or a flat run
  // with no variance) the prior implementation pinned the line to the
  // bottom edge, which looked like a hard underline glued to the
  // baseline — degenerate visual. Render a centered flat line instead
  // so the spark reads as "constant" rather than "broken".
  const isFlat = max - min < 1e-9;
  const range = isFlat ? 1 : max - min;
  const step = width / (data.length - 1);
  const points = data.map((v, i) => {
    const x = i * step;
    const y = isFlat
      ? height / 2
      : height - ((v - min) / range) * (height - 2) - 1;
    return [x, y] as const;
  });
  const linePath = points
    .map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`)
    .join(" ");
  const fillPath = fill
    ? `${linePath} L${width.toFixed(1)},${height} L0,${height} Z`
    : "";
  const fillId = `spark-fill-${Math.random().toString(36).slice(2, 8)}`;

  return (
    <svg width={width} height={height} className="overflow-visible">
      {fill && (
        <defs>
          <linearGradient id={fillId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.25" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
        </defs>
      )}
      {fill && <path d={fillPath} fill={`url(#${fillId})`} />}
      <path
        d={linePath}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
