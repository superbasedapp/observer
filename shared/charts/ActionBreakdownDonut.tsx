import { actionMeta } from "../lib/actions";
import { fmtCompact, fmtInt } from "../lib/format";

export type ActionBreakdownRow = {
  action_type: string;
  count: number;
};

// ActionBreakdownDonut renders the canonical session action mix. It accepts a
// structural row shared by the node and org APIs and deliberately ignores any
// app-specific failure/provenance fields.
export function ActionBreakdownDonut({
  rows,
  total,
}: {
  rows: ActionBreakdownRow[];
  total: number;
}) {
  const sorted = [...rows].sort((a, b) => b.count - a.count);
  const minShare = Math.max(1, total) * 0.01;
  const main = sorted.filter((row) => row.count >= minShare);
  const otherCount = sorted
    .filter((row) => row.count < minShare)
    .reduce((sum, row) => sum + row.count, 0);
  const slices: ActionBreakdownRow[] = otherCount > 0
    ? [...main, { action_type: "other", count: otherCount }]
    : main;
  const sum = Math.max(1, slices.reduce((n, row) => n + row.count, 0));
  const cx = 72;
  const cy = 72;
  const radius = 56;
  const inner = 32;
  let cursor = 0;

  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 p-4">
      <h4 className="text-[12px] font-semibold text-fg-1">Action breakdown</h4>
      <p className="mt-0.5 text-[10.5px] text-fg-3">{fmtInt(total)} actions in this session</p>
      <div className="mt-3 flex min-w-0 items-center gap-4">
        <svg
          width={144}
          height={144}
          viewBox="0 0 144 144"
          className="h-28 w-28 shrink-0 sm:h-36 sm:w-36"
          style={{ filter: "drop-shadow(0 1px 3px rgba(0,0,0,0.35))" }}
          aria-label={`${fmtInt(total)} actions`}
          role="img"
        >
          {slices.length === 0 && (
            <circle cx={cx} cy={cy} r={radius} fill="none" stroke="var(--line-2)" strokeWidth={radius - inner} />
          )}
          {slices.length === 1 && (
            <circle
              cx={cx}
              cy={cy}
              r={(radius + inner) / 2}
              fill="none"
              stroke={actionMeta(slices[0].action_type).colorVar}
              strokeWidth={radius - inner}
            />
          )}
          {slices.length > 1 && slices.map((slice) => {
            const meta = actionMeta(slice.action_type);
            const fraction = slice.count / sum;
            const start = (cursor / sum) * Math.PI * 2 - Math.PI / 2;
            cursor += slice.count;
            const end = (cursor / sum) * Math.PI * 2 - Math.PI / 2;
            const largeArc = fraction > 0.5 ? 1 : 0;
            const x0 = cx + Math.cos(start) * radius;
            const y0 = cy + Math.sin(start) * radius;
            const x1 = cx + Math.cos(end) * radius;
            const y1 = cy + Math.sin(end) * radius;
            const ix0 = cx + Math.cos(start) * inner;
            const iy0 = cy + Math.sin(start) * inner;
            const ix1 = cx + Math.cos(end) * inner;
            const iy1 = cy + Math.sin(end) * inner;
            const path = `M ${x0} ${y0} A ${radius} ${radius} 0 ${largeArc} 1 ${x1} ${y1} L ${ix1} ${iy1} A ${inner} ${inner} 0 ${largeArc} 0 ${ix0} ${iy0} Z`;
            return <path key={slice.action_type} d={path} fill={meta.colorVar} stroke="var(--bg-2)" strokeWidth={2} />;
          })}
          <text x={cx} y={cy + 6} textAnchor="middle" fontSize="22" fontWeight="700" fill="var(--fg-0)">
            {fmtCompact(total)}
          </text>
        </svg>
        <ul className="min-w-0 flex-1 divide-y divide-line-1 text-[11.5px]">
          {slices.slice(0, 8).map((slice) => {
            const meta = actionMeta(slice.action_type);
            const share = (slice.count / sum) * 100;
            return (
              <li key={slice.action_type} className="flex items-center justify-between gap-2 py-1">
                <span className="flex min-w-0 items-center gap-2">
                  <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: meta.colorVar }} />
                  <span className="truncate text-fg-1">{meta.label}</span>
                </span>
                <span className="flex shrink-0 items-baseline gap-2 font-mono tabular-nums">
                  <span className="text-fg-3">{fmtCompact(slice.count)}</span>
                  <span className="w-[44px] text-right font-semibold text-fg-0">{share.toFixed(1)}%</span>
                </span>
              </li>
            );
          })}
        </ul>
      </div>
    </section>
  );
}
