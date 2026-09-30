// Recharts custom tooltip styled with project tokens. Floats over
// the chart in a small panel; respects design system colors so it
// flips on theme switch without dark: variants.

import type { TooltipProps } from "recharts";
import type {
  NameType,
  ValueType,
} from "recharts/types/component/DefaultTooltipContent";

type Props = TooltipProps<ValueType, NameType> & {
  labelKey?: string;
  labelFormatter?: (raw: string) => string;
  formatItem?: (name: string, value: number) => string;
  extra?: (row: Record<string, number | string>) => string | null;
  // Item order. "reverse" (default) lists the last-drawn series first,
  // which matches a stack read top-down. "value" lists largest first, for
  // overlaid (unstacked) series where draw order says nothing about height.
  sort?: "reverse" | "value";
};

export function ChartTooltip({
  active,
  payload,
  label,
  labelFormatter,
  formatItem,
  extra,
  sort = "reverse",
}: Props) {
  if (!active || !payload || !payload.length) return null;

  const row = (payload[0]?.payload ?? {}) as Record<string, number | string>;
  const labelOut = labelFormatter ? labelFormatter(String(label)) : String(label);
  const extraStr = extra?.(row) ?? null;

  return (
    <div className="rounded-2 border border-line-3 bg-bg-3/95 px-3 py-2 text-[11px] shadow-2 backdrop-blur">
      <div className="mb-1 text-fg-3">{labelOut}</div>
      <ul className="space-y-0.5">
        {(sort === "value"
          ? payload
              .slice()
              .sort((a, b) => Number(b.value ?? 0) - Number(a.value ?? 0))
          : payload.slice().reverse()
        ).map((p, i) => (
            <li key={i} className="flex items-center gap-2 text-fg-1">
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{ background: String(p.color ?? p.fill ?? "var(--accent)") }}
              />
              <span className="flex-1">
                {formatItem
                  ? formatItem(String(p.name), Number(p.value ?? 0))
                  : `${p.name}: ${p.value}`}
              </span>
            </li>
          ))}
      </ul>
      {extraStr && (
        <div className="mt-1 border-t border-line-2 pt-1 text-fg-2">
          {extraStr}
        </div>
      )}
    </div>
  );
}
