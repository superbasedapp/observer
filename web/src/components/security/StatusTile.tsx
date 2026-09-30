import clsx from "clsx";
import { Tooltip } from "@/components/primitives";
import type { Tone } from "@shared/lib/tone";

// StatusTile - the compact labelled stat cell the Security page's Prompt
// guard card and the MCP access section both render (lighter than HeroStat:
// no icon, denser grid). The tile's border takes its tone; `sub` is either a
// visible third line (`subVisible`) or a keyboard-reachable tooltip. One
// component so the two security surfaces stop keeping private copies with
// their own tone -> border ladders.
//
// "ok" is accepted as an alias of "success": the MCP access view-model
// (@/lib/mcpAccess) speaks ok/warn/danger/neutral.
export type StatusTileTone = Tone | "ok";

const TONE_BORDER: Readonly<Record<Tone, string>> = {
  neutral: "border-line-2",
  success: "border-success/40",
  warn: "border-warn/40",
  danger: "border-danger/40",
  info: "border-info/40",
  accent: "border-accent/40",
};

function borderOf(tone: StatusTileTone): string {
  return TONE_BORDER[tone === "ok" ? "success" : tone] ?? TONE_BORDER.neutral;
}

export function StatusTile({
  label,
  value,
  sub,
  subVisible,
  tone,
}: {
  label: string;
  value: string;
  sub?: string;
  /** Render `sub` as a truncated third line (the full text on hover). */
  subVisible?: boolean;
  tone: StatusTileTone;
}) {
  const tile = (
    <div
      tabIndex={sub && !subVisible ? 0 : undefined}
      className={clsx(
        "rounded-2 border bg-bg-3 px-2.5 py-2",
        sub && !subVisible && "cursor-help focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring",
        borderOf(tone),
      )}
    >
      <div className="text-micro uppercase tracking-[0.06em] text-fg-3">{label}</div>
      <div className="mt-0.5 text-body font-semibold text-fg-0">{value}</div>
      {sub && subVisible && (
        <div className="mt-0.5 truncate text-[10.5px] text-fg-3" title={sub}>
          {sub}
        </div>
      )}
    </div>
  );
  if (!sub || subVisible) return tile;
  return <Tooltip content={sub}>{tile}</Tooltip>;
}
