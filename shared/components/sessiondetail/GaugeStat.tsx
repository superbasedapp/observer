import clsx from "clsx";
import type { ReactNode } from "react";
import { ProgressRing } from "../../primitives/ProgressRing";
import { AnimatedValue } from "../../primitives/Motion";
import { useHelpSlot } from "../../primitives/helpSlot";
import {
  GAUGE_BANDS,
  gaugeAriaLabel,
  gaugeTone,
  gaugeVariant,
  knownRatio,
  type GaugeBand,
  type GaugeVariant,
} from "./gaugeStat";

// GaugeStat: a HeroStat-shaped tile whose share-of-a-ceiling reads as one or
// more radial gauges (the session drawer's context-window fill and rate-limit
// windows). Same chrome as HeroStat (border, corner glow, label row, help
// slot, loading shimmer) so it sits in a HeroStat band without a seam; the
// ring tones and the tile chrome come from the GAUGE_BANDS table in
// gaugeStat.ts, never a ladder here.
//
// Unknown means unknown: an unknown ratio draws an EMPTY ring that says
// "unknown" (visibly and to assistive tech) beside whatever value text the
// caller has, never 0%. Pure: no fetch, no state, no router.

/** One ring on the tile. */
export type GaugeRing = {
  /** Accessible name, e.g. "5h window". */
  name: string;
  /** Filled share 0..1; null / undefined / non-finite is unknown. */
  ratio: number | null | undefined;
  /** Short text in the ring centre (e.g. "5h"); the share then sits below the ring. */
  caption?: string;
};

export type GaugeStatProps = {
  label: string;
  icon?: ReactNode;
  /** The single ring's share, 0..1 (null = unknown). Ignored when `rings` is set. */
  ratio?: number | null;
  /** Several rings (e.g. one per rate-limit window); the tile takes the worst one's tone. */
  rings?: readonly GaugeRing[];
  /** Headline text beside the ring(s). */
  value: ReactNode;
  unit?: ReactNode;
  sub?: ReactNode;
  cornerPill?: ReactNode;
  helpId?: string;
  loading?: boolean;
  /** Threshold table override (default GAUGE_BANDS). */
  bands?: readonly GaugeBand[];
  className?: string;
};

// Chrome per variant, the HeroStat recipe as data.
const CHROME: Readonly<Record<GaugeVariant, { value: string; border: string; glow: string }>> = {
  accent: { value: "text-accent", border: "border-accent/40", glow: "--accent-soft" },
  warn: { value: "text-warn", border: "border-warn/40", glow: "--warn-soft" },
  danger: { value: "text-danger", border: "border-danger/40", glow: "--danger-soft" },
};

function pctText(ratio: number): string {
  return `${Math.round(ratio * 100)}%`;
}

function Ring({ ring, bands }: { ring: GaugeRing; bands: readonly GaugeBand[] }) {
  const r = knownRatio(ring.ratio);
  const centre = ring.caption ?? (r != null ? pctText(r) : "unknown");
  const el = (
    <ProgressRing
      ratio={r ?? Number.NaN}
      tone={gaugeTone(r, bands)}
      size={56}
      stroke={5}
      // A known ring is a meter; an unknown one is labelled by its wrapper.
      label={r != null ? ring.name : undefined}
    >
      <span className={clsx(r == null && !ring.caption && "text-[8.5px] font-medium text-fg-3")}>
        {centre}
      </span>
    </ProgressRing>
  );
  return (
    <span className="flex shrink-0 flex-col items-center gap-0.5">
      {r != null ? (
        el
      ) : (
        <span role="img" aria-label={gaugeAriaLabel(ring.name, null)}>
          {el}
        </span>
      )}
      {ring.caption && (
        <span aria-hidden className="text-[10px] tabular-nums text-fg-3">
          {r != null ? pctText(r) : "unknown"}
        </span>
      )}
    </span>
  );
}

export function GaugeStat({
  label,
  icon,
  ratio,
  rings,
  value,
  unit,
  sub,
  cornerPill,
  helpId,
  loading,
  bands = GAUGE_BANDS,
  className,
}: GaugeStatProps) {
  const renderHelp = useHelpSlot();
  const list: readonly GaugeRing[] = rings ?? [{ name: label, ratio }];
  const chrome = CHROME[gaugeVariant(list.map((g) => g.ratio), bands)];
  return (
    <div
      className={clsx(
        "relative flex min-h-[140px] flex-col overflow-hidden rounded-3 border bg-bg-2 px-5 py-4",
        chrome.border,
        className,
      )}
    >
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background: `radial-gradient(circle at 100% 0%, color-mix(in srgb, var(${chrome.glow}) 92%, transparent), transparent 58%)`,
        }}
      />
      <div className={clsx("relative flex min-h-0 flex-1 flex-col", loading && "animate-shimmer overflow-hidden")}>
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-1.5 text-[10.5px] font-semibold uppercase tracking-[0.08em] text-fg-3">
            {icon && <span className="text-fg-3">{icon}</span>}
            {label}
            {helpId && renderHelp(helpId)}
            {loading && (
              <span aria-label="loading" className="ml-0.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
            )}
          </div>
          {cornerPill && <div className="shrink-0">{cornerPill}</div>}
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-2">
          <div className="flex items-start gap-2">
            {list.map((g) => (
              <Ring key={g.name} ring={g} bands={bands} />
            ))}
          </div>
          <div className="flex min-w-0 items-baseline gap-1.5">
            <span className={clsx("text-[34px] font-bold leading-[1.02] tracking-[-0.03em]", chrome.value)}>
              <AnimatedValue value={value} />
            </span>
            {unit && <span className="text-[15px] font-medium text-fg-2">{unit}</span>}
          </div>
        </div>
        {sub && <div className="mt-2 text-[12px] leading-snug text-fg-3">{sub}</div>}
      </div>
    </div>
  );
}
