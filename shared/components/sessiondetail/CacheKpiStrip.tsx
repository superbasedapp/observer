import clsx from "clsx";
import { Pill } from "../../primitives";
import { fmtCompact, fmtInt } from "../../lib/format";
import type { CacheKpiLike, CacheTier } from "../../lib/types";

// CacheKpiStrip + CacheTierBadge — the pure renderers of the session-detail
// Cache tab's summary rail: the tier badge and the KPI grid (events / hits /
// writes / rewrites / ratio / mispredicts / tokens R-W) with the flagged-
// rewrite note. Promoted into the shared design system so the org can surface
// the full KPI set (already on its SessionCacheResult) as the node-style strip.
// The live cache-expiry card and the /cache timeline fetch stay node-side.

export function CacheTierBadge({ tier }: { tier: CacheTier }) {
  const map: Record<CacheTier, { label: string; variant: "info" | "neutral" | "success" }> = {
    proxy: { label: "Tier 1 · proxy", variant: "success" },
    transcript: { label: "Tier 2 · transcript", variant: "info" },
    mixed: { label: "Mixed", variant: "info" },
    none: { label: "None", variant: "neutral" },
  };
  const { label, variant } = map[tier];
  return <Pill variant={variant}>{label}</Pill>;
}

// CacheKpiStrip — the bordered KPI grid + flagged-rewrite note. Pure: the cache
// summary counts in, the strip out.
export function CacheKpiStrip({ summary }: { summary: CacheKpiLike }) {
  const ratioLabel =
    summary.ratio > 0 ? `${summary.ratio.toFixed(1)}× R/W` : "-";
  return (
    <div className="rounded-3 border bg-bg-2 px-4 py-3">
      <div className="grid grid-cols-2 gap-3 text-[12px] sm:grid-cols-4 lg:grid-cols-7">
        <CacheStat label="Events" value={fmtInt(summary.event_count)} />
        <CacheStat label="Hits" value={fmtInt(summary.hit_count)} />
        <CacheStat label="Writes" value={fmtInt(summary.write_count)} />
        <CacheStat
          label="Rewrites"
          value={fmtInt(summary.rewrite_count)}
          warn={summary.rewrite_count > 0 && !summary.has_flagged_rewrites}
        />
        <CacheStat label="Ratio" value={ratioLabel} />
        <CacheStat
          label="Mispredicts"
          value={
            summary.zero_usage_count > 0 &&
            summary.mispredict_count === summary.zero_usage_count
              ? `${fmtInt(summary.mispredict_count)} (zero-usage)`
              : fmtInt(summary.mispredict_count)
          }
          muted={summary.mispredict_count === 0}
        />
        <CacheStat
          label="Tokens R / W"
          value={`${fmtCompact(summary.tokens_read)} / ${fmtCompact(summary.tokens_written)}`}
        />
      </div>
      {summary.has_flagged_rewrites && (
        <div className="mt-2 flex items-center gap-2 text-[10.5px] text-fg-3">
          <Pill variant="neutral">flagged</Pill>
          One or more rewrites carry a flagged cause (e.g. tools_changed
          on MCP server toggle). Real signal - not alarm-worthy unless
          it dominates.
        </div>
      )}
    </div>
  );
}

function CacheStat({
  label,
  value,
  warn,
  muted,
}: {
  label: string;
  value: string;
  warn?: boolean;
  muted?: boolean;
}) {
  return (
    <div className={clsx("flex flex-col", muted && "opacity-60")}>
      <span className="text-[10px] font-medium uppercase tracking-[0.05em] text-fg-3">
        {label}
      </span>
      <span
        className={clsx(
          "tabular-nums text-[13px] font-semibold",
          warn ? "text-warn" : "text-fg-1",
        )}
      >
        {value}
      </span>
    </div>
  );
}
