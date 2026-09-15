import { useMemo, useState, type ReactNode } from "react";
import { SegmentedControl, Tooltip } from "../../primitives";
import { fmtCompact, fmtInt, fmtUSD } from "../../lib/format";
import type { SessionModelBucketLike } from "../../lib/types";
import { defaultRenderCost, type RenderCost } from "./cost";

// ModelsUsedPanel — one horizontal stacked bar per model, segments colored by
// token bucket (input / cache read / cache write / output); a $ / Tokens
// SegmentedControl toggles the encoded metric. Promoted into the shared design
// system with a `renderCost` slot so the org renders its standalone dollar
// figures through <Money> (tokens / percent-of-cap) instead of bare USD.
//
// renderCost covers the STANDALONE dollar figures (subtitle total, per-model
// right label in $ mode, the per-model caption cost + tool cost). The stacked-
// bar SEGMENT hover tooltips still format precise USD via fmtUSD (a deep hover
// detail that would nest a tooltip inside tooltip content); that is a known
// residual for a surface that must never show bare USD.

// MODELS_USED_VISIBLE caps how many bars render before the "+N more"
// footer kicks in. Matches the ActionBreakdownDonut + TokenBucketsPanel
// row caps so the three side-by-side tiles have roughly equal height.
const MODELS_USED_VISIBLE = 6;

// BUCKETS is the canonical 4-bucket split used in both $ and Tokens
// modes. Colors mirror TokenBucketsPanel so the same hue means the
// same thing across the whole session-detail slide-over.
type BucketKey = "input" | "output" | "cache_read" | "cache_creation";
const BUCKETS: { key: BucketKey; label: string; color: string }[] = [
  { key: "input", label: "Net Input", color: "var(--tok-net)" },
  { key: "cache_read", label: "Cache Read", color: "var(--tok-read)" },
  { key: "cache_creation", label: "Cache Write", color: "var(--tok-write)" },
  { key: "output", label: "Output", color: "var(--tok-out)" },
];

type Mode = "cost" | "tokens";

function bucketValue(
  r: SessionModelBucketLike,
  bucket: BucketKey,
  mode: Mode,
): number {
  if (mode === "tokens") {
    switch (bucket) {
      case "input":
        return r.input;
      case "output":
        return r.output + (r.reasoning ?? 0);
      case "cache_read":
        return r.cache_read;
      case "cache_creation":
        return r.cache_creation;
    }
  }
  switch (bucket) {
    case "input":
      return r.input_cost_usd ?? 0;
    case "output":
      return r.output_cost_usd ?? 0;
    case "cache_read":
      return r.cache_read_cost_usd ?? 0;
    case "cache_creation":
      return r.cache_creation_cost_usd ?? 0;
  }
}

function modelTotal(r: SessionModelBucketLike, mode: Mode): number {
  return BUCKETS.reduce((a, b) => a + bucketValue(r, b.key, mode), 0);
}

export function ModelsUsedPanel({
  rows,
  totalCost,
  renderCost = defaultRenderCost,
}: {
  rows: SessionModelBucketLike[];
  totalCost: number;
  renderCost?: RenderCost;
}) {
  const [mode, setMode] = useState<Mode>("cost");

  // Filter zero-everything rows. Rank by cost first (then turn count as
  // tiebreak — useful for sessions where pricing isn't tied yet).
  const ranked = useMemo(() => {
    return [...rows]
      .filter(
        (r) =>
          r.cost_usd > 0 ||
          r.input + r.output + r.cache_read + r.cache_creation > 0,
      )
      .sort((a, b) => b.cost_usd - a.cost_usd || b.turn_count - a.turn_count);
  }, [rows]);

  // The maximum model total in the current mode is the reference for
  // bar widths — the top model takes the full track, everyone else is
  // proportional. Recompute when mode flips because the proportions
  // typically change (cost is dominated by output tokens, raw token
  // counts are dominated by cache reads).
  const maxTotal = Math.max(
    1,
    ...ranked.map((r) => modelTotal(r, mode)),
  );
  const grandTotalCost = useMemo(
    () => ranked.reduce((a, r) => a + r.cost_usd, 0),
    [ranked],
  );
  const grandTotalTokens = useMemo(
    () =>
      ranked.reduce(
        (a, r) => a + r.input + r.output + r.cache_read + r.cache_creation,
        0,
      ),
    [ranked],
  );

  const visible = ranked.slice(0, MODELS_USED_VISIBLE);
  const hidden = ranked.length - visible.length;

  const subtitle: ReactNode =
    ranked.length === 0
      ? "no model attribution captured for this session"
      : mode === "cost"
        ? (
            <>
              {ranked.length} model{ranked.length === 1 ? "" : "s"} ·{" "}
              {renderCost(totalCost > 0 ? totalCost : grandTotalCost, {
                kind: "model",
                tokens: grandTotalTokens,
              })}{" "}
              total · bar length = $ spent
            </>
          )
        : `${ranked.length} model${ranked.length === 1 ? "" : "s"} · ${fmtCompact(grandTotalTokens)} tok · bar length = tokens used`;

  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 p-4">
      <div className="flex items-baseline justify-between gap-2">
        <div>
          <h4 className="text-[12px] font-semibold text-fg-1">Models used</h4>
          <p className="mt-0.5 text-[10.5px] text-fg-3">{subtitle}</p>
        </div>
        {ranked.length > 0 && (
          <SegmentedControl<Mode>
            options={[
              { value: "cost", label: "$" },
              { value: "tokens", label: "tokens" },
            ]}
            value={mode}
            onChange={setMode}
            size="sm"
          />
        )}
      </div>
      {ranked.length === 0 ? (
        <div className="mt-3 text-[10.5px] text-fg-3">
          No tokens or cost are attributed to any model on this session yet.
        </div>
      ) : (
        <>
          <ul className="mt-3 space-y-2 text-[11.5px]">
            {visible.map((r) => {
              const total = modelTotal(r, mode);
              const widthPct = (total / maxTotal) * 100;
              const tokenTotal =
                r.input + r.output + r.cache_read + r.cache_creation;
              return (
                <li key={r.model} className="space-y-1">
                  <div className="flex items-baseline justify-between gap-2">
                    <Tooltip content={<span className="break-all font-mono">{r.model}</span>} maxWidth={360}>
                      <span
                        tabIndex={0}
                        className="cursor-help truncate text-fg-1 focus:outline-none"
                      >
                        {r.model}
                      </span>
                    </Tooltip>
                    {mode === "cost" ? (
                      <span className="shrink-0 font-mono tabular-nums font-semibold text-fg-0">
                        {renderCost(r.cost_usd, {
                          kind: "model",
                          tokens: tokenTotal,
                        })}
                      </span>
                    ) : (
                      <Tooltip content={`${fmtInt(tokenTotal)} tokens`}>
                        <span
                          tabIndex={0}
                          className="cursor-help shrink-0 font-mono tabular-nums font-semibold text-fg-0 focus:outline-none"
                        >
                          {fmtCompact(tokenTotal)}
                        </span>
                      </Tooltip>
                    )}
                  </div>
                  <div className="flex h-2.5 w-full overflow-hidden rounded-pill bg-bg-3">
                    <div
                      className="flex h-full"
                      style={{ width: `${widthPct}%` }}
                    >
                      {BUCKETS.map((b) => {
                        const v = bucketValue(r, b.key, mode);
                        if (v <= 0) return null;
                        const segPct = total > 0 ? (v / total) * 100 : 0;
                        const tip =
                          mode === "cost"
                            ? `${b.label}: ${fmtUSD(v, true)}`
                            : `${b.label}: ${fmtInt(v)} tokens`;
                        return (
                          <Tooltip key={b.key} content={tip}>
                            <span
                              style={{
                                width: `${segPct}%`,
                                background: b.color,
                              }}
                            />
                          </Tooltip>
                        );
                      })}
                    </div>
                  </div>
                  <div className="font-mono tabular-nums text-[10.5px] text-fg-3">
                    {fmtInt(r.turn_count)} turn
                    {r.turn_count === 1 ? "" : "s"} ·{" "}
                    {mode === "cost"
                      ? `${fmtCompact(tokenTotal)} tok`
                      : renderCost(r.cost_usd, {
                          kind: "model",
                          tokens: tokenTotal,
                        })}
                    {r.tool_cost_usd > 0 && (
                      <> · tool {renderCost(r.tool_cost_usd, { kind: "tool" })}</>
                    )}
                  </div>
                </li>
              );
            })}
            {hidden > 0 && (
              <li className="pt-1 text-center text-[10.5px] text-fg-3">
                +{hidden} more
              </li>
            )}
          </ul>
          <div className="mt-3 border-t border-line-1 pt-2">
            <ul className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10.5px] text-fg-2">
              {BUCKETS.map((b) => (
                <li key={b.key} className="flex items-center gap-1.5">
                  <span
                    aria-hidden
                    className="h-2 w-2 rounded-pill"
                    style={{ background: b.color }}
                  />
                  <span>{b.label}</span>
                </li>
              ))}
            </ul>
          </div>
        </>
      )}
    </section>
  );
}
