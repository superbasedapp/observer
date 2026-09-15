import { LOC_SUMMARY_PATH } from "@/lib/api";
import { fmtInt, fmtUSD } from "@/lib/format";
import { useApi } from "@/lib/useApi";
import { HelpInd } from "@/components/HelpInd";
import type { CostSummary, LOCSummaryResponse } from "@/lib/types";

// LOCPerDollarTile — AI code lines per dollar over the window
// (docs/plans/lines-of-code-tracking-plan-2026-09-07.md §3.4).
//
// This is a RATIO, not a score. It is deliberately not graded, not
// colour-coded good/bad, and never ranked - the plan's §3.5 rule is that no
// productivity score is derived from line counts, and a green/red tile IS a
// score. It shows the two inputs beside the quotient so the reader can see
// exactly what was divided by what.
//
// Scope honesty: /api/loc/summary takes only a DAY count (no hours, no custom
// range) and a NUMERIC project id, which the dashboard's project filter (a
// root path) cannot supply, and it has no tool filter at all. Rather than
// pass filters the server would silently drop - producing a window-wide
// numerator over a filtered denominator - the tile fetches BOTH sides at the
// same unfiltered day count and says so on its face.
export function LOCPerDollarTile({
  days,
  windowLabel,
  filtered,
}: {
  // days is the page window rounded up to whole days.
  days: number;
  // windowLabel is the page's own window chip text, shown so the reader can
  // see when the tile's day count is wider than the page's window.
  windowLabel: string;
  // filtered is true when a tool or project filter is active on the page, so
  // the tile can say it is NOT narrowed by it.
  filtered: boolean;
}) {
  const loc = useApi<LOCSummaryResponse>(LOC_SUMMARY_PATH, { days }, [days]);
  // The denominator is fetched at the SAME day count and with no tool or
  // project filter, so numerator and denominator always describe the same
  // slice of history.
  const cost = useApi<CostSummary>("/api/models", { days }, [days]);

  const loading = (loc.loading && !loc.data) || (cost.loading && !cost.data);
  const lines = loc.data?.ai_code_touched ?? 0;
  const spend = cost.data?.total_cost_usd ?? 0;
  // No rows at all is NOT "zero lines" - it means nothing has been counted.
  const uncounted = !!loc.data && loc.data.buckets.length === 0;
  const noCost = !cost.data || !(spend > 0);
  const ratio = !uncounted && !noCost ? lines / spend : null;

  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3">
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div className="min-w-[13rem]">
          <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
            AI code lines per dollar
            <HelpInd id="tile.loc_per_dollar" />
          </span>
          <span
            className={`mt-0.5 block text-[30px] font-bold leading-[1.05] tracking-[-0.02em] tabular-nums ${
              ratio === null ? "text-fg-3" : "text-fg-0"
            }`}
          >
            {loading ? "…" : ratio === null ? "-" : fmtRatio(ratio)}
          </span>
          <span className="mt-1 block text-[10.5px] text-fg-3">
            {uncounted
              ? "no line counts yet"
              : `${fmtInt(lines)} AI code lines ÷ ${fmtUSD(spend)}`}
          </span>
        </div>

        <div className="max-w-xl space-y-1 text-[10px] leading-relaxed text-fg-3">
          <p>
            Code lines the agent added or modified, divided by total spend over
            the same window. A ratio, not a rating - a low number can mean
            careful work on hard code, and a high one can mean boilerplate.
          </p>
          {uncounted && (
            <p>
              No line counts exist for this window. Run{" "}
              <code className="rounded-1 bg-bg-1 px-1 py-0.5 font-mono text-[9.5px] text-fg-2">
                observer backfill --loc
              </code>{" "}
              to populate history.
            </p>
          )}
          {!uncounted && noCost && (
            <p>
              No spend was recorded for this window, so there is nothing to
              divide by. Cost needs proxy or transcript token capture.
            </p>
          )}
          <p>
            Window: last {days} day{days === 1 ? "" : "s"}
            {windowLabel && ` (page window ${windowLabel})`} · all tools and
            projects.
            {filtered &&
              " Not narrowed by the tool or project filter: line counts are not filterable by either yet."}
          </p>
          {/* Honesty rule: with no editor reporting saves this counts only
              the agent's lines, so it must never be read as a whole-team
              output-per-dollar figure. The server owns the wording. */}
          {loc.data && loc.data.human_capture === "none" && (
            <p>{loc.data.capture_note}</p>
          )}
          {loc.data && loc.data.human_capture !== "none" && (
            <p>
              Human lines are excluded from this ratio; they are
              editor-reported (VS Code), not billed to the same spend.
            </p>
          )}
        </div>
      </div>
    </section>
  );
}

// fmtRatio keeps the quotient readable across three orders of magnitude
// without ever rendering Infinity or NaN (the caller has already guaranteed a
// positive denominator).
function fmtRatio(v: number): string {
  if (!Number.isFinite(v)) return "-";
  if (v >= 1000) return fmtInt(Math.round(v));
  if (v >= 10) return v.toFixed(0);
  if (v >= 1) return v.toFixed(1);
  return v.toFixed(2);
}
