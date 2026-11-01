import { Stagger, StatCard, Tooltip } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { TruncationBanner } from "@/components/projectdetail/TruncationBanner";
import { costLabel, dollarsShown, fmtInt, fmtPct, fmtUSD, withoutDollars } from "@/lib/format";
import type { ProjectDetail, ProjectRoiTile } from "@/lib/types";
import { CommitCaptureBanner } from "@/components/projectdetail/CommitCaptureBanner";
import { MetricIcon } from "@/components/MetricIcon";
import { CodeCommentSplit } from "@shared/primitives/CodeCommentSplit";

// OverviewTab — the Projects-detail landing tab (plan §3.5 OverviewTab).
// KPI band + the ROI proxy tiles, each carrying its own formula and caveat
// on its face (R5/R10: no metric renders without both). Deliberately
// ungraded and uncoloured — these are proxies for delivered value, not a
// score, so no tile uses a warn/danger tone to imply "bad".

export function OverviewTab({ d, onReload }: { d: ProjectDetail; onReload?: () => void }) {
  const aiLines = d.loc.ai_added + d.loc.ai_modified;
  const captureNotOk = d.capture.commits !== "ok";
  // A dollar-denominated proxy (usd, usd_per_line, usd_per_commit) has no
  // token form; the count / percent proxies stay.
  const roi = withoutDollars(d.roi, (t) => t.unit.startsWith("usd"));

  return (
    <div className="space-y-5">
      {captureNotOk && <CommitCaptureBanner projectId={d.project.id} capture={d.capture} onRescanned={onReload} />}
      {d.truncated && (
        <TruncationBanner>
          {costLabel(
            "Row caps hit: only the newest 10,000 prompts, 5,000 commits and 100,000 AI edits of this window feed the prompt-to-commit figures (commits linked, AI-touched files, attributed spend). Spend totals and per-session prompt counts are complete.",
            "Row caps hit: only the newest 10,000 prompts, 5,000 commits and 100,000 AI edits of this window feed the prompt-to-commit figures (commits linked, AI-touched files). Per-session prompt counts are complete.",
          )}
        </TruncationBanner>
      )}

      {/* The project's spend has no token count on this wire: in the org's
          token-usage view (format.ts cost affordances) the tile drops and the
          dollar-denominated ROI proxies with it. */}
      <Stagger className={dollarsShown() ? "grid grid-cols-2 gap-3 sm:grid-cols-4" : "grid grid-cols-2 gap-3 sm:grid-cols-3"}>
        {dollarsShown() && (
          <StatCard
            label="Spend"
            icon={<MetricIcon metric="spend" />}
            value={fmtUSD(d.spend.total_usd)}
            sub={
              d.spend.unpriced_turns
                ? `over ${d.window_days}d; ${fmtInt(d.spend.unpriced_turns)} turns unpriced (unknown model), excluded`
                : `over ${d.window_days}d`
            }
          />
        )}
        <StatCard label="Commits" icon={<MetricIcon metric="commits" />} value={fmtInt(d.commits.count)} sub={`${fmtInt(d.commits.ai_touched)} AI-touched`} />
        {/* AI code lines are code-category files only (docs/config lines are
            not code); the split below is the comment share of AI-authored
            lines, which needs no human measurement. */}
        <StatCard
          label="AI code lines"
          icon={<MetricIcon metric="aiCodeLines" />}
          value={fmtInt(aiLines)}
          sub={
            <span className="flex flex-col gap-0.5">
              <span>{`${fmtInt(d.loc.ai_added)} added, ${fmtInt(d.loc.ai_modified)} modified`}</span>
              {d.loc.ai_split && <CodeCommentSplit split={d.loc.ai_split} compact />}
            </span>
          }
        />
        {d.tasks.available ? (
          <StatCard label="Tasks" icon={<MetricIcon metric="tasks" />} value={`${fmtInt(d.tasks.done)}/${fmtInt(d.tasks.total)}`} sub={dollarsShown() ? `${fmtUSD(d.tasks.cost_usd)} attributed` : "done of total"} />
        ) : (
          <StatCard label="Tasks" icon={<MetricIcon metric="tasks" />} value="unavailable" sub="task rollup could not be loaded" />
        )}
      </Stagger>

      {d.loc.human_capture === "none" && (
        <p className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-[11px] text-fg-3">
          Human lines unmeasured for this project (no editor-reported saves) - no AI share is shown
          against it. Install the SuperBased VS Code extension to measure human-authored lines.
        </p>
      )}

      <div>
        <h3 className="mb-2 flex items-center text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          ROI proxies
          <HelpInd id="glossary.projects_roi_proxies" />
        </h3>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {roi.map((tile) => (
            <RoiTileCard key={tile.key} tile={tile} />
          ))}
          {roi.length === 0 && (
            <p className="col-span-full text-[11.5px] text-fg-3">
              No ROI proxies computed yet for this window.
            </p>
          )}
        </div>
      </div>

      <p className="text-[10.5px] text-fg-4">
        Commits reflect the checked-out branch (HEAD) of each project at scan time.
      </p>
    </div>
  );
}

function fmtRoiValue(tile: ProjectRoiTile): string {
  const { value, unit } = tile;
  if (!Number.isFinite(value)) return "-";
  // Dollar units: 2 decimals, escalating to 4 only for sub-cent amounts
  // that would otherwise round to $0.00 (the fmtTaskUSD rule).
  const usd = (v: number) => fmtUSD(v, v > 0 && v < 0.01);
  if (unit === "usd") return usd(value);
  if (unit === "usd_per_line") return `${fmtUSD(value, true)} / AI code line`;
  if (unit === "usd_per_commit") return `${usd(value)} / commit`;
  if (unit === "pct" || unit === "percent") return fmtPct(value);
  if (unit === "count" || unit === "ratio") {
    return Math.abs(value) >= 1000
      ? Math.round(value).toLocaleString("en-US")
      : Number.isInteger(value)
        ? value.toString()
        : value.toFixed(2);
  }
  const num =
    Math.abs(value) >= 1000
      ? Math.round(value).toLocaleString("en-US")
      : Number.isInteger(value)
        ? value.toString()
        : value.toFixed(2);
  return unit ? `${num} ${unit}` : num;
}

function RoiTileCard({ tile }: { tile: ProjectRoiTile }) {
  return (
    <div className="flex flex-col gap-1.5 rounded-3 border border-line-2 bg-bg-2 px-3.5 py-3">
      <div className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        {tile.label}
      </div>
      <div className="text-[20px] font-bold leading-none tracking-[-0.02em] text-fg-0">
        {tile.available ? fmtRoiValue(tile) : "-"}
      </div>
      <Tooltip content={<span className="font-mono text-[10.5px]">{tile.formula}</span>} maxWidth={360}>
        <div className="cursor-help truncate font-mono text-[10px] text-fg-4">{tile.formula}</div>
      </Tooltip>
      {(!tile.available || tile.caveat) && (
        <div className="text-[10.5px] text-fg-3">
          {!tile.available ? tile.caveat || "Not available for this project." : tile.caveat}
        </div>
      )}
    </div>
  );
}
