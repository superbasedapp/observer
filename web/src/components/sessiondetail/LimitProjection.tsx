import clsx from "clsx";
import type { ReactNode } from "react";
import { InfoDisclosure, Meter, Pill, Tooltip } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { dollarsShown, fmtCompact } from "@/lib/format";
import {
  amount,
  baseName,
  confidenceText,
  fmtWhen,
  joinParts,
  mixText,
  money,
  noteText,
  paceText,
  pct,
  projectionHeadline,
  projectionTitle,
  promptsText,
  relUnix,
  sourceLabel,
  trendText,
  type HeadlineTone,
} from "@/lib/limitProjection";
import type { PredictProjection, Projection } from "@/lib/types";

// LimitProjection renders the run-out projection inside the predictor card:
// one compact block per limit window (weekly first, then the 5-hour window)
// and, when a budget is in force, one per budget. Each block leads with one
// sentence, then a meter of used against the window elapsed, then four
// stats; the long tail sits behind "All stats" so the card stays scannable.
// Every number that rests on an assumption carries "est." with its formula
// in a tooltip. The wording lives in lib/limitProjection.ts.

const TONE_TEXT: Record<HeadlineTone, string> = {
  neutral: "text-fg-1",
  success: "text-success",
  warn: "text-warn",
  danger: "text-danger",
};

/** Est marks an estimate; the tooltip carries the formula. */
function Est({ formula }: { formula: string }) {
  return (
    <Tooltip maxWidth={320} content={formula}>
      <span tabIndex={0} className="ml-1 text-[9.5px] font-medium text-fg-3 underline decoration-dotted underline-offset-2 focus:outline-none">
        est.
      </span>
    </Tooltip>
  );
}

function Stat({ label, value, sub, est }: { label: string; value: string; sub?: string | null; est?: string }) {
  return (
    <div className="flex min-w-0 flex-col">
      <span className="text-[10px] font-medium uppercase tracking-[0.05em] text-fg-3">{label}</span>
      <span className="tabular-nums text-[12.5px] font-semibold text-fg-1">
        {value}
        {est && <Est formula={est} />}
      </span>
      {sub && <span className="mt-0.5 truncate text-[10px] text-fg-3">{sub}</span>}
    </div>
  );
}

/** UsedMeter: the share used, with a tick where an even spread would be now. */
function UsedMeter({ used, elapsed, tone }: { used: number; elapsed?: number; tone: "accent" | "warn" | "danger" }) {
  return (
    <div className="relative mt-1.5" title={elapsed != null ? `Used ${pct(used)} with ${pct(elapsed)} of the window gone` : undefined}>
      <Meter ratio={Math.min(1, used)} tone={tone} label={`Used ${pct(used)}`} />
      {elapsed != null && (
        <span
          aria-hidden
          className="absolute -top-0.5 h-2.5 w-0.5 rounded-pill bg-fg-2"
          style={{ left: `calc(${Math.min(1, Math.max(0, elapsed)) * 100}% - 1px)` }}
        />
      )}
    </div>
  );
}

type Row = [label: string, value: ReactNode];

/** allStatsRows is the long tail, only the rows with something true to say. */
function allStatsRows(p: Projection, countedTools: string[] | undefined, now: number): Row[] {
  const rows: (Row | null)[] = [];
  const add = (label: string, value: string | null | undefined, est?: string) => {
    if (value) rows.push([label, est ? <>{value}<Est formula={est} /></> : value]);
  };
  const isLimit = p.kind === "limit";
  if (p.state === "reset" || p.state === "no_reset_time") {
    // The window cannot be placed: only the reading itself is true to show.
    add("Reading", joinParts(p.used_frac != null ? `${pct(p.used_frac)} used` : null, sourceLabel(p.source), p.observed_at_unix != null ? relUnix(p.observed_at_unix, now) : null) || null);
    return rows.filter((r): r is Row => r !== null);
  }
  add(
    "Window",
    p.window_start_unix != null
      ? joinParts(
          `${fmtWhen(p.window_start_unix, now)} to ${p.resets_at_unix != null ? fmtWhen(p.resets_at_unix, now) : "now"}`,
          p.window_inferred ? "start inferred" : null,
        )
      : p.state === "session"
        ? "this session"
        : null,
  );
  add("Time to reset", p.resets_at_unix != null ? relUnix(p.resets_at_unix, now) : null);
  add("Window elapsed", p.elapsed_frac != null ? pct(p.elapsed_frac) : null);
  add(
    "Used",
    joinParts(
      p.used_frac_est != null ? pct(p.used_frac_est) : null,
      isLimit ? `${fmtCompact(p.used.tokens)} tok` : amount(p, p.spent),
      isLimit && dollarsShown() ? money(p.used.cost_usd) : null,
    ) || null,
    p.used_frac_is_estimate ? "The reading carried forward: reading + tokens captured since the reading / estimated limit size." : undefined,
  );
  add("Pace", paceText(p));
  if (p.burn) {
    const b = p.burn;
    add("Burn per hour", joinParts(b.frac_per_hour ? pct(b.frac_per_hour) : null, `${fmtCompact(b.tokens_per_hour)} tok`, dollarsShown() ? money(b.usd_per_hour) : null));
    add("Burn per day", joinParts(b.frac_per_day ? pct(b.frac_per_day) : null, `${fmtCompact(b.tokens_per_day)} tok`, dollarsShown() ? money(b.usd_per_day) : null), `Averaged over the ${b.basis_hours}h of this window so far.`);
  }
  const ro = p.run_out;
  if (ro?.runs_out_at_unix != null) add("Runs out", `${fmtWhen(ro.runs_out_at_unix, now)} at this rate`, "Now + share left / share used per hour.");
  if (ro?.projected_left_at_reset_frac != null) add("Left at reset", pct(ro.projected_left_at_reset_frac), "1 - (share used + share per hour x hours to reset).");
  if (ro?.safe_per_day_frac != null) {
    add(
      p.key === "5h" ? "Safe per hour" : "Safe per day",
      p.key === "5h"
        ? joinParts(pct(ro.safe_per_hour_frac), ro.safe_per_hour_tokens != null ? `${fmtCompact(ro.safe_per_hour_tokens)} tok` : null, dollarsShown() ? money(ro.safe_per_hour_usd) : null)
        : joinParts(pct(ro.safe_per_day_frac), ro.safe_per_day_tokens != null ? `${fmtCompact(ro.safe_per_day_tokens)} tok` : null, dollarsShown() ? money(ro.safe_per_day_usd) : null),
      p.state === "rolling" ? "The cap spread evenly over 7 days." : "What is left, spread evenly over the time to reset.",
    );
  }
  if (isLimit && p.capacity_tokens_est != null) {
    add("Whole limit", joinParts(`${fmtCompact(p.capacity_tokens_est)} tok`, dollarsShown() ? money(p.capacity_usd_est) : null), "Captured usage in the window / share used.");
  }
  const s = p.sessions;
  if (s) {
    add("Sessions in window", String(s.count));
    add("This session", joinParts(money(s.this_usd, s.this_tokens), s.this_share != null ? `${pct(s.this_share)} of the window` : null));
    add("Average session", money(s.avg_usd, s.avg_tokens));
  }
  if (p.more_sessions_est != null) add("More sessions", `about ${p.more_sessions_est}`, "What is left / the window's average session.");
  add("More prompts", promptsText(p), "What is left / the predictor's next-message cost (typical, with high and low messages).");
  if (p.five_hour_windows_left != null) add("5-hour windows left", `${p.five_hour_windows_left} before the weekly reset`);
  add("Trend", trendText(p));
  add("Token mix", mixText(p));
  if (p.top_models?.length) add("Top models", p.top_models.map((c) => `${c.name} ${pct(c.share)}`).join(", "));
  if (p.top_projects?.length) add("Top projects", p.top_projects.map((c) => `${baseName(c.name)} ${pct(c.share)}`).join(", "));
  add(
    "Counted",
    isLimit
      ? `Input, cache reads and writes, output and reasoning of ${(countedTools ?? []).join(", ") || "this tool's"} sessions captured here, through the proxy or not.`
      : "Input and output tokens, the way the budget counts them.",
  );
  if (isLimit) {
    add(
      "Reading",
      joinParts(sourceLabel(p.source), p.observed_at_unix != null ? relUnix(p.observed_at_unix, now) : null) || null,
    );
  } else {
    add("Budget", joinParts(p.scope ? p.scope.replace(":", " ") : null, p.enforcement === "hard" ? "blocks at 100%" : "warns only"));
  }
  add("Confidence", confidenceText(p));
  return rows.filter((r): r is Row => r !== null);
}

function headlineStats(p: Projection, now: number): ReactNode {
  const isLimit = p.kind === "limit";
  const stats: ReactNode[] = [];
  if (p.state === "reset" || p.state === "no_reset_time") return null;
  if (p.state === "reset_inferred") {
    stats.push(<Stat key="u" label="Used here" value={`${fmtCompact(p.used.tokens)} tok`} sub={dollarsShown() ? money(p.used.cost_usd) : null} est="This machine's captured usage since the inferred window start; the share of the limit is unknown until a new reading." />);
    stats.push(<Stat key="s" label="Sessions" value={String(p.used.sessions)} />);
    if (p.burn) stats.push(<Stat key="b" label="Per day" value={`${fmtCompact(p.burn.tokens_per_day)} tok`} sub={dollarsShown() ? money(p.burn.usd_per_day) : null} />);
  } else {
    const used = p.used_frac_est ?? p.used_frac;
    stats.push(
      <Stat
        key="u"
        label="Used"
        value={pct(used) || "?"}
        sub={isLimit ? joinParts(`${fmtCompact(p.used.tokens)} tok`, dollarsShown() ? money(p.used.cost_usd) : null) : amount(p, p.spent)}
        est={p.used_frac_is_estimate ? "Reading + tokens captured since the reading / estimated limit size." : undefined}
      />,
    );
    const leftSub = p.kind === "budget" && p.unit === "tokens"
      ? joinParts(p.left_tokens != null ? `${fmtCompact(p.left_tokens)} tok` : null, dollarsShown() ? money(p.left_usd) : null)
      : money(p.left_usd, p.left_tokens);
    stats.push(
      <Stat
        key="l"
        label="Left"
        value={pct(p.left_frac) || "?"}
        sub={leftSub ? `about ${leftSub}` : null}
        est={p.left_tokens_is_estimate || p.left_usd_is_estimate ? "Whole limit or cap x share left; a size the cap does not state is derived from captured usage." : undefined}
      />,
    );
    if (p.burn) {
      const perHour = p.key === "5h";
      stats.push(
        <Stat
          key="b"
          label={perHour ? "Burn per hour" : "Burn per day"}
          value={pct(perHour ? p.burn.frac_per_hour : p.burn.frac_per_day) || `${fmtCompact(perHour ? p.burn.tokens_per_hour : p.burn.tokens_per_day)} tok`}
          sub={perHour ? money(p.burn.usd_per_hour, p.burn.tokens_per_hour) : money(p.burn.usd_per_day, p.burn.tokens_per_day)}
          est={`Share used / ${p.burn.basis_hours}h elapsed in the window.`}
        />,
      );
    } else if (p.state !== "session") {
      stats.push(<Stat key="b" label="Burn" value="Not yet" sub="under an hour or nothing used" />);
    }
    if (p.more_prompts) {
      stats.push(<Stat key="p" label="Prompts left" value={`~${p.more_prompts.mid >= 10 ? Math.floor(p.more_prompts.mid) : p.more_prompts.mid}`} sub={promptsText(p)} est="What is left / the predictor's typical next-message cost." />);
    }
  }
  if (p.resets_at_unix != null && stats.length < 4) {
    stats.push(<Stat key="r" label="Resets" value={relUnix(p.resets_at_unix, now)} sub={fmtWhen(p.resets_at_unix, now)} />);
  }
  return <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-2 sm:grid-cols-4">{stats.slice(0, 4)}</div>;
}

/** ProjectionBlock is one limit window's or budget's projection. */
export function ProjectionBlock({
  p,
  countedTools,
  allOpen,
  nowMs,
}: {
  p: Projection;
  countedTools?: string[];
  /** Open "All stats" initially (tests and the narrow layout's preview). */
  allOpen?: boolean;
  nowMs?: number;
}) {
  const now = nowMs ?? Date.now();
  const h = projectionHeadline(p, now);
  const used = p.used_frac_est ?? p.used_frac;
  const meterTone = p.run_out?.exhausted ? "danger" : p.pace?.verdict === "ahead" || p.run_out?.runs_out_at_unix != null ? "warn" : "accent";
  const rows = allStatsRows(p, countedTools, now);
  const notes = (p.notes ?? []).filter((n) => n !== "exhausted").map(noteText).filter(Boolean);
  return (
    <div className="border-t border-line-1 pt-2 first:border-t-0 first:pt-0" data-projection={`${p.kind}-${p.key}`}>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-[10px] font-medium uppercase tracking-[0.05em] text-fg-3">{projectionTitle(p)}</span>
        {p.window_inferred && <Pill variant="neutral">window inferred</Pill>}
        {p.confidence === "low" && <Pill variant="neutral">low confidence</Pill>}
      </div>
      <p className={clsx("mt-0.5 text-[12px] font-semibold leading-snug", TONE_TEXT[h.tone])}>{h.text}</p>
      {h.sub && <p className="mt-0.5 text-[10.5px] text-fg-3">{h.sub}</p>}
      {used != null && p.state !== "reset" && p.state !== "reset_inferred" && (
        <UsedMeter used={used} elapsed={p.elapsed_frac} tone={meterTone} />
      )}
      {headlineStats(p, now)}
      {(rows.length > 0 || notes.length > 0) && (
        <InfoDisclosure summary="All stats" defaultOpen={allOpen} persistKey={allOpen ? undefined : "predict-projection-all-stats"} className="mt-2">
          <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-3 gap-y-1 text-[10.5px]">
            {rows.map(([label, value]) => (
              <div key={label} className="contents">
                <dt className="text-fg-3">{label}</dt>
                <dd className="min-w-0 break-words tabular-nums text-fg-2">{value}</dd>
              </div>
            ))}
          </dl>
          {notes.length > 0 && (
            <ul className="mt-1.5 list-disc space-y-0.5 pl-4 text-[10.5px] text-fg-3">
              {notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          )}
        </InfoDisclosure>
      )}
    </div>
  );
}

/** LimitProjectionList renders the limit windows' projections (weekly first). */
export function LimitProjectionList({ projection, allOpen, nowMs }: { projection?: PredictProjection; allOpen?: boolean; nowMs?: number }) {
  const limits = projection?.limits ?? [];
  if (limits.length === 0) return null;
  return (
    <div className="mt-2.5 space-y-2.5 border-t border-line-1 pt-2.5" aria-label="Run-out projection">
      <div className="flex items-center gap-1.5">
        <span className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">Run-out projection</span>
        <HelpInd id="glossary.limit_projection" />
      </div>
      {limits.map((p) => (
        <ProjectionBlock key={p.key} p={p} countedTools={projection?.counted_tools} allOpen={allOpen} nowMs={nowMs} />
      ))}
    </div>
  );
}

/** BudgetProjectionSection is absent when no budget is in force: no budget
 *  is never shown as "under budget". */
export function BudgetProjectionSection({ projection, allOpen, nowMs }: { projection?: PredictProjection; allOpen?: boolean; nowMs?: number }) {
  const budgets = projection?.budgets ?? [];
  if (budgets.length === 0) return null;
  return (
    <div className="rounded-3 border bg-bg-1 px-3 py-2.5" aria-label="Budget projection">
      <div className="flex items-center gap-1.5">
        <span className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">Budget</span>
        <HelpInd id="glossary.budget_projection" />
        {budgets.length > 1 && <span className="text-[10px] text-fg-3">· tightest first</span>}
      </div>
      <div className="mt-1.5 space-y-2.5">
        {budgets.map((p, i) => (
          <ProjectionBlock key={`${p.origin}-${p.key}-${p.unit}-${p.subject ?? ""}-${i}`} p={p} allOpen={allOpen} nowMs={nowMs} />
        ))}
      </div>
    </div>
  );
}
