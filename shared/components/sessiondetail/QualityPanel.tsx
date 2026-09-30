import type { ReactNode } from "react";
import { Pill } from "../../primitives";
import { vocabIcon } from "../../lib/vocabIcons";
import { ChartState } from "../../charts/ChartState";
import { fmtInt, fmtRelative, fmtDateTime } from "../../lib/format";
import {
  freshnessNote,
  qualityBand,
  qualityComponents,
  unscoredMessage,
  type QualityComponent,
  type SessionQualityLike,
} from "../../lib/sessionQuality";

// QualityPanel - the session quality score (spec §15.2) as one card: the
// 0-100 score with its band, the four weighted components that add up to it,
// and the token/turn side metrics the scorer records alongside. The node
// drawer renders it over GET /api/session/<id>/quality; the org drawer renders
// the same card over GET /api/org/sessions/<id>/quality, read-only.
//
// PURE: the caller fetches and passes the result plus load flags. `action` is
// a slot for an app-owned control (the node passes its "Score now" button;
// the org passes none); nothing here posts, routes or reads app state.
// Wording and arithmetic live in lib/sessionQuality.ts.

export type QualityPanelProps = {
  quality: SessionQualityLike | null | undefined;
  loading?: boolean;
  error?: Error | null;
  /** The read was a denial (HTTP 403, the apps' useApi `denied`): the panel
   *  renders the shared permission-denied state instead of an error. */
  denied?: boolean;
  /** The permission key the server's 403 named, when it named one. */
  deniedPermission?: string | null;
  action?: ReactNode;
  className?: string;
};

const TONE_FILL: Record<string, string> = {
  success: "bg-success",
  warn: "bg-warn",
  danger: "bg-danger",
};

export function QualityPanel({
  quality,
  loading = false,
  error = null,
  denied = false,
  deniedPermission = null,
  action,
  className,
}: QualityPanelProps) {
  const q = quality ?? null;
  const band = q?.scored && q.quality_score != null ? qualityBand(q.quality_score) : null;
  return (
    <section className={"rounded-3 border border-line-2 bg-bg-2 px-4 py-3 " + (className ?? "")}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Session quality
          {band && (
            <Pill variant={band.tone} icon={vocabIcon("qualityBand", band.label)}>
              {band.label}
            </Pill>
          )}
        </span>
        <span className="flex items-center gap-2">
          {q?.scored && q.scored_at && (
            <span className="text-[10px] text-fg-3" title={fmtDateTime(q.scored_at)}>
              scored {fmtRelative(q.scored_at)}
            </span>
          )}
          {action}
        </span>
      </div>
      <p className="mt-1 text-[10.5px] text-fg-3">
        A local, rule-based grade of how efficiently the agent worked: repeat reads, failed tool calls, how much of
        what it looked at it went on to change, and how long it kept going. No model is involved.
      </p>
      <ChartState
        loading={loading && !q}
        error={error}
        empty={false}
        height={96}
        denied={denied}
        deniedPermission={deniedPermission}
      >
        {q && (q.scored && q.quality_score != null ? <ScoredBody q={q} score={q.quality_score} tone={band?.tone ?? "warn"} /> : (
          <div className="mt-2 rounded-2 border border-line-2 bg-bg-1 px-3 py-2.5 text-[10.5px] leading-relaxed text-fg-3">
            {unscoredMessage(q)}
          </div>
        ))}
      </ChartState>
    </section>
  );
}

function ScoredBody({ q, score, tone }: { q: SessionQualityLike; score: number; tone: string }) {
  const comps = qualityComponents(q);
  const note = freshnessNote(q);
  const w = q.weights;
  return (
    <div className="mt-2.5 space-y-3">
      <div className="flex flex-wrap items-end gap-4">
        <div>
          <div className="text-[28px] font-semibold leading-none tabular-nums text-fg-1">
            {Math.round(score * 100)}
            <span className="ml-1 text-[12px] font-normal text-fg-3">/ 100</span>
          </div>
          <div className="mt-1 h-1.5 w-40 overflow-hidden rounded-full bg-bg-3">
            <div className={"h-full " + (TONE_FILL[tone] ?? "bg-accent")} style={{ width: `${clampPct(score)}%` }} />
          </div>
        </div>
        <SideFacts q={q} />
      </div>

      <div className="space-y-1.5">
        {comps.map((c) => (
          <ComponentRow key={c.key} c={c} />
        ))}
      </div>

      {note && (
        <p className="rounded-2 border border-line-2 bg-bg-1 px-2.5 py-1.5 text-[10px] leading-relaxed text-fg-3">{note}</p>
      )}
      <p className="text-[10px] text-fg-4">
        score = {pct(w.redundancy)} low redundancy + {pct(w.error)} tool success + {pct(w.exploration)} exploration +{" "}
        {pct(w.continuity)} continuity
      </p>
    </div>
  );
}

function ComponentRow({ c }: { c: QualityComponent }) {
  const recorded = c.goodness != null && c.points != null;
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_96px_72px] items-center gap-3">
      <div className="min-w-0">
        <div className="truncate text-[11px] text-fg-2">{c.label}</div>
        <div className="truncate text-[10px] text-fg-4">{c.hint}</div>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-bg-3">
        {recorded && <div className="h-full bg-accent" style={{ width: `${clampPct(c.goodness ?? 0)}%` }} />}
      </div>
      <div className="text-right text-[10.5px] tabular-nums text-fg-2">
        {recorded ? (
          <>
            {(c.points! * 100).toFixed(1)}
            <span className="text-fg-4"> / {Math.round(c.weight * 100)}</span>
          </>
        ) : (
          <span className="text-fg-4" title="Not recorded by the version that scored this session">
            not recorded
          </span>
        )}
      </div>
    </div>
  );
}

// SideFacts are the scorer's side metrics. Each renders only when recorded.
function SideFacts({ q }: { q: SessionQualityLike }) {
  const facts: { label: string; value: string; title: string }[] = [];
  if (q.turns_to_first_edit != null) {
    facts.push({ label: "Turn of first edit", value: fmtInt(q.turns_to_first_edit), title: "Turn index of the first file edit or write" });
  } else if (q.scored_action_count != null) {
    facts.push({ label: "Turn of first edit", value: "no edits", title: "The session never edited or wrote a file" });
  }
  if (q.onboarding_cost != null) {
    facts.push({ label: "Tokens before first edit", value: fmtInt(q.onboarding_cost), title: "Input + output tokens spent before the first edit (all of them when nothing was edited)" });
  }
  if (q.retry_cost_tokens != null) {
    facts.push({ label: "Tokens after failures", value: fmtInt(q.retry_cost_tokens), title: "Input + output tokens in the 5 minutes after each failed tool call - a rough retry cost" });
  }
  if (q.stale_reads_wasteful != null || q.stale_reads_necessary != null) {
    facts.push({
      label: "Stale re-reads",
      value: `${fmtInt(q.stale_reads_wasteful ?? 0)} avoidable / ${fmtInt(q.stale_reads_necessary ?? 0)} needed`,
      title: "Avoidable: the prior copy was still in the prompt cache. Needed: a compaction or cache expiry had evicted it.",
    });
  }
  if (facts.length === 0) return null;
  return (
    <div className="grid flex-1 grid-cols-2 gap-x-4 gap-y-1.5 sm:grid-cols-4">
      {facts.map((f) => (
        <div key={f.label} title={f.title} className="min-w-0">
          <div className="truncate text-[10px] text-fg-4">{f.label}</div>
          <div className="truncate text-[12px] tabular-nums text-fg-1">{f.value}</div>
        </div>
      ))}
    </div>
  );
}

function clampPct(fraction: number): number {
  return Math.max(0, Math.min(100, fraction * 100));
}

function pct(w: number): string {
  return `${Math.round(w * 100)}%`;
}
