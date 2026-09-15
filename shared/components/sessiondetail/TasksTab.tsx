import type { ReactNode } from "react";
import { Tooltip } from "../../primitives";
import { ChartState } from "../../charts/ChartState";
import { fmtCompact, fmtElapsed, fmtInt, fmtTaskUSD } from "../../lib/format";
import type { RenderCost } from "./cost";
import type {
  ExtraTaskColumn,
  TaskCostBucketLike,
  TaskItemLike,
  TaskReportLike,
} from "../../lib/types";

// Tasks tab — "what did this agent's todo/plan checklist look like, and
// how much time/tokens/actions went into each item?" (docs/task-tracking.md).
// Backed by the node's GET /api/session/<id>/tasks (a re-decode of actions the
// session already captured, not a new capture surface) and by the org's
// projection of the same shape.
//
// PURE: this component fetches nothing and owns no data state. The caller
// passes the already-loaded `report` plus the loading/error flags; the node's
// @/components/sessiondetail/TasksTab wrapper does the useApi call, the org
// does its own. Cost cells go through the injected `renderCost` seam so the
// org can render <Money> (tokens / percent-of-cap) where the node renders USD.
//
// HONEST EMPTY STATE. has_tasks is false for the large majority of
// sessions (measured ~80% on the grounding corpus) — a session simply
// never called a todo/plan tool. That is the calm, designed default, not
// a degraded state, mirroring CacheTab's "no dependency" pattern.

// defaultTaskRenderCost is the node's behaviour: the bare task-scale dollar
// figure (fmtTaskUSD keeps sub-cent precision, since a single task is often
// worth fractions of a cent). Deliberately NOT the shared `defaultRenderCost`,
// which is the tooltip-wrapped fmtUSD used by the KPI/model panels — the task
// table never had a hover tooltip on its cost cells and must not grow one.
export const defaultTaskRenderCost: RenderCost = (usd) => fmtTaskUSD(usd);

export type TasksTabProps = {
  /** The loaded report, or null/undefined while it is still loading. */
  report: TaskReportLike | null | undefined;
  /** True while the first load is in flight (the caller's `loading && !data`). */
  loading?: boolean;
  /** Load error, if any. */
  error?: Error | null;
  /**
   * Whether token usage was captured for this session. The caller resolves it
   * (the node: `report.token_usage_available ?? hasRecordedUsage(detail)`).
   * False makes every token/cost cell read "Unavailable" instead of a zero.
   */
  usageAvailable: boolean;
  /** Cost renderer; defaults to the node's compact USD figure. */
  renderCost?: RenderCost;
  /** App-supplied columns appended after Cost. Absent => node columns only. */
  extraColumns?: ExtraTaskColumn[];
  /** Extra content rendered under the caveat block (e.g. an org gate notice). */
  footer?: ReactNode;
};

export function TasksTab({
  report,
  loading = false,
  error = null,
  usageAvailable,
  renderCost = defaultTaskRenderCost,
  extraColumns,
  footer,
}: TasksTabProps) {
  return (
    <div className="mt-5">
      <ChartState
        loading={loading && !report}
        error={error}
        empty={!report}
        emptyHint="Loading task report…"
        height={100}
      >
        {report && (
          <TasksBody
            data={report}
            usageAvailable={usageAvailable}
            renderCost={renderCost}
            extraColumns={extraColumns}
            footer={footer}
          />
        )}
      </ChartState>
    </div>
  );
}

function TasksBody({
  data,
  usageAvailable,
  renderCost,
  extraColumns,
  footer,
}: {
  data: TaskReportLike;
  usageAvailable: boolean;
  renderCost: RenderCost;
  extraColumns?: ExtraTaskColumn[];
  footer?: ReactNode;
}) {
  if (!data.has_tasks) {
    return (
      <p className="rounded-3 border border-dashed border-line-2 px-4 py-3 text-[11.5px] text-fg-3">
        No task tracking for this session — it never called a todo/plan tool
        (<span className="font-mono">TaskCreate</span>/
        <span className="font-mono">TodoWrite</span>/
        <span className="font-mono">update_plan</span>/etc.). Most sessions
        don't; this is the normal case, not a gap.
      </p>
    );
  }

  // Default sort: cost descending, elapsed as tiebreak — measured on the
  // grounding corpus that 51% of tasks are sub-minute flips, so cost is
  // the more informative primary ordering.
  const items = [...(data.items ?? [])].sort(
    (a, b) => b.cost_usd - a.cost_usd || b.elapsed_seconds - a.elapsed_seconds,
  );

  const extras = extraColumns ?? [];
  // 720 is the node's built-in min-width budget; each extra column adds its
  // own px contribution (default 90), exactly like MessagesTable. With no
  // extra columns the node's original `min-w-[720px]` utility class is used
  // verbatim so the node markup is unchanged.
  const extraWidth = extras.reduce((sum, c) => sum + (c.width ?? 90), 0);

  return (
    <div className="space-y-2">
      {!usageAvailable && (
        <p className="text-[11.5px] text-fg-3">No token usage was captured for these tasks. Their statuses and elapsed times are available; token counts and costs are unknown.</p>
      )}
      <div className="overflow-x-auto rounded-3 border border-line-2">
        <table
          className={
            extraWidth === 0
              ? "w-full min-w-[720px] text-left text-[11.5px]"
              : "w-full text-left text-[11.5px]"
          }
          style={extraWidth === 0 ? undefined : { minWidth: 720 + extraWidth }}
        >
          <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
            <tr className="border-b border-line-2">
              <th className="py-1.5 pl-2 font-medium">Task</th>
              <th className="py-1.5 font-medium">Status</th>
              <th className="py-1.5 text-right font-medium">Elapsed</th>
              <th className="py-1.5 text-right font-medium">Actions</th>
              <th className="py-1.5 text-right font-medium">
                Tokens (in / out)
              </th>
              <th
                className={
                  extras.length === 0
                    ? "py-1.5 pr-2 text-right font-medium"
                    : "py-1.5 text-right font-medium"
                }
              >
                Cost
              </th>
              {extras.map((c, i) => (
                <th
                  key={c.id}
                  className={[
                    "py-1.5 font-medium",
                    c.align === "left" ? "text-left" : "text-right",
                    i === extras.length - 1 ? "pr-2" : "",
                  ]
                    .filter(Boolean)
                    .join(" ")}
                >
                  {c.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {items.map((it) => (
              <TaskRow
                key={it.key}
                item={it}
                usageAvailable={usageAvailable}
                renderCost={renderCost}
                extras={extras}
              />
            ))}
            <BucketRow
              label="between tasks"
              bucket={data.between_tasks}
              usageAvailable={usageAvailable}
              renderCost={renderCost}
              extras={extras}
            />
            <BucketRow
              label="shared"
              bucket={data.shared}
              usageAvailable={usageAvailable}
              renderCost={renderCost}
              extras={extras}
            />
            {data.sidechain && (
              <BucketRow
                label="sub-agent (sidechain)"
                bucket={data.sidechain}
                renderCost={renderCost}
                extras={extras}
              />
            )}
          </tbody>
        </table>
      </div>

      <div className="space-y-1 px-1 text-[10.5px] text-fg-3">
        <p>
          <span className="font-medium text-fg-2">between tasks</span> = no
          task was in progress when that usage happened.{" "}
          <span className="font-medium text-fg-2">shared</span> = two or more
          tasks were in progress at once (bucketed together, never split
          evenly). Only ~52% of a session's usage attributes to one specific
          task on average — these are first-class totals here, not a
          rounding residue.
        </p>
        {data.sidechain && (
          <p>
            <span className="font-medium text-fg-2">
              sub-agent (sidechain)
            </span>{" "}
            usage is reported separately, never folded into any task above —
            a sub-agent's free-text owner name can't be resolved to the
            actual spawned session.
          </p>
        )}
        {data.unmatched_count > 0 && !data.all_keys_native && (
          <p>
            {data.unmatched_count} item{data.unmatched_count === 1 ? "" : "s"}{" "}
            could not be matched across updates (the tool has no stable id —
            text changed between snapshots).
          </p>
        )}
        {data.cost_note && <p>{data.cost_note}</p>}
        {footer}
      </div>
    </div>
  );
}

function statusLabel(item: TaskItemLike): string {
  const base = item.status || item.raw_status || "unknown";
  if (item.still_open) return `${base} (open)`;
  if (item.never_activated) {
    // NeverActivated means "closed without ever passing through
    // in_progress" — the closing status can be completed, cancelled,
    // deleted, or the synthetic "vanished", independent of
    // never_activated itself. Render the real terminal_status rather
    // than hardcoding "completed": a cancelled- or vanished-before-
    // started task previously lied and said "completed (never
    // activated)".
    return `${item.terminal_status || base} (never activated)`;
  }
  return base;
}

// VANISHED_GLOSS explains taskflow.StatusVanished — a synthetic status
// no vendor ever emits (docs/task-tracking.md): a whole-list-rewrite
// snapshot stopped listing an item that was last-known in_progress, so
// its open window is closed at the last sighting rather than left open
// forever. Distinct from a real completion or cancellation.
const VANISHED_GLOSS =
  "dropped from the list while in progress — a later snapshot no longer listed it, so this isn't a real completion or cancellation.";

function statusGloss(item: TaskItemLike): string | null {
  if (item.terminal_status === "vanished" || item.status === "vanished") {
    return VANISHED_GLOSS;
  }
  return null;
}

function TaskRow({
  item,
  usageAvailable,
  renderCost,
  extras,
}: {
  item: TaskItemLike;
  usageAvailable: boolean;
  renderCost: RenderCost;
  extras: ExtraTaskColumn[];
}) {
  const elapsedLabel =
    item.elapsed_seconds > 0
      ? fmtElapsed(Math.round(item.elapsed_seconds))
      : "-";
  return (
    <tr className="border-b border-line-1 last:border-b-0 hover:bg-bg-3/40">
      <Tooltip
        content={<span className="break-words">{item.content}</span>}
        maxWidth={360}
      >
        <td
          tabIndex={0}
          title={item.content}
          className="max-w-[260px] cursor-help truncate py-1.5 pl-2 text-fg-1 focus:outline-none"
        >
          {item.content || "(no text)"}
        </td>
      </Tooltip>
      <td className="py-1.5 text-fg-2">
        {statusGloss(item) ? (
          <Tooltip content={<span>{statusGloss(item)}</span>} maxWidth={280}>
            <span
              tabIndex={0}
              className="cursor-help underline decoration-dotted decoration-fg-4 focus:outline-none"
            >
              {statusLabel(item)}
            </span>
          </Tooltip>
        ) : (
          statusLabel(item)
        )}
      </td>
      <td className="py-1.5 text-right tabular-nums text-fg-2">
        {elapsedLabel}
      </td>
      <td className="py-1.5 text-right tabular-nums text-fg-2">
        {fmtInt(item.actions_count)}
      </td>
      <td className="py-1.5 text-right tabular-nums text-fg-2">
        {usageAvailable ? `${fmtCompact(item.tokens.input_tokens)} / ${fmtCompact(item.tokens.output_tokens)}` : "Unavailable"}
      </td>
      <td
        className={
          extras.length === 0
            ? "py-1.5 pr-2 text-right tabular-nums text-fg-1"
            : "py-1.5 text-right tabular-nums text-fg-1"
        }
      >
        {!usageAvailable ? "Unavailable" : item.unpriced ? (
          <span className="text-fg-3">unpriced</span>
        ) : (
          renderCost(item.cost_usd, {
            kind: "total",
            tokens: taskTokenTotal(item),
          })
        )}
      </td>
      {extras.map((c, i) => (
        <td
          key={c.id}
          className={[
            "py-1.5 text-fg-2",
            c.align === "left" ? "text-left" : "text-right tabular-nums",
            i === extras.length - 1 ? "pr-2" : "",
          ]
            .filter(Boolean)
            .join(" ")}
        >
          {c.render(item)}
        </td>
      ))}
    </tr>
  );
}

function BucketRow({
  label,
  bucket,
  usageAvailable = true,
  renderCost,
  extras,
}: {
  label: string;
  bucket: TaskCostBucketLike;
  usageAvailable?: boolean;
  renderCost: RenderCost;
  extras: ExtraTaskColumn[];
}) {
  return (
    <tr className="border-t border-line-2 bg-bg-1/60 last:border-b-0">
      <td className="py-1.5 pl-2 italic text-fg-3">{label}</td>
      <td className="py-1.5 text-fg-4">—</td>
      <td className="py-1.5 text-right text-fg-4">—</td>
      <td className="py-1.5 text-right tabular-nums text-fg-2">
        {fmtInt(bucket.actions_count)}
      </td>
      <td className="py-1.5 text-right tabular-nums text-fg-2">
        {usageAvailable ? `${fmtCompact(bucket.tokens.input_tokens)} / ${fmtCompact(bucket.tokens.output_tokens)}` : "Unavailable"}
      </td>
      <td
        className={
          extras.length === 0
            ? "py-1.5 pr-2 text-right tabular-nums text-fg-1"
            : "py-1.5 text-right tabular-nums text-fg-1"
        }
      >
        {!usageAvailable ? "Unavailable" : bucket.unpriced ? (
          <span className="text-fg-3">unpriced</span>
        ) : (
          renderCost(bucket.cost_usd, {
            kind: "total",
            tokens: taskTokenTotal(bucket),
          })
        )}
      </td>
      {extras.map((c, i) => (
        <td
          key={c.id}
          className={[
            "py-1.5 text-fg-2",
            c.align === "left" ? "text-left" : "text-right tabular-nums",
            i === extras.length - 1 ? "pr-2" : "",
          ]
            .filter(Boolean)
            .join(" ")}
        >
          {c.renderBucket ? c.renderBucket(bucket, label) : "—"}
        </td>
      ))}
    </tr>
  );
}

// taskTokenTotal is the token count behind one bucket's cost figure — the
// context the org's <Money> renderer reads to show tokens instead of dollars.
// The node's defaultRenderCost ignores it.
function taskTokenTotal(b: TaskCostBucketLike): number {
  const t = b.tokens;
  return (
    (t.input_tokens || 0) +
    (t.output_tokens || 0) +
    (t.cache_read_tokens || 0) +
    (t.cache_write_tokens || 0)
  );
}

// fmtTaskUSD is re-exported so a caller that wants the node's task-scale money
// formatting (sub-cent precision) in its own renderCost has one import site.
export { fmtTaskUSD };
