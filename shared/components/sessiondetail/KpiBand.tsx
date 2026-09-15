import { Fragment, type ReactNode } from "react";
import clsx from "clsx";
import { BigStat, Tooltip } from "../../primitives";
import { ClockIcon, DollarIcon, LayersIcon, LightningIcon } from "../../lib/icons";
import { fmtCompact, fmtDuration, fmtInt } from "../../lib/format";
import { elapsedMillis, elapsedSub } from "../../lib/sessionElapsed";
import { defaultRenderCost, type RenderCost } from "./cost";

// KpiBand — the four always-visible session-detail tiles (cost / actions /
// elapsed / tokens). Promoted into the shared design system so the node and
// org drawers render the same headline band above the tab strip.
//
// It takes PLAIN numbers/strings rather than a node SessionDetail, so the org
// can feed it from its own rollup row, and a `renderCost` slot so the org
// renders the three cost figures through its <Money> formatter (tokens /
// percent-of-cap) instead of bare USD. The node maps SessionDetail -> props in
// its shim.

export type KpiBandProps = {
  // Total / API / Tool cost for this session, in USD.
  cost: number;
  aiCost: number;
  toolCost: number;
  // Action counts. `ungraded` (events that are neither ok nor failed) is
  // derived as total - success - failure.
  totalActions: number;
  successActions: number;
  failureActions: number;
  // Sum of net input + cache read + cache write + output tokens.
  totalTokens: number;
  // Optional context-budget estimate shown when there is no billed usage.
  contextBudgetTokens?: number;
  // Human note explaining why billed tokens are empty (shown as the tokens
  // tile's sub-title only when there is no billed usage).
  tokensNote?: string;
  // Timestamps for the Elapsed tile (started/ended/last-activity, RFC3339).
  startedAt: string;
  endedAt?: string | null;
  lastActivityAt?: string | null;
  // renderCost renders the three cost figures; default is the node's fmtUSD.
  renderCost?: RenderCost;
  // usageRecorded distinguishes "usage was not captured" (unknown) from a real
  // zero, for the tokens and cost tiles (deployed node fix 1896d8dc9). The node
  // passes hasRecordedUsage(d); UNDEFINED keeps today's totalTokens>0 / cost>0
  // behaviour, so the org (which does not pass it) is byte-for-byte unchanged.
  usageRecorded?: boolean;
  // costSub replaces the cost tile's sub-label in the no-split branch (where
  // the node shows "no proxy capture for this session"). The org passes its
  // own sub-label here (e.g. its proxy-turn count), since it suppresses the
  // API/Tool split. Absent => the node's default text.
  costSub?: ReactNode;
};

export function KpiBand({
  cost,
  aiCost,
  toolCost,
  totalActions,
  successActions,
  failureActions,
  totalTokens,
  contextBudgetTokens,
  tokensNote,
  startedAt,
  endedAt,
  lastActivityAt,
  renderCost = defaultRenderCost,
  costSub,
  usageRecorded,
}: KpiBandProps) {
  // Prefer ended_at; fall back to last_activity_at (server COALESCE of the
  // last action's timestamp) so a never-closed session shows real elapsed,
  // not start→now.
  const elapsedMs = elapsedMillis(startedAt, endedAt ?? lastActivityAt);
  const ungraded = totalActions - successActions - failureActions;
  const hasProxyCost = cost > 0 || aiCost > 0;
  // usageUnknown is set only when the caller explicitly signals uncaptured
  // usage (node). When usageRecorded is undefined (org) hasTokens keeps the
  // totalTokens>0 rule and the "Unknown" branches never fire.
  const usageUnknown = usageRecorded === false;
  const hasTokens = usageRecorded ?? totalTokens > 0;
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      <CostStat
        cost={cost}
        aiCost={aiCost}
        toolCost={toolCost}
        totalTokens={totalTokens}
        muted={!hasProxyCost}
        renderCost={renderCost}
        costSub={costSub}
        usageRecorded={usageRecorded}
        tokensNote={tokensNote}
      />
      <BigStat
        label="Actions"
        icon={<LightningIcon size={12} />}
        value={fmtInt(totalActions)}
        sub={renderActionsSub(successActions, failureActions, ungraded)}
        warn={failureActions > 0}
      />
      <BigStat
        label="Elapsed"
        icon={<ClockIcon size={12} />}
        value={elapsedMs != null ? fmtDuration(elapsedMs) : "(open)"}
        sub={elapsedSub({ ended_at: endedAt, last_activity_at: lastActivityAt })}
      />
      <BigStat
        label="Tokens"
        icon={<LayersIcon size={12} />}
        value={
          usageUnknown
            ? "Unknown"
            : hasTokens
              ? fmtCompact(totalTokens)
              : contextBudgetTokens
                ? `~${fmtCompact(contextBudgetTokens)}`
                : fmtCompact(totalTokens)
        }
        sub={
          usageUnknown
            ? contextBudgetTokens
              ? `context ~${fmtCompact(contextBudgetTokens)} (est.) · usage missing`
              : "usage not captured"
            : hasTokens
              ? "net + cache R/W + output"
              : contextBudgetTokens
                ? "context budget (est.) · not billed"
                : "no billed usage"
        }
        // Honour tokensNote in BOTH branches: it is the tokens tile's tooltip
        // whenever provided (the org may attach one even when it has billed
        // tokens). The node only sets tokensNote when there is no billed usage,
        // so this leaves the node unchanged (`"" || undefined` => undefined).
        subTitle={tokensNote || undefined}
        muted={!hasTokens}
      />
    </div>
  );
}

// CostStat — Total cost hero tile with explicit API + Tool sub-lines
// rendered as a two-row grid below the headline number. Per design's
// page-sessions.jsx mockup the slide-over makes the 3-way split
// visible at-a-glance rather than buried in a single "api X · tool Y"
// caption line. Each of the three figures renders through `renderCost`.
function CostStat({
  cost,
  aiCost,
  toolCost,
  totalTokens,
  muted,
  renderCost,
  costSub,
  usageRecorded,
  tokensNote,
}: {
  cost: number;
  aiCost: number;
  toolCost: number;
  totalTokens: number;
  muted?: boolean;
  renderCost: RenderCost;
  costSub?: ReactNode;
  usageRecorded?: boolean;
  tokensNote?: string;
}) {
  const hasSplit = aiCost > 0 || toolCost > 0;
  // usageKnown is true only when the caller (node) explicitly signals whether
  // usage was captured; the org leaves it undefined and the "Unknown" / "usage
  // not captured" branches below never fire (today's rendering, unchanged).
  const usageKnown = usageRecorded !== undefined;
  const hasCost = !!usageRecorded || hasSplit || cost > 0;
  return (
    <div
      className={clsx(
        "relative flex flex-col gap-1 overflow-hidden rounded-3 border bg-bg-2 px-4 py-3.5",
        "border-accent/40 ring-1 ring-accent-ring",
      )}
    >
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(circle at 100% 0%, var(--accent-soft), transparent 60%)",
        }}
      />
      <div className="relative">
        <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
          <DollarIcon size={12} />
          Total cost
        </span>
        {usageKnown && !hasCost ? (
          <Tooltip content={tokensNote ?? "Usage not captured; cost unknown"}>
            <span
              tabIndex={0}
              className={clsx(
                "mt-0.5 block cursor-help text-[34px] font-bold leading-[1.05] tracking-[-0.02em] focus:outline-none",
                muted ? "text-fg-2" : "text-fg-0",
              )}
            >
              Unknown
            </span>
          </Tooltip>
        ) : (
          <span
            className={clsx(
              "mt-0.5 block text-[34px] font-bold leading-[1.05] tracking-[-0.02em]",
              muted ? "text-fg-2" : "text-fg-0",
            )}
          >
            {renderCost(cost, { kind: "kpi", tokens: totalTokens })}
          </span>
        )}
        {hasSplit ? (
          <div className="mt-1 grid grid-cols-2 gap-x-3 gap-y-0.5 text-[10.5px]">
            <span className="text-fg-3">API</span>
            <span className="text-right font-mono tabular-nums text-fg-1">
              {renderCost(aiCost, { kind: "api" })}
            </span>
            <span className="text-fg-3">Tool</span>
            <span className="text-right font-mono tabular-nums text-fg-2">
              {renderCost(toolCost, { kind: "tool" })}
            </span>
          </div>
        ) : usageKnown ? (
          <span className="mt-1 block text-[10.5px] text-fg-3">
            {hasCost ? "recorded usage" : "usage not captured"}
          </span>
        ) : costSub != null ? (
          <span className="mt-1 block text-[10.5px] text-fg-3">{costSub}</span>
        ) : (
          <span className="mt-1 block text-[10.5px] text-fg-3">
            no proxy capture for this session
          </span>
        )}
      </div>
    </div>
  );
}

function renderActionsSub(
  ok: number,
  fail: number,
  ungraded: number,
): ReactNode {
  // Most observer events (user_prompt, post_tool_batch, instructions_loaded)
  // aren't success/fail-graded, so the bare ok/fail split would be
  // misleading. Surface the ungraded count explicitly when significant.
  //
  // STATE ENCODED IN FORM (design proposal, failure 05: "a session with 4
  // failed actions and one with none look the same until you read the
  // digits"). The failure count is the ONE segment here that changes what an
  // operator should do next, so it carries danger colour and weight while the
  // ok / ungraded counts stay neutral — colour marks the exception, not the
  // whole line.
  const parts: ReactNode[] = [];
  if (ok > 0) parts.push(<span key="ok">{fmtInt(ok)} ok</span>);
  if (fail > 0) {
    parts.push(
      <span key="fail" className="font-semibold text-danger">
        {fmtInt(fail)} failed
      </span>,
    );
  }
  if (ungraded > 0) parts.push(<span key="ev">{fmtInt(ungraded)} event</span>);
  if (parts.length === 0) return "no graded outcomes";
  return parts.map((p, i) => (
    <Fragment key={i}>
      {i > 0 && " · "}
      {p}
    </Fragment>
  ));
}
