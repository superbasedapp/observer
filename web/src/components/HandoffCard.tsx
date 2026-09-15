import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import clsx from "clsx";
import { ComboChip, SegmentedControl, ToolBadge, Tooltip } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { HelpInd } from "@/components/HelpInd";
import { CopyOnClick } from "@/components/CopyOnClick";
import { fetchJSON } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { fmtClock, fmtCompact, fmtShortId, fmtUSD } from "@/lib/format";
import type {
  HandoffBoundary,
  HandoffResponse,
  SessionLaunchResponse,
} from "@/lib/types";
import { useLaunchDock } from "@/components/LaunchDock";

// HandoffCard — session handoff / continue-anywhere (docs/session-handoff.md,
// plan §15 P2). The card is the entry point; the modal holds the target
// picker (integration-registry-derived), the fork picker (stable snap-table
// boundaries only — unstable rows stay visible but disabled with the exact
// reason), the priced carry table, and the Confirm that writes
// HANDOFF-<shortid>.md via POST /api/session/<id>/handoff.
//
// Honesty rules carried into the UI: this is NOT cache migration — the
// provider cache cannot move, and the full-carry row prices rehydration.

export function HandoffCard({
  sessionId,
  tool,
}: {
  sessionId: string;
  tool: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <section className="mt-5 rounded-3 border bg-bg-2 px-4 py-3">
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Continue in another tool
          <HelpInd id="card.handoff" />
        </span>
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="rounded-2 border border-accent/40 bg-accent/10 px-2.5 py-1 text-[11px] font-medium text-accent hover:bg-accent/20 focus:outline-none"
        >
          Continue in…
        </button>
      </div>
      <p className="mt-1 text-[10.5px] text-fg-3">
        Distill this session into a scrubbed handover doc another AI tool can
        pick up, forked from any stable point. The provider cache cannot move
        with it - the estimate prices what rehydration costs instead.
      </p>
      {open && (
        <HandoffModal
          sessionId={sessionId}
          sourceTool={tool}
          onClose={() => setOpen(false)}
        />
      )}
    </section>
  );
}

const CARRY_OPTIONS = [
  { value: "metadata", label: "Metadata" },
  { value: "distilled", label: "Distilled" },
  { value: "distilled_tail", label: "Distilled + tail" },
  // full = the excerpted flow + [msg <id>] tags + an MCP hint; the target
  // pulls full bodies on demand via get_session_message.
  { value: "full", label: "Full" },
  // full_cache = the un-excerpted read bodies inlined into the doc, so the
  // new session loads the source read cache up front (no MCP round-trips).
  // Only grounded when the source adapter has a FullTranscriptReader
  // (est.data.full_cache_available) — see carryOptionsFor below, which
  // greys this entry out honestly instead of offering a choice that
  // silently collapses to "full".
  { value: "full_cache", label: "Full + cache" },
];

// carryOptionsFor marks "Full + cache" disabled — with the exact reason —
// when the source adapter has no un-excerpted (FullTranscriptReader) read to
// back it. `available` is undefined while the estimate is still loading, in
// which case the option stays enabled rather than flashing disabled first;
// the backend's own carry_used degrade (full_cache → full) already keeps
// the priced table honest for that brief window.
function carryOptionsFor(available: boolean | undefined) {
  if (available !== false) return CARRY_OPTIONS;
  return CARRY_OPTIONS.map((opt) =>
    opt.value === "full_cache"
      ? {
          ...opt,
          disabled: true,
          disabledReason:
            "Unavailable - this source has no full-body reader, so Full + cache would carry the same excerpted bodies as Full.",
        }
      : opt,
  );
}

function HandoffModal({
  sessionId,
  sourceTool,
  onClose,
}: {
  sessionId: string;
  sourceTool: string;
  onClose: () => void;
}) {
  const [target, setTarget] = useState("");
  const [carry, setCarry] = useState(""); // "" = [handoff] config default
  // fork = null → last message (the default that never asks).
  const [fork, setFork] = useState<number | null>(null);
  const [result, setResult] = useState<HandoffResponse | null>(null);
  const [posting, setPosting] = useState(false);
  const [postErr, setPostErr] = useState<string | null>(null);
  // Launched terminals are owned by the app-level dock so they survive this
  // modal closing (and can be minimized without being killed).
  const dock = useLaunchDock();

  const est = useApi<HandoffResponse>(
    `/api/session/${sessionId}/handoff/estimate`,
    {
      to: target || undefined,
      carry: carry || undefined,
      fork: fork ?? undefined,
    },
    [sessionId, target, carry, fork],
  );

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Don't leave the user stuck on a now-disabled choice: if they'd picked
  // full_cache and the estimate comes back reporting the source has no
  // full-body reader, drop back to the config default — full_cache would
  // have degraded to an identical-to-full doc anyway (carry_used already
  // reflects that), so this loses nothing.
  useEffect(() => {
    if (carry === "full_cache" && est.data?.full_cache_available === false) {
      setCarry("");
    }
  }, [carry, est.data?.full_cache_available]);

  const carryOptions = useMemo(
    () => carryOptionsFor(est.data?.full_cache_available),
    [est.data?.full_cache_available],
  );

  const targetOptions = useMemo(
    () =>
      (est.data?.targets ?? []).map((t) => ({
        value: t.tool,
        label: t.tool === sourceTool ? `${t.tool} (source)` : t.tool,
        searchable: t.tool.toLowerCase(),
        title: t.note || undefined,
      })),
    [est.data?.targets, sourceTool],
  );

  async function confirm() {
    setPosting(true);
    setPostErr(null);
    try {
      const r = await fetchJSON<HandoffResponse>(
        `/api/session/${sessionId}/handoff`,
        undefined,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            to: target,
            carry,
            fork_message: fork ?? 0,
          }),
        },
      );
      setResult(r);
    } catch (e) {
      setPostErr(e instanceof Error ? e.message : String(e));
    } finally {
      setPosting(false);
    }
  }

  // launch starts the target tool in the embedded web terminal (seeded with
  // the same handover), rather than writing the doc for the operator to run
  // themselves. Uses the same to/carry/fork selection.
  async function launch() {
    setPosting(true);
    setPostErr(null);
    try {
      const r = await fetchJSON<SessionLaunchResponse>(
        `/api/session/${sessionId}/launch`,
        undefined,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ to: target, carry, fork_message: fork ?? 0 }),
        },
      );
      // Hand the session to the app-level dock and close this picker — the
      // terminal now lives above the modal, so closing it doesn't kill it.
      dock.launch({ token: r.token, tool: target, sessionId, hasProjectRoot: r.has_project_root ?? false });
      onClose();
    } catch (e) {
      setPostErr(e instanceof Error ? e.message : String(e));
    } finally {
      setPosting(false);
    }
  }

  const d = est.data;
  const carryUsed = d?.carry_used ?? "";
  const canLaunch = !!d?.targets?.find((t) => t.tool === target)?.launchable;

  return createPortal(
    <div
      className="fixed inset-0 z-[80] flex items-center justify-center bg-black/50 p-6"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Continue this session in another tool"
    >
      <div
        className="flex max-h-[88vh] w-[880px] flex-col overflow-hidden rounded-3 border bg-bg-1 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-2 border-b px-5 py-3">
          <span className="flex items-center gap-2 text-[13px] font-semibold text-fg-1">
            Continue in…
            <span className="flex items-center gap-1.5 text-[11px] font-normal text-fg-3">
              <ToolBadge tool={sourceTool} />
              <span className="font-mono" title={sessionId}>{fmtShortId(sessionId, 8)}</span>
            </span>
          </span>
          <button
            type="button"
            onClick={onClose}
            className="rounded-2 px-2 py-0.5 text-[12px] text-fg-3 hover:bg-bg-3 hover:text-fg-1 focus:outline-none"
          >
            ✕ Close
          </button>
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
          {result ? (
            <HandoffResult result={result} onDone={onClose} />
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-3">
                <ComboChip
                  value={target}
                  onChange={setTarget}
                  options={targetOptions}
                  label="Target tool"
                  placeholder="Filter tools…"
                />
                <SegmentedControl
                  size="sm"
                  value={carry || carryUsed}
                  onChange={setCarry}
                  options={carryOptions}
                />
                {d?.estimate.target_model && (
                  <span className="text-[10.5px] text-fg-3">
                    priced at{" "}
                    <span className="font-mono text-fg-2">
                      {d.estimate.target_model}
                    </span>
                  </span>
                )}
              </div>

              {d?.degrade_reason && (
                <p className="rounded-2 border border-warn/30 bg-warn/10 px-3 py-1.5 text-[10.5px] text-fg-2">
                  {d.degrade_reason}
                </p>
              )}
              {d?.context_warning && (
                <p className="flex items-start gap-1.5 rounded-2 border border-warn/30 bg-warn/10 px-3 py-1.5 text-[10.5px] text-fg-2">
                  <span aria-hidden>⚠</span>
                  <span>{d.context_warning}</span>
                </p>
              )}
              {d?.fork.snapped && d.fork.reason && (
                <p className="text-[10.5px] text-fg-3">fork: {d.fork.reason}</p>
              )}

              <ChartState
                loading={est.loading && !est.data}
                error={est.error}
                empty={!d}
                emptyHint="Computing estimate…"
                height={160}
              >
                {d && (
                  <>
                    <EstimateTable d={d} carrySelected={carry} />
                    {d.boundaries && d.boundaries.length > 0 ? (
                      <ForkPicker
                        boundaries={d.boundaries}
                        resolvedIndex={d.fork.resolved_index}
                        onPick={(idx) => setFork(idx)}
                      />
                    ) : (
                      <p className="text-[10.5px] text-fg-3">
                        No readable transcript - the handoff proceeds with
                        action-derived metadata only, forked at the session
                        end.
                      </p>
                    )}
                  </>
                )}
              </ChartState>
            </>
          )}
        </div>

        {!result && (
          <div className="flex items-center justify-between gap-3 border-t px-5 py-3">
            <span className="text-[10.5px] text-fg-3">
              Writes HANDOFF-*.md into the project root + one node-local
              record. The doc carries scrubbed conversation excerpts.
            </span>
            <span className="flex items-center gap-2">
              {postErr && (
                <span className="max-w-[320px] truncate text-[10.5px] text-danger" title={postErr}>
                  {postErr}
                </span>
              )}
              {canLaunch && (
                <Tooltip content="Start the tool here in an embedded terminal, seeded with the same handover - no local shell needed.">
                  <span>
                    <button
                      type="button"
                      disabled={!target || posting || !!est.error}
                      onClick={launch}
                      className={clsx(
                        "rounded-2 px-3 py-1.5 text-[12px] font-medium focus:outline-none",
                        target && !posting && !est.error
                          ? "border border-accent/40 text-accent hover:bg-accent/15"
                          : "cursor-not-allowed border bg-bg-3 text-fg-3",
                      )}
                    >
                      {posting ? "Launching…" : `Launch ${target} here`}
                    </button>
                  </span>
                </Tooltip>
              )}
              <Tooltip
                content={
                  target
                    ? "Write the handover doc for the selected target tool."
                    : "Pick a target tool first - the doc's header and pricing name it."
                }
              >
                <span>
                  <button
                    type="button"
                    disabled={!target || posting || !!est.error}
                    onClick={confirm}
                    className={clsx(
                      "rounded-2 px-3 py-1.5 text-[12px] font-medium focus:outline-none",
                      target && !posting && !est.error
                        ? "border border-accent/40 bg-accent/15 text-accent hover:bg-accent/25"
                        : "cursor-not-allowed border bg-bg-3 text-fg-3",
                    )}
                  >
                    {posting ? "Writing…" : "Write handover doc"}
                  </button>
                </span>
              </Tooltip>
            </span>
          </div>
        )}
      </div>
    </div>,
    document.body,
  );
}

// EstimateTable — the plan §9 priced-transaction table: one row per carry
// mode at the target model. Rows the backend cannot ground are simply
// absent (e.g. full without known context tokens), never fabricated.
function EstimateTable({
  d,
  carrySelected,
}: {
  d: HandoffResponse;
  carrySelected: string;
}) {
  const active = carrySelected || d.carry_used;
  return (
    <div className="overflow-hidden rounded-2 border">
      <table className="w-full text-[11px]">
        <thead>
          <tr className="border-b bg-bg-2 text-left text-[10px] uppercase tracking-[0.06em] text-fg-3">
            <th className="px-3 py-1.5 font-semibold">Carry</th>
            <th className="px-3 py-1.5 text-right font-semibold">Tokens</th>
            <th className="px-3 py-1.5 text-right font-semibold">Cost</th>
            <th className="px-3 py-1.5 font-semibold">What moves</th>
          </tr>
        </thead>
        <tbody>
          {d.estimate.rows.map((r) => (
            <tr
              key={r.mode}
              className={clsx(
                "border-b last:border-b-0",
                r.mode === active ? "bg-accent/10" : undefined,
              )}
            >
              <td className="px-3 py-1.5 font-mono text-fg-1">
                {r.mode === active ? "▸ " : ""}
                {r.mode}
              </td>
              <td className="px-3 py-1.5 text-right tabular-nums text-fg-2">
                {fmtCompact(r.tokens)}
              </td>
              <td className="px-3 py-1.5 text-right tabular-nums text-fg-1">
                {fmtUSD(r.cost_usd, true)}
              </td>
              <td className="px-3 py-1.5 text-fg-3">{r.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {d.estimate.fork_share < 1 && (
        <p className="border-t bg-bg-2 px-3 py-1 text-[10px] text-fg-3">
          Fork share {Math.round(d.estimate.fork_share * 100)}% - the full row
          is scaled to the cut.
        </p>
      )}
      {d.estimate.stay && (d.estimate.stay.has_band || d.estimate.stay.has_cache_value) && (
        <p className="border-t bg-bg-2 px-3 py-1 text-[10px] text-fg-3">
          Stay option (source tool):
          {d.estimate.stay.has_band &&
            ` next message ≈ ${fmtUSD(d.estimate.stay.next_message_low_usd, true)} / ${fmtUSD(d.estimate.stay.next_message_mid_usd, true)} / ${fmtUSD(d.estimate.stay.next_message_high_usd, true)} (low/typical/high)`}
          {d.estimate.stay.has_band && d.estimate.stay.has_cache_value && " ·"}
          {d.estimate.stay.has_cache_value &&
            ` live cache value at risk if you leave: ${fmtUSD(d.estimate.stay.cache_value_at_risk_usd, true)}`}
        </p>
      )}
    </div>
  );
}

// ForkPicker — the message timeline as fork candidates. Stable boundaries
// (snap-table accepted) are selectable; unstable rows stay visible but
// disabled with the exact rule reason (honest-disabled-copy rule).
function ForkPicker({
  boundaries,
  resolvedIndex,
  onPick,
}: {
  boundaries: HandoffBoundary[];
  resolvedIndex: number;
  onPick: (idx: number) => void;
}) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Fork point - {boundaries.length} messages
        </span>
        <span className="text-[10px] text-fg-3">
          included ▸ marks the cut · cumulative weight = share of the
          transcript carried
        </span>
      </div>
      <div className="max-h-[240px] overflow-y-auto rounded-2 border">
        <table className="w-full text-[11px]">
          <tbody>
            {boundaries.map((b) => {
              const selected = b.index === resolvedIndex;
              const row = (
                <tr
                  key={b.index}
                  onClick={b.stable ? () => onPick(b.index) : undefined}
                  className={clsx(
                    "border-b last:border-b-0",
                    b.stable
                      ? "cursor-pointer hover:bg-bg-3"
                      : "opacity-45",
                    selected ? "bg-accent/10" : undefined,
                  )}
                >
                  <td className="w-8 px-2 py-1 text-right font-mono text-fg-3">
                    {selected ? "▸" : ""}
                    {b.index}
                  </td>
                  <td className="w-16 px-2 py-1">
                    <span
                      className={clsx(
                        "text-[10px] font-semibold uppercase",
                        b.role === "user" ? "text-accent" : "text-fg-3",
                      )}
                    >
                      {b.role}
                    </span>
                  </td>
                  <td className="w-24 whitespace-nowrap px-2 py-1 text-[10px] tabular-nums text-fg-3">
                    {b.time ? fmtClock(b.time) : "-"}
                  </td>
                  <td className="max-w-0 truncate px-2 py-1 text-fg-2">
                    {b.preview || (
                      <span className="text-fg-3">
                        {b.tool_call_count
                          ? `${b.tool_call_count} tool call${b.tool_call_count > 1 ? "s" : ""}`
                          : "(no text)"}
                      </span>
                    )}
                  </td>
                  <td className="w-20 px-2 py-1 text-right tabular-nums text-[10px] text-fg-3">
                    {Math.round(b.cumulative_share * 100)}%
                  </td>
                </tr>
              );
              return b.stable ? (
                row
              ) : (
                <Tooltip key={b.index} content={`Not a stable fork point: ${b.reason}`}>
                  {row}
                </Tooltip>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// HandoffResult — the post-write confirmation: where the doc landed and
// what to do next in the target tool.
function HandoffResult({
  result,
  onDone,
}: {
  result: HandoffResponse;
  onDone: () => void;
}) {
  return (
    <div className="space-y-3">
      <p className="text-[12px] text-fg-1">
        Handover written{result.target_tool ? ` for ${result.target_tool}` : ""}
        {" - carry "}
        <span className="font-mono">{result.carry_used}</span>.
      </p>
      {result.doc_path && (
        <CopyOnClick
          value={result.doc_path}
          className="block rounded-2 border bg-bg-2 px-3 py-2 font-mono text-[11px] text-fg-2"
        >
          {result.doc_path}
        </CopyOnClick>
      )}
      <p className="text-[11px] text-fg-2">
        Open the target tool in this project and ask it to read that file.
      </p>
      {result.gitignore_hint && (
        <p className="rounded-2 border border-warn/30 bg-warn/10 px-3 py-1.5 text-[10.5px] text-fg-2">
          Hint: add <span className="font-mono">HANDOFF-*.md</span> to
          .gitignore - the handover carries conversation excerpts.
        </p>
      )}
      <button
        type="button"
        onClick={onDone}
        className="rounded-2 border px-3 py-1.5 text-[12px] text-fg-2 hover:bg-bg-3 focus:outline-none"
      >
        Done
      </button>
    </div>
  );
}
