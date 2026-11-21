import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Pagination, Pill } from "../../primitives";
import { fmtBytes, fmtClock, fmtDuration, fmtInt } from "../../lib/format";
import {
  ROLLUPS_PER_PAGE,
  SERVICES_PER_PAGE,
  budgetHit,
  captureLine,
  pageOf,
  rollupPage,
  rollupTotals,
  sortRollups,
  type ProcessSummaryResponse,
  type ProcessSummaryRollup,
  type ProcessSummaryService,
} from "../../lib/processCaptureSummary";
import type { RenderMessageLink } from "./ProcessTree";

// ProcessCaptureBlocks - the three summary blocks of a session's process
// capture (docs/plans/process-capture-budget-plan-2026-11-04.md 4.7 / 4.8):
// the capture line, the services the agent started, and the rolled-up groups.
// Promoted from web/src/components/ProcessesSection.tsx (which re-exports
// them) so the org drawer's System panel renders the same design. Pure: the
// data and the message-link control are passed in; paging is local state.

// CaptureLine is the one line that says how much of the session's process
// activity was kept: "Kept 3,412 of 92,428 · 61,203 folded · ...". A session
// captured before capture limits says so instead.
export function CaptureLine({ summary }: { summary: ProcessSummaryResponse }) {
  const hit = budgetHit(summary);
  return (
    <div
      className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-3 border border-line-2 bg-bg-2 px-3 py-2 text-[11.5px] text-fg-2"
      data-testid="process-capture-line"
    >
      <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">Capture</span>
      <span className="tabular-nums">{captureLine(summary)}</span>
      {hit && !summary.legacy && <Pill variant="warn">budget</Pill>}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <span className="whitespace-nowrap">
      <span className="text-fg-4">{label} </span>
      <span className="tabular-nums text-fg-2">{value}</span>
    </span>
  );
}

// ServicesBlock lists the services the agent started (dev servers, watchers,
// apps): one row per service root, ten a page. Without renderMessageLink a
// spawning message id renders as plain text.
export function ServicesBlock({
  services,
  renderMessageLink,
}: {
  services: ProcessSummaryService[];
  renderMessageLink?: RenderMessageLink;
}) {
  const [page, setPage] = useState(1);
  useEffect(() => {
    if (page > 1 && (page - 1) * SERVICES_PER_PAGE >= services.length) setPage(1);
  }, [services.length, page]);
  const shown = pageOf(services, page, SERVICES_PER_PAGE);
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 p-3" data-testid="process-services">
      <div className="mb-1.5 flex flex-wrap items-baseline justify-between gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">Services · started by the agent</span>
        <span className="text-[10.5px] text-fg-3">
          {fmtInt(services.length)} service{services.length === 1 ? "" : "s"}
        </span>
      </div>
      <ul className="m-0 list-none space-y-2 p-0">
        {shown.map((s) => (
          <li key={s.root_key} className="text-[11.5px]">
            <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
              <span className="font-mono text-fg-1">{s.exe || s.root_key}</span>
              {s.argv_preview && (
                <span className="min-w-0 max-w-full truncate font-mono text-[10.5px] text-fg-3" title={s.argv_preview}>
                  {s.argv_preview}
                </span>
              )}
            </div>
            <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[10.5px] text-fg-3">
              {s.started_at && <Stat label="started" value={fmtClock(s.started_at)} />}
              {s.last_seen && <Stat label="last seen" value={fmtClock(s.last_seen)} />}
              {s.turn_index != null && <Stat label="turn" value={s.turn_index} />}
              {s.action_id != null && <Stat label="tool call" value={`#${s.action_id}`} />}
              {s.message_id && (
                <span className="whitespace-nowrap">
                  <span className="text-fg-4">message </span>
                  {renderMessageLink ? renderMessageLink(s.message_id) : <span className="font-mono">{s.message_id}</span>}
                </span>
              )}
              <Stat label="kept" value={fmtInt(s.kept ?? 0)} />
              <Stat label="rolled up" value={fmtInt(s.rolled_up ?? 0)} />
              {(s.cpu_sum_ms ?? 0) > 0 && <Stat label="CPU" value={fmtDuration(s.cpu_sum_ms)} />}
              {(s.peak_rss_bytes ?? 0) > 0 && <Stat label="peak memory" value={fmtBytes(s.peak_rss_bytes)} />}
            </div>
          </li>
        ))}
      </ul>
      {services.length > SERVICES_PER_PAGE && (
        <Pagination page={page} limit={SERVICES_PER_PAGE} total={services.length} onPage={setPage} />
      )}
    </div>
  );
}

// RolledUpBlock lists the runs the capture budget counted but did not keep as
// rows, grouped by why (over budget, folded helpers, service children,
// unattributed), with exact counts. Ten rows a page.
export function RolledUpBlock({ rollups }: { rollups: ProcessSummaryRollup[] }) {
  const [page, setPage] = useState(1);
  const sorted = useMemo(() => sortRollups(rollups), [rollups]);
  const totals = useMemo(() => rollupTotals(rollups), [rollups]);
  useEffect(() => {
    if (page > 1 && (page - 1) * ROLLUPS_PER_PAGE >= sorted.length) setPage(1);
  }, [sorted.length, page]);
  const rows = rollupPage(sorted, page, ROLLUPS_PER_PAGE);
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 p-3" data-testid="process-rollups">
      <div className="mb-1.5 flex flex-wrap items-baseline justify-between gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">Rolled up · counted, not kept</span>
        <span className="flex flex-wrap items-center gap-1">
          {totals.map((t) => (
            <Pill key={t.kind} variant="neutral">{`${t.label} ${fmtInt(t.count)}`}</Pill>
          ))}
        </span>
      </div>
      <ul className="m-0 list-none space-y-1.5 p-0">
        {rows.map(({ rollup: r, heading }, i) => (
          <li key={`${r.group_kind}-${r.exe_basename ?? ""}-${r.example_argv_preview ?? ""}-${i}`} className="text-[11.5px]">
            {heading && (
              <div className={"text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3 " + (i === 0 ? "" : "mt-2")}>
                {heading}
              </div>
            )}
            <div className="mt-0.5 flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
              <span className="font-mono text-fg-1">{r.exe_basename || "unknown"}</span>
              <Pill variant="neutral">{`×${fmtInt(r.count)}`}</Pill>
              {(r.failed_count ?? 0) > 0 && <Pill variant="danger">{`${fmtInt(r.failed_count)} failed`}</Pill>}
              {r.example_argv_preview && (
                <span className="min-w-0 max-w-full truncate font-mono text-[10.5px] text-fg-3" title={r.example_argv_preview}>
                  {r.example_argv_preview}
                </span>
              )}
            </div>
            <div className="mt-0.5 flex flex-wrap items-center gap-x-3 text-[10.5px] text-fg-3">
              {(r.duration_sum_ms ?? 0) > 0 && <Stat label="total" value={fmtDuration(r.duration_sum_ms)} />}
              {(r.duration_max_ms ?? 0) > 0 && <Stat label="longest" value={fmtDuration(r.duration_max_ms)} />}
              {(r.cpu_sum_ms ?? 0) > 0 && <Stat label="CPU" value={fmtDuration(r.cpu_sum_ms)} />}
              {(r.peak_rss_bytes ?? 0) > 0 && <Stat label="peak memory" value={fmtBytes(r.peak_rss_bytes)} />}
            </div>
          </li>
        ))}
      </ul>
      {sorted.length > ROLLUPS_PER_PAGE && (
        <Pagination page={page} limit={ROLLUPS_PER_PAGE} total={sorted.length} onPage={setPage} />
      )}
    </div>
  );
}
