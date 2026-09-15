import { useState } from "react";
import clsx from "clsx";
import { Pill, SegmentedControl, Tooltip } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { CopyOnClick } from "@/components/CopyOnClick";
import { Pagination } from "@/components/DataTable";
import { fmtInt } from "@/lib/format";
import type { SessionMessages, SessionRawEvents } from "@/lib/types";
import {
  MESSAGES_LIMIT,
  MESSAGE_COLUMNS,
  MESSAGE_PRESETS,
  RAW_EVENTS_LIMIT,
  loadStoredMsgPreset,
  storeMsgPreset,
  visibleMessageColumns,
  type MessageColumnPreset,
  type MessageSortKey,
  type SortDir,
} from "./messagesModel";
import { MessagesTable } from "./MessagesTable";

// Messages tab — the session's substance: the per-message timeline plus the
// raw source rows the timeline was derived from.
//
// EXTRACTED, NOT REWRITTEN. Every fetch still lives in the shell
// (SessionDetailPanel): the shell owns the /messages request because its
// `total` feeds the tab-strip count, so the count stays honest whether or not
// this tab is on screen — and because moving the fetch here would have changed
// polling behaviour, which this split explicitly does not do. This module is
// presentation only.
export function MessagesTab({
  tool,
  messages,
  watchMode,
  onStopWatch,
  effectiveDetail,
  onTokenDetail,
  browserSession,
  focusMid,
  stickToEdge,
  onStickChange,
  followEdge,
  sortBy,
  sortDir,
  onSort,
  msgPage,
  onMsgPage,
  raw,
}: {
  tool: string | undefined;
  messages: {
    data: SessionMessages | null;
    loading: boolean;
    error: Error | null;
  };
  watchMode: boolean;
  onStopWatch: () => void;
  effectiveDetail: "turn" | "inference";
  onTokenDetail: (v: "turn" | "inference") => void;
  browserSession: boolean;
  focusMid: string | null;
  stickToEdge: boolean;
  onStickChange: (atEdge: boolean) => void;
  followEdge: "bottom" | "top" | "none";
  sortBy: MessageSortKey;
  sortDir: SortDir;
  onSort: (key: MessageSortKey) => void;
  msgPage: number;
  onMsgPage: (p: number) => void;
  raw: {
    open: boolean;
    onToggle: () => void;
    data: SessionRawEvents | null;
    loading: boolean;
    error: Error | null;
    page: number;
    onPage: (p: number) => void;
  };
}) {
  // Column preset. Lives HERE, not in the shell: it is presentation state
  // that touches no request param (the server already returns every field and
  // sorts the whole timeline regardless), so routing it through
  // SessionDetailPanel would add a prop pair for nothing. Seeded from
  // localStorage so the operator's pick survives closing the panel.
  const [preset, setPreset] = useState<MessageColumnPreset>(loadStoredMsgPreset);
  const columns = visibleMessageColumns(preset, sortBy);
  const hidden = MESSAGE_COLUMNS.length - columns.length;
  return (
    <div className="space-y-5">
      <RawEventsPanel
        open={raw.open}
        onToggle={raw.onToggle}
        data={raw.data}
        loading={raw.loading}
        error={raw.error}
        page={raw.page}
        onPage={raw.onPage}
      />

      {messages.data?.account_summary && (
        <div className="rounded border border-stroke px-3 py-2 text-xs text-fg-3" aria-label="Session account coverage">
          <span className="font-medium text-fg-2">Observed accounts: </span>
          {messages.data.account_summary.accounts.map(a => a.email || a.name || a.account_id).join(", ") || "None captured"}
          <span className="block mt-1">{messages.data.account_summary.observed} messages with login evidence · {messages.data.account_summary.unknown} unknown · {messages.data.account_summary.conflicts} conflicting. Login snapshots do not confirm billing identity.</span>
        </div>
      )}
      <section className="space-y-2">
        {/* flex-wrap on both rails: the header now carries up to three
            controls, and on a sub-lg screen they must stack rather than push
            the section (and the table's scroll container) sideways. */}
        <h3 className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
            Messages
          </span>
          <span className="flex flex-wrap items-center gap-3">
            {watchMode && (
              <span className="flex items-center gap-1.5 rounded-pill border border-success/30 bg-success-soft px-2 py-0.5 text-[10px] font-semibold lowercase tracking-[0.02em] text-success">
                <span className="relative h-1.5 w-1.5 rounded-full bg-success">
                  <span className="absolute inset-0 animate-ping rounded-full bg-success/50" />
                </span>
                Watching live - read-only
                <button
                  type="button"
                  onClick={onStopWatch}
                  className="ml-1 text-fg-3 underline hover:text-fg-1 focus:outline-none"
                  title="Stop watching - return to normal 8s refresh and free navigation."
                >
                  stop
                </button>
              </span>
            )}
            {/* Group toggle is meaningful for codex (v1.7.24+ emits
                one token row per model inference). Codex DEFAULTS to
                "inference" (its informative grain — turn collapses
                the per-inference rows). For Anthropic adapters
                (claudecode et al.) "inference" is identical to "turn"
                — the watcher already emits one row per upstream
                msg_xxx — so the toggle is a no-op and stays hidden. */}
            {tool === "codex" && (
              <>
                <Tooltip content="Group token rows by model inference (default for codex - one row per token_count event) or by user-turn (sums each turn's inferences). Tool calls always stay grouped at the turn level. Tok/s is more accurate in Turn view: a single inference has no measured duration, so per-inference rows show “-”, while a turn spans its inferences' timestamps.">
                  <span>
                    <SegmentedControl
                      size="sm"
                      value={effectiveDetail}
                      onChange={(v) => onTokenDetail(v as "turn" | "inference")}
                      options={[
                        { value: "turn", label: "Turn" },
                        { value: "inference", label: "Inference" },
                      ]}
                    />
                  </span>
                </Tooltip>
                {effectiveDetail === "inference" && (
                  <button
                    type="button"
                    onClick={() => onTokenDetail("turn")}
                    className="text-[10.5px] text-accent hover:underline focus:outline-none"
                    title="Per-inference rows have no measured duration; switch to Turn for accurate Tok/s."
                  >
                    Tok/s? use Turn
                  </button>
                )}
              </>
            )}
            {/* Column preset. SegmentedControl (not a checkbox popover) for
                the same reason the Turn/Inference toggle beside it is one:
                this is a small set of MUTUALLY EXCLUSIVE views, and the
                dashboard's established control for that, in this exact
                header, is the segmented pill. Four short labels stay one row
                at phone width; the tooltip carries what each one shows,
                following the Turn/Inference precedent of wrapping the whole
                control rather than inventing per-option tooltips. */}
            <Tooltip
              content={
                <span className="block">
                  Which columns the timeline shows. All {MESSAGE_COLUMNS.length}{" "}
                  columns stay one click away under “All”; the active sort
                  column is always shown, whatever the preset.
                  {MESSAGE_PRESETS.map((p) => (
                    <span key={p.id} className="mt-1 block">
                      <b>{p.label}</b> - {p.hint}
                    </span>
                  ))}
                </span>
              }
              maxWidth={420}
            >
              <span>
                <SegmentedControl
                  size="sm"
                  value={preset}
                  onChange={(v) => {
                    const next = v as MessageColumnPreset;
                    setPreset(next);
                    storeMsgPreset(next);
                  }}
                  options={MESSAGE_PRESETS.map((p) => ({
                    value: p.id,
                    label: p.label,
                  }))}
                />
              </span>
            </Tooltip>
            <span className="text-[10.5px] text-fg-3">
              {messages.data
                ? `${fmtInt(messages.data.total)} total · click row to expand tool calls`
                : "Loading…"}
              {/* Say out loud that columns are hidden — a narrowed table that
                  doesn't admit it reads as missing data. */}
              {hidden > 0 && ` · ${hidden} columns hidden`}
            </span>
          </span>
        </h3>
        <ChartState
          loading={messages.loading}
          error={messages.error}
          empty={!messages.data?.messages.length}
          emptyHint="No messages indexed for this session."
          height={160}
        >
          {messages.data && (
            <MessagesTable
              rows={messages.data.messages}
              columns={columns}
              focusMid={focusMid}
              browser={browserSession}
              watch={watchMode}
              stick={stickToEdge}
              onStickChange={onStickChange}
              follow={followEdge}
              sortBy={sortBy}
              sortDir={sortDir}
              onSort={onSort}
            />
          )}
        </ChartState>
        {messages.data && messages.data.total > MESSAGES_LIMIT && (
          <Pagination
            page={msgPage}
            limit={MESSAGES_LIMIT}
            total={messages.data.total}
            onPage={onMsgPage}
            loading={messages.loading}
          />
        )}
      </section>
    </div>
  );
}

function RawEventsPanel({
  open,
  onToggle,
  data,
  loading,
  error,
  page,
  onPage,
}: {
  open: boolean;
  onToggle: () => void;
  data: SessionRawEvents | null;
  loading: boolean;
  error: Error | null;
  page: number;
  onPage: (page: number) => void;
}) {
  return (
    <section className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Source rows
        </h3>
        <div className="flex items-center gap-3">
          {data && (
            <span className="text-[10.5px] text-fg-3">
              {fmtInt(data.total)} rows · {fmtInt(data.sources.length)} sources
            </span>
          )}
          <button
            type="button"
            onClick={onToggle}
            className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11px] font-medium text-fg-1 hover:border-accent/40 hover:text-accent focus:outline-none focus:ring-2 focus:ring-accent-ring"
          >
            {open ? "Hide all data" : "View all data"}
          </button>
        </div>
      </div>
      {open && (
        <>
          <ChartState
            loading={loading && !data}
            error={error}
            empty={!data?.rows.length}
            emptyHint="No source JSONL rows found for this session."
            height={140}
          >
            {data && (
              <div className="overflow-hidden rounded-2 border border-line-2 bg-bg-1">
                <div className="border-b border-line-2 bg-bg-2 px-3 py-2">
                  <div className="flex flex-wrap gap-2">
                    {data.sources.map((source, i) => (
                      <Tooltip key={`${source.path}-${i}`} content={source.path}>
                        <span
                          tabIndex={0}
                          className={clsx(
                            "max-w-full truncate rounded-2 border px-2 py-0.5 font-mono text-[10.5px] focus:outline-none",
                            source.error
                              ? "border-warn/40 text-warn"
                              : "border-line-2 text-fg-2",
                          )}
                        >
                          {i + 1}: {source.path.split("/").pop()} · {fmtInt(source.rows)}
                        </span>
                      </Tooltip>
                    ))}
                  </div>
                </div>
                <div className="max-h-[520px] overflow-auto">
                  <table className="w-full min-w-[980px] text-left text-[12px]">
                    <thead className="sticky top-0 z-[1] border-b border-line-2 bg-bg-2 text-[10px] uppercase tracking-[0.06em] text-fg-3">
                      <tr>
                        <th className="w-[86px] px-3 py-2">Line</th>
                        <th className="w-[170px] px-2 py-2">Type</th>
                        <th className="w-[160px] px-2 py-2">ID</th>
                        <th className="w-[180px] px-2 py-2">Time</th>
                        <th className="px-2 py-2">Row</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line-1">
                      {data.rows.map((row) => (
                        <tr key={`${row.source_index}:${row.line}:${row.byte_offset}`} className="align-top">
                          <td className="px-3 py-2 font-mono text-[11px] text-fg-3">
                            {row.source_index + 1}:{row.line}
                          </td>
                          <td className="px-2 py-2">
                            <div className="flex flex-wrap gap-1">
                              {row.type && <Pill variant="neutral">{row.type}</Pill>}
                              {row.payload_type && row.payload_type !== row.type && (
                                <Pill variant="neutral">{row.payload_type}</Pill>
                              )}
                              {row.role && <Pill variant="neutral">{row.role}</Pill>}
                              {!row.valid_json && <Pill variant="warn">not json</Pill>}
                            </div>
                          </td>
                          <td className="max-w-[160px] truncate px-2 py-2 font-mono text-[11px] text-fg-2">
                            {row.event_id || "-"}
                          </td>
                          <td className="px-2 py-2 font-mono text-[11px] text-fg-3">
                            {row.timestamp || "-"}
                          </td>
                          <td className="px-2 py-2">
                            <CopyOnClick value={row.excerpt} className="block">
                              <pre className="max-h-[160px] overflow-auto whitespace-pre-wrap break-words rounded-1 bg-bg-0 p-2 font-mono text-[11px] leading-5 text-fg-1">
                                {row.excerpt}
                                {row.excerpt_truncated ? "\n...(truncated)" : ""}
                              </pre>
                            </CopyOnClick>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </ChartState>
          {data && data.total > RAW_EVENTS_LIMIT && (
            <Pagination
              page={page}
              limit={RAW_EVENTS_LIMIT}
              total={data.total}
              onPage={onPage}
              loading={loading}
            />
          )}
        </>
      )}
    </section>
  );
}
