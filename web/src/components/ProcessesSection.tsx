import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable, Pagination } from "@/components/DataTable";
import { pageSlice } from "@/lib/codeSecurity";
import { FINDING_GROUPS_PER_PAGE, MAX_OCCURRENCES_SHOWN, groupProcessFindings } from "@/lib/processFindings";
import {
  TREE_WINDOW_LIMIT,
  countNodes,
  mergeWindows,
  oldestStartedAt,
  servicesRunning,
  windowNote,
} from "@/lib/processCapture";
import { useProcessSummary } from "@/lib/useProcessSummary";
import { Icon, InlineLoading, Pill, Spinner, Tooltip } from "@/components/primitives";
import { severityTone } from "@shared/lib/guardCatalog";
import { VocabPill } from "@shared/lib/vocabPill";
import {
  CaptureLine,
  ProcessTree,
  RolledUpBlock,
  ServicesBlock,
  flattenProcessNodes,
  processHasMetrics,
} from "@shared/components/sessiondetail";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { fmtBytes, fmtClock, fmtDuration, fmtInt } from "@/lib/format";
import type {
  ProcessFinding,
  ProcessDiagnostics,
  ProcessNetworkEvent,
  ProcessNode,
  SessionNetworkResponse,
  SessionProcessResponse,
} from "@/lib/types";
import { ChevronDown, ChevronRight, TriangleAlert } from "lucide-react";

// ProcessesSection — the Process Observability panel in the session-detail
// slide-over (docs/process-observability.md §13.1). The whole section is a
// disclosure: COLLAPSED by default (sticky in localStorage) and lazy-loaded —
// a closed section makes no request and skips the daemon's correlation passes.
// Open it for the OS-level process tree (attribution + the §9.2.4 spawning
// message link + per-process CPU/memory/disk metrics with sparklines) and the
// observe-only §14 findings.
//
// The tree/table/call-stack body (tree rows, sortable table, the spawn-chain
// chart and stack, the Tree|Table|Call stack switcher, collapse-all,
// sparklines, metric badges) was promoted into the shared design system
// (ProcessTree) so the node and org System tabs render the same views. The
// capture-diagnostics panel (with its Settings deep-links), findings list,
// network egress list and the /processes fetch stay node-side.

const SECTION_OPEN_KEY = "sb_proc_section_open";

// FindingsList is the observe-only findings block: identical findings (same
// rule, executable and detail) fold into one row with a count, worst severity
// first, ten rows a page. A folded row expands to its occurrences, each of
// which can pick its process in the views below.
export function FindingsList({
  findings,
  onSelectProc,
}: {
  findings: ProcessFinding[];
  onSelectProc?: (key: string | null) => void;
}) {
  const groups = useMemo(() => groupProcessFindings(findings), [findings]);
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  // A new data load can shrink the list below the current page.
  const shown = pageSlice(groups, page, FINDING_GROUPS_PER_PAGE);
  useEffect(() => {
    if (page > 1 && (page - 1) * FINDING_GROUPS_PER_PAGE >= groups.length) setPage(1);
  }, [groups.length, page]);
  const toggle = (key: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 p-3" data-testid="process-findings">
      <div className="mb-1.5 flex flex-wrap items-baseline justify-between gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">Findings · observe-only</span>
        <span className="text-[10.5px] text-fg-3">
          {fmtInt(findings.length)} finding{findings.length === 1 ? "" : "s"}
          {groups.length < findings.length ? ` in ${fmtInt(groups.length)} kinds` : ""}
        </span>
      </div>
      <ul className="m-0 list-none space-y-1 p-0">
        {shown.map((g) => {
          const open = expanded.has(g.key);
          return (
            <li key={g.key} className="text-[11.5px]">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                {/* Process findings share the guard severity scale (info / warn / high). */}
                <VocabPill vocab="guardSeverity" value={g.severity} tone={severityTone(g.severity)} />
                <span className="font-mono text-fg-2">{g.rule_id.replace(/^process\./, "")}</span>
                {g.exe_basename && <span className="text-fg-1">{g.exe_basename}</span>}
                {g.detail && <span className="text-fg-3">{g.detail}</span>}
                {g.count > 1 && <Pill variant="neutral">{`×${fmtInt(g.count)}`}</Pill>}
                <span className="text-[10.5px] tabular-nums text-fg-4">{g.count > 1 ? "last " : ""}{fmtClock(g.last)}</span>
                {(g.count > 1 || onSelectProc) && (
                  <button
                    type="button"
                    onClick={() => (g.count > 1 ? toggle(g.key) : onSelectProc?.(g.items[0].process_key))}
                    aria-expanded={g.count > 1 ? open : undefined}
                    className="text-[10.5px] text-accent hover:underline"
                  >
                    {g.count > 1 ? (open ? "Hide" : "Show each") : "Show process"}
                  </button>
                )}
              </div>
              {open && (
                <ul className="m-0 mt-1 list-none space-y-0.5 border-l border-line-2 py-0.5 pl-3">
                  {g.items.slice(0, MAX_OCCURRENCES_SHOWN).map((it, i) => (
                    <li key={`${it.process_key}-${i}`} className="flex flex-wrap items-center gap-x-2 text-[10.5px] text-fg-3">
                      <span className="tabular-nums">{fmtClock(it.timestamp)}</span>
                      {it.turn_index != null && <span>turn {it.turn_index}</span>}
                      {it.target && <span className="font-mono text-fg-2">{it.target}</span>}
                      {onSelectProc && (
                        <button
                          type="button"
                          onClick={() => onSelectProc(it.process_key)}
                          className="text-accent hover:underline"
                        >
                          Show process
                        </button>
                      )}
                    </li>
                  ))}
                  {g.items.length > MAX_OCCURRENCES_SHOWN && (
                    <li className="text-[10.5px] text-fg-4">
                      and {fmtInt(g.items.length - MAX_OCCURRENCES_SHOWN)} more
                    </li>
                  )}
                </ul>
              )}
            </li>
          );
        })}
      </ul>
      {groups.length > FINDING_GROUPS_PER_PAGE && (
        <Pagination page={page} limit={FINDING_GROUPS_PER_PAGE} total={groups.length} onPage={setPage} />
      )}
    </div>
  );
}

function ProcessDiagnosticsPanel({
  diagnostics,
  hasProcessRows,
  hasNetworkRows,
}: {
  diagnostics?: ProcessDiagnostics;
  hasProcessRows: boolean;
  hasNetworkRows: boolean;
}) {
  if (!diagnostics) return null;
  const reasons = new Set(diagnostics.reason_codes ?? []);
  const show =
    !hasProcessRows ||
    reasons.has("process_disabled") ||
    reasons.has("process_network_disabled") ||
    reasons.has("network_body_capture_disabled") ||
    reasons.has("proxy_only_network_events");
  if (!show) return null;
  const processURL = diagnostics.process_settings_url || "/settings?section=process";
  const proxyURL = diagnostics.proxy_settings_url || "/settings?section=proxy";
  const backfillURL = diagnostics.backfill_settings_url || "/settings?section=backfill";
  const restartURL = diagnostics.restart_settings_url || "/settings?section=health";

  return (
    <div className="space-y-2 rounded-3 border border-line-2 bg-bg-2 p-3 text-[11.5px] text-fg-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
          Capture diagnostics
        </div>
        <div className="flex flex-wrap gap-1">
          <Pill variant={diagnostics.process_enabled ? "success" : "warn"}>
            process {diagnostics.process_enabled ? "on" : "off"}
          </Pill>
          <Pill variant={diagnostics.process_network_enabled ? "success" : "warn"}>
            network {diagnostics.process_network_enabled ? "on" : "off"}
          </Pill>
          <Pill variant={diagnostics.process_network_body_capture ? "accent" : "neutral"}>
            bodies {diagnostics.process_network_capture_bodies || "off"}
          </Pill>
        </div>
      </div>

      {!diagnostics.process_enabled && (
        <p>
          Process rows are opt-in. Open{" "}
          <Link to={processURL} className="text-accent hover:underline">
            Settings → Process
          </Link>{" "}
          and enable <code className="rounded-1 bg-bg-3 px-1">Process table</code>.
        </p>
      )}
      {!diagnostics.process_network_enabled && (
        <p>
          API/network calls need{" "}
          <Link to={processURL} className="text-accent hover:underline">
            Settings → Process → Network capture
          </Link>{" "}
          with <code className="rounded-1 bg-bg-3 px-1">Enabled</code> on.
        </p>
      )}
      {diagnostics.process_network_enabled && !diagnostics.process_network_body_capture && (
        <p>
          Network metadata can be listed, but request/response excerpts require{" "}
          <Link to={processURL} className="text-accent hover:underline">
            Body capture = proxied
          </Link>
          . Payload capture is only for superbased-proxied/plaintext flows; non-proxied TLS stays metadata-only.
        </p>
      )}
      {hasNetworkRows && !hasProcessRows && (
        <p>
          This session has proxy network events but no OS process rows. The API calls table is still shown below; the process table needs live process capture while the tool is running.
        </p>
      )}
      {!hasNetworkRows && !hasProcessRows && (
        <p>
          Historical sessions may not have process/network rows. Run new tool sessions with superbased running after changing settings; use{" "}
          <Link to={backfillURL} className="text-accent hover:underline">
            Backfill
          </Link>{" "}
          for transcript-derived fields only.
        </p>
      )}
      <p>
        If you save process, network, or proxy settings, restart superbased from{" "}
        <Link to={restartURL} className="text-accent hover:underline">
          Settings → Health
        </Link>
        . Also check{" "}
        <Link to={proxyURL} className="text-accent hover:underline">
          Settings → Proxy
        </Link>{" "}
        if Codex is not routed through the superbased proxy.
      </p>
    </div>
  );
}

function NetworkEventsPanel({ sessionId }: { sessionId: string }) {
  const [selected, setSelected] = useState<number | null>(null);
  const list = useApi<SessionNetworkResponse>(
    `/api/session/${sessionId}/network?limit=50`,
    undefined,
    [sessionId],
  );
  const detail = useApi<ProcessNetworkEvent>(
    selected ? `/api/process/network/${selected}` : null,
    undefined,
    [selected],
  );
  const events = list.data?.events ?? [];
  // The list is the most recent events in capture order, so no column sorts.
  const columns = useMemo<ColumnDef<NetworkEventRow, unknown>[]>(
    () => [
      {
        id: "time",
        header: "Time",
        enableSorting: false,
        cell: ({ row }) => (
          <span className="whitespace-nowrap tabular-nums text-fg-3">
            {fmtClock(row.original.timestamp)}
          </span>
        ),
      },
      {
        id: "target",
        header: "Target",
        enableSorting: false,
        meta: { mono: true },
        cell: ({ row }) => (
          <span className="block max-w-[300px] truncate" title={row.original.target}>
            {row.original.target || "-"}
          </span>
        ),
      },
      {
        id: "source",
        header: "Source",
        enableSorting: false,
        cell: ({ row }) => (
          <span className="text-fg-3">
            {row.original.exe_basename ||
              (row.original.process_key.startsWith("proxy:") ? "proxy" : "process")}
          </span>
        ),
      },
      {
        id: "body",
        header: "Body",
        enableSorting: false,
        cell: ({ row }) => (
          <Pill variant={row.original.has_body ? "accent" : "neutral"}>
            {row.original.has_body ? "captured" : "metadata"}
          </Pill>
        ),
      },
      {
        id: "view",
        header: () => <span className="sr-only">Detail</span>,
        enableSorting: false,
        meta: { align: "right" },
        cell: ({ row }) => (
          <button
            type="button"
            onClick={() => setSelected((v) => (v === row.original.id ? null : row.original.id))}
            className="text-accent hover:underline"
          >
            {selected === row.original.id ? "hide" : "view"}
          </button>
        ),
      },
    ],
    [selected],
  );
  if (!list.loading && events.length === 0) return null;
  return (
    <div className="space-y-2 rounded-3 border border-line-2 bg-bg-2 p-3">
      <div className="flex items-center justify-between gap-2">
        <div className="text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
          Network egress · on demand
        </div>
        <span className="text-[10px] text-fg-3">
          {list.loading ? <Spinner size="xs" label="Loading network egress" /> : `${fmtInt(events.length)} recent`}
        </span>
      </div>
      <DataTable<NetworkEventRow>
        data={events}
        columns={columns}
        rowKey={(ev) => String(ev.id)}
        minWidth={680}
        loading={list.loading}
        rowClassName={(ev) => (selected === ev.id ? "bg-accent/10" : undefined)}
      />
      {selected && (
        <ChartState
          loading={detail.loading && !detail.data}
          error={detail.error}
          denied={detail.denied}
          deniedPermission={detail.deniedPermission}
          empty={!detail.data}
          emptyHint="Network event not found."
          height={80}
        >
          {detail.data && (
            <NetworkEventDetail event={detail.data} />
          )}
        </ChartState>
      )}
    </div>
  );
}

type NetworkEventRow = SessionNetworkResponse["events"][number];

function NetworkEventDetail({ event }: { event: ProcessNetworkEvent }) {
  const body = event.body;
  if (!body) {
    return (
      <div className="rounded-2 border border-line-2 bg-bg-3/40 p-2 text-caption text-fg-3">
        Metadata-only event. Payload/response were not captured for this flow.
      </div>
    );
  }
  return (
    <div className="space-y-2 rounded-2 border border-line-2 bg-bg-3/40 p-2 text-caption">
      <div className="flex flex-wrap items-center gap-2 text-fg-3">
        <Pill variant="accent">{body.capture_source}</Pill>
        {body.status_code ? <span>status {body.status_code}</span> : null}
        {body.duration_ms ? <span>{fmtDuration(body.duration_ms)}</span> : null}
        {body.response_content_type ? <span>{body.response_content_type}</span> : null}
      </div>
      <BodyBlock
        title={`Request · ${fmtBytes(body.request_body_bytes ?? 0)}${body.request_body_truncated ? " · truncated" : ""}`}
        text={body.request_body}
        fallback={body.body_unavailable_reason}
      />
      <BodyBlock
        title={`Response · ${fmtBytes(body.response_body_bytes ?? 0)}${body.response_body_truncated ? " · truncated" : ""}`}
        text={body.response_body}
        fallback={body.body_unavailable_reason}
      />
    </div>
  );
}

function BodyBlock({
  title,
  text,
  fallback,
}: {
  title: string;
  text?: string;
  fallback?: string;
}) {
  return (
    <div>
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        {title}
      </div>
      {text ? (
        <pre className="max-h-[220px] overflow-auto rounded-2 bg-bg-3/50 p-2 font-mono text-[10.5px] text-fg-2">
          {text}
        </pre>
      ) : (
        <div className="rounded-2 bg-bg-3/40 p-2 text-fg-3">
          {fallback ? `Unavailable: ${fallback}` : "No body captured."}
        </div>
      )}
    </div>
  );
}

// MessageLinkRenderer renders the id of the message that started something as
// a jump link (the control the tree uses); absent, a plain id.
type MessageLinkRenderer = (id: string) => React.ReactNode;

function messageLinkFor(onFocusMessage?: (messageId: string) => void): MessageLinkRenderer | undefined {
  if (!onFocusMessage) return undefined;
  return (id: string) => (
    <Tooltip content={`Jump to the message that spawned this process (${id})`}>
      <button
        type="button"
        onClick={() => onFocusMessage(id)}
        className="font-mono text-caption text-accent hover:underline focus:outline-none focus-visible:ring-1 focus-visible:ring-accent-ring"
      >
        {id}
      </button>
    </Tooltip>
  );
}

// CaptureLine / ServicesBlock / RolledUpBlock moved to the shared design
// system (shared/components/sessiondetail/ProcessCaptureBlocks.tsx) so the org
// drawer's System panel renders the same blocks; re-exported for this file's
// importers.
export { CaptureLine, RolledUpBlock, ServicesBlock };

// PROC_REFRESH_MS: how often the open Processes panel re-polls while something
// is still running. Slower than the rest of the drawer (8s) — a process tree
// changes far less than the live conversation, and each poll can trigger a
// server-side correlation refresh. A fully-exited tree stops polling entirely.
const PROC_REFRESH_MS = 15000;

export function ProcessesSection({
  sessionId,
  onFocusMessage,
  selectedProc,
  onSelectProc,
  onOpenTimeline,
}: {
  sessionId: string | null;
  onFocusMessage?: (messageId: string) => void;
  // The process picked in Tree / Table / Call stack (the shell keeps it in
  // `?proc=`). Omitted: ProcessTree keeps the selection locally.
  selectedProc?: string | null;
  onSelectProc?: (key: string | null) => void;
  onOpenTimeline?: () => void;
}) {
  const [open, setOpen] = useState<boolean>(() => {
    try {
      return localStorage.getItem(SECTION_OPEN_KEY) === "1";
    } catch {
      return false;
    }
  });
  // A link that names a process (`?proc=`) opens the section: it is otherwise
  // collapsed by default and the picked process would be invisible.
  useEffect(() => {
    if (selectedProc) setOpen(true);
  }, [selectedProc]);
  const toggleOpen = useCallback(() => {
    setOpen((v) => {
      const next = !v;
      try {
        localStorage.setItem(SECTION_OPEN_KEY, next ? "1" : "0");
      } catch {
        /* ignore */
      }
      return next;
    });
  }, []);

  // poll gates the auto-refresh: only re-poll while something is still running
  // (a fully-exited tree is static). Set by an effect once data has loaded, so
  // the first fetch is one-shot and polling starts only if needed.
  const [poll, setPoll] = useState(false);

  // The summary is read first and is what gets polled (a small document with
  // an ETag; an unchanged session answers 304). A daemon without the endpoint
  // answers 404: `summary.unavailable` then restores the earlier behaviour,
  // the tree alone, polled itself while something runs.
  const summary = useProcessSummary(sessionId, open, open && poll ? PROC_REFRESH_MS : 0);
  const sum = summary.data;

  // The tree is re-read when the summary's ETag moves (the capture changed),
  // never on its own timer. treeRev counts those moves after the first read.
  const [treeRev, setTreeRev] = useState(0);
  const lastEtag = useRef<string | null>(null);
  useEffect(() => {
    lastEtag.current = null;
    setTreeRev(0);
  }, [sessionId]);
  useEffect(() => {
    const e = summary.etag;
    if (e && lastEtag.current && e !== lastEtag.current) setTreeRev((r) => r + 1);
    if (e) lastEtag.current = e;
  }, [summary.etag]);

  // Lazy-load: only fetch (and trigger the daemon's correlation passes) once the
  // section is open, and only after the summary has answered. A closed section
  // makes no request. The window is the most recent TREE_WINDOW_LIMIT rows; an
  // older daemon ignores the limit and returns the whole tree.
  const procs = useApi<SessionProcessResponse>(
    open && sessionId && !summary.loading ? `/api/session/${sessionId}/processes?limit=${TREE_WINDOW_LIMIT}` : null,
    undefined,
    [sessionId, open, treeRev],
    open && poll && summary.unavailable ? { refreshMs: PROC_REFRESH_MS } : undefined,
  );
  const data = procs.data;
  const findings = data?.findings ?? [];

  // "Load earlier" windows, newest-last-loaded; dropped when the session changes.
  const [earlier, setEarlier] = useState<ProcessNode[][]>([]);
  const [earlierMore, setEarlierMore] = useState<boolean | null>(null);
  const [earlierBusy, setEarlierBusy] = useState(false);
  const [earlierErr, setEarlierErr] = useState<string | null>(null);
  useEffect(() => {
    setEarlier([]);
    setEarlierMore(null);
    setEarlierErr(null);
  }, [sessionId]);

  const roots = useMemo<ProcessNode[]>(
    () => (!data ? [] : earlier.length > 0 ? mergeWindows(earlier, data.roots) : data.roots),
    [data, earlier],
  );
  const hasMoreEarlier = earlier.length === 0 || earlierMore == null ? Boolean(data?.truncated) : earlierMore;
  const loadEarlier = useCallback(async () => {
    if (!sessionId || earlierBusy) return;
    const to = oldestStartedAt(roots);
    if (!to) return;
    setEarlierBusy(true);
    setEarlierErr(null);
    try {
      const r = await fetchJSON<SessionProcessResponse>(`/api/session/${sessionId}/processes`, {
        limit: TREE_WINDOW_LIMIT,
        to,
      });
      const known = new Set(roots.map((n) => n.process_key));
      const fresh = (r.roots ?? []).filter((n) => !known.has(n.process_key));
      // A window with nothing new ends the paging, so a boundary row cannot loop.
      setEarlier((cur) => (fresh.length > 0 ? [...cur, r.roots] : cur));
      setEarlierMore(fresh.length > 0 && Boolean(r.truncated));
    } catch (e) {
      setEarlierErr(e instanceof Error ? e.message : String(e));
    } finally {
      setEarlierBusy(false);
    }
  }, [sessionId, earlierBusy, roots]);

  const flat = useMemo(() => flattenProcessNodes(roots), [roots]);
  const shownCount = useMemo(() => countNodes(roots), [roots]);
  const hasProcessRows = Boolean((data && data.total > 0) || shownCount > 0);
  const hasNetworkRows = Boolean(data && (data.network_total ?? 0) > 0);
  const runningCount = useMemo(() => flat.filter((n) => !n.exited).length, [flat]);
  const withMetrics = useMemo(() => flat.filter(processHasMetrics).length, [flat]);
  const hasSummaryRows = Boolean(sum && (sum.observed > 0 || (sum.rollups?.length ?? 0) > 0 || (sum.services?.length ?? 0) > 0));

  // Auto-refresh only while open AND something is still running - a fully-exited
  // tree never changes, so one fetch is enough (A2). Derived after the fetch so
  // the first load is one-shot; polling then starts only if needed. A service
  // seen alive a moment ago counts as running even when the tree window shows
  // none of its rows.
  const servicesLive = servicesRunning(sum?.services, Date.now());
  useEffect(() => {
    setPoll(open && (runningCount > 0 || servicesLive));
  }, [open, runningCount, servicesLive]);

  // The spawning-message link is injected into the shared ProcessTree; without
  // an onFocusMessage handler the tree renders a plain, non-interactive id.
  const renderMessageLink = messageLinkFor(onFocusMessage);

  const total = sum && !sum.legacy ? sum.kept : (data?.total ?? 0);
  const headline = data
    ? `${fmtInt(total)} captured · ${fmtInt(runningCount)} running${
        withMetrics > 0 ? ` · ${fmtInt(withMetrics)} with metrics` : ""
      }${data.network_total ? ` · net ${fmtInt(data.network_total)}` : ""}`
    : null;
  const summaryText = headline ?? (open ? <InlineLoading size="sm" label="Loading processes" /> : "click to load OS-level process tree");

  return (
    <section className="space-y-2">
      <h3>
        <button
          type="button"
          onClick={toggleOpen}
          className="flex w-full items-center justify-between gap-2 text-left focus:outline-none"
          aria-expanded={open}
        >
          <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
            <Icon icon={open ? ChevronDown : ChevronRight} size="xs" className="text-fg-3" />
            Processes
          </span>
          <span className="inline-flex items-center gap-1 text-[10.5px] text-fg-3">
            {summaryText}
            {data && findings.length > 0 && (
              <>
                {" · "}
                <Icon icon={TriangleAlert} size={10} label="findings" className="text-warn" />
                {fmtInt(findings.length)}
              </>
            )}
          </span>
        </button>
      </h3>

      {open && (
        <ChartState
          loading={procs.loading && !data}
          error={procs.error}
          denied={procs.denied}
          deniedPermission={procs.deniedPermission}
          empty={!data}
          emptyHint="No process diagnostics loaded yet."
          height={120}
        >
          {data && (
            <div className="space-y-3">
              <ProcessDiagnosticsPanel
                diagnostics={data.diagnostics}
                hasProcessRows={hasProcessRows || hasSummaryRows}
                hasNetworkRows={hasNetworkRows}
              />

              {sum && (hasSummaryRows || sum.legacy) && <CaptureLine summary={sum} />}

              {findings.length > 0 && <FindingsList findings={findings} onSelectProc={onSelectProc} />}

              {/* network_total is a count: a bare `0 &&` would render "0". */}
              {(data.network_total ?? 0) > 0 && sessionId && (
                <NetworkEventsPanel sessionId={sessionId} />
              )}

              {sum && (sum.services?.length ?? 0) > 0 && (
                <ServicesBlock services={sum.services ?? []} renderMessageLink={renderMessageLink} />
              )}

              {sum && (sum.rollups?.length ?? 0) > 0 && <RolledUpBlock rollups={sum.rollups ?? []} />}

              {hasProcessRows && (
                <div className="space-y-2">
                  {(data.truncated || earlier.length > 0) && (
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-fg-3" data-testid="process-window-note">
                      <span>{windowNote(shownCount, sum && !sum.legacy ? sum.kept : data.total)}</span>
                      {hasMoreEarlier && (
                        <button
                          type="button"
                          onClick={() => void loadEarlier()}
                          disabled={earlierBusy}
                          className="text-accent hover:underline disabled:opacity-50"
                        >
                          {earlierBusy ? "Loading…" : "Load earlier"}
                        </button>
                      )}
                      {earlierErr && <span className="text-danger">{earlierErr}</span>}
                    </div>
                  )}
                  <ProcessTree
                    roots={roots}
                    total={shownCount}
                    sessionKey={sessionId}
                    renderMessageLink={renderMessageLink}
                    onOpenMessage={onFocusMessage}
                    onOpenTimeline={onOpenTimeline}
                    sessionLabel={sessionId ? `Session ${sessionId.slice(0, 8)}` : "Session"}
                    {...(onSelectProc ? { selectedKey: selectedProc ?? null, onSelectedKeyChange: onSelectProc } : {})}
                  />
                </div>
              )}
            </div>
          )}
        </ChartState>
      )}
    </section>
  );
}
