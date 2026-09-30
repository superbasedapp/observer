import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/DataTable";
import { Icon, InlineLoading, Pill, Spinner, Tooltip } from "@/components/primitives";
import { severityTone } from "@shared/lib/guardCatalog";
import { VocabPill } from "@shared/lib/vocabPill";
import {
  ProcessTree,
  flattenProcessNodes,
  processHasMetrics,
} from "@shared/components/sessiondetail";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import { fmtBytes, fmtClock, fmtDuration, fmtInt } from "@/lib/format";
import type {
  ProcessFinding,
  ProcessDiagnostics,
  ProcessNetworkEvent,
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
// The tree/table body (tree rows, sortable table, Tree|Table toggle, collapse-
// all, sparklines, metric badges) was promoted into the shared design system
// (ProcessTree) so the node and org System tabs render the same tree. The
// capture-diagnostics panel (with its Settings deep-links), findings list,
// network egress list and the /processes fetch stay node-side.

const SECTION_OPEN_KEY = "sb_proc_section_open";

function FindingRow({ f }: { f: ProcessFinding }) {
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11.5px]">
      {/* Process findings share the guard severity scale (info / warn / high). */}
      <VocabPill vocab="guardSeverity" value={f.severity} tone={severityTone(f.severity)} />
      <span className="font-mono text-fg-2">{f.rule_id.replace(/^process\./, "")}</span>
      {f.exe_basename && <span className="text-fg-1">{f.exe_basename}</span>}
      {f.detail && <span className="text-fg-3">{f.detail}</span>}
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
          . Payload capture is only for SuperBased-proxied/plaintext flows; non-proxied TLS stays metadata-only.
        </p>
      )}
      {hasNetworkRows && !hasProcessRows && (
        <p>
          This session has proxy network events but no OS process rows. The API calls table is still shown below; the process table needs live process capture while the tool is running.
        </p>
      )}
      {!hasNetworkRows && !hasProcessRows && (
        <p>
          Historical sessions may not have process/network rows. Run new tool sessions with SuperBased running after changing settings; use{" "}
          <Link to={backfillURL} className="text-accent hover:underline">
            Backfill
          </Link>{" "}
          for transcript-derived fields only.
        </p>
      )}
      <p>
        If you save process, network, or proxy settings, restart SuperBased from{" "}
        <Link to={restartURL} className="text-accent hover:underline">
          Settings → Health
        </Link>
        . Also check{" "}
        <Link to={proxyURL} className="text-accent hover:underline">
          Settings → Proxy
        </Link>{" "}
        if Codex is not routed through the SuperBased proxy.
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

// PROC_REFRESH_MS: how often the open Processes panel re-polls while something
// is still running. Slower than the rest of the drawer (8s) — a process tree
// changes far less than the live conversation, and each poll can trigger a
// server-side correlation refresh. A fully-exited tree stops polling entirely.
const PROC_REFRESH_MS = 15000;

export function ProcessesSection({
  sessionId,
  onFocusMessage,
}: {
  sessionId: string | null;
  onFocusMessage?: (messageId: string) => void;
}) {
  const [open, setOpen] = useState<boolean>(() => {
    try {
      return localStorage.getItem(SECTION_OPEN_KEY) === "1";
    } catch {
      return false;
    }
  });
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

  // Lazy-load: only fetch (and trigger the daemon's correlation passes) once the
  // section is open. A closed section makes no request.
  const procs = useApi<SessionProcessResponse>(
    open && sessionId ? `/api/session/${sessionId}/processes` : null,
    undefined,
    [sessionId, open],
    open && poll ? { refreshMs: PROC_REFRESH_MS } : undefined,
  );
  const data = procs.data;
  const findings = data?.findings ?? [];

  const flat = useMemo(() => (data ? flattenProcessNodes(data.roots) : []), [data]);
  const hasProcessRows = Boolean(data && data.total > 0);
  const hasNetworkRows = Boolean(data && (data.network_total ?? 0) > 0);
  const runningCount = useMemo(() => flat.filter((n) => !n.exited).length, [flat]);
  const withMetrics = useMemo(() => flat.filter(processHasMetrics).length, [flat]);

  // Auto-refresh only while open AND something is still running — a fully-exited
  // tree never changes, so one fetch is enough (A2). Derived after the fetch so
  // the first load is one-shot; polling then starts only if needed.
  useEffect(() => {
    setPoll(open && runningCount > 0);
  }, [open, runningCount]);

  // The spawning-message link is injected into the shared ProcessTree; without
  // an onFocusMessage handler the tree renders a plain, non-interactive id.
  const renderMessageLink = onFocusMessage
    ? (id: string) => (
        <Tooltip content={`Jump to the message that spawned this process (${id})`}>
          <button
            type="button"
            onClick={() => onFocusMessage(id)}
            className="font-mono text-caption text-accent hover:underline focus:outline-none focus-visible:ring-1 focus-visible:ring-accent-ring"
          >
            {id}
          </button>
        </Tooltip>
      )
    : undefined;

  const summary = data
    ? `${fmtInt(data.total)} captured · ${fmtInt(runningCount)} running${
        withMetrics > 0 ? ` · ${fmtInt(withMetrics)} with metrics` : ""
      }${data.network_total ? ` · net ${fmtInt(data.network_total)}` : ""}`
    : open
      ? <InlineLoading size="sm" label="Loading processes" />
      : "click to load OS-level process tree";

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
            {summary}
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
                hasProcessRows={hasProcessRows}
                hasNetworkRows={hasNetworkRows}
              />

              {findings.length > 0 && (
                <div className="space-y-1.5 rounded-3 border border-line-2 bg-bg-2 p-3">
                  <div className="text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
                    Findings · observe-only
                  </div>
                  {findings.map((f) => (
                    <FindingRow key={f.process_key + f.rule_id} f={f} />
                  ))}
                </div>
              )}

              {data.network_total && sessionId && (
                <NetworkEventsPanel sessionId={sessionId} />
              )}

              {hasProcessRows && (
                <ProcessTree
                  roots={data.roots}
                  total={data.total}
                  sessionKey={sessionId}
                  renderMessageLink={renderMessageLink}
                />
              )}
            </div>
          )}
        </ChartState>
      )}
    </section>
  );
}
