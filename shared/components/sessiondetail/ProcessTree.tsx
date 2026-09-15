import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Pill } from "../../primitives";
import { fmtBytes, fmtClock, fmtDuration, fmtInt } from "../../lib/format";
import type { MetricSampleLike, ProcessNodeLike } from "../../lib/types";

// ProcessTree — the OS-level process tree/table view of the session-detail
// System tab: the Tree | Table toggle, Collapse-all, the recursive tree rows
// with attribution + spawning-message link + per-process CPU/memory/disk
// metrics and working-set sparkline, and the sortable, row-capped Table view.
// Promoted into the shared design system so the org can render the node-style
// tree (building `children` from parent_run_key) instead of a flat table.
//
// It is pure: process nodes in, tree/table out. The two node couplings are
// dropped/injected — the react-router deep-links live in the node's
// diagnostics panel (which stays node-side), and the spawning-message link is
// injected via `renderMessageLink` so the caller decides whether it navigates.
// The /processes fetch, capture-diagnostics panel, findings and network egress
// list all stay node-side; this component renders only the tree/table body.

type PillVariant = "neutral" | "success" | "warn" | "danger" | "info" | "accent";

// LARGE_TREE_THRESHOLD: above this many captured processes the tree opens
// collapsed-to-roots, so a huge session (e.g. a long-running daemon subtree)
// doesn't render thousands of nodes + sparklines at once.
const LARGE_TREE_THRESHOLD = 150;
// TABLE_ROW_CAP: the Table view renders at most this many rows (the top ones by
// the active sort) with a "show all" escape hatch.
const TABLE_ROW_CAP = 100;

function attributionVariant(source: string): PillVariant {
  switch (source) {
    case "env_token":
    case "bridge":
    case "adapter_pid":
      return "accent";
    case "inherited":
      return "neutral";
    case "none":
      return "warn";
    default:
      return "info";
  }
}

function runtimeLabel(n: ProcessNodeLike): string {
  if (!n.exited) return "running";
  if (n.exit_signal && n.exit_signal > 0) return `sig ${n.exit_signal}`;
  return `exit ${n.exit_code}`;
}

function attributionLabel(n: ProcessNodeLike): string {
  const conf =
    n.attribution_confidence && n.attribution_confidence !== "none"
      ? `/${n.attribution_confidence}`
      : "";
  return `${n.attribution_source}${conf}`;
}

// isDerived marks a row synthesized from the AI tool's own exec record (a
// run_command action) rather than observed at the OS level — the commands the
// poll backend missed (sub-interval, born-and-died-between-ticks). Such rows
// carry the deterministic message link but no pid / resource metrics / subtree.
// Keyed on attribution_source (action_correlation) + the pid 0 sentinel.
function isDerived(n: ProcessNodeLike): boolean {
  return n.attribution_source === "action_correlation" && n.pid === 0;
}

// derivedRuntimeLabel reports the coarse outcome of a derived command. The
// actions table records only a success boolean (no numeric exit code), so a
// derived row can honestly say "ok" / "failed", not "exit 137".
function derivedRuntimeLabel(n: ProcessNodeLike): string {
  return n.exit_code === 0 ? "ok" : "failed";
}

// processHasMetrics reports whether a node carries any renderable resource
// metric. Exported so a node-side summary line can count "N with metrics".
export function processHasMetrics(n: ProcessNodeLike): boolean {
  return !!(
    (n.cpu_ms && n.cpu_ms > 0) ||
    (n.working_set_bytes && n.working_set_bytes > 0) ||
    (n.read_bytes && n.read_bytes > 0) ||
    (n.write_bytes && n.write_bytes > 0)
  );
}

function countDescendants(node: ProcessNodeLike): number {
  let n = node.children.length;
  for (const c of node.children) n += countDescendants(c);
  return n;
}

// flattenProcessNodes walks the tree into a flat pre-order list. Exported so a
// node-side summary line can derive running / with-metrics counts.
export function flattenProcessNodes(roots: ProcessNodeLike[]): ProcessNodeLike[] {
  const out: ProcessNodeLike[] = [];
  const walk = (ns: ProcessNodeLike[]) => {
    for (const n of ns) {
      out.push(n);
      walk(n.children);
    }
  };
  walk(roots);
  return out;
}

// RenderMessageLink renders the spawning-message affordance for a process. The
// node passes a callback that focuses the message; when absent, ProcessTree
// renders a plain, non-interactive id.
export type RenderMessageLink = (messageId: string) => ReactNode;

function MessageCell({
  node,
  renderMessageLink,
}: {
  node: ProcessNodeLike;
  renderMessageLink?: RenderMessageLink;
}) {
  if (!node.message_id) return null;
  if (renderMessageLink) return <>{renderMessageLink(node.message_id)}</>;
  return (
    <span className="font-mono text-[11px] text-accent">{node.message_id}</span>
  );
}

// Sparkline — a tiny SVG polyline of a metric series (default: working set).
function Sparkline({
  samples,
  pick,
  title,
}: {
  samples: MetricSampleLike[];
  pick: (s: MetricSampleLike) => number;
  title?: string;
}) {
  if (!samples || samples.length < 2) return null;
  const vals = samples.map(pick);
  const max = Math.max(1, ...vals);
  const w = 54;
  const h = 14;
  const pts = vals
    .map((v, i) => {
      const x = (i / (vals.length - 1)) * (w - 2) + 1;
      const y = h - 1 - (v / max) * (h - 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg
      width={w}
      height={h}
      viewBox={`0 0 ${w} ${h}`}
      className="shrink-0 text-accent"
      aria-hidden
    >
      {title ? <title>{title}</title> : null}
      <polyline points={pts} fill="none" stroke="currentColor" strokeWidth="1" />
    </svg>
  );
}

// MetricBadges — compact CPU / memory / disk/network readouts + a working-set
// sparkline.
function MetricBadges({ node }: { node: ProcessNodeLike }) {
  if (!processHasMetrics(node) && !node.network_count) return null;
  const ws = node.working_set_bytes ?? 0;
  const peak = node.peak_rss_bytes ?? 0;
  const rb = node.read_bytes ?? 0;
  const wb = node.write_bytes ?? 0;
  const memTitle =
    peak > ws ? `working set ${fmtBytes(ws)} · peak ${fmtBytes(peak)}` : `working set ${fmtBytes(ws)}`;
  return (
    <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[10.5px] text-fg-3">
      {node.cpu_ms != null && node.cpu_ms > 0 && (
        <span title="cumulative CPU time (user+system)">⏱ {fmtDuration(node.cpu_ms)}</span>
      )}
      {ws > 0 && (
        <span title={memTitle}>
          ▦ {fmtBytes(ws)}
          {peak > ws ? <span className="text-fg-4"> /{fmtBytes(peak)}</span> : null}
        </span>
      )}
      {(rb > 0 || wb > 0) && (
        <span title={`disk read ${fmtBytes(rb)} · write ${fmtBytes(wb)}`}>
          ↓{fmtBytes(rb)} ↑{fmtBytes(wb)}
        </span>
      )}
      {node.thread_count != null && node.thread_count > 0 && (
        <span className="text-fg-4" title="threads">
          {node.thread_count}t
        </span>
      )}
      {node.metric_samples && node.metric_samples.length >= 2 && (
        <Sparkline
          samples={node.metric_samples}
          pick={(s) => s.ws}
          title="working-set trend"
        />
      )}
      {node.network_count != null && node.network_count > 0 && (
        <span title="network_connect events captured for this process">
          net {fmtInt(node.network_count)}
        </span>
      )}
    </span>
  );
}

function ProcessTreeNode({
  node,
  depth,
  collapsed,
  onToggle,
  renderMessageLink,
}: {
  node: ProcessNodeLike;
  depth: number;
  collapsed: Set<string>;
  onToggle: (key: string) => void;
  renderMessageLink?: RenderMessageLink;
}) {
  const hasChildren = node.children.length > 0;
  const isCollapsed = collapsed.has(node.process_key);
  return (
    <div>
      <div
        className="flex flex-wrap items-center gap-x-2 gap-y-0.5 border-b border-line-1/60 py-[3px] text-[12px] last:border-b-0"
        style={{ paddingLeft: depth * 14 }}
      >
        {hasChildren ? (
          <button
            type="button"
            onClick={() => onToggle(node.process_key)}
            className="w-[16px] select-none text-left text-fg-3 hover:text-fg-1"
            aria-label={isCollapsed ? "Expand" : "Collapse"}
            title={
              isCollapsed
                ? `Expand (${countDescendants(node)} descendant${countDescendants(node) === 1 ? "" : "s"})`
                : "Collapse"
            }
          >
            {isCollapsed ? "▸" : "▾"}
          </button>
        ) : (
          <span className="w-[16px] select-none text-fg-4">·</span>
        )}
        <span className="font-mono text-fg-1">{node.exe || "?"}</span>
        {isDerived(node) ? (
          <>
            <Pill
              variant="neutral"
              title="From the tool's own exec record (run_command action) - no OS process was captured for this command (it finished between poll ticks), so there is no pid, resource metrics, or subtree. The message link is exact."
            >
              from tool log
            </Pill>
            <span className={node.exit_code === 0 ? "text-fg-3" : "text-danger"}>
              {derivedRuntimeLabel(node)}
            </span>
          </>
        ) : (
          <>
            <span className="text-fg-3">pid {node.pid}</span>
            <Pill variant={attributionVariant(node.attribution_source)}>
              {attributionLabel(node)}
            </Pill>
            <span className={node.exited ? "text-fg-3" : "text-success"}>
              {runtimeLabel(node)}
            </span>
          </>
        )}
        {node.started_at && (
          <span className="text-fg-4" title={`started ${node.started_at}`}>
            {fmtClock(node.started_at)}
          </span>
        )}
        {isCollapsed && hasChildren && (
          <span className="text-fg-3" title="hidden descendants">
            +{countDescendants(node)}
          </span>
        )}
        <MetricBadges node={node} />
        {node.command && (
          <span className="truncate text-fg-3" title={node.command}>
            ↳ {node.command}
            {node.turn_index != null ? ` · turn ${node.turn_index}` : ""}
          </span>
        )}
        <MessageCell node={node} renderMessageLink={renderMessageLink} />
        {node.container_id && (
          <Pill variant="info" title="container id (cgroup-derived)">
            {node.container_id}
          </Pill>
        )}
      </div>
      {hasChildren &&
        !isCollapsed &&
        node.children.map((c) => (
          <ProcessTreeNode
            key={c.process_key}
            node={c}
            depth={depth + 1}
            collapsed={collapsed}
            onToggle={onToggle}
            renderMessageLink={renderMessageLink}
          />
        ))}
    </div>
  );
}

type SortKey = "cpu" | "mem" | "disk" | "start" | "exe" | "dur";

function sortValue(n: ProcessNodeLike, key: SortKey): number | string {
  switch (key) {
    case "cpu":
      return n.cpu_ms ?? 0;
    case "mem":
      return Math.max(n.working_set_bytes ?? 0, n.peak_rss_bytes ?? 0);
    case "disk":
      return (n.read_bytes ?? 0) + (n.write_bytes ?? 0);
    case "start":
      return n.pid; // stable proxy; the API already orders by start time
    case "exe":
      return (n.exe || "").toLowerCase();
    case "dur":
      return n.duration_ms ?? 0;
  }
}

function ProcessTable({
  nodes,
  renderMessageLink,
  extended = false,
}: {
  nodes: ProcessNodeLike[];
  renderMessageLink?: RenderMessageLink;
  // extended opts the Table view into the org's extra columns (cwd + duration)
  // and honest peak-RSS memory labelling. Each addition is still gated on
  // per-row data presence below. The node omits it, keeping the Table view
  // byte-for-byte unchanged.
  extended?: boolean;
}) {
  const [sortKey, setSortKey] = useState<SortKey>("mem");
  const [desc, setDesc] = useState(true);
  const [showAll, setShowAll] = useState(false);
  // Only show the org's extra columns when opted in AND some visible row
  // actually carries the field (an org session with no cwd gets no cwd column).
  const showCwd = extended && nodes.some((n) => n.cwd && n.cwd.length > 0);
  const showDuration =
    extended && nodes.some((n) => n.duration_ms != null && n.duration_ms > 0);
  const sorted = useMemo(() => {
    const arr = [...nodes];
    arr.sort((a, b) => {
      const av = sortValue(a, sortKey);
      const bv = sortValue(b, sortKey);
      let c: number;
      if (typeof av === "number" && typeof bv === "number") c = av - bv;
      else c = String(av).localeCompare(String(bv));
      return desc ? -c : c;
    });
    return arr;
  }, [nodes, sortKey, desc]);
  // Cap the rendered rows so a huge session doesn't build a 1,000-row table; the
  // sort puts the most relevant rows first, and "show all" lifts the cap (C1).
  const capped = sorted.length > TABLE_ROW_CAP && !showAll;
  const visible = capped ? sorted.slice(0, TABLE_ROW_CAP) : sorted;

  const Header = ({ k, label, right }: { k: SortKey; label: string; right?: boolean }) => (
    <th
      className={`cursor-pointer select-none py-1 font-medium hover:text-fg-1 ${right ? "text-right" : "text-left"}`}
      onClick={() => {
        if (sortKey === k) setDesc((v) => !v);
        else {
          setSortKey(k);
          setDesc(true);
        }
      }}
    >
      {label}
      {sortKey === k ? (desc ? " ↓" : " ↑") : ""}
    </th>
  );

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] text-left text-[11.5px]">
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr className="border-b border-line-2">
            <Header k="exe" label="Process" />
            {showCwd && <th className="py-1 pl-2 font-medium">cwd</th>}
            <th className="py-1 font-medium">pid</th>
            <th className="py-1 font-medium">started</th>
            {showDuration && <Header k="dur" label="Duration" right />}
            <th className="py-1 font-medium">state</th>
            <Header k="cpu" label="CPU" right />
            <Header k="mem" label="Memory" right />
            <Header k="disk" label="Disk R/W" right />
            <th className="py-1 pl-2 font-medium">message</th>
          </tr>
        </thead>
        <tbody>
          {visible.map((n) => (
            <tr key={n.process_key} className="border-b border-line-1/60 last:border-b-0">
              <td className="py-1 pr-2 font-mono text-fg-1">{n.exe || "?"}</td>
              {showCwd && (
                <td
                  className="max-w-[260px] truncate py-1 pl-2 pr-2 font-mono text-fg-3"
                  title={n.cwd || undefined}
                >
                  {n.cwd || "-"}
                </td>
              )}
              <td
                className="py-1 pr-2 text-fg-3"
                title={isDerived(n) ? "from the tool's exec record - no OS process captured" : undefined}
              >
                {isDerived(n) ? <span className="text-fg-4">tool log</span> : n.pid}
              </td>
              <td className="py-1 pr-2 whitespace-nowrap tabular-nums text-fg-3" title={n.started_at || undefined}>
                {fmtClock(n.started_at)}
              </td>
              {showDuration && (
                <td className="py-1 pr-2 text-right font-mono tabular-nums text-fg-3">
                  {n.duration_ms && n.duration_ms > 0 ? fmtDuration(n.duration_ms) : "-"}
                </td>
              )}
              {isDerived(n) ? (
                <td className={`py-1 pr-2 ${n.exit_code === 0 ? "text-fg-3" : "text-danger"}`}>
                  {derivedRuntimeLabel(n)}
                </td>
              ) : (
                <td className={`py-1 pr-2 ${n.exited ? "text-fg-3" : "text-success"}`}>
                  {runtimeLabel(n)}
                </td>
              )}
              <td className="py-1 pr-2 text-right font-mono tabular-nums text-fg-2">
                {n.cpu_ms ? fmtDuration(n.cpu_ms) : "-"}
              </td>
              <td
                className="py-1 pr-2 text-right font-mono tabular-nums text-fg-2"
                title={
                  extended && !n.working_set_bytes && n.peak_rss_bytes
                    ? "peak RSS (no working-set sample captured)"
                    : undefined
                }
              >
                {n.working_set_bytes ? (
                  fmtBytes(n.working_set_bytes)
                ) : extended && n.peak_rss_bytes ? (
                  <>
                    {fmtBytes(n.peak_rss_bytes)}
                    <span className="text-fg-4"> peak</span>
                  </>
                ) : (
                  "-"
                )}
              </td>
              <td className="py-1 pr-2 text-right font-mono tabular-nums text-fg-3">
                {(n.read_bytes ?? 0) + (n.write_bytes ?? 0) > 0
                  ? `↓${fmtBytes(n.read_bytes ?? 0)} ↑${fmtBytes(n.write_bytes ?? 0)}`
                  : "-"}
              </td>
              <td className="py-1 pl-2">
                <MessageCell node={n} renderMessageLink={renderMessageLink} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {sorted.length > TABLE_ROW_CAP && (
        <button
          type="button"
          onClick={() => setShowAll((v) => !v)}
          className="mt-1 text-[10.5px] text-fg-3 hover:text-fg-1"
        >
          {showAll ? `Show top ${TABLE_ROW_CAP}` : `Show all ${fmtInt(sorted.length)} (showing ${TABLE_ROW_CAP})`}
        </button>
      )}
    </div>
  );
}

// ProcessTree — the Tree | Table toggle + Collapse-all + the tree/table body,
// owning the view + collapsed state. Feed it the roots and total; it opens a
// large tree collapsed-to-roots once per `sessionKey`.
export function ProcessTree({
  roots,
  total,
  sessionKey,
  renderMessageLink,
  extendedTableColumns = false,
}: {
  roots: ProcessNodeLike[];
  total: number;
  // sessionKey scopes the one-time large-tree collapse-to-roots so it runs
  // once per session, not on every roots update.
  sessionKey?: string | null;
  renderMessageLink?: RenderMessageLink;
  // extendedTableColumns opts the Table view into the org's cwd + duration
  // columns and honest peak-RSS memory labelling (each still gated on per-row
  // data presence). The node omits it, so its Table view is byte-for-byte
  // unchanged. It only affects the Table view, never the Tree view.
  extendedTableColumns?: boolean;
}) {
  const [view, setView] = useState<"tree" | "table">("tree");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const toggle = useCallback((key: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const flat = useMemo(() => flattenProcessNodes(roots), [roots]);

  const parentKeys = useMemo(() => {
    const keys: string[] = [];
    const walk = (nodes: ProcessNodeLike[]) => {
      for (const n of nodes) {
        if (n.children.length > 0) {
          keys.push(n.process_key);
          walk(n.children);
        }
      }
    };
    walk(roots);
    return keys;
  }, [roots]);
  const allCollapsed = parentKeys.length > 0 && parentKeys.every((k) => collapsed.has(k));

  // Large trees open collapsed-to-roots so a huge session doesn't render
  // thousands of nodes + sparklines at once (C1). Runs once per session key, on
  // the first data load — leaves the operator's manual expand/collapse alone
  // after.
  const collapseInitRef = useRef<string | null>(null);
  const sk = sessionKey ?? "";
  useEffect(() => {
    if (collapseInitRef.current === sk) return;
    collapseInitRef.current = sk;
    if (total > LARGE_TREE_THRESHOLD) setCollapsed(new Set(parentKeys));
  }, [sk, total, parentKeys]);

  return (
    <>
      <div className="flex items-center justify-between gap-2">
        <div className="flex overflow-hidden rounded-2 border border-line-2 text-[10.5px]">
          {(["tree", "table"] as const).map((v) => (
            <button
              key={v}
              type="button"
              onClick={() => setView(v)}
              className={
                view === v
                  ? "bg-accent-soft px-2 py-0.5 text-accent"
                  : "px-2 py-0.5 text-fg-3 hover:text-fg-1"
              }
            >
              {v === "tree" ? "Tree" : "Table"}
            </button>
          ))}
        </div>
        {view === "tree" && parentKeys.length > 0 && (
          <button
            type="button"
            onClick={() => setCollapsed(allCollapsed ? new Set() : new Set(parentKeys))}
            className="text-[10.5px] text-fg-3 hover:text-fg-1"
          >
            {allCollapsed ? "Expand all" : "Collapse all"}
          </button>
        )}
      </div>

      <div className="rounded-3 border border-line-2 bg-bg-2 p-3">
        {view === "tree" ? (
          roots.map((r) => (
            <ProcessTreeNode
              key={r.process_key}
              node={r}
              depth={0}
              collapsed={collapsed}
              onToggle={toggle}
              renderMessageLink={renderMessageLink}
            />
          ))
        ) : (
          <ProcessTable
            nodes={flat}
            renderMessageLink={renderMessageLink}
            extended={extendedTableColumns}
          />
        )}
      </div>
    </>
  );
}
