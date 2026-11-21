import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type MouseEvent,
  type ReactNode,
} from "react";
import clsx from "clsx";
import { Icon, InfoDisclosure, Pill } from "../../primitives";
import { fmtBytes, fmtClock, fmtDuration, fmtInt } from "../../lib/format";
import type { MetricSampleLike, ProcessNodeLike } from "../../lib/types";
import {
  FOLD_TOTAL_THRESHOLD,
  captureGaps,
  chainOf,
  indexProcesses,
  stepInList,
  type ProcessStackIndex,
} from "../../lib/processLayout";
import { ProcessFlame, processDomId, spawnLinkOf } from "./ProcessFlame";
import { ProcessSpawnStack } from "./ProcessSpawnStack";
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  ChevronRight,
  CornerDownRight,
  MemoryStick,
  Timer,
  TriangleAlert,
} from "lucide-react";

// ProcessTree - the OS-level process view of the session-detail System tab,
// in three ways over the same data: Tree (who started whom, nested), Table
// (sortable, flat) and Call stack (the spawn chain over time: ProcessFlame +
// ProcessSpawnStack). One picked process is shared by all three, so switching
// views keeps it; the caller may own that selection (the node keeps it in the
// URL as ?proc=) or leave it to local state.
//
// Promoted into the shared design system so the org can render the node-style
// tree (building `children` from parent_run_key) instead of a flat table.
//
// It is pure: process nodes in, views out. The node couplings are injected:
// the spawning-message link (`renderMessageLink` for the Tree/Table cells,
// `onOpenMessage` for the Call stack and the selection strip) and the session
// timeline link (`onOpenTimeline`). The /processes fetch, capture-diagnostics
// panel, findings and network egress list all stay node-side.

type PillVariant = "neutral" | "success" | "warn" | "danger" | "info" | "accent";

/** The three views of the processes panel. */
export type ProcessView = "tree" | "table" | "stack";

const VIEW_LABELS: Readonly<Record<ProcessView, string>> = {
  tree: "Tree",
  table: "Table",
  stack: "Call stack",
};

// LARGE_TREE_THRESHOLD: above this many captured processes the tree opens
// collapsed-to-roots, so a huge session (e.g. a long-running daemon subtree)
// doesn't render thousands of nodes + sparklines at once.
const LARGE_TREE_THRESHOLD = 150;
// TABLE_ROW_CAP: the Table view renders at most this many rows (the top ones by
// the active sort) with a "show all" escape hatch.
const TABLE_ROW_CAP = 100;

// ATTRIBUTION_VARIANT - how a process was attributed to the session: a
// direct signal (env token, pid bridge, adapter pid) is accent, inherited
// from the parent is neutral, none is warn; any other source reads info.
const ATTRIBUTION_VARIANT: Readonly<Record<string, PillVariant>> = {
  env_token: "accent",
  bridge: "accent",
  adapter_pid: "accent",
  inherited: "neutral",
  none: "warn",
};

function attributionVariant(source: string): PillVariant {
  return ATTRIBUTION_VARIANT[source] ?? "info";
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

// fromControl: a click that landed on a button or link inside a row acts on
// that control, not on the row's selection.
function fromControl(e: MouseEvent<HTMLElement>): boolean {
  return !!(e.target as HTMLElement).closest("button, a, input, label");
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
        <span className="inline-flex items-center gap-0.5" title="cumulative CPU time (user+system)">
          <Icon icon={Timer} size={10} />
          {fmtDuration(node.cpu_ms)}
        </span>
      )}
      {ws > 0 && (
        <span className="inline-flex items-center gap-0.5" title={memTitle}>
          <Icon icon={MemoryStick} size={10} />
          {fmtBytes(ws)}
          {peak > ws ? <span className="text-fg-4"> /{fmtBytes(peak)}</span> : null}
        </span>
      )}
      {(rb > 0 || wb > 0) && (
        <span title={`disk read ${fmtBytes(rb)} · write ${fmtBytes(wb)}`}>
          <DiskIO read={rb} write={wb} />
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

type SelectionProps = {
  selectedKey: string | null;
  ancestors: ReadonlySet<string>;
  onSelect: (key: string) => void;
  idPrefix: string;
};

function ProcessTreeNode({
  node,
  depth,
  collapsed,
  onToggle,
  renderMessageLink,
  sel,
}: {
  node: ProcessNodeLike;
  depth: number;
  collapsed: Set<string>;
  onToggle: (key: string) => void;
  renderMessageLink?: RenderMessageLink;
  sel: SelectionProps;
}) {
  const hasChildren = node.children.length > 0;
  const isCollapsed = collapsed.has(node.process_key);
  const isSel = sel.selectedKey === node.process_key;
  const isAnc = !isSel && sel.ancestors.has(node.process_key);
  return (
    <div role="none">
      <div
        id={processDomId(sel.idPrefix, node.process_key)}
        role="treeitem"
        aria-level={depth + 1}
        aria-selected={isSel}
        aria-expanded={hasChildren ? !isCollapsed : undefined}
        onClick={(e) => {
          if (!fromControl(e)) sel.onSelect(node.process_key);
        }}
        className={clsx(
          "flex cursor-pointer flex-wrap items-center gap-x-2 gap-y-0.5 rounded-1 border-b border-line-1/60 py-[3px] text-[12px] last:border-b-0 hover:bg-bg-3",
          isSel && "bg-accent-soft shadow-[inset_2px_0_0_var(--accent)] hover:bg-accent-soft",
        )}
        style={{ paddingLeft: depth * 14 + 2 }}
      >
        {hasChildren ? (
          <button
            type="button"
            tabIndex={-1}
            onClick={() => onToggle(node.process_key)}
            className="w-[16px] select-none text-left text-fg-3 hover:text-fg-1"
            aria-label={isCollapsed ? "Expand" : "Collapse"}
            title={
              isCollapsed
                ? `Expand (${countDescendants(node)} descendant${countDescendants(node) === 1 ? "" : "s"})`
                : "Collapse"
            }
          >
            <Icon icon={isCollapsed ? ChevronRight : ChevronDown} size="xs" />
          </button>
        ) : (
          <span className="w-[16px] select-none text-fg-4">·</span>
        )}
        <span className={clsx("font-mono", isAnc ? "text-accent" : "text-fg-1")}>{node.exe || "?"}</span>
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
            <span className={node.exited ? (node.exit_code !== 0 || (node.exit_signal ?? 0) > 0 ? "text-danger" : "text-fg-3") : "text-success"}>
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
            <Icon icon={CornerDownRight} size={10} className="mr-0.5 inline-block align-middle" />
            {node.command}
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
      {hasChildren && !isCollapsed && (
        <div role="group">
          {node.children.map((c) => (
            <ProcessTreeNode
              key={c.process_key}
              node={c}
              depth={depth + 1}
              collapsed={collapsed}
              onToggle={onToggle}
              renderMessageLink={renderMessageLink}
              sel={sel}
            />
          ))}
        </div>
      )}
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
  sel,
  onOpenSelected,
}: {
  nodes: ProcessNodeLike[];
  renderMessageLink?: RenderMessageLink;
  // extended opts the Table view into the org's extra columns (cwd + duration)
  // and honest peak-RSS memory labelling. Each addition is still gated on
  // per-row data presence below. The node omits it.
  extended?: boolean;
  sel: SelectionProps;
  onOpenSelected: () => void;
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
  // A selection made in another view may sit below the row cap: lift the cap
  // so the picked row is always on screen.
  const selIdx = sel.selectedKey ? sorted.findIndex((n) => n.process_key === sel.selectedKey) : -1;
  useEffect(() => {
    if (selIdx >= TABLE_ROW_CAP) setShowAll(true);
  }, [selIdx]);
  // Cap the rendered rows so a huge session doesn't build a 1,000-row table; the
  // sort puts the most relevant rows first, and "show all" lifts the cap (C1).
  const capped = sorted.length > TABLE_ROW_CAP && !showAll;
  const visible = capped ? sorted.slice(0, TABLE_ROW_CAP) : sorted;
  const keys = useMemo(() => visible.map((n) => n.process_key), [visible]);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const next = stepInList(keys, sel.selectedKey, e.key === "ArrowDown" ? 1 : -1);
      if (next) sel.onSelect(next);
    } else if (e.key === "Home" || e.key === "End") {
      e.preventDefault();
      const k = e.key === "Home" ? keys[0] : keys[keys.length - 1];
      if (k) sel.onSelect(k);
    } else if (e.key === "Enter") {
      onOpenSelected();
    }
  };

  const Header = ({ k, label, right }: { k: SortKey; label: string; right?: boolean }) => (
    <th
      className={`cursor-pointer select-none py-1 font-medium hover:text-fg-1 ${right ? "text-right" : "text-left"}`}
      aria-sort={sortKey === k ? (desc ? "descending" : "ascending") : undefined}
      onClick={() => {
        if (sortKey === k) setDesc((v) => !v);
        else {
          setSortKey(k);
          setDesc(true);
        }
      }}
    >
      <span className="inline-flex items-center gap-0.5">
        {label}
        {sortKey === k && <Icon icon={desc ? ArrowDown : ArrowUp} size={10} />}
      </span>
    </th>
  );

  return (
    <div
      className="overflow-x-auto rounded-1 outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
      tabIndex={0}
      role="grid"
      aria-label="Processes"
      aria-activedescendant={sel.selectedKey && selIdx >= 0 ? processDomId(sel.idPrefix, sel.selectedKey) : undefined}
      onKeyDown={onKeyDown}
    >
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
          {visible.map((n) => {
            const isSel = n.process_key === sel.selectedKey;
            return (
              <tr
                key={n.process_key}
                id={processDomId(sel.idPrefix, n.process_key)}
                aria-selected={isSel}
                onClick={(e) => {
                  if (!fromControl(e)) sel.onSelect(n.process_key);
                }}
                className={clsx(
                  "cursor-pointer border-b border-line-1/60 last:border-b-0 hover:bg-bg-3",
                  isSel && "bg-accent-soft shadow-[inset_2px_0_0_var(--accent)] hover:bg-accent-soft",
                )}
              >
                <td className={clsx("py-1 pr-2 pl-1 font-mono", !isSel && sel.ancestors.has(n.process_key) ? "text-accent" : "text-fg-1")}>
                  {n.exe || "?"}
                </td>
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
                  <td className={`py-1 pr-2 ${n.exited ? (n.exit_code !== 0 || (n.exit_signal ?? 0) > 0 ? "text-danger" : "text-fg-3") : "text-success"}`}>
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
                    ? <DiskIO read={n.read_bytes ?? 0} write={n.write_bytes ?? 0} />
                    : "-"}
                </td>
                <td className="py-1 pl-2">
                  <MessageCell node={n} renderMessageLink={renderMessageLink} />
                </td>
              </tr>
            );
          })}
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

// SelectionStrip - shown above Tree and Table: the picked process's spawn path
// (each step clickable), the turn and message that started it, and a jump to
// the Call stack view. It is what makes the shared selection visible when the
// picked row has scrolled away.
function SelectionStrip({
  index,
  selectedKey,
  onSelect,
  onOpenMessage,
  onShowStack,
  sessionLabel,
}: {
  index: ProcessStackIndex;
  selectedKey: string | null;
  onSelect: (key: string) => void;
  onOpenMessage?: (messageId: string) => void;
  onShowStack: () => void;
  sessionLabel: string;
}) {
  const chain = chainOf(index, selectedKey);
  if (!chain.length) {
    return (
      <div className="rounded-2 border border-dashed border-line-2 px-2.5 py-1.5 text-[11.5px] text-fg-3">
        Pick a process in any view. It stays picked when you switch between Tree, Table and Call stack.
      </div>
    );
  }
  const path = chain.slice().reverse();
  const MAX = 6;
  const shown = path.length > MAX ? [path[0], ...path.slice(path.length - (MAX - 1))] : path;
  const hidden = path.length - shown.length;
  const link = spawnLinkOf(index, selectedKey);
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-2 border border-accent-ring bg-accent-soft px-2.5 py-1.5 text-[11.5px]">
      <span className="text-[10px] uppercase tracking-[0.06em] text-fg-4">Selected</span>
      <nav aria-label="Spawn path of the selected process" className="flex min-w-0 flex-wrap items-center gap-0.5">
        <span className="px-1 text-fg-3">{sessionLabel}</span>
        {shown.map((it, i) => (
          <span key={it.key} className="inline-flex items-center gap-0.5">
            <span className="text-[10px] text-fg-4" aria-hidden>
              ›
            </span>
            {hidden > 0 && i === 1 && (
              <span className="px-1 text-fg-4" title={`${hidden} more`}>
                …
              </span>
            )}
            <button
              type="button"
              onClick={() => onSelect(it.key)}
              aria-current={it.key === selectedKey ? "true" : undefined}
              className={clsx(
                "rounded-1 px-1 font-mono text-[11px] hover:bg-bg-4",
                it.key === selectedKey ? "font-medium text-fg-0" : "text-fg-2",
              )}
            >
              {it.node.exe || "?"}
              {it.key === selectedKey && !it.derived ? <span className="text-fg-3"> {it.node.pid}</span> : null}
            </button>
          </span>
        ))}
      </nav>
      <span className="ml-auto flex flex-wrap items-center gap-x-3">
        {link &&
          (link.node.message_id && onOpenMessage ? (
            <button
              type="button"
              onClick={() => onOpenMessage(link.node.message_id!)}
              className="text-accent hover:underline"
              title="Open the message that started this process"
            >
              {link.node.turn_index != null ? `Turn ${link.node.turn_index}` : "Started by"} · open message
            </button>
          ) : link.node.turn_index != null ? (
            <span className="text-fg-3">Turn {link.node.turn_index}</span>
          ) : null)}
        <button type="button" onClick={onShowStack} className="text-accent hover:underline">
          Show call stack →
        </button>
      </span>
    </div>
  );
}

// ProcessTree — the Tree | Table | Call stack switcher + body, owning the view
// and collapsed state (and the selection, unless the caller owns it). Feed it
// the roots and total; it opens a large tree collapsed-to-roots once per
// `sessionKey`.
export function ProcessTree({
  roots,
  total,
  sessionKey,
  renderMessageLink,
  extendedTableColumns = false,
  selectedKey: selectedProp,
  onSelectedKeyChange,
  onOpenMessage,
  onOpenTimeline,
  sessionLabel = "Session",
  nowMs,
  initialView = "tree",
}: {
  roots: ProcessNodeLike[];
  total: number;
  // sessionKey scopes the one-time large-tree collapse-to-roots so it runs
  // once per session, not on every roots update.
  sessionKey?: string | null;
  renderMessageLink?: RenderMessageLink;
  // extendedTableColumns opts the Table view into the org's cwd + duration
  // columns and honest peak-RSS memory labelling (each still gated on per-row
  // data presence). It only affects the Table view.
  extendedTableColumns?: boolean;
  // selectedKey / onSelectedKeyChange let the caller own the picked process
  // (the node keeps it in the URL). Omit both for local selection state.
  selectedKey?: string | null;
  onSelectedKeyChange?: (key: string | null) => void;
  // onOpenMessage opens the message (and so the turn) that started a process;
  // used by the Call stack view and the selection strip. Absent: plain text.
  onOpenMessage?: (messageId: string) => void;
  // onOpenTimeline opens the session's message timeline (the session frame of
  // the spawn stack). Absent: no link.
  onOpenTimeline?: () => void;
  // sessionLabel names the session frame / root bar, e.g. "Session 7f3c2a91".
  sessionLabel?: string;
  // nowMs is the right edge for running processes (defaults to the render time).
  nowMs?: number;
  initialView?: ProcessView;
}) {
  const [view, setView] = useState<ProcessView>(initialView);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [localSel, setLocalSel] = useState<string | null>(null);
  const controlled = onSelectedKeyChange !== undefined;
  const selectedKey = controlled ? (selectedProp ?? null) : localSel;
  const select = useCallback(
    (key: string | null) => {
      if (controlled) onSelectedKeyChange?.(key);
      else setLocalSel(key);
    },
    [controlled, onSelectedKeyChange],
  );

  const toggle = useCallback((key: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const flat = useMemo(() => flattenProcessNodes(roots), [roots]);
  // now is captured per data load so a re-render does not move every bar.
  const now = useMemo(() => nowMs ?? Date.now(), [nowMs, roots]); // eslint-disable-line react-hooks/exhaustive-deps
  const index = useMemo(() => indexProcesses(roots, now), [roots, now]);
  const ancestors = useMemo(() => new Set(chainOf(index, selectedKey).map((it) => it.key)), [index, selectedKey]);

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

  // A process picked elsewhere (Call stack, Table, a deep link) must be visible
  // in the Tree: open its collapsed ancestors.
  useEffect(() => {
    if (!selectedKey) return;
    const anc = chainOf(index, selectedKey).slice(1).map((it) => it.key);
    setCollapsed((prev) => {
      if (!anc.some((k) => prev.has(k))) return prev;
      const next = new Set(prev);
      for (const k of anc) next.delete(k);
      return next;
    });
  }, [selectedKey, index]);

  // Keep the picked row in view when it changes.
  const idPrefix = "proc";
  useEffect(() => {
    if (!selectedKey || view === "stack") return;
    const el = document.getElementById(processDomId(`${idPrefix}-${view}`, selectedKey));
    el?.scrollIntoView?.({ block: "nearest" });
  }, [selectedKey, view]);

  const openSelected = useCallback(() => {
    const link = spawnLinkOf(index, selectedKey);
    if (link?.node.message_id && onOpenMessage) onOpenMessage(link.node.message_id);
  }, [index, selectedKey, onOpenMessage]);

  // Tree keyboard: up/down walk the visible rows, left collapses or goes to the
  // parent, right expands or goes to the first child, Enter opens the message.
  const visibleTreeKeys = useMemo(() => {
    const out: string[] = [];
    const walk = (ns: ProcessNodeLike[]) => {
      for (const n of ns) {
        out.push(n.process_key);
        if (n.children.length && !collapsed.has(n.process_key)) walk(n.children);
      }
    };
    walk(roots);
    return out;
  }, [roots, collapsed]);
  const onTreeKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const cur = selectedKey ? index.byKey.get(selectedKey) : undefined;
    switch (e.key) {
      case "ArrowDown":
      case "ArrowUp": {
        e.preventDefault();
        const next = stepInList(visibleTreeKeys, selectedKey, e.key === "ArrowDown" ? 1 : -1);
        if (next) select(next);
        return;
      }
      case "ArrowLeft": {
        if (!cur) return;
        e.preventDefault();
        if (cur.node.children.length && !collapsed.has(cur.key)) toggle(cur.key);
        else if (cur.parentKey) select(cur.parentKey);
        return;
      }
      case "ArrowRight": {
        if (!cur || !cur.node.children.length) return;
        e.preventDefault();
        if (collapsed.has(cur.key)) toggle(cur.key);
        else select(cur.node.children[0].process_key);
        return;
      }
      case "Enter":
        openSelected();
        return;
    }
  };

  const gaps = useMemo(() => captureGaps(index), [index]);
  const gapParts: string[] = [];
  if (gaps.exitNotSeen) gapParts.push(`${fmtInt(gaps.exitNotSeen)} not seen exiting (drawn faded)`);
  if (gaps.parentNotCaptured) gapParts.push(`${fmtInt(gaps.parentNotCaptured)} whose parent was never captured`);
  if (gaps.toolLogOnly) gapParts.push(`${fmtInt(gaps.toolLogOnly)} known only from the tool log (dashed)`);

  const selProps = (v: ProcessView): SelectionProps => ({
    selectedKey,
    ancestors,
    onSelect: select,
    idPrefix: `${idPrefix}-${v}`,
  });

  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div
          role="tablist"
          aria-label="Process view"
          className="flex w-full overflow-hidden rounded-2 border border-line-2 text-[11px] sm:w-auto"
        >
          {(["tree", "table", "stack"] as const).map((v) => (
            <button
              key={v}
              type="button"
              role="tab"
              aria-selected={view === v}
              onClick={() => setView(v)}
              className={clsx(
                "flex-1 px-3 py-1 sm:flex-none [&+&]:border-l [&+&]:border-line-2",
                view === v ? "bg-accent-soft text-accent" : "text-fg-3 hover:text-fg-1",
              )}
            >
              {VIEW_LABELS[v]}
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

      {view === "stack" ? (
        <div className="space-y-2">
          <StackNotice total={flat.length} gapParts={gapParts} />
          {/* The chart takes the full width; the spawn stack sits below it. */}
          <ProcessFlame
            index={index}
            selectedKey={selectedKey}
            onSelect={select}
            onOpenMessage={onOpenMessage}
            sessionLabel={sessionLabel}
            nowMs={now}
            idPrefix={`${idPrefix}-stack`}
          />
          <ProcessSpawnStack
            index={index}
            selectedKey={selectedKey}
            onSelect={select}
            onOpenMessage={onOpenMessage}
            onOpenTimeline={onOpenTimeline}
            onShowView={setView}
            sessionLabel={sessionLabel}
          />
        </div>
      ) : (
        <SelectionStrip
          index={index}
          selectedKey={selectedKey}
          onSelect={select}
          onOpenMessage={onOpenMessage}
          onShowStack={() => setView("stack")}
          sessionLabel={sessionLabel}
        />
      )}

      {view !== "stack" && (
        <div className="rounded-3 border border-line-2 bg-bg-2 p-3">
          {view === "tree" ? (
            <div
              role="tree"
              aria-label="Process tree"
              tabIndex={0}
              onKeyDown={onTreeKeyDown}
              aria-activedescendant={
                selectedKey && visibleTreeKeys.includes(selectedKey)
                  ? processDomId(`${idPrefix}-tree`, selectedKey)
                  : undefined
              }
              className="rounded-1 outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
            >
              {roots.map((r) => (
                <ProcessTreeNode
                  key={r.process_key}
                  node={r}
                  depth={0}
                  collapsed={collapsed}
                  onToggle={toggle}
                  renderMessageLink={renderMessageLink}
                  sel={selProps("tree")}
                />
              ))}
            </div>
          ) : (
            <ProcessTable
              nodes={flat}
              renderMessageLink={renderMessageLink}
              extended={extendedTableColumns}
              sel={selProps("table")}
              onOpenSelected={openSelected}
            />
          )}
        </div>
      )}
    </>
  );
}

/**
 * StackNotice is the Call stack view's one compact line: what the capture
 * missed (warn toned, only when it missed something) and, for a large
 * session, that the chart opens on a window and folds identical parallel
 * processes, with the longer explanation behind "Why?". Nothing to say,
 * nothing rendered.
 */
export function StackNotice({ total, gapParts }: { total: number; gapParts: readonly string[] }) {
  const large = total > FOLD_TOTAL_THRESHOLD;
  if (!gapParts.length && !large) return null;
  return (
    <div role="note" className="text-[11px] leading-5 text-fg-3">
      {gapParts.length > 0 && (
        <span className="mr-2">
          <Icon icon={TriangleAlert} size={12} className="mr-1 inline-block align-[-2px] text-warn" />
          <span className="font-medium text-warn">Partial capture:</span>{" "}
          <span className="text-fg-2">
            of {fmtInt(total)} processes, {gapParts.join(", ")}.
          </span>
        </span>
      )}
      {large && (
        <>
          <span className="mr-1.5">Opens on a window of the session; identical processes share one bar.</span>
          <InfoDisclosure summary="Why?" className="inline">
            To keep the chart fast, a session with more than {fmtInt(FOLD_TOTAL_THRESHOLD)} processes opens on a
            window of the session instead of the whole span, and identical processes that ran side by side (test
            workers, a parallel build) share one bar. Zoom out or press Fit to see the whole session; click a shared
            bar to show each process in it.
          </InfoDisclosure>
        </>
      )}
    </div>
  );
}

// DiskIO renders a read/write byte pair as arrow glyphs (down = read,
// up = write), shared by the metric badges and the flat table.
function DiskIO({ read, write }: { read: number; write: number }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className="inline-flex items-center">
        <Icon icon={ArrowDown} size={10} label="read" />
        {fmtBytes(read)}
      </span>
      <span className="inline-flex items-center">
        <Icon icon={ArrowUp} size={10} label="write" />
        {fmtBytes(write)}
      </span>
    </span>
  );
}
