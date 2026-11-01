import { useEffect, useState, type KeyboardEvent, type ReactNode } from "react";
import clsx from "clsx";
import { fmtBytes, fmtClock, fmtDuration, fmtInt } from "../../lib/format";
import {
  STACK_KEYS,
  chainOf,
  fmtOffset,
  isAgentProcess,
  moveSelection,
  parentNotCaptured,
  stackText,
  type ProcessStackIndex,
  type ProcessStackItem,
} from "../../lib/processLayout";
import { Pill } from "../../primitives";
import { processStateLabel, processStateTone } from "./ProcessFlame";

// ProcessSpawnStack - the list half of the "Call stack" view: for the picked
// process, the chain of processes that started it, read like a stack trace
// (the picked process on top, the session at the bottom). Each frame says what
// ran, for how long, how it ended, and, where the capture linked it, which turn
// and message started it. Its children are listed below so the reader can step
// down as well as up.
//
// Pure presentation. Selection is the caller's; message navigation and the
// session timeline link are injected.

const MAX_CHILD_CHIPS = 8;

export type ProcessSpawnStackProps = {
  index: ProcessStackIndex;
  selectedKey: string | null;
  onSelect: (key: string | null) => void;
  onOpenMessage?: (messageId: string) => void;
  /** Opens the session's message timeline. Absent: the session frame has no link. */
  onOpenTimeline?: () => void;
  /** Switches the Processes panel to another view with the same selection. */
  onShowView?: (view: "tree" | "table") => void;
  sessionLabel: string;
};

export function ProcessSpawnStack({
  index,
  selectedKey,
  onSelect,
  onOpenMessage,
  onOpenTimeline,
  onShowView,
  sessionLabel,
}: ProcessSpawnStackProps) {
  const chain = chainOf(index, selectedKey);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(t);
  }, [copied]);

  if (!chain.length) {
    return (
      <aside className="rounded-3 border border-line-2 bg-bg-2" aria-label="Spawn stack">
        <Header title="Spawn stack" />
        <div className="px-4 py-7 text-center">
          <div className="text-[13px] font-medium text-fg-1">Pick a process</div>
          <p className="mt-1 text-[11.5px] text-fg-3">
            Click any bar to see the chain of processes that started it, from the session down. Arrow keys move
            between processes.
          </p>
        </div>
      </aside>
    );
  }

  const picked = chain[0];
  const kids = index.children.get(picked.key) ?? [];
  const top = chain[chain.length - 1];
  const orphan = parentNotCaptured(index, top);

  const onKeyDown = (e: KeyboardEvent<HTMLOListElement>) => {
    const move = STACK_KEYS[e.key];
    if (!move) return;
    e.preventDefault();
    onSelect(moveSelection(index, selectedKey, move));
  };

  const copy = () => {
    const text = stackText(chain, sessionLabel);
    try {
      void navigator.clipboard?.writeText(text);
      setCopied(true);
    } catch {
      /* clipboard blocked: nothing to do */
    }
  };

  return (
    <aside className="min-w-0 rounded-3 border border-line-2 bg-bg-2" aria-label="Spawn stack">
      <Header title={`Spawn stack · ${fmtInt(chain.length)} deep`}>
        <button type="button" onClick={copy} className="hover:text-fg-1" title="Copy the stack as text">
          {copied ? "Copied" : "Copy"}
        </button>
        {onShowView && (
          <>
            <button type="button" onClick={() => onShowView("tree")} className="hidden hover:text-fg-1 sm:inline">
              Show in tree
            </button>
            <button type="button" onClick={() => onShowView("table")} className="hidden hover:text-fg-1 sm:inline">
              In table
            </button>
          </>
        )}
      </Header>

      <ol className="py-1.5 outline-none" tabIndex={0} onKeyDown={onKeyDown} aria-label="Processes from the picked one up to the session">
        {chain.map((it, i) => (
          <Frame
            key={it.key}
            item={it}
            index={index}
            current={i === 0}
            showSpawn={startsOwnCommand(it, chain[i + 1])}
            onSelect={onSelect}
            onOpenMessage={onOpenMessage}
          />
        ))}
        {orphan && (
          <li className="relative py-1.5 pl-[34px] pr-3">
            <Rail />
            <span aria-hidden className="absolute left-[12px] top-[10px] h-[11px] w-[11px] rounded-full border-2 border-dashed border-line-3 bg-bg-2" />
            <div className="flex flex-wrap items-baseline gap-1.5">
              <span className="text-[12px] font-medium italic text-fg-2">Parent not captured</span>
              <span className="font-mono text-[10.5px] text-fg-4">pid {top.node.ppid}</span>
            </div>
            <div className="text-[10.5px] text-fg-3">
              This process was started by one the capture never saw, so the chain stops here.
            </div>
          </li>
        )}
        <li className="relative py-1.5 pl-[34px] pr-3">
          <Rail last />
          <span aria-hidden className="absolute left-[12px] top-[10px] h-[11px] w-[11px] rounded-[3px] border-2 border-line-3 bg-bg-2" />
          <div className="text-[12px] font-medium text-fg-1">{sessionLabel}</div>
          {onOpenTimeline && (
            <button type="button" onClick={onOpenTimeline} className="text-[10.5px] text-accent hover:underline">
              Open the session timeline in Messages
            </button>
          )}
        </li>
      </ol>

      <div className="border-t border-line-1 px-3 py-2 text-[11px]">
        <div className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Started {fmtInt(kids.length)} process{kids.length === 1 ? "" : "es"}
        </div>
        {kids.length ? (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {kids.slice(0, MAX_CHILD_CHIPS).map((k) => (
              <button
                key={k.key}
                type="button"
                onClick={() => onSelect(k.key)}
                className={clsx(
                  "rounded-1 border border-line-2 bg-bg-3 px-1.5 font-mono text-[10.5px] hover:border-accent-ring hover:text-accent",
                  k.failed ? "text-danger" : "text-fg-2",
                )}
              >
                {k.node.exe}
                {k.derived ? "" : ` ${k.node.pid}`}
              </button>
            ))}
            {kids.length > MAX_CHILD_CHIPS && (
              <span className="self-center text-fg-4">+{fmtInt(kids.length - MAX_CHILD_CHIPS)}</span>
            )}
          </div>
        ) : (
          <div className="mt-0.5 text-fg-4">None. This process did not start any others.</div>
        )}
      </div>
      <p className="px-3 pb-2.5 text-[10.5px] text-fg-4">
        This shows which process started which, as the operating system recorded it. It is not a code-level call
        stack.
      </p>
    </aside>
  );
}

function Header({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2 border-b border-line-1 px-3 py-2">
      <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">{title}</span>
      {children && <span className="flex gap-3 text-[11px] text-fg-3">{children}</span>}
    </div>
  );
}

function Rail({ first, last }: { first?: boolean; last?: boolean }) {
  return (
    <span
      aria-hidden
      className="absolute left-[17px] border-l border-line-3"
      style={{ top: first ? 14 : 0, bottom: last ? "calc(100% - 14px)" : 0 }}
    />
  );
}

// startsOwnCommand: the "started by" line belongs on the frame where a tool
// call's link begins, not repeated on every descendant that inherited it.
function startsOwnCommand(it: ProcessStackItem, parent: ProcessStackItem | undefined): boolean {
  const n = it.node;
  if (!n.message_id && n.turn_index == null) return false;
  if (!parent) return true;
  return parent.node.message_id !== n.message_id || parent.node.turn_index !== n.turn_index;
}

function Frame({
  item,
  index,
  current,
  showSpawn,
  onSelect,
  onOpenMessage,
}: {
  item: ProcessStackItem;
  index: ProcessStackIndex;
  current: boolean;
  showSpawn: boolean;
  onSelect: (key: string) => void;
  onOpenMessage?: (messageId: string) => void;
}) {
  const n = item.node;
  const dot = clsx(
    "absolute left-[12px] top-[10px] h-[11px] w-[11px] rounded-full border-2",
    current
      ? "border-accent bg-accent"
      : item.failed
        ? "border-danger"
        : item.endKind === "running"
          ? "border-success"
          : isAgentProcess(n)
            ? "border-info"
            : "border-line-3",
    !current && "bg-bg-2",
    isAgentProcess(n) && "rounded-[3px]",
  );
  const mem = n.working_set_bytes || n.peak_rss_bytes;
  return (
    <li
      className={clsx("relative cursor-pointer py-1.5 pl-[34px] pr-3 hover:bg-bg-3", current && "bg-accent-soft")}
      onClick={() => onSelect(item.key)}
      aria-current={current ? "true" : undefined}
    >
      <Rail first={current} />
      <span aria-hidden className={dot} />
      <div className="flex flex-wrap items-baseline gap-x-1.5">
        <span className="font-mono text-[12px] font-medium text-fg-0">{n.exe || "?"}</span>
        {item.derived ? (
          <Pill variant="neutral" title="From the tool's own record of the command. No operating system process was captured for it.">
            from tool log
          </Pill>
        ) : (
          <span className="font-mono text-[10.5px] text-fg-4">pid {n.pid}</span>
        )}
        <span className={clsx("text-[10.5px]", processStateTone(item))}>{processStateLabel(item)}</span>
      </div>
      {n.argv_preview && (
        <div className="truncate font-mono text-[10.5px] text-fg-3" title={n.argv_preview}>
          {n.argv_preview}
        </div>
      )}
      <div className="flex flex-wrap gap-x-2 text-[10.5px] text-fg-3">
        <span className="tabular-nums">
          {fmtOffset(item.start - index.minStart)} · {fmtClock(n.started_at)}
        </span>
        <span>
          {item.endKind === "running"
            ? `${fmtDuration(item.end - item.start)} so far`
            : item.endKind === "unseen"
              ? `at least ${fmtDuration(item.end - item.start)}`
              : fmtDuration(item.end - item.start)}
        </span>
        {n.cpu_ms ? <span>{fmtDuration(n.cpu_ms)} cpu</span> : null}
        {mem ? <span>{fmtBytes(mem)}</span> : null}
      </div>
      {showSpawn && (
        <div
          className="mt-1 flex flex-wrap items-center gap-x-2 rounded-1 border border-line-1 bg-bg-3 px-1.5 py-[2px] text-[10.5px]"
          onClick={(e) => e.stopPropagation()}
        >
          <span className="text-fg-4">started by</span>
          <span className="text-fg-2">
            {n.turn_index != null ? `turn ${n.turn_index}` : "a tool call"}
            {n.command ? `: ${n.command}` : ""}
          </span>
          {n.message_id &&
            (onOpenMessage ? (
              <button
                type="button"
                onClick={() => onOpenMessage(n.message_id!)}
                className="font-mono text-accent hover:underline"
                title="Open the message that started this process"
              >
                {n.message_id}
              </button>
            ) : (
              <span className="font-mono text-fg-3">{n.message_id}</span>
            ))}
        </div>
      )}
    </li>
  );
}
