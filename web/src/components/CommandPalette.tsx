import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import clsx from "clsx";
import { NAV_ITEMS } from "@/lib/nav";
import { useTour } from "@/components/tour/TourProvider";
import { useFilters } from "@/lib/filters";
import { toolMeta } from "@/lib/tools";
import { fmtShortId } from "@/lib/format";
import type {
  ActionListRow,
  ActionsResponse,
  SessionRow,
  SessionsResponse,
} from "./../lib/types";
import { ToolDot, TruncatedPath } from "./primitives";

// CommandPalette — ⌘K / Ctrl-K modal palette. Three sections:
// Jump (pages), Sessions (recent N), Actions (recent N). Filters by
// the same `useFilters().query` global so existing per-page filters
// (Sessions table) stay live as the user types. Arrow keys traverse
// a flat list; Enter activates; Esc / backdrop / ⌘K closes.

type JumpItem = {
  kind: "page";
  key: string;
  label: string;
  hint: string;
  path: string;
};

type SessionItem = {
  kind: "session";
  key: string;
  id: string;
  tool: string;
  project: string;
  started_at: string;
};

type ActionItem = {
  kind: "action";
  key: string;
  id: number;
  tool: string;
  action_type: string;
  target: string;
  timestamp: string;
};

// CommandItem — an app action (not a navigation target) that runs an
// arbitrary callback. Kept as its own kind so activate() dispatches on
// shape, not on a magic path string.
type CommandItem = {
  kind: "command";
  key: string;
  label: string;
  hint: string;
  run: () => void;
};

type Item = JumpItem | SessionItem | ActionItem | CommandItem;

const RECENT_LIMIT = 8;

export function CommandPalette({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const navigate = useNavigate();
  const { startTour } = useTour();
  const { query, setQuery } = useFilters();
  const [sessions, setSessions] = useState<SessionRow[] | null>(null);
  const [actions, setActions] = useState<ActionListRow[] | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Lazy-load recent sessions + actions the first time the palette
  // opens. Cache for the session — re-opening doesn't re-fetch.
  useEffect(() => {
    if (!open) return;
    if (sessions != null && actions != null) return;
    let cancelled = false;
    (async () => {
      try {
        const [sRes, aRes] = await Promise.all([
          fetch(`/api/sessions?page=1&limit=${RECENT_LIMIT}`),
          fetch(`/api/actions?limit=${RECENT_LIMIT}`),
        ]);
        if (cancelled) return;
        const sJson: SessionsResponse = await sRes.json();
        const aJson: ActionsResponse = await aRes.json();
        setSessions(sJson.rows ?? []);
        setActions(aJson.rows ?? []);
        setLoadErr(null);
      } catch (e) {
        if (cancelled) return;
        setLoadErr(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open, sessions, actions]);

  // Focus search on open + reset cursor.
  useEffect(() => {
    if (!open) return;
    setActiveIdx(0);
    requestAnimationFrame(() => {
      inputRef.current?.focus();
      inputRef.current?.select();
    });
  }, [open]);

  // Esc closes; arrows scroll cursor through flat item list. Live for
  // both the modal backdrop and the input (input handles its own key
  // events; we also listen at document so arrows work even if focus
  // leaves the input).
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const items = useMemo<Item[]>(() => {
    const q = query.trim().toLowerCase();
    const commands: CommandItem[] = [
      {
        kind: "command",
        key: "cmd:tour",
        label: "Start product tour",
        hint: "Replay the guided walkthrough",
        run: startTour,
      },
    ];
    const pages: JumpItem[] = NAV_ITEMS.map((n) => ({
      kind: "page",
      key: `page:${n.path}`,
      label: n.label,
      hint: `Jump to ${n.label}`,
      path: n.path,
    }));
    const sessRows: SessionItem[] = (sessions ?? []).map((r) => ({
      kind: "session",
      key: `sess:${r.id}`,
      id: r.id,
      tool: r.tool,
      project: r.project,
      started_at: r.started_at,
    }));
    const actRows: ActionItem[] = (actions ?? []).map((r) => ({
      kind: "action",
      key: `act:${r.id}`,
      id: r.id,
      tool: r.tool,
      action_type: r.action_type,
      target: r.target,
      timestamp: r.timestamp,
    }));
    if (!q) return [...commands, ...pages, ...sessRows, ...actRows];
    const matchCmd = (i: CommandItem) =>
      i.label.toLowerCase().includes(q) || i.hint.toLowerCase().includes(q);
    const matchPage = (i: JumpItem) =>
      i.label.toLowerCase().includes(q) || i.path.includes(q);
    const matchSess = (i: SessionItem) =>
      i.id.toLowerCase().includes(q) ||
      i.project.toLowerCase().includes(q) ||
      i.tool.toLowerCase().includes(q);
    const matchAct = (i: ActionItem) =>
      i.action_type.toLowerCase().includes(q) ||
      i.target.toLowerCase().includes(q) ||
      i.tool.toLowerCase().includes(q);
    return [
      ...commands.filter(matchCmd),
      ...pages.filter(matchPage),
      ...sessRows.filter(matchSess),
      ...actRows.filter(matchAct),
    ];
  }, [query, sessions, actions, startTour]);

  // Keep cursor in range as the items list narrows.
  useEffect(() => {
    if (activeIdx >= items.length) setActiveIdx(Math.max(0, items.length - 1));
  }, [items.length, activeIdx]);

  function activate(it: Item) {
    if (it.kind === "command") {
      it.run();
      onClose();
      return;
    }
    if (it.kind === "page") navigate(it.path);
    else if (it.kind === "session") {
      // Push the session id into Sessions filter via globalQuery and
      // jump to Sessions. The id prefix-search will isolate the row;
      // user can click in to open the SessionDetailPanel.
      setQuery(it.id.slice(0, 12));
      navigate("/sessions");
    } else if (it.kind === "action") {
      setQuery(it.target.slice(0, 40));
      navigate("/actions");
    }
    onClose();
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIdx((i) => Math.min(items.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIdx((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const it = items[activeIdx];
      if (it) activate(it);
    }
  }

  // Split the flat items list back into sections for rendering — but
  // keep the original index so the keyboard cursor works against the
  // same flat array.
  const sections: { title: string; rows: { item: Item; idx: number }[] }[] =
    useMemo(() => {
      const cmds: { item: Item; idx: number }[] = [];
      const pages: { item: Item; idx: number }[] = [];
      const sess: { item: Item; idx: number }[] = [];
      const acts: { item: Item; idx: number }[] = [];
      items.forEach((it, idx) => {
        if (it.kind === "command") cmds.push({ item: it, idx });
        else if (it.kind === "page") pages.push({ item: it, idx });
        else if (it.kind === "session") sess.push({ item: it, idx });
        else acts.push({ item: it, idx });
      });
      const out: { title: string; rows: { item: Item; idx: number }[] }[] = [];
      if (cmds.length) out.push({ title: "Commands", rows: cmds });
      if (pages.length) out.push({ title: "Jump to", rows: pages });
      if (sess.length) out.push({ title: "Recent sessions", rows: sess });
      if (acts.length) out.push({ title: "Recent actions", rows: acts });
      return out;
    }, [items]);

  const body = (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            key="palette-backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.12, ease: "easeOut" }}
            onClick={onClose}
            className="fixed inset-0 z-[80] bg-black/55 backdrop-blur-sm"
          />
          <motion.div
            key="palette-panel"
            initial={{ opacity: 0, scale: 0.97, y: -8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.97, y: -8 }}
            transition={{ duration: 0.14, ease: "easeOut" }}
            role="dialog"
            aria-label="Command palette"
            className="fixed inset-0 z-[90] grid place-items-start justify-center pt-[12vh]"
            onClick={(e) => {
              // Clicking the wrapper (not the inner card) closes.
              if (e.target === e.currentTarget) onClose();
            }}
          >
            <div className="w-[min(560px,92vw)] overflow-hidden rounded-3 border border-line-2 bg-bg-1 shadow-drawer">
              <div className="flex items-center gap-2 border-b border-line-1 bg-bg-2/70 px-3 py-2.5">
                <SearchIcon />
                <input
                  ref={inputRef}
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={onKeyDown}
                  placeholder="Search pages, sessions, actions…"
                  className="h-7 flex-1 appearance-none bg-transparent text-[12.5px] text-fg-0 placeholder:text-fg-4 focus:outline-none"
                />
                <kbd className="rounded-1 border border-line-3 bg-bg-3 px-1.5 py-0.5 font-mono text-[9.5px] text-fg-3">
                  Esc
                </kbd>
              </div>
              <div
                className="max-h-[50vh] overflow-y-auto py-1"
                onKeyDown={onKeyDown}
                tabIndex={-1}
              >
                {loadErr && (
                  <p className="px-3 py-3 text-[11px] text-danger">
                    Failed to load recents: {loadErr}
                  </p>
                )}
                {sections.length === 0 ? (
                  <p className="px-3 py-6 text-center text-[11.5px] text-fg-3">
                    {sessions == null
                      ? "Loading recents…"
                      : query.trim()
                        ? `No matches for "${query.trim()}".`
                        : "No recent data."}
                  </p>
                ) : (
                  sections.map((sec) => (
                    <section key={sec.title}>
                      <header className="sticky top-0 z-10 bg-bg-1/95 px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
                        {sec.title}
                      </header>
                      {sec.rows.map(({ item, idx }) => (
                        <Row
                          key={item.key}
                          item={item}
                          active={idx === activeIdx}
                          onHover={() => setActiveIdx(idx)}
                          onActivate={() => activate(item)}
                        />
                      ))}
                    </section>
                  ))
                )}
              </div>
              <footer className="flex items-center justify-between gap-3 border-t border-line-1 bg-bg-2/40 px-3 py-1.5 text-[10px] text-fg-3">
                <span className="flex items-center gap-1.5">
                  <Kbd>↑</Kbd>
                  <Kbd>↓</Kbd>
                  to navigate
                </span>
                <span className="flex items-center gap-1.5">
                  <Kbd>Enter</Kbd>
                  to open
                </span>
                <span className="flex items-center gap-1.5">
                  <Kbd>⌘K</Kbd>
                  to toggle
                </span>
              </footer>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );

  // Portal to <body> so the palette overlays the entire app shell
  // (sidebar + topbar + page content) without interference from any
  // ancestor stacking context.
  if (typeof document === "undefined") return null;
  return createPortal(body, document.body);
}

function Row({
  item,
  active,
  onHover,
  onActivate,
}: {
  item: Item;
  active: boolean;
  onHover: () => void;
  onActivate: () => void;
}) {
  return (
    <button
      type="button"
      onMouseEnter={onHover}
      onClick={onActivate}
      title={item.kind === "session" ? item.id : undefined}
      className={clsx(
        "flex w-full items-center gap-2 px-3 py-1.5 text-left transition-colors",
        active ? "bg-accent-soft text-fg-0" : "bg-transparent text-fg-1",
      )}
    >
      {renderRow(item)}
    </button>
  );
}

function renderRow(item: Item): ReactNode {
  if (item.kind === "command") {
    return (
      <>
        <PlayIcon />
        <span className="text-[12px] font-semibold">{item.label}</span>
        <span className="ml-auto text-[10.5px] text-fg-3">{item.hint}</span>
      </>
    );
  }
  if (item.kind === "page") {
    return (
      <>
        <PageIcon />
        <span className="text-[12px] font-semibold">{item.label}</span>
        <span className="ml-auto font-mono text-[10.5px] text-fg-3">
          {item.path}
        </span>
      </>
    );
  }
  if (item.kind === "session") {
    return (
      <>
        <ToolDot tool={item.tool} />
        <span className="font-mono text-[11px] text-accent">
          {fmtShortId(item.id, 12)}
        </span>
        <TruncatedPath
          value={item.project || "-"}
          className="font-mono text-[10.5px] text-fg-3"
          tooltipMaxWidth={360}
        />
        <span className="ml-auto shrink-0 text-[10.5px] text-fg-3">
          {toolMeta(item.tool).label}
        </span>
      </>
    );
  }
  return (
    <>
      <ToolDot tool={item.tool} />
      <span className="text-[11.5px] text-fg-0">{item.action_type}</span>
      <span className="min-w-0 truncate font-mono text-[10.5px] text-fg-3">
        {item.target}
      </span>
      <span className="ml-auto shrink-0 font-mono text-[10.5px] text-fg-3">
        #{item.id}
      </span>
    </>
  );
}

function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="rounded-1 border border-line-3 bg-bg-3 px-1 py-px font-mono text-[9.5px] text-fg-2">
      {children}
    </kbd>
  );
}

function SearchIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden>
      <circle cx="7" cy="7" r="4.5" stroke="currentColor" strokeWidth="1.4" />
      <path
        d="m10.5 10.5 3 3"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

function PageIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden
      className="text-fg-3"
    >
      <path
        d="M4 2.5h5l3 3V13a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1Z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M9 2.5V6h3"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function PlayIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden
      className="text-accent"
    >
      <path
        d="M5 3.5v9l7-4.5-7-4.5Z"
        fill="currentColor"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinejoin="round"
      />
    </svg>
  );
}
