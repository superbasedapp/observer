import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import clsx from "clsx";
import { History, Play, Zap, type LucideIcon } from "lucide-react";
import { NAV_ITEMS } from "@/lib/nav";
import { useMessagesSummary } from "@/lib/useMessagesSummary";
import { showMessagesNav } from "@/lib/adminMessages";
import { NODE_TAB_ROUTES, nodeTabJumps } from "@/lib/pageTabRoutes";
import { useGovernanceVisibility } from "@/lib/governance";
import { hiddenNavIds, withoutHiddenPaths } from "@/lib/visibility";
import { useInactiveNavIds } from "@/lib/useComponents";
import { hiddenTabIds, withoutHiddenTabPaths } from "@/lib/tabVisibility";
import { useTour } from "@/components/tour/TourProvider";
import { openFirstRun } from "@/lib/firstRun";
import { useFilters } from "@/lib/filters";
import { toolMeta } from "@/lib/tools";
import { fmtShortId } from "@/lib/format";
import type {
  ActionListRow,
  ActionsResponse,
  SessionRow,
  SessionsResponse,
} from "./../lib/types";
import { Icon, InlineLoading, ToolDot, TruncatedPath } from "./primitives";
import { CommandPaletteShell, type PaletteSection } from "@shared/components/palette/CommandPalette";

// CommandPalette: the node's Cmd-K / Ctrl-K sources over the shared palette
// shell (shared/components/palette/CommandPalette.tsx owns the chrome and
// the keyboard). Sections: Commands, Jump (pages and page tabs), recent
// Sessions, recent Actions. Filters by the same `useFilters().query` global
// so existing per-page filters (Sessions table) stay live as the user types.

type JumpItem = {
  kind: "page";
  key: string;
  label: string;
  hint: string;
  path: string;
  /** Old names a search also finds this jump by (a retired page). */
  aliases?: readonly string[];
  /** A page-tab jump: listed only once the viewer types, so the bare
   *  palette stays one row per page. */
  tab?: boolean;
  // The page's own nav glyph (lib/nav.ts is the one owner), so every Jump
  // row reads like its sidebar entry instead of one generic page icon.
  icon: LucideIcon;
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

// KIND_ICON — the glyph for every non-page row kind, table-driven so a new
// kind is one row here (pages take their glyph from the nav table instead).
// Tone rides along so the command row keeps its accent play marker.
const KIND_ICON: Record<Exclude<Item["kind"], "page">, { icon: LucideIcon; tone: string }> = {
  command: { icon: Play, tone: "text-accent" },
  session: { icon: History, tone: "text-fg-3" },
  action: { icon: Zap, tone: "text-fg-3" },
};

const RECENT_LIMIT = 8;

// Every page tab is a jump too ("Security › Prompt guard"), generated from
// lib/pageTabRoutes.ts (built on nodePageTabs.ts, the ids and labels the
// pages read), never hand-listed here. The page glyph comes from the nav
// table like every other Jump row.
const NAV_BY_ID = new Map(NAV_ITEMS.map((n) => [n.id, n]));
const TAB_PAGES: JumpItem[] = nodeTabJumps().flatMap((j) => {
  const nav = NAV_BY_ID.get(j.navId);
  if (!nav) return [];
  const label = `${nav.label} › ${j.tabLabel}`;
  return [
    {
      kind: "page" as const,
      key: `page:${j.to}`,
      label,
      hint: `Jump to ${label}`,
      path: j.to,
      icon: nav.icon,
      aliases: j.aliases,
      tab: true,
    },
  ];
});

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

  // Pages (and page tabs) hidden on this machine are not offered as jumps.
  // Fails closed until the posture is known (Sol A4-05).
  const gov = useGovernanceVisibility();
  // A page hidden by governance or owned by an inactive component is not
  // offered (modular packaging plan 7.3).
  const inactiveNav = useInactiveNavIds();
  // Messages is offered only on an enrolled node (D-695), like the nav.
  const messagesShown = showMessagesNav(useMessagesSummary().data);
  const hiddenPages = useMemo(
    () => [...hiddenNavIds(gov.gov), ...inactiveNav, ...(messagesShown ? [] : ["messages"])],
    [gov.gov, inactiveNav, messagesShown],
  );
  const hiddenTabs = hiddenTabIds(gov.gov);

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
      {
        kind: "command",
        key: "cmd:firstrun",
        label: "Show history capture",
        hint: "AI tools found here and how much of their history is captured",
        // After the palette has closed, so the dialog takes focus last.
        run: () => window.setTimeout(openFirstRun, 0),
      },
    ];
    const pages: JumpItem[] = withoutHiddenPaths(NAV_ITEMS, (n) => n.path, hiddenPages, NAV_ITEMS).map((n) => ({
      kind: "page",
      key: `page:${n.path}`,
      label: n.label,
      hint: `Jump to ${n.label}`,
      path: n.path,
      icon: n.icon,
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
    const tabPages = withoutHiddenTabPaths(
      withoutHiddenPaths(TAB_PAGES, (j) => j.path, hiddenPages, NAV_ITEMS),
      (j) => j.path,
      hiddenTabs,
      NODE_TAB_ROUTES,
    );
    const matchCmd = (i: CommandItem) =>
      i.label.toLowerCase().includes(q) || i.hint.toLowerCase().includes(q);
    const matchPage = (i: JumpItem) =>
      i.label.toLowerCase().includes(q) ||
      i.path.includes(q) ||
      (i.aliases ?? []).some((a) => a.toLowerCase().includes(q));
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
      ...tabPages.filter(matchPage),
      ...sessRows.filter(matchSess),
      ...actRows.filter(matchAct),
    ];
  }, [query, sessions, actions, startTour, hiddenPages, hiddenTabs]);

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

  // Split the flat items list into the shell's sections (order kept).
  const sections = useMemo<PaletteSection[]>(() => {
    const by: Record<Item["kind"], Item[]> = { command: [], page: [], session: [], action: [] };
    for (const it of items) by[it.kind].push(it);
    const toRows = (list: Item[]) =>
      list.map((it) => ({
        key: it.key,
        body: renderRow(it),
        title: it.kind === "session" ? it.id : undefined,
        onActivate: () => activate(it),
      }));
    return [
      { title: "Commands", rows: toRows(by.command) },
      { title: "Jump to", rows: toRows(by.page) },
      { title: "Recent sessions", rows: toRows(by.session) },
      { title: "Recent actions", rows: toRows(by.action) },
    ];
    // activate closes over navigate / setQuery / onClose, all stable per open.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items]);

  return (
    <CommandPaletteShell
      open={open}
      onClose={onClose}
      query={query}
      onQueryChange={setQuery}
      sections={sections}
      placeholder="Search pages, sessions, actions…"
      error={loadErr ? `Failed to load recents: ${loadErr}` : null}
      empty={
        sessions == null ? (
          <InlineLoading label="Loading recents" />
        ) : query.trim() ? (
          `No matches for "${query.trim()}".`
        ) : (
          "No recent data."
        )
      }
    />
  );
}

function renderRow(item: Item): ReactNode {
  if (item.kind === "command") {
    return (
      <>
        <KindIcon kind={item.kind} />
        <span className="text-[12px] font-semibold">{item.label}</span>
        <span className="ml-auto text-[10.5px] text-fg-3">{item.hint}</span>
      </>
    );
  }
  if (item.kind === "page") {
    return (
      <>
        <Icon icon={item.icon} size="xs" className="shrink-0 text-fg-3" />
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
        <KindIcon kind={item.kind} />
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
      <KindIcon kind={item.kind} />
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

// KindIcon renders the KIND_ICON row for a non-page item kind.
function KindIcon({ kind }: { kind: keyof typeof KIND_ICON }) {
  const k = KIND_ICON[kind];
  return <Icon icon={k.icon} size="xs" className={clsx("shrink-0", k.tone)} />;
}
