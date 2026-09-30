import { useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import clsx from "clsx";
import {
  useFilters,
  windowLabel,
  windowParams,
  type CustomRange,
  type Window,
} from "@/lib/filters";
import { useApi } from "@/lib/useApi";
import type { ToolsResponse, ProjectsResponse } from "@/lib/types";
import { toolMeta } from "@/lib/tools";
import { filterScopeFor, ignoredFilters } from "@/lib/filterScope";
import {
  ComboChip,
  type ComboOption,
  DateRangePopover,
  Icon,
  ToolDot,
  Tooltip,
} from "./primitives";
import { HelpInd } from "./HelpInd";
import { Box, Clock, Folder, Search } from "lucide-react";

const WINDOW_OPTIONS: ComboOption[] = [
  { value: "1h", label: "1 hr", searchable: "1 hr hour sub-day" },
  { value: "12h", label: "12 hrs", searchable: "12 hrs hours sub-day" },
  { value: "1d", label: "1 day", searchable: "1 day 24h" },
  { value: "7d", label: "7 days", searchable: "7 days week" },
  { value: "14d", label: "14 days", searchable: "14 days fortnight" },
  { value: "30d", label: "30 days", searchable: "30 days month" },
  { value: "90d", label: "90 days", searchable: "90 days quarter" },
  { value: "1y", label: "1 year", searchable: "1 year 365 days" },
  { value: "all", label: "All time", searchable: "all time everything" },
  { value: "custom", label: "Custom…", searchable: "custom range dates" },
];

export function FilterBar({
  onOpenPalette,
}: {
  onOpenPalette: () => void;
}) {
  const { win, customRange, tool, setTool, project, setProject, query } =
    useFilters();
  // Route-aware: only the filters the current page actually reads are shown
  // (lib/filterScope.ts). Search opens the global palette, so it stays.
  const { pathname } = useLocation();
  const scope = filterScopeFor(pathname);
  const ignored = ignoredFilters(scope, { tool, project });

  // /api/tools is the source of truth for which tools have data in
  // the active window (mirrors the legacy dashboard's behaviour). Neither
  // list is fetched on a page that does not show its picker.
  const tools = useApi<ToolsResponse>(
    scope.tool ? "/api/tools" : null,
    { ...windowParams(win, customRange) },
    [win, customRange],
  );
  const projects = useApi<ProjectsResponse>(scope.project ? "/api/projects" : null);

  return (
    <div className="flex flex-wrap items-center gap-2 gap-y-2 border-b border-line-1 bg-bg-1 px-3 py-2 lg:h-[var(--filterbar-h)] lg:flex-nowrap lg:gap-3 lg:px-5 lg:py-0">
      {scope.window && <WindowSelect />}

      {scope.tool && (
        <ToolSelect
          value={tool}
          onChange={setTool}
          tools={tools.data?.tools ?? []}
        />
      )}

      {scope.project && (
        <ProjectSelect
          value={project}
          onChange={setProject}
          projects={projects.data?.rows ?? []}
        />
      )}

      <SearchTrigger query={query} onOpen={onOpenPalette} />

      {/* A tool / project filter that is set but not read here is still
          applied on the pages that read it; say so rather than hide it. */}
      {ignored.length > 0 && (
        <span className="text-[11px] text-fg-3">
          {ignored.length === 2 ? "Tool and project filters" : ignored[0] === "tool" ? "The tool filter" : "The project filter"}{" "}
          {ignored.length === 2 ? "do" : "does"} not apply to this page
        </span>
      )}

      {/* Spacer pushes the loading note to the right on desktop; on
          mobile it would force an unwanted wrap break, so it's hidden
          below lg (the wrapped controls flow left-to-right instead). */}
      <div className="hidden flex-1 lg:block" />
      <span className="text-[11px] text-fg-3">
        {tools.loading || projects.loading ? "loading filters…" : null}
      </span>
    </div>
  );
}

// SearchTrigger — button-chip that opens the ⌘K palette. Mirrors
// design/shell.jsx:168-172. When a global query is set, the chip
// shows it (truncated) so the user has visible feedback that a
// search is in effect. The ⌘K shortcut is wired in App.tsx so it
// works from anywhere, not just FilterBar mount.
function SearchTrigger({
  query,
  onOpen,
}: {
  query: string;
  onOpen: () => void;
}) {
  const trimmed = query.trim();
  return (
    <Tooltip
      content={
        <>
          Open command palette <kbd>⌘K</kbd> - search pages, sessions, actions
        </>
      }
      maxWidth={320}
    >
    <button
      type="button"
      onClick={onOpen}
      className={clsx(
        "flex h-7 items-center gap-1.5 rounded-2 border bg-bg-2 px-2 text-[11px] transition-colors",
        trimmed
          ? "border-accent/50 text-fg-1"
          : "border-line-2 text-fg-3 hover:bg-bg-3 hover:text-fg-1",
      )}
    >
      <Icon icon={Search} size={11} />
      {trimmed ? (
        <span className="max-w-[180px] truncate font-mono text-[11px] text-fg-0">
          {trimmed}
        </span>
      ) : (
        <span>Search anything…</span>
      )}
      <kbd className="ml-0.5 rounded-1 border border-line-3 bg-bg-3 px-1 py-px font-mono text-[9.5px] text-fg-3">
        ⌘K
      </kbd>
    </button>
    </Tooltip>
  );
}

// WindowSelect — the global time-scope chip. Reuses ComboChip for
// the flat preset list; selecting "Custom…" defers to a
// DateRangePopover (ComboChip only renders flat options) that applies
// an explicit [since, until] range. The chip label stays compact
// ("30d", "1h", "Jul 10 → Jul 16") via windowLabel.
function WindowSelect() {
  const { win, customRange, setWin, setCustomRange } = useFilters();
  const [customOpen, setCustomOpen] = useState(false);

  function onPick(next: string) {
    if (next === "custom") {
      // Don't commit the window yet — open the range editor and only
      // switch to "custom" once the operator applies a valid range.
      setCustomOpen(true);
      return;
    }
    setCustomOpen(false);
    setWin(next as Window);
  }

  function applyCustom(r: CustomRange) {
    setCustomRange(r);
    setWin("custom");
    setCustomOpen(false);
  }

  return (
    <div className="relative flex items-center gap-1" data-tour="global-filter">
      <ComboChip
        label="Window"
        value={win}
        onChange={onPick}
        options={WINDOW_OPTIONS}
        icon={<Icon icon={Clock} size={13} className="text-fg-3" />}
        popoverWidth={200}
        placeholder="Filter windows…"
        buttonValueRender={() => (
          <b className="font-semibold text-fg-0">
            {windowLabel(win, customRange)}
          </b>
        )}
      />
      <HelpInd id="filter.window" />
      {customOpen && (
        <DateRangePopover
          value={customRange}
          onApply={applyCustom}
          onClose={() => setCustomOpen(false)}
        />
      )}
    </div>
  );
}

function ToolSelect({
  value,
  onChange,
  tools,
}: {
  value: string;
  onChange: (s: string) => void;
  tools: { tool: string; action_count: number }[];
}) {
  const options = useMemo<ComboOption[]>(() => {
    const opts: ComboOption[] = [
      {
        value: "all",
        label: "All tools",
        searchable: "all tools",
      },
    ];
    for (const t of tools) {
      const meta = toolMeta(t.tool);
      opts.push({
        value: t.tool,
        label: meta.label,
        searchable: `${meta.label} ${t.tool}`.toLowerCase(),
        leading: <ToolDot tool={t.tool} />,
        rightMeta: t.action_count.toLocaleString(),
      });
    }
    return opts;
  }, [tools]);

  return (
    <ComboChip
      label="Tool"
      value={value}
      onChange={onChange}
      options={options}
      icon={<Icon icon={Box} size={13} className="text-fg-3" />}
      popoverWidth={300}
      placeholder="Filter tools…"
      // The chip shows the APPLIED filter, even before /api/tools answers (a
      // filter restored from the URL is in force while the list loads).
      buttonValueRender={() => {
        if (value === "all") {
          return <b className="font-semibold text-fg-0">all</b>;
        }
        return (
          <span className="flex items-center gap-1.5">
            <ToolDot tool={value} />
            <b className="font-semibold text-fg-0">{toolMeta(value).label}</b>
          </span>
        );
      }}
    />
  );
}

function ProjectSelect({
  value,
  onChange,
  projects,
}: {
  value: string;
  onChange: (s: string) => void;
  projects: { root_path: string; action_count: number }[];
}) {
  const options = useMemo<ComboOption[]>(() => {
    const opts: ComboOption[] = [
      {
        value: "all",
        label: "All projects",
        searchable: "all projects",
      },
    ];
    for (const p of projects) {
      opts.push({
        value: p.root_path,
        label: (
          <span className="font-mono text-[11px]">{shortenPath(p.root_path)}</span>
        ),
        searchable: p.root_path.toLowerCase(),
        title: p.root_path,
        rightMeta: p.action_count.toLocaleString(),
      });
    }
    return opts;
  }, [projects]);

  return (
    <ComboChip
      label="Project"
      value={value}
      onChange={onChange}
      options={options}
      icon={<Icon icon={Folder} size={13} className="text-fg-3" />}
      popoverWidth={420}
      placeholder="Filter projects…"
      // Like the tool chip: the applied filter, even before /api/projects
      // answers.
      buttonValueRender={() => {
        if (value === "all") {
          return <b className="font-semibold text-fg-0">all</b>;
        }
        return (
          <Tooltip
            content={<span className="break-all font-mono">{value}</span>}
            maxWidth={420}
          >
            <b
              tabIndex={0}
              className="max-w-[200px] cursor-help truncate font-mono text-[11px] font-semibold text-fg-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]"
            >
              {shortenPath(value)}
            </b>
          </Tooltip>
        );
      }}
    />
  );
}

function shortenPath(p: string): string {
  if (!p) return "-";
  const parts = p.split("/").filter(Boolean);
  if (parts.length <= 2) return p;
  return ".../" + parts.slice(-2).join("/");
}
