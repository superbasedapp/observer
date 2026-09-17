import { useState } from "react";
import clsx from "clsx";
import { ChevronDown, ChevronRight, Copy } from "lucide-react";
import {
  Pill,
  SlideOver,
  ToolBadge,
  Tooltip,
  TruncatedPath,
} from "@/components/primitives";
import { CopyOnClick } from "@/components/CopyOnClick";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import { fmtBytes, fmtDateTime, fmtRelative } from "@/lib/format";
import {
  DEFAULT_GUIDANCE_USAGE_WINDOW_DAYS,
  fetchGuidanceFile,
  formatGuidanceUsageSummary,
  formatKind,
  formatUsageUnavailable,
  groupGuidance,
  guidanceUsagePill,
  PROJECTS_GUIDANCE_FILE_PATH,
  PROJECTS_GUIDANCE_PATH,
  summarizeGuidanceUsage,
  usageLine,
  type GuidanceFileResponse,
  type GuidanceRow,
  type GuidanceToolGroup,
  type ProjectGuidanceResponse,
} from "@/lib/guidance";

// GuidanceCard renders one project's guidance-file inventory (CLAUDE.md,
// AGENTS.md, .cursorrules, .claude/skills/*, etc): what each AI tool reads,
// grouped by tool then kind, plus an honest per-tool usage-measurability
// line (never a fabricated invocation count) and a click-through file
// viewer.
export function GuidanceCard({ root }: { root: string }) {
  const data = useApi<ProjectGuidanceResponse>(
    PROJECTS_GUIDANCE_PATH,
    { root },
    [root],
  );
  const [viewerRel, setViewerRel] = useState<string | null>(null);

  const rows = data.data?.rows ?? [];
  const projectRows = rows.filter((r) => r.scope === "project");
  const userRows = rows.filter((r) => r.scope === "user");
  const projectGroups = groupGuidance(projectRows);
  const userGroups = groupGuidance(userRows);
  const measurable = data.data?.tools_measurable ?? {};
  const windowDays =
    data.data?.usage_window_days ?? DEFAULT_GUIDANCE_USAGE_WINDOW_DAYS;
  // A degraded usage read marks every row not_measurable, so the summary
  // would be null anyway; the explicit banner is what stops that reading as
  // "nothing is measurable here".
  const usageUnavailable = data.data?.usage_unavailable === true;
  // Only measurable rows are counted, so a project full of cursor rules
  // never reads as "0 of 12 invoked".
  const skillSummary = usageUnavailable
    ? null
    : formatGuidanceUsageSummary(
        summarizeGuidanceUsage(rows, "skill"),
        windowDays,
      );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line-2 pb-3">
        <div className="min-w-0">
          <h3 className="text-[13px] font-semibold text-fg-0">
            Guidance files
          </h3>
          <p className="mt-0.5 text-[11px] text-fg-3">
            {data.data
              ? `${rows.length} file${rows.length === 1 ? "" : "s"} across ${
                  projectGroups.length + userGroups.length
                } tool${projectGroups.length + userGroups.length === 1 ? "" : "s"}`
              : "Loading…"}
            {data.data?.scanned_at && (
              <> · last scanned {fmtRelative(data.data.scanned_at)}</>
            )}
          </p>
          {skillSummary && (
            <p className="mt-0.5 text-[11px] text-fg-2">{skillSummary}</p>
          )}
          {usageUnavailable && (
            <p className="mt-0.5 text-[11px] text-fg-3">
              {formatUsageUnavailable(data.data?.usage_error_class)}
            </p>
          )}
        </div>
      </div>

      <ChartState
        loading={data.loading && !data.data}
        error={data.error}
        empty={data.data != null && rows.length === 0}
        emptyHint="No instructions, skills, agents, commands, rules or config files were found for this project yet."
        height={140}
      >
        <div className="space-y-3">
          {projectGroups.map((g) => (
            <ToolGroupPanel
              key={g.tool}
              group={g}
              measurable={measurable[g.tool]}
              windowDays={windowDays}
              defaultOpen
              onOpenFile={setViewerRel}
            />
          ))}

          {userGroups.length > 0 && (
            <CollapsibleSection
              title="From your home directory"
              sub={`${userRows.length} user-scope file${userRows.length === 1 ? "" : "s"} shared across every project for the matching tool(s), not specific to this one`}
              defaultOpen={false}
            >
              <div className="space-y-3 pt-2">
                {userGroups.map((g) => (
                  <ToolGroupPanel
                    key={g.tool}
                    group={g}
                    measurable={measurable[g.tool]}
                    windowDays={windowDays}
                    defaultOpen={false}
                    onOpenFile={setViewerRel}
                  />
                ))}
              </div>
            </CollapsibleSection>
          )}
        </div>
      </ChartState>

      <GuidanceFileViewer
        root={root}
        rel={viewerRel}
        onClose={() => setViewerRel(null)}
      />
    </div>
  );
}

// ---------------------------------------------------------------- groups

function CollapsibleSection({
  title,
  sub,
  defaultOpen,
  children,
}: {
  title: string;
  sub?: string;
  defaultOpen: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-2 border border-line-2 bg-bg-3/30">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left"
        aria-expanded={open}
      >
        {open ? (
          <ChevronDown size={14} className="shrink-0 text-fg-3" />
        ) : (
          <ChevronRight size={14} className="shrink-0 text-fg-3" />
        )}
        <div className="min-w-0">
          <div className="text-[12px] font-semibold text-fg-1">{title}</div>
          {sub && <div className="text-[10.5px] text-fg-3">{sub}</div>}
        </div>
      </button>
      {open && <div className="px-3 pb-3">{children}</div>}
    </div>
  );
}

function ToolGroupPanel({
  group,
  measurable,
  windowDays,
  defaultOpen,
  onOpenFile,
}: {
  group: GuidanceToolGroup;
  measurable: boolean | undefined;
  windowDays: number;
  defaultOpen: boolean;
  onOpenFile: (rel: string) => void;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-2 border border-line-2 bg-bg-2">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left"
        aria-expanded={open}
      >
        {open ? (
          <ChevronDown size={14} className="shrink-0 text-fg-3" />
        ) : (
          <ChevronRight size={14} className="shrink-0 text-fg-3" />
        )}
        <ToolBadge tool={group.tool} />
        <span className="font-mono text-[10px] text-fg-4 tabular-nums">
          {group.total}
        </span>
        <span className="ml-auto hidden shrink-0 text-[10.5px] text-fg-3 sm:inline">
          {usageLine(group.tool, measurable, windowDays)}
        </span>
      </button>
      {open && (
        <div className="space-y-3 border-t border-line-1 px-3 py-3">
          {group.kinds.map((k) => (
            <KindTable
              key={k.kind}
              kind={k.kind}
              rows={k.rows}
              windowDays={windowDays}
              onOpenFile={onOpenFile}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function KindTable({
  kind,
  rows,
  windowDays,
  onOpenFile,
}: {
  kind: string;
  rows: GuidanceRow[];
  windowDays: number;
  onOpenFile: (rel: string) => void;
}) {
  return (
    <div>
      <div className="mb-1 text-[10px] font-medium uppercase tracking-[0.06em] text-fg-3">
        {formatKind(kind)}
        <span className="ml-1 font-mono normal-case tracking-normal text-fg-4">
          {rows.length}
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[520px] text-left text-[11.5px]">
          <tbody>
            {rows.map((r) => (
              <tr
                key={r.rel_path}
                onClick={() => onOpenFile(r.rel_path)}
                className={clsx(
                  "cursor-pointer border-b border-line-1 last:border-b-0 hover:bg-bg-3/40",
                  !r.present && "opacity-60",
                )}
              >
                <td className="py-1.5 pl-1 align-top">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="font-semibold text-fg-1">
                      {r.name}
                    </span>
                    {!r.present && <Pill variant="warn">removed</Pill>}
                    {r.parse_error && (
                      <Pill variant="danger" title={r.parse_error}>
                        parse error
                      </Pill>
                    )}
                    <UsagePill row={r} windowDays={windowDays} />
                  </div>
                  {r.description && (
                    <div className="mt-0.5 max-w-[440px] truncate text-fg-3">
                      {r.description}
                    </div>
                  )}
                  <TruncatedPath
                    value={r.rel_path}
                    className="mt-0.5 max-w-[440px] font-mono text-[10.5px] text-fg-4"
                  />
                </td>
                <td className="w-[90px] py-1.5 text-right align-top tabular-nums text-fg-3">
                  {fmtBytes(r.size_bytes)}
                </td>
                <td className="w-[150px] py-1.5 pr-1 text-right align-top tabular-nums text-fg-3">
                  <Tooltip content={fmtDateTime(r.modified_at)}>
                    <span tabIndex={0} className="cursor-help focus:outline-none">
                      {fmtRelative(r.modified_at)}
                    </span>
                  </Tooltip>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// UsagePill renders the wave-2 per-file usage fact, and renders NOTHING for a
// file whose usage cannot be observed — the tool-group header already says
// "usage is not measurable", and a pill there would dress an absence of
// evidence up as evidence of absence.
function UsagePill({
  row,
  windowDays,
}: {
  row: GuidanceRow;
  windowDays: number;
}) {
  const usage = guidanceUsagePill(row);
  if (!usage) return null;
  if (usage.never) {
    return (
      <Pill
        variant="neutral"
        title={`No ${usage.verb === "loaded" ? "load" : "invocation"} of this file was captured in this project in the last ${windowDays} days.`}
      >
        never {usage.verb} ({windowDays}d)
      </Pill>
    );
  }
  return (
    <Pill
      variant="success"
      title={
        usage.last
          ? `Last ${usage.verb} ${fmtDateTime(usage.last)}`
          : undefined
      }
    >
      {usage.verb} {usage.count}x
      {usage.last ? `, last ${fmtRelative(usage.last)}` : null}
    </Pill>
  );
}

// ---------------------------------------------------------------- viewer

function GuidanceFileViewer({
  root,
  rel,
  onClose,
}: {
  root: string;
  rel: string | null;
  onClose: () => void;
}) {
  const path = rel ? PROJECTS_GUIDANCE_FILE_PATH : null;
  const file = useApi<GuidanceFileResponse>(
    path,
    rel ? { root, rel } : undefined,
    [root, rel],
  );

  return (
    <SlideOver
      open={rel != null}
      onClose={onClose}
      title={rel ?? ""}
      subtitle={file.data?.scrubbed ? "Scrubbed for secrets" : undefined}
      width={720}
    >
      <div className="p-4">
        <ChartState
          loading={file.loading && !file.data}
          error={file.error}
          empty={false}
          height={200}
        >
          {file.data && (
            <div className="space-y-3">
              {file.data.truncated && (
                <Pill variant="warn">
                  Truncated — showing a partial preview of this file
                </Pill>
              )}
              <div className="flex items-center justify-between gap-2">
                <span className="text-[10.5px] text-fg-3">
                  {file.data.scrubbed
                    ? "Secrets are scrubbed from this preview before it ever leaves the file."
                    : null}
                </span>
                <CopyOnClick value={file.data.content}>
                  <span className="flex h-6 items-center gap-1 rounded-2 border border-line-2 bg-bg-2 px-2 text-[10.5px] text-fg-2 hover:bg-bg-3 hover:text-fg-0">
                    <Copy size={12} /> Copy
                  </span>
                </CopyOnClick>
              </div>
              <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap break-words rounded-2 border border-line-2 bg-bg-3/40 p-3 font-mono text-[11px] leading-relaxed text-fg-1">
                {file.data.content}
              </pre>
            </div>
          )}
        </ChartState>
      </div>
    </SlideOver>
  );
}

// fetchGuidanceFile is re-exported here only so a caller that already
// imports GuidanceCard can prefetch a file without a second import path.
export { fetchGuidanceFile };
