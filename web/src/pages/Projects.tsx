import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/DataTable";
import {
  ExecutionLocationBadge,
  PageHeader,
  Pill,
  SlideOver,
  Tooltip,
  TruncatedPath,
} from "@/components/primitives";
import { groupCloudTwins, offMachineSessions } from "@/lib/cloudLane";
import { ChartState } from "@/components/ChartState";
import { GuidanceCard } from "@/components/GuidanceCard";
import { ProjectDetailPanel } from "@/components/ProjectDetailPanel";
import { useApi } from "@/lib/useApi";
import { useFilters, windowLabel, windowParams } from "@/lib/filters";
import { costLabel, fmtInt, fmtRelative, fmtUSD, withoutDollars } from "@/lib/format";
import { COMMIT_CAPTURE, commitCaptureTip } from "@/lib/vocabTones";
import { VocabPill } from "@shared/lib/vocabPill";
import { CodeCommentSplit } from "@shared/primitives/CodeCommentSplit";
import {
  fetchProjectsGuidanceSummary,
  PROJECTS_GUIDANCE_SUMMARY_PATH,
  type GuidanceSummaryRow,
} from "@/lib/guidance";
import type { ProjectRow, ProjectsResponse } from "@/lib/types";
import { navIcon } from "@/lib/nav";

// ProjectsPage lists every project Observer has seen (from /api/projects)
// merged with the guidance-file inventory (/api/projects/guidance/summary),
// so a project row shows both its capture activity and how many
// instructions/skills/agents/commands/rules/config files exist for it.
// Clicking a row opens a deep-linkable (`?root=`) SlideOver with the full
// GuidanceCard breakdown for that project.
export function ProjectsPage() {
  // The whole filter bar applies (lib/filterScope.ts): the window bounds the
  // counted activity and the spend / code / commit columns, tool and model
  // narrow sessions, actions and spend, project keeps its one row.
  const { win, customRange, tool, model, project } = useFilters();
  const projects = useApi<ProjectsResponse>(
    "/api/projects",
    {
      ...windowParams(win, customRange),
      tool: tool !== "all" ? tool : undefined,
      project: project !== "all" ? project : undefined,
      model: model !== "all" ? model : undefined,
    },
    [win, customRange, tool, model, project],
  );
  const winText = windowLabel(win, customRange);
  // The drawer follows the same window (REVIEW-3 P3-25), capped at the
  // detail routes' 365-day ceiling.
  const drawerWin = useMemo(() => windowParams(win, customRange, { maxDays: 365 }), [win, customRange]);
  const summary = useApi<GuidanceSummaryRow[]>(PROJECTS_GUIDANCE_SUMMARY_PATH);

  const [searchParams, setSearchParams] = useSearchParams();
  const selectedRoot = searchParams.get("root");
  const setSelectedRoot = (root: string | null) => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (root) next.set("root", root);
        else next.delete("root");
        return next;
      },
      { replace: true },
    );
  };
  // `?project=<id>` opens the new ROI/commit-alignment detail panel. Kept
  // as a SEPARATE param from `?root=` (rather than reusing it) because a
  // project row that has never been through the commit-scanner / cost
  // engine wiring may carry no `id` yet (R7: the composite fields are
  // additive and omitempty) — that row falls back to the legacy guidance
  // SlideOver instead, and the two params can never collide since only one
  // opens at a time from a row click.
  const selectedProjectId = searchParams.get("project");
  const setSelectedProjectId = (id: number | null) => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (id != null) next.set("project", String(id));
        else next.delete("project");
        return next;
      },
      { replace: true },
    );
  };

  const columns = useMemo(() => {
    const summaryByRoot = new Map<string, GuidanceSummaryRow>();
    for (const s of summary.data ?? []) {
      summaryByRoot.set(s.project_root, s);
    }
    // Spend is dollars only: dropped in the org's token-usage view.
    return withoutDollars(projectColumns(summaryByRoot, winText), (c) => c.id === "spend");
  }, [summary.data, winText]);
  // Code lines and commits belong to the project, not to a tool or model,
  // so those two filters leave them as the window's project totals.
  const narrowedNote =
    tool !== "all" || model !== "all"
      ? "Tool and model filters narrow sessions, actions and spend; AI code lines and commits stay project totals for the window."
      : "";

  // A synthetic cloud project ("cloud:<remote>") lists right under the
  // local project with the same remote (cloud-agents lane CA-B5); a header
  // sort reorders freely, and the Project cell still names the twin.
  const rows = useMemo(() => groupCloudTwins(projects.data?.rows ?? []), [projects.data]);
  const loading = projects.loading && !projects.data;
  const error = projects.error;

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("projects")}
        title="Projects"
        sub={`Every project Observer has captured activity for: ${costLabel("spend, ", "")}commits, AI-vs-human lines, prompt-to-commit alignment, and the instructions/skills/agents/commands/rules/config files each AI tool reads from it (CLAUDE.md, AGENTS.md, .cursorrules, .claude/skills/*, and similar).`}
        helpId="tab.projects"
      />
      {narrowedNote && <p className="-mt-3 text-[11.5px] text-fg-3">{narrowedNote}</p>}

      <ChartState
        loading={loading}
        error={error}
        denied={projects.denied}
        deniedPermission={projects.deniedPermission}
        empty={!loading && rows.length === 0}
        emptyHint={
          win === "all" && tool === "all" && model === "all" && project === "all"
            ? "No projects captured yet. Once an AI tool runs inside a project directory, it will show up here."
            : "No project has activity under the current filters. Widen the window or clear a filter."
        }
        height={240}
      >
        <div className="rounded-3 border border-line-2 bg-bg-2">
          <DataTable<ProjectRow>
            data={rows}
            columns={columns}
            rowKey={(r) => r.root_path}
            minWidth={960}
            // Unpaginated: every captured project is one row, hundreds on a
            // busy node. Render in batches as the list scrolls.
            incrementalRows={100}
            onRowClick={(r) =>
              r.id != null ? setSelectedProjectId(r.id) : setSelectedRoot(r.root_path)
            }
          />
        </div>
      </ChartState>

      <SlideOver
        open={selectedRoot != null}
        onClose={() => setSelectedRoot(null)}
        title={selectedRoot ? <ProjectTitle root={selectedRoot} /> : ""}
        width={960}
      >
        {selectedRoot && (
          <div className="p-4">
            <GuidanceCard root={selectedRoot} />
          </div>
        )}
      </SlideOver>

      <ProjectDetailPanel
        projectId={selectedProjectId != null ? Number(selectedProjectId) : null}
        open={selectedProjectId != null}
        onClose={() => setSelectedProjectId(null)}
        win={drawerWin}
        tool={tool}
        model={model}
      />
    </div>
  );
}

// ProjectCell: the project path plus where its sessions ran (cloud-agents
// lane CA-B5). A synthetic cloud project ("cloud:<remote>", a remote-only
// session's home) carries a "cloud project" pill and, once a local checkout
// of the same remote exists, is indented under it. A project with sessions
// that ran in a vendor cloud or on a worker carries the badge and the count.
function ProjectCell({ r }: { r: ProjectRow }) {
  const off = offMachineSessions(r.execution_mix);
  const twinned = r.cloud_twin_of != null;
  return (
    <span className={twinned ? "flex min-w-0 items-center gap-1.5 pl-4" : "flex min-w-0 items-center gap-1.5"}>
      {twinned && (
        <Tooltip content="Same repository as the project above, captured with no local checkout. Its sessions also show in that project's Where it ran lane.">
          <span tabIndex={0} aria-label="grouped under the project above" className="text-fg-4 focus:outline-none">
            ↳
          </span>
        </Tooltip>
      )}
      <TruncatedPath value={r.root_path} className="max-w-[360px] font-mono text-fg-1" />
      {r.synthetic_cloud && (
        <Pill case="none" title="A project named after its repository: sessions that ran in the cloud with no local checkout.">
          cloud project
        </Pill>
      )}
      {off > 0 && (
        <span className="inline-flex shrink-0 items-center gap-1">
          <ExecutionLocationBadge
            location={(r.execution_mix?.vendor_cloud ?? 0) > 0 ? "vendor_cloud" : "customer_worker"}
          />
          <span className="font-mono text-[10.5px] text-fg-3">{fmtInt(off)}</span>
        </span>
      )}
    </span>
  );
}

function ProjectTitle({ root }: { root: string }) {
  return (
    <TruncatedPath value={root} className="max-w-[640px] font-mono" />
  );
}

// numOrNull sorts a missing value ("-") below every real number, so an
// ascending sort does not open on a column of dashes.
function numOrNull(v: number | null | undefined): number {
  return v ?? -Infinity;
}

// timeOrNull turns an optional timestamp into a sortable epoch-ms value.
function timeOrNull(iso: string | null | undefined): number {
  const t = iso ? new Date(iso).getTime() : NaN;
  return Number.isFinite(t) ? t : -Infinity;
}

// projectColumns: every numeric / time column sorts by its raw value; rows
// keep the server's order until a header is clicked.
function projectColumns(
  summaryByRoot: Map<string, GuidanceSummaryRow>,
  winText: string,
): ColumnDef<ProjectRow, unknown>[] {
  return [
    {
      id: "project",
      header: "Project",
      accessorKey: "root_path",
      cell: ({ row }) => <ProjectCell r={row.original} />,
    },
    {
      id: "sessions",
      header: "Sessions",
      accessorFn: (r) => r.session_count,
      meta: { align: "right" },
      cell: ({ row }) => <span className="text-fg-2">{fmtInt(row.original.session_count)}</span>,
    },
    {
      id: "actions",
      header: "Actions",
      accessorFn: (r) => r.action_count,
      meta: { align: "right" },
      cell: ({ row }) => <span className="text-fg-2">{fmtInt(row.original.action_count)}</span>,
    },
    {
      id: "spend",
      header: `Spend (${winText})`,
      accessorFn: (r) => numOrNull(r.spend_usd_30d),
      meta: { align: "right" },
      cell: ({ row }) => {
        const r = row.original;
        return (
          <Tooltip
            content={
              r.spend_unpriced_turns_30d
                ? `${fmtInt(r.spend_unpriced_turns_30d)} turns unpriced (no pricing entry for their model), excluded`
                : undefined
            }
          >
            <span
              tabIndex={r.spend_unpriced_turns_30d ? 0 : undefined}
              className="text-fg-1 focus:outline-none"
            >
              {r.spend_usd_30d != null ? fmtUSD(r.spend_usd_30d) : "-"}
              {r.spend_unpriced_turns_30d ? "*" : ""}
            </span>
          </Tooltip>
        );
      },
    },
    {
      id: "ai_lines",
      header: "AI code lines",
      accessorFn: (r) => numOrNull(r.ai_code_lines_30d),
      meta: { align: "right" },
      cell: ({ row }) => (
        <span className="text-fg-2">
          {row.original.ai_code_lines_30d != null ? fmtInt(row.original.ai_code_lines_30d) : "-"}
          {row.original.ai_split_30d && (
            <div className="text-[10px] text-fg-4">
              <CodeCommentSplit split={row.original.ai_split_30d} variant="share" /> comments
            </div>
          )}
        </span>
      ),
    },
    {
      id: "commits",
      header: "Commits",
      accessorFn: (r) => numOrNull(r.commits_30d),
      meta: { align: "right" },
      cell: ({ row }) => {
        const r = row.original;
        return (
          <span className="inline-flex items-center gap-1.5 text-fg-2">
            {r.commits_30d != null ? fmtInt(r.commits_30d) : "-"}
            {r.capture && r.capture.commits !== "ok" && (
              <VocabPill
                vocab="commitCapture"
                table={COMMIT_CAPTURE}
                value={r.capture.commits}
                title={commitCaptureTip(r.capture)}
              />
            )}
          </span>
        );
      },
    },
    {
      id: "last_commit",
      header: "Last commit",
      accessorFn: (r) => timeOrNull(r.last_commit_at),
      meta: { align: "right" },
      cell: ({ row }) => (
        <span className="text-fg-3">
          {row.original.last_commit_at ? fmtRelative(row.original.last_commit_at) : "-"}
        </span>
      ),
    },
    {
      id: "guidance_files",
      header: "Guidance files",
      accessorFn: (r) => numOrNull(summaryByRoot.get(r.root_path)?.files),
      meta: { align: "right" },
      cell: ({ row }) => {
        const g = summaryByRoot.get(row.original.root_path);
        return <span className="text-fg-1">{g ? fmtInt(g.files) : "-"}</span>;
      },
    },
    {
      id: "last_scanned",
      header: "Last scanned",
      accessorFn: (r) => timeOrNull(summaryByRoot.get(r.root_path)?.last_scanned),
      meta: { align: "right" },
      cell: ({ row }) => {
        const g = summaryByRoot.get(row.original.root_path);
        return (
          <span className="text-fg-3">
            {g?.last_scanned ? fmtRelative(g.last_scanned) : "-"}
          </span>
        );
      },
    },
    {
      id: "last_seen",
      header: "Last seen",
      accessorFn: (r) => timeOrNull(r.last_seen),
      meta: { align: "right" },
      cell: ({ row }) => (
        <span className="text-fg-3">
          {row.original.last_seen ? fmtRelative(row.original.last_seen) : "-"}
        </span>
      ),
    },
  ];
}

// Re-exported so a caller that wants to warm the guidance summary cache
// before navigating here can do so without reaching into lib/guidance
// directly.
export { fetchProjectsGuidanceSummary };
