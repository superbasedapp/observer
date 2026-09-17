import { useSearchParams } from "react-router-dom";
import {
  PageHeader,
  SlideOver,
  TruncatedPath,
} from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { GuidanceCard } from "@/components/GuidanceCard";
import { useApi } from "@/lib/useApi";
import { fmtInt, fmtRelative } from "@/lib/format";
import {
  fetchProjectsGuidanceSummary,
  PROJECTS_GUIDANCE_SUMMARY_PATH,
  type GuidanceSummaryRow,
} from "@/lib/guidance";
import type { ProjectRow, ProjectsResponse } from "@/lib/types";

// ProjectsPage lists every project Observer has seen (from /api/projects)
// merged with the guidance-file inventory (/api/projects/guidance/summary),
// so a project row shows both its capture activity and how many
// instructions/skills/agents/commands/rules/config files exist for it.
// Clicking a row opens a deep-linkable (`?root=`) SlideOver with the full
// GuidanceCard breakdown for that project.
export function ProjectsPage() {
  const projects = useApi<ProjectsResponse>("/api/projects");
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

  const summaryByRoot = new Map<string, GuidanceSummaryRow>();
  for (const s of summary.data ?? []) {
    summaryByRoot.set(s.project_root, s);
  }

  const rows = projects.data?.rows ?? [];
  const loading = projects.loading && !projects.data;
  const error = projects.error;

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Projects"
        sub="Every project Observer has captured activity for, and the instructions/skills/agents/commands/rules/config files each AI tool reads from it (CLAUDE.md, AGENTS.md, .cursorrules, .claude/skills/*, and similar)."
      />

      <ChartState
        loading={loading}
        error={error}
        empty={!loading && rows.length === 0}
        emptyHint="No projects captured yet. Once an AI tool runs inside a project directory, it will show up here."
        height={240}
      >
        <div className="overflow-x-auto rounded-3 border border-line-2 bg-bg-2">
          <table className="w-full min-w-[760px] text-left text-[11.5px]">
            <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
              <tr className="border-b border-line-2">
                <th className="py-2 pl-3 font-medium">Project</th>
                <th className="py-2 text-right font-medium">Sessions</th>
                <th className="py-2 text-right font-medium">Actions</th>
                <th className="py-2 text-right font-medium">Guidance files</th>
                <th className="py-2 text-right font-medium">Last scanned</th>
                <th className="py-2 pr-3 text-right font-medium">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <ProjectRowLine
                  key={r.root_path}
                  row={r}
                  guidance={summaryByRoot.get(r.root_path)}
                  onOpen={() => setSelectedRoot(r.root_path)}
                />
              ))}
            </tbody>
          </table>
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
    </div>
  );
}

function ProjectTitle({ root }: { root: string }) {
  return (
    <TruncatedPath value={root} className="max-w-[640px] font-mono" />
  );
}

function ProjectRowLine({
  row,
  guidance,
  onOpen,
}: {
  row: ProjectRow;
  guidance: GuidanceSummaryRow | undefined;
  onOpen: () => void;
}) {
  return (
    <tr
      onClick={onOpen}
      className="cursor-pointer border-b border-line-1 last:border-b-0 hover:bg-bg-3/40"
    >
      <td className="py-2 pl-3">
        <TruncatedPath
          value={row.root_path}
          className="max-w-[360px] font-mono text-fg-1"
        />
      </td>
      <td className="py-2 text-right tabular-nums text-fg-2">
        {fmtInt(row.session_count)}
      </td>
      <td className="py-2 text-right tabular-nums text-fg-2">
        {fmtInt(row.action_count)}
      </td>
      <td className="py-2 text-right tabular-nums text-fg-1">
        {guidance ? fmtInt(guidance.files) : "-"}
      </td>
      <td className="py-2 text-right tabular-nums text-fg-3">
        {guidance?.last_scanned ? fmtRelative(guidance.last_scanned) : "-"}
      </td>
      <td className="py-2 pr-3 text-right tabular-nums text-fg-3">
        {row.last_seen ? fmtRelative(row.last_seen) : "-"}
      </td>
    </tr>
  );
}

// Re-exported so a caller that wants to warm the guidance summary cache
// before navigating here can do so without reaching into lib/guidance
// directly.
export { fetchProjectsGuidanceSummary };
