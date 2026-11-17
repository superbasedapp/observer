import { useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Button, Card, Pill } from "@/components/primitives";
import { DataTable, Pagination } from "@/components/DataTable";
import { ChartState } from "@/components/ChartState";
import type { ApiState } from "@/lib/useApi";
import { fmtInt, fmtRelative } from "@/lib/format";
import { isSetupReason } from "@/lib/scannerProblems";
import { failureWords, problemRunText, problemRuns, capList } from "@/lib/secCoverage";
import {
  lastPage,
  pageSlice,
  PROJECTS_PAGE_SIZE,
  sortProjectsBy,
  type FindingSort,
  projectHref,
  projectLabel,
  reasonWords,
  worstSeverity,
  type SecurityProject,
  type SecurityStatus,
} from "@/lib/codeSecurity";
import { toneOf, type Tone } from "../../../../shared/lib/tone";
import { NodeLink } from "./NodeLink";
import { SbomExportButton } from "./SbomExportButton";

// ProjectsCard is the Projects tab's table: each row NAMES its project
// (linked to its Projects-page detail; the root path in the tooltip), its
// commit gate, open findings (worst severity, linking to the Findings tab),
// the ecosystems scanned, last scan, the scanners that failed (in words;
// setup facts such as "not installed" are one notice above the table, not a
// pill per row), an Export SBOM button once a dependency scan stored the
// project's packages (SbomExportButton), and a Scan button that opens the
// page's Scan dialog. Rows
// needing attention sort first. The list is paged on the client (25 a page);
// a header sort orders ALL rows before paging, and returns to page 1.

// One tone per posture state (the five states of section 4.8).
export const STATE_TONE: Readonly<Record<string, Tone>> = {
  clean: "success",
  dirty: "warn",
  blocking: "danger",
  unknown: "warn",
  absent: "neutral",
};

// One tone per finding severity.
export const SEVERITY_TONE: Readonly<Record<string, Tone>> = {
  critical: "danger",
  high: "danger",
  medium: "warn",
  low: "info",
  info: "neutral",
};

/** Ecosystems shown in a row before "+N". */
const ECOSYSTEMS_SHOWN = 3;

export function ProjectsCard({
  status,
  projects,
  ecosystems,
  onScanProject,
  onShowFindings,
  scanning,
  emptyHint,
}: {
  status: ApiState<SecurityStatus>;
  /** The rows to list (the tab's filtered set); the status's projects when omitted. */
  projects?: SecurityProject[];
  /** Scanned ecosystems per project root hash (secCoverage.ecosystemsByProject). */
  ecosystems?: Record<string, string[]>;
  onScanProject: (hash: string) => void;
  onShowFindings: (hash: string) => void;
  /** A scan is running or being sent: Scan waits. */
  scanning?: boolean;
  emptyHint?: string;
}) {
  const [sorting, setSorting] = useState<FindingSort>([]);
  const [page, setPage] = useState(1);
  const source = projects ?? status.data?.projects ?? [];
  const all = useMemo(() => sortProjectsBy(source, sorting), [source, sorting]);
  const rows = useMemo(() => pageSlice(all, page, PROJECTS_PAGE_SIZE), [all, page]);
  const columns = useMemo<ColumnDef<SecurityProject>[]>(
    () => [
      {
        id: "project",
        header: "Project",
        accessorFn: (p) => projectLabel(p),
        cell: ({ row }) => {
          const p = row.original;
          return (
            <div className="min-w-0">
              <NodeLink to={projectHref(p.project_id)} variant="text" title={p.root_path || p.project_root_hash}>
                {projectLabel(p)}
              </NodeLink>
              {!p.active && <span className="ml-2 text-[11px] text-fg-3">idle</span>}
            </div>
          );
        },
      },
      {
        id: "state",
        header: "Commit gate",
        accessorFn: (p) => p.state,
        cell: ({ row }) => {
          const p = row.original;
          return (
            <Pill variant={toneOf(STATE_TONE, p.state)} title={reasonWords(p.reason)}>
              {p.state === "blocking" ? `blocking (${p.blocking})` : p.state}
            </Pill>
          );
        },
      },
      {
        id: "open",
        header: "Open findings",
        sortDescFirst: true,
        accessorFn: (p) => p.open,
        cell: ({ row }) => {
          const p = row.original;
          if (p.open === 0) return <span className="text-fg-3">none</span>;
          const worst = worstSeverity(p.counts);
          return (
            <button
              type="button"
              className="inline-flex items-center gap-2 text-fg-1 hover:text-accent"
              onClick={(e) => {
                e.stopPropagation();
                onShowFindings(p.project_root_hash);
              }}
            >
              <span className="tabular-nums">{fmtInt(p.open)}</span>
              {worst && <Pill variant={toneOf(SEVERITY_TONE, worst)}>{`worst: ${worst}`}</Pill>}
            </button>
          );
        },
      },
      {
        id: "ecosystems",
        header: "Ecosystems",
        enableSorting: false,
        cell: ({ row }) => {
          const list = ecosystems?.[row.original.project_root_hash];
          if (!list || list.length === 0) return <span className="text-fg-3">none scanned</span>;
          const { shown, more } = capList(list, ECOSYSTEMS_SHOWN);
          return (
            <span className="text-fg-2" title={list.join(", ")}>
              {shown.join(", ")}
              {more > 0 && <span className="text-fg-3">{` +${more}`}</span>}
            </span>
          );
        },
      },
      {
        id: "last_scan",
        header: "Last scan",
        sortDescFirst: true,
        accessorFn: (p) => p.last_scan_at ?? "",
        cell: ({ row }) => {
          const p = row.original;
          return <span className={p.last_scan_at ? "text-fg-2" : "text-fg-3"}>{p.last_scan_at ? fmtRelative(p.last_scan_at) : "never"}</span>;
        },
      },
      {
        id: "scanners",
        header: "Scanners",
        enableSorting: false,
        cell: ({ row }) => {
          const problems = problemRuns(row.original.runs ?? [], isSetupReason);
          if (problems.length === 0) return <span className="text-fg-3">no problems</span>;
          return (
            <div className="flex flex-col items-start gap-1">
              {problems.map((r) => (
                <Pill
                  key={r.driver}
                  variant={r.outcome === "failed" ? "danger" : "warn"}
                  case="none"
                  title={[reasonWords(r.outcome), failureWords(r.reason)].filter(Boolean).join(": ")}
                >
                  {problemRunText(r)}
                </Pill>
              ))}
            </div>
          );
        },
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => {
          const p = row.original;
          if (!p.project_id) return null;
          return (
            <div className="flex justify-end gap-1.5">
              {/* Export SBOM once a dependency scan stored the project's
                  packages (its ecosystems are known). */}
              {(ecosystems?.[p.project_root_hash]?.length ?? 0) > 0 && <SbomExportButton hash={p.project_root_hash} />}
              <Button
                size="sm"
                variant="secondary"
                disabled={scanning}
                onClick={(e) => {
                  e.stopPropagation();
                  onScanProject(p.project_root_hash);
                }}
              >
                Scan
              </Button>
            </div>
          );
        },
      },
    ],
    [ecosystems, scanning, onScanProject, onShowFindings],
  );
  return (
    <Card title="Projects" sub={status.data ? `Security module: ${status.data.module}` : undefined} stale={status.isStale}>
      <ChartState
        kind="table"
        loading={status.loading && !status.data}
        stale={status.isStale}
        onRetry={status.reload}
        error={status.error}
        denied={status.denied}
        empty={!status.loading && all.length === 0}
        emptyHint={emptyHint ?? "No projects yet: a project appears once an AI tool session runs in it."}
      >
        <div className="rounded-3 border border-line-2">
          <DataTable<SecurityProject>
            data={rows}
            columns={columns}
            rowKey={(p) => p.project_root_hash}
            minWidth={900}
            sorting={sorting}
            onSortingChange={(s) => {
              setSorting(s.map((x) => ({ id: x.id, desc: x.desc })));
              setPage(1);
            }}
            onRowClick={(p) => onShowFindings(p.project_root_hash)}
          />
        </div>
        {all.length > PROJECTS_PAGE_SIZE && (
          <Pagination page={Math.min(page, lastPage(all.length, PROJECTS_PAGE_SIZE))} limit={PROJECTS_PAGE_SIZE} total={all.length} onPage={setPage} />
        )}
      </ChartState>
    </Card>
  );
}
