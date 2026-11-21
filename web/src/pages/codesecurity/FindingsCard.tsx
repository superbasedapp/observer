import { useMemo } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Pill } from "@/components/primitives";
import { DataTable, Pagination } from "@/components/DataTable";
import { ChartState } from "@/components/ChartState";
import type { ApiState } from "@/lib/useApi";
import { fmtRelative } from "@/lib/format";
import {
  FINDINGS_PAGE_SIZE,
  findingWhere,
  normalizeFindingSort,
  type FindingSort,
  type FindingsListPage,
  type FindingsListRow,
  projectHref,
  projectLabel,
  sessionHref,
  type SecurityProject,
} from "@/lib/codeSecurity";
import { categoryLabel, FINDINGS_SLOW_LINE, languageLabel } from "@/lib/findingsLabels";
import { toneOf } from "../../../../shared/lib/tone";
import { NodeLink } from "./NodeLink";
import { NamedLoading } from "./NamedLoading";
import { SEVERITY_TONE } from "./ProjectsCard";
import { SignalLabels } from "./DependencyDetail";
import { FixButton } from "./FixButton";

// FindingsCard is the Findings tab's ungrouped list (Group by: None): one
// row per finding, each linking its project and session and opening the
// finding's drawer (`?finding=<id>`) on click. The filters are the tab's
// filter bar (FindingsFilterBar), read from the URL; the tab's card holds
// both. The list is paged and sorted by the server (the rank, severity,
// last seen and first seen are the sortable columns; the rank is the
// default: KEV-listed dependency findings first, then reach, then EPSS,
// then severity, every other finding kept where severity puts it); the tab
// owns the page and sort state and re-fetches.
//
// While the first page loads, the line above the skeleton says what is
// loading (NamedLoading); a refetch keeps the old rows, dimmed.

export function FindingsCard({
  findings,
  projects,
  onOpen,
  page,
  sorting,
  onPage,
  onSorting,
  emptyHint = "No open findings. Run a scan to check again.",
  loadingLabel = "Loading findings",
  onFix,
}: {
  findings: ApiState<FindingsListPage>;
  projects: SecurityProject[];
  onOpen: (id: string) => void;
  page: number;
  sorting: FindingSort;
  onPage: (p: number) => void;
  onSorting: (s: FindingSort) => void;
  emptyHint?: string;
  /** What the loading line says while the first page loads. */
  loadingLabel?: string;
  /** "Fix with an agent" on an open finding's row (absent: no column). */
  onFix?: (id: string) => void;
}) {
  const byHash = useMemo(() => new Map(projects.map((p) => [p.project_root_hash, p])), [projects]);
  const rows = findings.data?.findings ?? [];
  // FIRST's citation rides every shown EPSS score (one line under the table).
  const epssCitation = rows.find((f) => f.exploit?.epss_citation)?.exploit?.epss_citation;
  const columns = useMemo<ColumnDef<FindingsListRow>[]>(
    () => [
      {
        id: "severity",
        header: "Severity",
        accessorFn: (f) => f.severity,
        sortDescFirst: true,
        cell: ({ row }) => <Pill variant={toneOf(SEVERITY_TONE, row.original.severity)}>{row.original.severity}</Pill>,
      },
      {
        id: "rule",
        header: "Finding",
        enableSorting: false,
        accessorFn: (f) => f.rule_id,
        cell: ({ row }) => {
          const f = row.original;
          const sub = [f.rule_id, categoryLabel(f.category), f.language ? languageLabel(f.language) : ""].filter(Boolean).join(" · ");
          return (
            <div className="min-w-0">
              <div className="truncate text-fg-1">{f.message}</div>
              <div className="mt-0.5 font-mono text-[11px] text-fg-3">{sub}</div>
              {f.package && (
                <div className="mt-0.5 truncate font-mono text-[11px] text-fg-2" data-testid="code-security-finding-package">
                  {f.package}
                </div>
              )}
            </div>
          );
        },
      },
      {
        // The ranking rule's column (sort=rank, the default): a dependency
        // row's KEV, EPSS and reach labels. It ranks and labels only.
        id: "rank",
        header: "Exploit and reach",
        accessorFn: (f) => f.exploit?.badges.join(" ") ?? "",
        sortDescFirst: true,
        cell: ({ row }) => <SignalLabels finding={row.original} />,
      },
      {
        id: "project",
        header: "Project",
        enableSorting: false,
        accessorFn: (f) => {
          const p = byHash.get(f.project_root_hash);
          return p ? projectLabel(p) : "";
        },
        cell: ({ row }) => {
          const p = byHash.get(row.original.project_root_hash);
          const label = p ? projectLabel(p) : projectLabel({ project_root_hash: row.original.project_root_hash });
          return (
            <NodeLink to={projectHref(p?.project_id)} variant="text" title={p?.root_path}>
              {label}
            </NodeLink>
          );
        },
      },
      {
        id: "where",
        header: "Where",
        enableSorting: false,
        accessorFn: (f) => findingWhere(f),
        cell: ({ row }) => <span className="font-mono text-[11.5px] text-fg-2">{findingWhere(row.original)}</span>,
      },
      {
        id: "session",
        header: "Session",
        enableSorting: false,
        accessorFn: (f) => f.session_id ?? "",
        cell: ({ row }) => {
          const sid = row.original.session_id;
          if (!sid) return <span className="text-fg-3">none</span>;
          return (
            <NodeLink to={sessionHref(sid)} title={sid}>
              {sid.slice(0, 8)}
            </NodeLink>
          );
        },
      },
      {
        id: "last_seen",
        header: "Last seen",
        accessorFn: (f) => f.last_seen,
        sortDescFirst: true,
        cell: ({ row }) => <span className="text-fg-3">{fmtRelative(row.original.last_seen)}</span>,
      },
      {
        id: "first_seen",
        header: "First seen",
        accessorFn: (f) => f.first_seen,
        sortDescFirst: true,
        cell: ({ row }) => <span className="text-fg-3">{fmtRelative(row.original.first_seen)}</span>,
      },
      ...(onFix
        ? [
            {
              id: "fix",
              header: "",
              enableSorting: false,
              accessorFn: (f: FindingsListRow) => f.id,
              cell: ({ row }: { row: { original: FindingsListRow } }) =>
                row.original.status === "open" ? (
                  <FixButton iconOnly onClick={() => onFix(row.original.id)} testId="code-security-fix-finding" />
                ) : null,
            } satisfies ColumnDef<FindingsListRow>,
          ]
        : []),
    ],
    [byHash, onFix],
  );
  const firstLoad = findings.loading && !findings.data;
  if (firstLoad) {
    return (
      <NamedLoading active label={loadingLabel} slowLine={FINDINGS_SLOW_LINE}>
        <ChartState kind="table" loading error={null} empty={false}>
          {null}
        </ChartState>
      </NamedLoading>
    );
  }
  return (
    <ChartState
      kind="table"
      loading={false}
      stale={findings.isStale}
      onRetry={findings.reload}
      error={findings.error}
      denied={findings.denied}
      empty={!findings.loading && rows.length === 0}
      emptyHint={emptyHint}
    >
      <div className="rounded-3 border border-line-2">
        <DataTable<FindingsListRow>
          data={rows}
          columns={columns}
          rowKey={(f) => f.id}
          // The server orders the whole filtered set (the rank by default);
          // the table does not reorder the page it is given.
          sorting={sorting}
          onSortingChange={(s) => onSorting(normalizeFindingSort(s))}
          loading={findings.isStale}
          minWidth={1040}
          onRowClick={(f) => onOpen(f.id)}
        />
      </div>
      {epssCitation && (
        <p className="mt-2 mb-0 text-[11px] text-fg-3" data-testid="code-security-list-epss-citation">
          {epssCitation}
        </p>
      )}
      {findings.data && (
        <Pagination
          page={page}
          limit={findings.data.limit || FINDINGS_PAGE_SIZE}
          total={findings.data.total}
          onPage={onPage}
          loading={findings.isStale}
        />
      )}
    </ChartState>
  );
}
