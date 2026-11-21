import { useMemo } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Pill } from "@/components/primitives";
import { DataTable, Pagination } from "@/components/DataTable";
import { ChartState } from "@/components/ChartState";
import type { ApiState } from "@/lib/useApi";
import { fmtInt, fmtRelative } from "@/lib/format";
import { FINDING_GROUPS_PAGE_SIZE, projectLabel, type FindingSort, type SecurityProject } from "@/lib/codeSecurity";
import type { FindingGroup, FindingGroupsPage, FindingsGroupBy } from "@/lib/codeSecurityApi";
import { categoryLabel, ecosystemLabel, FINDINGS_SLOW_LINE, groupColumnLabel } from "@/lib/findingsLabels";
import { toneOf } from "../../../../shared/lib/tone";
import { NamedLoading } from "./NamedLoading";
import { SEVERITY_TONE } from "./ProjectsCard";
import { FixButton } from "./FixButton";

// FindingGroupsTable is the Findings tab's grouped list: one row per issue
// (the same advisory on the same package version, or the same rule on the
// same path, however many worktrees repeat it), per package, per rule or
// per project (GET /api/security/findings/groups?by=). A row shows its
// worst severity, what it is, how many projects and findings it covers and
// when it was last seen; clicking it lists that group's findings, ungrouped
// (lib/codeSecurityApi.ts groupDrillDown, applied by the tab). Paged and
// sorted by the server (severity, findings and last seen are sortable).

type By = Exclude<FindingsGroupBy, "none">;

/** groupLines is what a group row says in its first column: a main line
 *  and a muted mono line under it. */
export function groupLines(by: By, g: FindingGroup, projectName: (hash: string) => string): { main: string; sub: string; mono: boolean } {
  switch (by) {
    case "issue": {
      const where = g.package ? `${g.package} · ${ecosystemLabel(g.ecosystem)}` : g.rel_path || "the project";
      return { main: g.message || g.rule_id || where, sub: [g.rule_id, where].filter(Boolean).join(" · "), mono: false };
    }
    case "package":
      return { main: g.package || "Unknown package", sub: ecosystemLabel(g.ecosystem), mono: true };
    case "rule":
      return {
        main: g.message || g.rule_id || "Unknown rule",
        sub: [g.rule_id, g.category ? categoryLabel(g.category) : ""].filter(Boolean).join(" · "),
        mono: false,
      };
    case "project":
      return { main: projectName(g.project_root_hash ?? ""), sub: "", mono: false };
  }
}

export function FindingGroupsTable({
  by,
  groups,
  projects,
  page,
  sorting,
  onPage,
  onSorting,
  onDrill,
  emptyHint,
  loadingLabel,
  onFix,
}: {
  by: By;
  groups: ApiState<FindingGroupsPage>;
  projects: SecurityProject[];
  page: number;
  sorting: FindingSort;
  onPage: (p: number) => void;
  onSorting: (s: FindingSort) => void;
  /** A row's click: list this group's findings. */
  onDrill: (g: FindingGroup) => void;
  emptyHint: string;
  loadingLabel: string;
  /** "Fix with an agent" on a group's row (absent: no column). */
  onFix?: (g: FindingGroup) => void;
}) {
  const projectName = useMemo(() => {
    const byHash = new Map(projects.map((p) => [p.project_root_hash, p]));
    return (hash: string) => projectLabel(byHash.get(hash) ?? { project_root_hash: hash });
  }, [projects]);
  const rows = groups.data?.groups ?? [];
  const columns = useMemo<ColumnDef<FindingGroup>[]>(() => {
    const cols: ColumnDef<FindingGroup>[] = [
      {
        id: "severity",
        header: "Severity",
        accessorFn: (g) => g.max_severity,
        sortDescFirst: true,
        cell: ({ row }) => <Pill variant={toneOf(SEVERITY_TONE, row.original.max_severity)}>{row.original.max_severity}</Pill>,
      },
      {
        id: "group",
        header: groupColumnLabel(by),
        enableSorting: false,
        accessorFn: (g) => g.key,
        cell: ({ row }) => {
          const l = groupLines(by, row.original, projectName);
          return (
            <div className="min-w-0" data-testid="code-security-group-row">
              <div className={l.mono ? "truncate font-mono text-[12px] text-fg-1" : "truncate text-fg-1"}>{l.main}</div>
              {l.sub && <div className="mt-0.5 truncate font-mono text-[11px] text-fg-3">{l.sub}</div>}
            </div>
          );
        },
      },
    ];
    // A project group is one project: its project count says nothing.
    if (by !== "project") {
      cols.push({
        id: "projects",
        header: "Projects",
        enableSorting: false,
        accessorFn: (g) => g.projects,
        cell: ({ row }) => <span className="tabular-nums text-fg-2">{fmtInt(row.original.projects)}</span>,
      });
    }
    cols.push(
      {
        id: "count",
        header: "Findings",
        accessorFn: (g) => g.count,
        sortDescFirst: true,
        cell: ({ row }) => <span className="tabular-nums text-fg-2">{fmtInt(row.original.count)}</span>,
      },
      {
        id: "last_seen",
        header: "Last seen",
        accessorFn: (g) => g.last_seen,
        sortDescFirst: true,
        cell: ({ row }) => <span className="text-fg-3">{fmtRelative(row.original.last_seen)}</span>,
      },
    );
    if (onFix) {
      cols.push({
        id: "fix",
        header: "",
        enableSorting: false,
        accessorFn: (g) => g.key,
        cell: ({ row }) => <FixButton iconOnly onClick={() => onFix(row.original)} testId="code-security-fix-group" />,
      });
    }
    return cols;
  }, [by, projectName, onFix]);
  if (groups.loading && !groups.data) {
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
      stale={groups.isStale}
      onRetry={groups.reload}
      error={groups.error}
      denied={groups.denied}
      empty={!groups.loading && rows.length === 0}
      emptyHint={emptyHint}
    >
      <div className="rounded-3 border border-line-2">
        <DataTable<FindingGroup>
          data={rows}
          columns={columns}
          rowKey={(g) => g.key}
          sorting={sorting}
          onSortingChange={onSorting}
          loading={groups.isStale}
          minWidth={720}
          onRowClick={onDrill}
        />
      </div>
      {groups.data && (
        <Pagination
          page={page}
          limit={groups.data.limit || FINDING_GROUPS_PAGE_SIZE}
          total={groups.data.total}
          onPage={onPage}
          loading={groups.isStale}
        />
      )}
    </ChartState>
  );
}
