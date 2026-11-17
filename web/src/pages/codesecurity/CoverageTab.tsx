import { useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Button, Card, ConfirmButton, Pill, SinglePicker, TableSkeleton } from "@/components/primitives";
import { DataTable } from "@/components/DataTable";
import { ChartState } from "@/components/ChartState";
import { useApi, type ApiState } from "@/lib/useApi";
import { fmtInt, fmtRelative } from "@/lib/format";
import {
  NEEDS_ONLINE,
  driverLabel,
  reasonGroups,
  capList,
  coverageSummary,
  ecosystemRows,
  hasCoverage,
  latestRuns,
  needsOnline,
  onlineCheckAction,
  supportedOnlineAction,
  supportNote,
  type EcosystemRow,
  type ReasonGroup,
  type ProjectRef,
} from "@/lib/secCoverage";
import { projectLabel, reasonWords, type SecurityStatus } from "@/lib/codeSecurity";
import type { CoverageProject, CoverageResponse, CoverageRun } from "@/lib/codeSecurityApi";
import { CheckFamiliesCard } from "./CheckFamiliesCard";
import { NamedLoading } from "./NamedLoading";
import type { SecurityScan } from "./useSecurityScan";

// CoverageTab answers "what is checked" (CheckFamiliesCard: one row per
// checking family and its state) and "which languages and package types are supported,
// found and scanned" (redesign plan sections 3.8 and 4.5): the supported
// table, what each ecosystem did in your projects, the files that were found
// but not read (grouped by reason, with what to do), and one project's runs.
// Everything comes from GET /api/security/coverage, the latest dependency
// run's recorded coverage per project; nothing is captured anew.
//
// Files only the online check can read (needs_online_lookup) carry a
// "Check online" control, on their group and on one project's runs
// (decision P-1 of docs/plans/dashboard-cli-parity-plan-2026-11-06.md): it
// starts a scan of those projects with the dependency step and online
// checks, after a confirm that says what is sent; while online checks are
// off or their disclosure is not accepted it links to Scanners > Package
// checks instead (lib/secCoverage onlineCheckAction).

/** CheckOnline is the "Check online" control for some projects. On a
 *  supported row (supported) it is also the way to turn the online check on
 *  when no project has the ecosystem's files yet, and its setup link stands
 *  alone because the row's note already says why. */
function CheckOnline({
  scan,
  projects,
  onOpenScanners,
  testId,
  supported = false,
}: {
  scan?: SecurityScan;
  projects: string[];
  onOpenScanners?: () => void;
  testId: string;
  supported?: boolean;
}) {
  if (!scan) return null;
  const input = { online: scan.view?.online, steps: scan.view?.steps ?? [], projects, running: scan.running };
  const act = supported ? supportedOnlineAction(input) : onlineCheckAction(input);
  if (act.kind === "none") return null;
  if (act.kind === "busy") {
    return (
      <Button size="sm" variant="secondary" disabled title={act.why} data-testid={testId}>
        {act.label}
      </Button>
    );
  }
  if (act.kind === "setup") {
    return (
      <span className="text-[12px] text-fg-3" data-testid={testId}>
        {supported ? "" : `${act.why}. `}
        {onOpenScanners ? (
          <button type="button" className="text-accent hover:underline" onClick={onOpenScanners}>
            {act.label}
          </button>
        ) : (
          act.label
        )}
      </span>
    );
  }
  const body = act.body;
  return (
    <ConfirmButton
      size="sm"
      variant="secondary"
      armedVariant="primary"
      onConfirm={() => void scan.start(body)}
      disabled={scan.sending}
      loading={scan.sending}
      confirmLabel="Start the online check?"
      armedNote={act.sends}
    >
      <span data-testid={testId}>{act.label}</span>
    </ConfirmButton>
  );
}

/** Names listed in a cell before "and N more". */
const NAMES_SHOWN = 4;
/** Files listed in an expanded group before "and N more". */
const FILES_SHOWN = 20;

function names(list: ProjectRef[]): string {
  const { shown, more } = capList(list, NAMES_SHOWN);
  return shown.map((p) => p.name).join(", ") + (more > 0 ? ` and ${more} more` : "");
}

/** SupportedFiles is the files cell: what the scanners read, then the
 *  ecosystem's files they find but do not read (each a gap when met). */
export function SupportedFiles({ files, unread }: { files: readonly string[]; unread: readonly string[] }) {
  return (
    <span className="flex flex-col gap-0.5 font-mono text-[11.5px]" data-testid="coverage-supported-files">
      <span className="text-fg-2">{files.join(", ") || "-"}</span>
      {unread.length > 0 && (
        <span className="text-fg-3" data-testid="coverage-unread-files">
          <span className="font-sans">Found, not read: </span>
          {unread.join(", ")}
        </span>
      )}
    </span>
  );
}

function SupportedTable({ rows, scan, onOpenScanners }: { rows: EcosystemRow[]; scan?: SecurityScan; onOpenScanners?: () => void }) {
  const columns = useMemo<ColumnDef<EcosystemRow>[]>(
    () => [
      {
        id: "ecosystem",
        header: "Ecosystem",
        accessorFn: (r) => r.ecosystem,
        cell: ({ row }) => <span className="font-medium text-fg-1">{row.original.ecosystem}</span>,
      },
      {
        id: "files",
        header: "Files",
        enableSorting: false,
        cell: ({ row }) => <SupportedFiles files={row.original.supported?.files ?? []} unread={row.original.supported?.unread_files ?? []} />,
      },
      {
        id: "scanners",
        header: "Scanners",
        enableSorting: false,
        cell: ({ row }) => <span className="text-fg-2">{(row.original.supported?.drivers ?? []).map(driverLabelShort).join(", ") || "-"}</span>,
      },
      {
        id: "advisories",
        header: "Advisory source",
        enableSorting: false,
        cell: ({ row }) => {
          const s = row.original.supported;
          if (!s) return <span className="text-fg-3">-</span>;
          const note = supportNote(s, scan?.view?.online?.open === true);
          return (
            <div className="flex flex-col items-start gap-1">
              <span className={s.advisory_source ? "text-fg-2" : "text-fg-3"}>{s.advisory_source || "none"}</span>
              {note && (
                <Pill variant={note.tone === "warn" ? "warn" : "neutral"} case="none">
                  {note.text}
                </Pill>
              )}
              {s.online_only && (
                <CheckOnline
                  supported
                  scan={scan}
                  projects={[...row.original.scanned, ...row.original.detectedOnly].map((p) => p.hash)}
                  onOpenScanners={onOpenScanners}
                  testId="coverage-supported-check-online"
                />
              )}
            </div>
          );
        },
      },
      {
        id: "database",
        header: "Local database",
        enableSorting: false,
        cell: ({ row }) => {
          const s = row.original.supported;
          if (!s || !s.advisory_source) return <span className="text-fg-3">not applicable</span>;
          return <Pill variant={s.database_installed ? "success" : "neutral"}>{s.database_installed ? "installed" : "not installed"}</Pill>;
        },
      },
    ],
    [scan, onOpenScanners],
  );
  return (
    <div className="rounded-3 border border-line-2">
      <DataTable<EcosystemRow> data={rows} columns={columns} rowKey={(r) => r.ecosystem} minWidth={760} emptyMessage="No ecosystems reported." />
    </div>
  );
}

// "scalibr" and "osv" as the short scanner names the supported table lists.
function driverLabelShort(d: string): string {
  return d === "osv" ? "osv-scanner" : d;
}

function InProjects({ rows }: { rows: EcosystemRow[] }) {
  const used = rows.filter((r) => r.scanned.length + r.detectedOnly.length > 0);
  if (used.length === 0) return <p className="text-[12.5px] text-fg-3">No supported files were found in your projects.</p>;
  const columns: ColumnDef<EcosystemRow>[] = [
    { id: "ecosystem", header: "Ecosystem", accessorFn: (r) => r.ecosystem, cell: ({ row }) => <span className="font-medium text-fg-1">{row.original.ecosystem}</span> },
    {
      id: "scanned",
      header: "Scanned in",
      accessorFn: (r) => r.scanned.length,
      sortDescFirst: true,
      cell: ({ row }) => {
        const r = row.original;
        if (r.scanned.length === 0) return <span className="text-fg-3">no project</span>;
        return (
          <span title={r.scanned.map((p) => p.name).join(", ")}>
            <span className="tabular-nums text-fg-1">{fmtInt(r.scanned.length)}</span>
            <span className="text-fg-3">{` ${r.scanned.length === 1 ? "project" : "projects"}: `}</span>
            <span className="text-fg-2">{names(r.scanned)}</span>
          </span>
        );
      },
    },
    {
      id: "detected",
      header: "Found but not scanned",
      enableSorting: false,
      cell: ({ row }) => {
        const r = row.original;
        if (r.detectedOnly.length === 0) return <span className="text-fg-3">none</span>;
        return (
          <span title={r.detectedOnly.map((p) => p.name).join(", ")} className="text-warn">
            {names(r.detectedOnly)}
          </span>
        );
      },
    },
  ];
  return (
    <div className="rounded-3 border border-line-2">
      <DataTable<EcosystemRow> data={used} columns={columns} rowKey={(r) => r.ecosystem} minWidth={640} />
    </div>
  );
}

function ReasonGroupBlock({ group, scan, onOpenScanners }: { group: ReasonGroup; scan?: SecurityScan; onOpenScanners?: () => void }) {
  const [open, setOpen] = useState(false);
  const { shown, more } = capList(group.entries, FILES_SHOWN);
  const hidden = more + group.hidden;
  return (
    <li className="rounded-2 border border-line-2 bg-bg-1 px-3 py-2.5" data-testid="reason-group">
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1">
        <div className="min-w-0">
          <div className="text-[13px] font-medium text-fg-1">{group.words.charAt(0).toUpperCase() + group.words.slice(1)}</div>
          {group.action && <div className="text-[12px] text-fg-2">{group.action}</div>}
          {group.reason === NEEDS_ONLINE && (
            <div className="mt-1">
              <CheckOnline scan={scan} projects={group.projectHashes} onOpenScanners={onOpenScanners} testId="coverage-check-online" />
            </div>
          )}
        </div>
        <div className="flex items-center gap-3 text-[12px] text-fg-3">
          <span>
            <span className="tabular-nums text-fg-1">{fmtInt(group.count)}</span>
            {` ${group.count === 1 ? "file" : "files"} in ${group.projects} ${group.projects === 1 ? "project" : "projects"}`}
          </span>
          {group.entries.length > 0 && (
            <button type="button" aria-expanded={open} onClick={() => setOpen((v) => !v)} className="text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]">
              {open ? "Hide files" : "Show files"}
            </button>
          )}
        </div>
      </div>
      {open && (
        <ul className="mt-2 space-y-0.5 text-[12px]">
          {shown.map((e) => (
            <li key={`${e.hash}|${e.path}`} className="flex flex-wrap gap-x-2">
              <span className="text-fg-2">{e.project}</span>
              <span className="break-all font-mono text-[11.5px] text-fg-3">{e.path}</span>
            </li>
          ))}
          {hidden > 0 && <li className="text-fg-3">{`and ${fmtInt(hidden)} more`}</li>}
        </ul>
      )}
    </li>
  );
}

function runColumns(): ColumnDef<CoverageRun>[] {
  return [
    { id: "driver", header: "Scanner", accessorFn: (r) => r.driver, cell: ({ row }) => driverLabel(row.original.driver) },
    {
      id: "when",
      header: "When",
      accessorFn: (r) => r.started_at,
      cell: ({ row }) => <span className="text-fg-2">{row.original.started_at ? fmtRelative(row.original.started_at) : "never"}</span>,
    },
    {
      id: "outcome",
      header: "Outcome",
      enableSorting: false,
      cell: ({ row }) => {
        const r = row.original;
        const bad = r.outcome === "failed";
        return (
          <Pill variant={bad ? "danger" : r.outcome === "ok" || r.outcome === "clean" ? "success" : "neutral"} case="none" title={r.reason ? reasonWords(r.reason) : undefined}>
            {reasonWords(r.outcome) + (r.reason ? ` (${reasonWords(r.reason)})` : "")}
          </Pill>
        );
      },
    },
    {
      id: "scanned",
      header: "Ecosystems scanned",
      enableSorting: false,
      cell: ({ row }) => <span className="text-fg-2">{row.original.scanned.length > 0 ? row.original.scanned.join(", ") : "none"}</span>,
    },
    {
      id: "skipped",
      header: "Files not read",
      enableSorting: false,
      cell: ({ row }) => {
        const r = row.original;
        if (r.skipped_total === 0 && r.skipped.length === 0) return <span className="text-fg-3">none</span>;
        const { shown } = capList(r.skipped, 5);
        const total = Math.max(r.skipped_total, r.skipped.length);
        return (
          <div className="space-y-0.5 text-[12px]">
            <div className="tabular-nums text-fg-1">{fmtInt(total)}</div>
            {shown.map((f) => (
              <div key={f.path} className="break-all">
                <span className="font-mono text-[11.5px] text-fg-3">{f.path}</span>
                <span className="text-fg-3">{` - ${reasonWords(f.reason)}`}</span>
              </div>
            ))}
            {total - shown.length > 0 && <div className="text-fg-3">{`and ${fmtInt(total - shown.length)} more`}</div>}
          </div>
        );
      },
    },
  ];
}

function ProjectRuns({ cov, scan, onOpenScanners }: { cov: CoverageResponse; scan?: SecurityScan; onOpenScanners?: () => void }) {
  const withRuns = useMemo(() => cov.projects.filter((p) => (p.runs ?? []).length > 0), [cov.projects]);
  const [hash, setHash] = useState("");
  const options = useMemo(() => withRuns.map((p) => ({ id: p.project_root_hash, label: projectLabel({ name: p.name, project_root_hash: p.project_root_hash }) })), [withRuns]);
  const picked: CoverageProject | undefined = withRuns.find((p) => p.project_root_hash === hash);
  const columns = useMemo(runColumns, []);
  return (
    <div className="space-y-3">
      <div className="w-full sm:w-80">
        <SinglePicker value={hash} onChange={setHash} options={options} placeholder="Pick a project" ariaLabel="Project" emptyHint="No project has a dependency scan yet." />
      </div>
      {picked ? (
        <div className="space-y-2">
          <div className="rounded-3 border border-line-2">
            <DataTable<CoverageRun> data={latestRuns(picked.runs)} columns={columns} rowKey={(r) => r.driver} minWidth={720} />
          </div>
          {needsOnline(picked) && (
            <div className="flex flex-wrap items-center gap-2 text-[12px] text-fg-3">
              <span>Some of its files are checked only online.</span>
              <CheckOnline scan={scan} projects={[picked.project_root_hash]} onOpenScanners={onOpenScanners} testId="coverage-project-check-online" />
            </div>
          )}
        </div>
      ) : (
        <p className="text-[12.5px] text-fg-3">Pick a project to see what each scanner read and skipped there.</p>
      )}
    </div>
  );
}

export function CoverageTab({
  status,
  scan,
  onOpenScanners,
}: {
  status: ApiState<SecurityStatus>;
  /** The page's scan job: its online check state and its start. */
  scan?: SecurityScan;
  /** Switches to the Scanners tab (where online checks are turned on). */
  onOpenScanners?: () => void;
}) {
  const cov = useApi<CoverageResponse>("/api/security/coverage");
  const data = cov.data;
  const projectCount = status.data?.projects.length;
  const rows = useMemo(() => (data ? ecosystemRows(data) : []), [data]);
  const groups = useMemo(() => (data ? reasonGroups(data) : []), [data]);
  const summary = useMemo(() => (data ? coverageSummary(data) : null), [data]);

  if (cov.loading && !data) {
    return (
      <NamedLoading
        active
        label={projectCount != null ? `Loading coverage for ${fmtInt(projectCount)} ${projectCount === 1 ? "project" : "projects"}` : "Loading coverage"}
        slowLine="Reading each project's latest dependency scan."
      >
        <TableSkeleton rows={8} />
      </NamedLoading>
    );
  }
  if (!data) {
    // Error or denial: ChartState draws the retry, denial or empty state.
    return (
      <Card title="Coverage">
        <ChartState kind="table" loading={false} error={cov.error} denied={cov.denied} onRetry={cov.reload} empty={!cov.error} emptyHint="Coverage is not available yet.">
          {null}
        </ChartState>
      </Card>
    );
  }
  const scanned = hasCoverage(data);
  return (
    <div className="space-y-4">
      <CheckFamiliesCard families={data.families} stale={cov.isStale} />
      <Card
        title="Supported"
        sub="Languages and package types the dependency scanners read, and where their vulnerability data comes from."
        stale={cov.isStale}
      >
        <SupportedTable
          rows={[...rows].sort((a, b) => a.ecosystem.localeCompare(b.ecosystem)).filter((r) => r.supported)}
          scan={scan}
          onOpenScanners={onOpenScanners}
        />
      </Card>
      <Card
        title="In your projects"
        sub={summary && scanned ? `${summary.ecosystemsScanned} ecosystems scanned across ${summary.projectsWithRuns} projects` : undefined}
        stale={cov.isStale}
      >
        <ChartState kind="table" loading={false} error={null} empty={!scanned} emptyHint="No dependency scan has run yet. Run a scan to see coverage.">
          <InProjects rows={rows} />
        </ChartState>
      </Card>
      <Card title="Files we found but did not read" sub={scanned && summary ? `${fmtInt(summary.filesSkipped)} files` : undefined} stale={cov.isStale}>
        <ChartState kind="list" loading={false} error={null} empty={!scanned || groups.length === 0} emptyHint={scanned ? "Every supported file that was found was read." : "No dependency scan has run yet. Run a scan to see coverage."}>
          <ul className="space-y-2">
            {groups.map((g) => (
              <ReasonGroupBlock key={g.reason} group={g} scan={scan} onOpenScanners={onOpenScanners} />
            ))}
          </ul>
        </ChartState>
      </Card>
      <Card title="One project" sub="What each scanner did in a single project." stale={cov.isStale}>
        <ChartState kind="table" loading={false} error={null} empty={!scanned} emptyHint="No dependency scan has run yet. Run a scan to see coverage.">
          <ProjectRuns cov={data} scan={scan} onOpenScanners={onOpenScanners} />
        </ChartState>
      </Card>
    </div>
  );
}
