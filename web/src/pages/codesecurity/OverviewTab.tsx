import { useMemo } from "react";
import { Link } from "react-router-dom";
import { Button, Card, EmptyState, Pill, StatCard, StatStrip } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { useApi, type ApiState } from "@/lib/useApi";
import type { QueryParams } from "@/lib/api";
import { fmtInt } from "@/lib/format";
import { scanSummary, type SecurityProject, type SecurityStatus } from "@/lib/codeSecurity";
import {
  EMPTY_FINDINGS_FILTERS,
  findingsHref,
  groupDrillDown,
  type CoverageResponse,
  type FindingGroup,
  type FindingGroupsPage,
} from "@/lib/codeSecurityApi";
import { problemCounts, scannerProblems, type ScannerProblem, type ScannerProblemTab } from "@/lib/scannerProblems";
import { coverageSummary, hasCoverage, reasonGroups } from "@/lib/secCoverage";
import type { CodeSecurityTab } from "@/lib/nodePageTabs";
import { toneOf } from "@shared/lib/tone";
import { SecAssessCard } from "@/components/secassess/SecAssessCard";
import { NamedLoading } from "./NamedLoading";
import { ScanJobSummary } from "./ScanJobSummary";
import { SEVERITY_TONE } from "./ProjectsCard";
import type { SecurityScan } from "./useSecurityScan";

// OverviewTab is the Code security page's default tab (redesign plan
// docs/plans/code-security-page-redesign-plan-2026-11-06.md section 4.1):
// it answers "am I safe, and what do I fix first". Top to bottom: the
// headline numbers (counted on distinct issues, so 20 worktrees repeating
// one advisory count once), the worst open issues, the scanner problems
// (each one once, with why and what to do; a scanner that is not set up is
// a setup notice, never a failing scan), the coverage summary and the last
// scan. Every block names what it is loading (NamedLoading over the shared
// skeleton) and every failure has a retry. Working surface: calm, no
// mascot.

/** The open-issues read the Overview and the page header share (one
 *  request through the query cache): the five worst open issues, and
 *  by_severity counted over every open issue. */
export const OPEN_ISSUES_PATH = "/api/security/findings/groups";
export const OPEN_ISSUES_PARAMS: QueryParams = { by: "issue", status: "open", limit: 5, sort: "severity", dir: "desc" };

/** useOpenIssues reads the worst open issues (shared with the page header). */
export function useOpenIssues(): ApiState<FindingGroupsPage> {
  return useApi<FindingGroupsPage>(OPEN_ISSUES_PATH, OPEN_ISSUES_PARAMS);
}

/** The coverage read the Overview, Projects and Coverage tabs share. */
export const COVERAGE_PATH = "/api/security/coverage";

/** The line a slow read shows after a few seconds. */
const SLOW_LINE = "Still reading. The daemon may be busy with other work.";

/** The page's own tab links (the default tab is the bare path). */
function tabHref(tab: CodeSecurityTab): string {
  return tab === "overview" ? "/code-security" : `/code-security?tab=${tab}`;
}

function plural(n: number, one: string, many: string): string {
  return `${fmtInt(n)} ${n === 1 ? one : many}`;
}

/** issueLines is how one issue reads in the list: a dependency by its
 *  package, with its ecosystem and advisory; anything else by its message
 *  (or rule), with the rule and the path. */
export function issueLines(g: FindingGroup): { title: string; detail: string } {
  if (g.package) {
    return { title: g.package, detail: [g.ecosystem, g.message || g.rule_id].filter(Boolean).join(" · ") };
  }
  const title = g.message || g.rule_id || "Unnamed issue";
  return { title, detail: [g.message ? g.rule_id : "", g.rel_path].filter(Boolean).join(" · ") };
}

/** IssueList is the "Needs attention" rows: worst severity, the issue, how
 *  many projects have it, each linking to that issue's findings. */
export function IssueList({ groups }: { groups: FindingGroup[] }) {
  return (
    <ul className="m-0 min-w-0 list-none divide-y divide-line-1 p-0" aria-label="Worst open issues">
      {groups.map((g) => {
        const { title, detail } = issueLines(g);
        return (
          <li key={g.key} className="min-w-0">
            <Link
              to={findingsHref(groupDrillDown("issue", g, EMPTY_FINDINGS_FILTERS))}
              className="-mx-2 flex min-w-0 items-start gap-2 rounded-2 px-2 py-2 hover:bg-bg-3"
            >
              <Pill variant={toneOf(SEVERITY_TONE, g.max_severity)} className="mt-0.5 shrink-0">
                {g.max_severity || "unknown"}
              </Pill>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[13px] text-fg-1">{title}</span>
                {detail && <span className="block truncate text-[11.5px] text-fg-3">{detail}</span>}
              </span>
              <span className="shrink-0 pt-0.5 text-[12px] text-fg-3">{plural(g.projects, "project", "projects")}</span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

/** The line under a problem: how many projects it left unchecked. */
function problemProjectsLine(p: ScannerProblem): string {
  const n = p.projects.length;
  if (n === 0) return "";
  return `${plural(n, "project", "projects")} not checked with it`;
}

/** ProblemList is the scanner problems that need the person (failing, then
 *  setup), each with its one next step, then the scanners that are off as
 *  quiet lines. */
export function ProblemList({ problems, onOpenTab }: { problems: ScannerProblem[]; onOpenTab: (tab: ScannerProblemTab) => void }) {
  const attention = problems.filter((p) => p.kind !== "off");
  const off = problems.filter((p) => p.kind === "off");
  return (
    <div className="min-w-0 space-y-3 text-[12.5px]">
      {attention.length === 0 ? (
        <p className="m-0 text-fg-2">Every scanner that is on ran without a problem.</p>
      ) : (
        <ul className="m-0 min-w-0 list-none divide-y divide-line-1 p-0" aria-label="Scanner problems">
          {attention.map((p) => {
            const line = problemProjectsLine(p);
            const action = p.action;
            return (
              <li key={`${p.driver}|${p.reason}`} className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1.5 py-2">
                <Pill variant={p.kind === "failing" ? "warn" : "neutral"} className="shrink-0">
                  {p.kind === "failing" ? "failing" : "setup"}
                </Pill>
                <span className="min-w-0 flex-1 basis-48">
                  <span className="block text-fg-1">{p.words}</span>
                  {line && <span className="block text-[11.5px] text-fg-3">{line}</span>}
                </span>
                {action && (
                  <Button size="sm" variant="secondary" onClick={() => onOpenTab(action.tab)}>
                    {action.label}
                  </Button>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {off.length > 0 && (
        <div className="min-w-0 space-y-0.5">
          <div className="flex flex-wrap items-center gap-2">
            <p className="m-0 text-[11.5px] font-medium text-fg-3">Off on this machine</p>
            {off[0]?.action && (
              <Button size="sm" variant="ghost" onClick={() => onOpenTab(off[0]!.action!.tab)}>
                Turn on in Scanners
              </Button>
            )}
          </div>
          <ul className="m-0 min-w-0 list-none space-y-0.5 p-0 text-fg-3" aria-label="Scanners that are off">
            {off.map((p) => (
              <li key={`${p.driver}|${p.reason}`} className="min-w-0 break-words">
                {p.words}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function openTotals(projects: SecurityProject[]): { open: number; withOpen: number } {
  let open = 0;
  let withOpen = 0;
  for (const p of projects) {
    open += p.open;
    if (p.open > 0) withOpen++;
  }
  return { open, withOpen };
}

const linkClass = "text-[12px] text-accent hover:underline";

export function OverviewTab({
  status,
  scan,
  onOpenScan,
  onOpenTab,
}: {
  status: ApiState<SecurityStatus>;
  scan: SecurityScan;
  /** Opens the page's Scan dialog. */
  onOpenScan: () => void;
  /** Switches the page to another tab. */
  onOpenTab: (tab: CodeSecurityTab) => void;
}) {
  const issues = useOpenIssues();
  const coverage = useApi<CoverageResponse>(COVERAGE_PATH);
  const projects = useMemo(() => status.data?.projects ?? [], [status.data]);
  const steps = useMemo(() => scan.view?.steps ?? [], [scan.view]);
  const problems = useMemo(() => scannerProblems(projects, steps), [projects, steps]);
  const counts = problemCounts(problems);
  const summary = scanSummary(projects);
  const blockingFindings = projects.reduce((n, p) => n + (p.state === "blocking" ? p.blocking : 0), 0);
  const totals = openTotals(projects);
  const statusLoading = status.loading && !status.data;
  // The problems read the scanner list too: wait for it, so a not-ready
  // scanner's notice does not appear a moment after its projects' rows.
  const problemsLoading = statusLoading || (scan.loading && !scan.view);
  const issuesLoading = issues.loading && !issues.data;
  const bySeverity = issues.data?.by_severity ?? {};
  const critical = bySeverity.critical ?? 0;
  const high = bySeverity.high ?? 0;
  // A read that has not answered shows nothing while it loads and "n/a"
  // after it failed: never a zero it did not count.
  const statusValue = (n: number) => (status.data ? fmtInt(n) : statusLoading ? "" : "n/a");
  const issueValue = (n: number) => (issues.data ? fmtInt(n) : issuesLoading ? "" : "n/a");
  const issueSub = issues.error ? "Could not load" : "open, each counted once";
  const statusSub = (line: string) => (status.data ? line : status.error ? "Could not load" : undefined);
  const blockedLine =
    summary.blocking > 0
      ? `${summary.blocking === 1 ? "project" : "projects"} · ${plural(blockingFindings, "blocking finding", "blocking findings")}`
      : "Every project can commit";
  const scannersLine =
    counts.attention === 0
      ? "All working"
      : [
          counts.setup > 0 ? `${fmtInt(counts.setup)} ${counts.setup === 1 ? "needs" : "need"} setup` : "",
          counts.failing > 0 ? `${fmtInt(counts.failing)} failing` : "",
        ]
          .filter(Boolean)
          .join(", ");
  const groups = issues.data?.groups ?? [];
  const cov = coverage.data;
  const covSummary = useMemo(() => (cov ? coverageSummary(cov) : null), [cov]);
  const covReasons = useMemo(() => (cov ? reasonGroups(cov).slice(0, 3) : []), [cov]);

  const issuesLabel = status.data
    ? `Loading the open issues: ${fmtInt(totals.open)} open findings across ${plural(totals.withOpen, "project", "projects")}`
    : "Loading the open issues";
  const coverageLabel = status.data
    ? `Loading coverage for ${plural(projects.length, "project", "projects")}`
    : "Loading coverage";

  return (
    <div className="min-w-0 space-y-4" data-testid="code-security-overview">
      <StatStrip cols={4} ariaLabel="Code security at a glance">
        <StatCard
          label="Commits blocked"
          value={statusValue(summary.blocking)}
          sub={statusSub(blockedLine)}
          warn={summary.blocking > 0}
          loading={statusLoading}
          stale={status.isStale}
          linkTo={tabHref("projects")}
        />
        <StatCard
          label="Critical issues"
          value={issueValue(critical)}
          sub={issueSub}
          warn={critical > 0}
          loading={issuesLoading}
          stale={issues.isStale}
          linkTo={findingsHref({ severity: ["critical"] })}
        />
        <StatCard
          label="High issues"
          value={issueValue(high)}
          sub={issueSub}
          warn={high > 0}
          loading={issuesLoading}
          stale={issues.isStale}
          linkTo={findingsHref({ severity: ["high"] })}
        />
        <StatCard
          label="Scanners needing attention"
          value={statusValue(counts.attention)}
          sub={statusSub(scannersLine)}
          warn={counts.attention > 0}
          loading={problemsLoading}
          stale={status.isStale}
          linkTo={tabHref("scanners")}
        />
      </StatStrip>

      <div className="grid min-w-0 gap-4 xl:grid-cols-2">
        <Card
          className="min-w-0 xl:col-span-2"
          title="Needs attention"
          sub="The worst open issues first, each counted once however many projects repeat it."
          actions={
            <Link to={findingsHref({})} className={linkClass}>
              See all findings
            </Link>
          }
          stale={issues.isStale}
        >
          <NamedLoading active={issuesLoading} label={issuesLabel} slowLine={SLOW_LINE} />
          <ChartState
            kind="list"
            height={200}
            loading={issuesLoading}
            error={issues.notInstalled ? null : issues.error}
            denied={issues.denied}
            onRetry={issues.reload}
            empty={false}
          >
            {!issues.data ? (
              // Not read on this machine (the route is hidden or not in this
              // build): never "no open issues", which would be a claim.
              <p className="m-0 text-[12.5px] text-fg-3">Open issues are not available here.</p>
            ) : groups.length === 0 ? (
              <EmptyState
                variant="inline"
                className="py-4"
                illustration="all-clear"
                illustrationSize={88}
                title="No open issues"
              />
            ) : (
              <IssueList groups={groups} />
            )}
          </ChartState>
        </Card>

        <Card
          className="min-w-0"
          title="Scanner problems"
          sub="Why a scanner did not check a project, and what to do. A missing tool shows here once."
          stale={status.isStale}
        >
          <NamedLoading active={problemsLoading} label="Loading the scanners" slowLine={SLOW_LINE} />
          <ChartState
            kind="list"
            height={140}
            loading={problemsLoading}
            error={status.error}
            denied={status.denied}
            onRetry={status.reload}
            empty={false}
          >
            <ProblemList problems={problems} onOpenTab={onOpenTab} />
          </ChartState>
        </Card>

        <Card
          className="min-w-0"
          title="Coverage"
          sub="Which package types the dependency scans read, and the files they skipped."
          actions={
            <Link to={tabHref("coverage")} className={linkClass}>
              See coverage
            </Link>
          }
          stale={coverage.isStale}
        >
          <NamedLoading active={coverage.loading && !cov} label={coverageLabel} slowLine={SLOW_LINE} />
          <ChartState
            kind="list"
            height={140}
            loading={coverage.loading && !cov}
            error={coverage.notInstalled ? null : coverage.error}
            denied={coverage.denied}
            onRetry={coverage.reload}
            empty={false}
          >
            {!cov ? (
              <p className="m-0 text-[12.5px] text-fg-3">Coverage is not available here.</p>
            ) : !hasCoverage(cov) || !covSummary ? (
              <div className="space-y-3 text-[12.5px]">
                <p className="m-0 text-fg-2">No dependency scan has recorded its coverage yet.</p>
                <Button size="sm" variant="secondary" onClick={onOpenScan}>
                  Scan…
                </Button>
              </div>
            ) : (
              <div className="min-w-0 space-y-2 text-[12.5px]">
                <p className="m-0 text-fg-1">
                  {plural(covSummary.ecosystemsScanned, "ecosystem", "ecosystems")} scanned across{" "}
                  {plural(covSummary.projectsWithRuns, "project", "projects")}
                </p>
                {covSummary.filesSkipped === 0 ? (
                  <p className="m-0 text-fg-3">No dependency file was skipped.</p>
                ) : (
                  <>
                    <p className="m-0 text-fg-2">
                      {plural(covSummary.filesSkipped, "file", "files")} found but not read
                    </p>
                    <ul className="m-0 min-w-0 list-none space-y-0.5 p-0 text-fg-3" aria-label="Why files were skipped">
                      {covReasons.map((g) => (
                        <li key={g.reason} className="min-w-0 break-words">
                          {g.words}: {plural(g.count, "file", "files")}
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            )}
          </ChartState>
        </Card>

        <Card className="min-w-0 xl:col-span-2" title="Last scan">
          <NamedLoading active={scan.loading && !scan.view} label="Loading the last scan" slowLine={SLOW_LINE} />
          <ChartState
            kind="list"
            height={96}
            loading={scan.loading && !scan.view}
            error={scan.error}
            denied={scan.denied}
            onRetry={scan.reload}
            empty={false}
          >
            <ScanJobSummary job={scan.job} onOpenScan={onOpenScan} steps={steps} />
          </ChartState>
        </Card>

        <SecAssessCard projects={projects} />
      </div>
    </div>
  );
}
