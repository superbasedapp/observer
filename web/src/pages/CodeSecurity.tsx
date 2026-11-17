import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Button, PageHeader, TabPanel, TabStrip, useTabVisited, type TabDef } from "@/components/primitives";
import { apiCache, useApi } from "@/lib/useApi";
import { navIcon } from "@/lib/nav";
import { useUrlTab } from "@/lib/useUrlTab";
import { usePageTabs } from "@/lib/governance";
import { CODE_SECURITY_TABS, defaultTab, type CodeSecurityTab } from "@/lib/nodePageTabs";
import { fmtInt } from "@/lib/format";
import { scanSummary, sortProjects, type SecurityStatus } from "@/lib/codeSecurity";
import { findingsHref, type FindingGroupsPage } from "@/lib/codeSecurityApi";
import { problemCounts, scannerProblems } from "@/lib/scannerProblems";
import { COVERAGE_PATH, OverviewTab, useOpenIssues } from "./codesecurity/OverviewTab";
import { FindingsTab } from "./codesecurity/FindingsTab";
import { ProjectsTab } from "./codesecurity/ProjectsTab";
import { CoverageTab } from "./codesecurity/CoverageTab";
import { ScannersTab } from "./codesecurity/ScannersTab";
import { ExceptionsTab } from "./codesecurity/ExceptionsTab";
import { BaselinesTab } from "./codesecurity/BaselinesTab";
import { ScanDialog } from "./codesecurity/ScanDialog";
import { ScanProgressBar } from "./codesecurity/ScanProgressBar";
import { useSecurityScan, type SecurityScan } from "./codesecurity/useSecurityScan";
import { FIX_ATTEMPTS_PATH } from "@/lib/securityFix";

// Code security (the security pillar's module root, component `security`;
// security pillar plan sections 4.10 and 6.3). Guard keeps its own Security
// page; this one sits beside it and reads only /api/security.
//
// This file is the page SHELL (redesign plan
// docs/plans/code-security-page-redesign-plan-2026-11-06.md, sections 4.1
// and 8): the header with a one-line posture ("2 projects block commits ·
// 14 critical, 38 high open · 1 scanner needs setup") and the Scan button,
// the scan progress bar under it on every tab, and the tab strip. Each tab
// lives in its own file under ./codesecurity and loads only once visited:
//   Overview    (default) the headline numbers, the worst open issues, the
//               scanner problems, coverage and the last scan;
//   Findings    the filter bar, grouping, the list and each finding's drawer;
//   Projects    each project's commit gate, open findings and scanner state;
//   Coverage    the ecosystems the scanners read, found and skipped;
//   Scanners    every scanner's switch, install and database state, and setup;
//   Exceptions  local, expiring, one finding each, never rule-wide;
//   Baselines   the commit a project's findings are judged against, with the
//               local git hooks and the AI change records.
// The page owns the reads every tab shares (the posture, the scan job, the
// open issues) and the Scan dialog: a project row's Scan opens it with that
// project chosen. Every action here is also a CLI verb (`observer security
// scan|code scan|iac scan|actionlint`, `observer security exception`,
// `observer security baseline`).
//
// A project is always NAMED (lib/codeSecurity.ts projectLabel), never shown
// as its root hash (review doc
// docs/plans/node-code-security-page-review-2026-11-02.md).
//
// Working surface: calm register, zero delight elements (Obs rides only the
// scan job's own progress track, in ScanProgressBar).

// The subtitle while the posture has not loaded.
const FALLBACK_SUB =
  "Commit-gate posture, findings, exceptions and baselines for every project on this machine. Preview.";

// The URL param the finding drawer is addressed by (FindingsTab owns it).
const FINDING_PARAM = "finding";

/** postureLine is the header's one line: commits blocked, the critical and
 *  high issues still open (each counted once), and the scanners that need
 *  setup or are failing. A part whose read has not answered is left out. */
function postureLine(
  status: SecurityStatus | null,
  issues: FindingGroupsPage | null,
  scanners: { setup: number; failing: number },
): string {
  if (!status) return FALLBACK_SUB;
  const parts: string[] = [];
  const blocking = scanSummary(status.projects).blocking;
  parts.push(
    blocking === 0
      ? "No commit is blocked"
      : `${fmtInt(blocking)} ${blocking === 1 ? "project blocks" : "projects block"} commits`,
  );
  if (issues) {
    const critical = issues.by_severity?.critical ?? 0;
    const high = issues.by_severity?.high ?? 0;
    parts.push(
      critical + high === 0
        ? "No critical or high issue open"
        : `${fmtInt(critical)} critical, ${fmtInt(high)} high open`,
    );
  }
  if (scanners.setup > 0) {
    parts.push(`${fmtInt(scanners.setup)} ${scanners.setup === 1 ? "scanner needs" : "scanners need"} setup`);
  }
  if (scanners.failing > 0) {
    parts.push(`${fmtInt(scanners.failing)} ${scanners.failing === 1 ? "scanner is" : "scanners are"} failing`);
  }
  return parts.join(" · ");
}

// SCAN_BUTTON_RULES: why the header's Scan button cannot open the dialog
// yet, walked top-down (the first row that holds wins). A scanner that is
// not ready does not disable it: the dialog says why and links to Scanners.
const SCAN_BUTTON_RULES: readonly { when: (s: SecurityScan) => boolean; reason: string }[] = [
  { when: (s) => s.view != null, reason: "" },
  { when: (s) => s.loading, reason: "Loading the scanners" },
  { when: (s) => s.denied, reason: "Scans start on this machine only" },
  { when: (s) => s.error != null, reason: "The scanners did not load" },
  { when: () => true, reason: "Scanning is not available here" },
];

function scanButtonReason(scan: SecurityScan): string {
  return SCAN_BUTTON_RULES.find((r) => r.when(scan))?.reason ?? "";
}

export function CodeSecurityPage() {
  const pageTabs = usePageTabs("code-security", CODE_SECURITY_TABS);
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  // A link from before the redesign, when Findings was the default tab
  // (`/code-security?finding=<id>`), still opens that finding's drawer: it
  // reads as the Findings tab at once, and the URL is rewritten to say so.
  const legacyFinding = !params.get("tab") && params.get(FINDING_PARAM) != null && pageTabs.ids.includes("findings");
  const [tab, setTab] = useUrlTab(pageTabs.ids, legacyFinding ? "findings" : defaultTab(pageTabs));
  useEffect(() => {
    if (!legacyFinding) return;
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.set("tab", "findings");
        return next;
      },
      { replace: true },
    );
  }, [legacyFinding, setParams]);

  const status = useApi<SecurityStatus>("/api/security/status");
  // The Overview's open-issues read (one request, shared through the cache):
  // the posture line's critical and high counts.
  const issues = useOpenIssues();
  const reloadStatus = status.reload;
  const reloadIssues = issues.reload;
  const onScanFinished = useCallback(() => {
    reloadStatus();
    reloadIssues();
    // The coverage a finished scan recorded (read by Overview, Projects and
    // Coverage): refetched where shown, dropped otherwise.
    apiCache.invalidate(COVERAGE_PATH);
    // A rescan decides whether a fix attempt's findings cleared.
    apiCache.invalidate(FIX_ATTEMPTS_PATH);
  }, [reloadStatus, reloadIssues]);
  const scan = useSecurityScan(onScanFinished);

  const projects = useMemo(() => status.data?.projects ?? [], [status.data]);
  const sortedProjects = useMemo(() => sortProjects(projects), [projects]);
  const problems = useMemo(() => scannerProblems(projects, scan.view?.steps ?? []), [projects, scan.view]);
  const counts = problemCounts(problems);

  // The Scan dialog: `seq` remounts it on each open, so a project row's
  // choice never carries into the next open from the header.
  const [dialog, setDialog] = useState<{ open: boolean; projects?: string[]; seq: number }>({ open: false, seq: 0 });
  const openScan = useCallback((chosen?: string[]) => setDialog((d) => ({ open: true, projects: chosen, seq: d.seq + 1 })), []);
  const closeScan = useCallback(() => setDialog((d) => ({ ...d, open: false })), []);

  const visited: Record<CodeSecurityTab, boolean> = {
    overview: useTabVisited<CodeSecurityTab>("overview", tab),
    findings: useTabVisited<CodeSecurityTab>("findings", tab),
    projects: useTabVisited<CodeSecurityTab>("projects", tab),
    coverage: useTabVisited<CodeSecurityTab>("coverage", tab),
    scanners: useTabVisited<CodeSecurityTab>("scanners", tab),
    exceptions: useTabVisited<CodeSecurityTab>("exceptions", tab),
    baselines: useTabVisited<CodeSecurityTab>("baselines", tab),
  };
  const tabs: TabDef<CodeSecurityTab>[] = pageTabs.ids.map((id): TabDef<CodeSecurityTab> => ({
    id,
    label: CODE_SECURITY_TABS.labels[id],
    // From reads the page already holds: a scanner that needs setup or fails.
    dot: id === "scanners" && counts.attention > 0 ? "warn" : null,
  }));
  const scanReason = scan.running ? "" : scanButtonReason(scan);

  return (
    <div className="space-y-6 p-4 sm:p-6" data-page="code-security">
      <PageHeader
        icon={navIcon("code-security")}
        title="Code security"
        sub={postureLine(status.data, issues.data, counts)}
        right={
          <div className="flex flex-col items-end gap-1">
            <Button
              variant="primary"
              loading={scan.running}
              disabled={scanReason !== ""}
              title={scanReason || undefined}
              onClick={() => openScan()}
            >
              {scan.running ? "Scanning" : "Scan…"}
            </Button>
            {scanReason && <span className="max-w-[9rem] text-right text-[11px] leading-snug text-fg-3">{scanReason}</span>}
          </div>
        }
      />
      <ScanProgressBar scan={scan} />
      <TabStrip tabs={tabs} value={tab} onChange={setTab} idPrefix="code-security" ariaLabel="Code security sections" className="mb-4" />
      <TabPanel id="overview" active={tab} idPrefix="code-security">
        {visited.overview && <OverviewTab status={status} scan={scan} onOpenScan={() => openScan()} onOpenTab={setTab} />}
      </TabPanel>
      <TabPanel id="findings" active={tab} idPrefix="code-security">
        {visited.findings && <FindingsTab status={status} scan={scan} />}
      </TabPanel>
      <TabPanel id="projects" active={tab} idPrefix="code-security">
        {visited.projects && (
          <ProjectsTab
            status={status}
            onScanProject={(hash) => openScan([hash])}
            onShowFindings={(hash) => navigate(findingsHref({ project: [hash] }))}
            scanning={scan.running}
          />
        )}
      </TabPanel>
      <TabPanel id="coverage" active={tab} idPrefix="code-security">
        {visited.coverage && <CoverageTab status={status} scan={scan} onOpenScanners={() => setTab("scanners")} />}
      </TabPanel>
      <TabPanel id="scanners" active={tab} idPrefix="code-security">
        {visited.scanners && (
          <ScannersTab
            status={status}
            onChanged={() => {
              status.reload();
              // A scanner switched on or off changes which scan steps are ready.
              scan.reload();
            }}
          />
        )}
      </TabPanel>
      <TabPanel id="exceptions" active={tab} idPrefix="code-security">
        {visited.exceptions && <ExceptionsTab />}
      </TabPanel>
      <TabPanel id="baselines" active={tab} idPrefix="code-security">
        {visited.baselines && <BaselinesTab projects={sortedProjects} />}
      </TabPanel>
      <ScanDialog
        key={dialog.seq}
        open={dialog.open}
        onClose={closeScan}
        scan={scan}
        projects={projects}
        initialProjects={dialog.projects}
        onOpenScanners={() => {
          closeScan();
          setTab("scanners");
        }}
      />
    </div>
  );
}
