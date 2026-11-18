import { useMemo, useState, type MouseEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Button, Callout, Input, Toggle } from "@/components/primitives";
import { useApi, type ApiState } from "@/lib/useApi";
import type { SecurityStatus } from "@/lib/codeSecurity";
import type { CoverageResponse } from "@/lib/codeSecurityApi";
import { isSetupReason } from "@/lib/scannerProblems";
import { ecosystemsByProject, filterProjects, idleHiddenLine, setupNoticeLine, setupNotices } from "@/lib/secCoverage";
import { ProjectsCard } from "./ProjectsCard";

// ProjectsTab is the Code security page's Projects tab (redesign plan
// section 4.1): a search box, the idle-projects switch (off: only projects
// with recent sessions, with the count of the idle ones left out), one notice
// for the setup facts that used to be a pill on every row ("osv-scanner is not
// installed"), and the projects table. Scan opens the page's Scan dialog for
// the row's project; the open-findings count opens the Findings tab filtered
// to it.

export function ProjectsTab({
  status,
  onScanProject,
  onShowFindings,
  scanning,
}: {
  status: ApiState<SecurityStatus>;
  onScanProject: (hash: string) => void;
  onShowFindings: (hash: string) => void;
  /** A scan is running: the row Scan buttons wait. */
  scanning?: boolean;
}) {
  const [query, setQuery] = useState("");
  const [showIdle, setShowIdle] = useState(false);
  const navigate = useNavigate();
  // The Scanner setup callout's way forward: the Scanners tab, where each
  // scanner is installed and turned on.
  const openScanners = (e: MouseEvent<HTMLButtonElement | HTMLAnchorElement>) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    navigate("/code-security?tab=scanners");
  };
  // The ecosystems column reads the coverage; a failed read only leaves the
  // column at "none scanned", never the table.
  const coverage = useApi<CoverageResponse>("/api/security/coverage");
  const all = status.data?.projects ?? [];
  const { rows, hiddenIdle } = useMemo(() => filterProjects(all, query, showIdle), [all, query, showIdle]);
  const notices = useMemo(() => setupNotices(all, isSetupReason), [all]);
  const ecosystems = useMemo(() => ecosystemsByProject(coverage.data), [coverage.data]);
  const hiddenLine = idleHiddenLine(hiddenIdle);
  const searching = query.trim() !== "";
  const emptyHint =
    all.length > 0 && rows.length === 0
      ? searching
        ? "No project matches this search."
        : "No active projects. Turn on “Show idle projects” to list the rest."
      : undefined;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="w-full sm:w-72">
          <Input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by project name or path"
            aria-label="Search projects"
          />
        </div>
        <Toggle on={showIdle} onChange={setShowIdle} label="Show idle projects" />
        {hiddenLine && !showIdle && <span className="text-[12px] text-fg-3">{hiddenLine}</span>}
      </div>
      {notices.length > 0 && (
        <Callout
          tone="info"
          title="Scanner setup"
          action={
            <Button size="sm" variant="secondary" href="/code-security?tab=scanners" onClick={openScanners}>
              Open Scanners
            </Button>
          }
        >
          <ul className="space-y-0.5">
            {notices.map((n) => (
              <li key={`${n.driver}|${n.reason}`}>{setupNoticeLine(n)}</li>
            ))}
          </ul>
        </Callout>
      )}
      <ProjectsCard
        status={status}
        projects={rows}
        ecosystems={ecosystems}
        onScanProject={onScanProject}
        onShowFindings={onShowFindings}
        scanning={scanning}
        emptyHint={emptyHint}
      />
    </div>
  );
}
