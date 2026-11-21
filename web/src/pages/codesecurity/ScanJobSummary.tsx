import { Button } from "@/components/primitives";
import { fmtRelative } from "@/lib/format";
import { asTimed, failedResults, jobOnlineSuffix, jobResultLine, jobStepIds, runningParts, stepLabel } from "@/lib/scanSteps";
import type { ScanJob, ScanStep } from "@/lib/codeSecurity";

// ScanJobSummary is the Overview's "last scan" body: what ran, when, how it
// came out, what failed and why, and a way to scan again.

export function ScanJobSummary({
  job,
  onOpenScan,
  steps = [],
}: {
  job: ScanJob | null;
  onOpenScan: () => void;
  /** The node's scanner list, for the scanners' labels. */
  steps?: ScanStep[];
}) {
  const timed = asTimed(job);
  if (!job || !timed) {
    return (
      <div className="space-y-3 text-[12.5px]" data-testid="scan-job-summary">
        <p className="m-0 text-fg-3">No scan has run from this page since the daemon started.</p>
        <Button size="sm" variant="primary" onClick={onOpenScan}>
          Scan now
        </Button>
      </div>
    );
  }
  const running = job.state === "running";
  const ran = jobStepIds(timed).map((id) => stepLabel(id, steps));
  const failures = failedResults(job, steps);
  return (
    <div className="space-y-3 text-[12.5px]" data-testid="scan-job-summary">
      <div className="space-y-1">
        <p className="m-0 text-fg-1">{running ? runningParts(timed, steps).join(" · ") : jobResultLine(job)}</p>
        <p className="m-0 text-fg-3">
          {running ? `Started ${fmtRelative(job.started_at)}` : `Finished ${fmtRelative(job.finished_at)}`}
          {ran.length > 0 && ` · ${ran.join(", ")}${jobOnlineSuffix(job)}`}
        </p>
      </div>
      {failures.length > 0 && (
        <ul className="m-0 min-w-0 list-none space-y-1 p-0" aria-label="Scanners that failed">
          {failures.map((f, i) => (
            <li key={`${f.project}-${f.step}-${i}`} className="min-w-0 truncate text-fg-2">
              {`${f.project}: ${f.step} failed (${f.reason})`}
            </li>
          ))}
        </ul>
      )}
      <Button size="sm" variant="secondary" onClick={onOpenScan} disabled={running}>
        Scan again
      </Button>
    </div>
  );
}
