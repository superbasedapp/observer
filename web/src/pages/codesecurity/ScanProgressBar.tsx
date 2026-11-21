import { useRef, useState } from "react";
import { Button, Meter } from "@/components/primitives";
import { ObsJobRider } from "@shared/primitives/ObsFlight";
import { asTimed, elapsedLabel, jobResultLine, runningParts } from "@/lib/scanSteps";
import { scanProgress } from "@/lib/codeSecurity";
import { ScanJobGrid, useNow } from "./ScanJobGrid";
import type { SecurityScan } from "./useSecurityScan";

// ScanProgressBar is the strip under the Code security header while a scan
// runs, and for the result of one that finished in this page session until
// it is dismissed. The line is a polite live region; the rider sits on the
// job's own determinate track (the design system allows Obs there).

export function ScanProgressBar({ scan }: { scan: SecurityScan }) {
  const job = scan.job;
  const running = scan.running;
  const [dismissed, setDismissed] = useState<string | null>(null);
  const [details, setDetails] = useState(false);
  const now = useNow(running);

  // The job already on the daemon when this page first loaded is history,
  // not this session's scan; any other job id is this session's.
  const baseline = useRef<{ id: string | null } | null>(null);
  if (baseline.current == null && scan.view) baseline.current = { id: job && !running ? job.id : null };

  const timed = asTimed(job);
  if (!job || !timed) return null;
  const finished = !running && baseline.current != null && baseline.current.id !== job.id && dismissed !== job.id;
  if (!running && !finished) return null;

  const steps = scan.view?.steps ?? [];
  const parts = running ? runningParts(timed, steps) : [];
  const stepClock = running ? elapsedLabel(timed.current?.started_at, now) : "";
  const total = running ? elapsedLabel(job.started_at, now) : "";

  return (
    <div className="min-w-0 space-y-2 rounded-lg border border-line-1 bg-bg-1 px-4 py-3 text-[12.5px]" data-testid="scan-progress-bar">
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        <div role="status" aria-live="polite" className="min-w-0 flex-1 truncate text-fg-1">
          {running ? (
            <>
              {parts.join(" · ")}
              {/* The clocks tick every second: kept out of the live region's
                  announcements (aria-hidden), shown to the eye only. */}
              {stepClock && <span aria-hidden>{` · ${stepClock}`}</span>}
              {total && <span aria-hidden className="text-fg-3">{` (total ${total})`}</span>}
            </>
          ) : (
            jobResultLine(job)
          )}
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <Button size="sm" variant="secondary" onClick={() => setDetails((v) => !v)} aria-expanded={details}>
            {details ? "Hide details" : "Details"}
          </Button>
          {running ? (
            <Button size="sm" variant="danger-outline" onClick={() => void scan.cancel()} disabled={scan.sending}>
              Cancel scan
            </Button>
          ) : (
            <Button size="sm" variant="secondary" onClick={() => setDismissed(job.id)}>
              Dismiss
            </Button>
          )}
        </div>
      </div>
      {(running || job.state === "done") && (
        <div className="space-y-1">
          <ObsJobRider ratio={running ? scanProgress(job) : 1} />
          <Meter ratio={running ? scanProgress(job) : 1} tone="accent" label="Projects scanned" />
        </div>
      )}
      {details && <ScanJobGrid job={job} steps={steps} />}
    </div>
  );
}
