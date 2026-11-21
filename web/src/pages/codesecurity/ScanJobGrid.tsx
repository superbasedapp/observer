import { useEffect, useState } from "react";
import { Pill } from "@/components/primitives";
import { clockLabel, asTimed, cellOf, elapsedLabel, jobStepIds, onlineResultNote, resultsOf, stepLabel } from "@/lib/scanSteps";
import { projectHref, scanRunning, type ScanJob, type ScanStep } from "@/lib/codeSecurity";
import { NodeLink } from "./NodeLink";

// ScanJobGrid is a scan job as projects x scanners: each cell the step's
// outcome, how long it took, or that it is waiting or running, and, for a
// job that asked for online checks, whether the dependency step checked
// online there or why not. A working surface: calm register, no mascot.

/** useNow is the current time in ms, re-read every second while active. */
export function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [active]);
  return now;
}

export function ScanJobGrid({ job, steps }: { job: ScanJob; steps: ScanStep[] }) {
  const timed = asTimed(job);
  const running = scanRunning(job);
  const now = useNow(running);
  if (!timed) return null;
  const cols = jobStepIds(timed);
  if (job.projects.length === 0) {
    return <p className="m-0 text-[12.5px] text-fg-3">No project has started yet.</p>;
  }
  return (
    <div className="min-w-0 overflow-x-auto" data-testid="scan-job-grid">
      <table className="w-full text-[12.5px]">
        <thead className="text-left text-fg-3">
          <tr>
            <th className="py-1.5 pr-3 font-normal">Project</th>
            {cols.map((id) => (
              <th key={id} className="py-1.5 pr-3 font-normal">
                {stepLabel(id, steps)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {job.projects.map((p) => {
            const results = resultsOf(p);
            return (
              <tr key={p.project_root_hash} className="border-t border-line-1 align-top">
                <td className="py-1.5 pr-3">
                  <NodeLink to={projectHref(p.project_id)} variant="text">
                    {p.name}
                  </NodeLink>
                </td>
                {cols.map((id) => {
                  const result = results.find((r) => r.id === id);
                  const here =
                    running && timed.current?.project_root_hash === p.project_root_hash && (timed.current.step_id ?? "") === id;
                  const cell = cellOf({ result, running: here, jobRunning: running });
                  const detail = here
                    ? elapsedLabel(timed.current?.started_at, now)
                    : cell.durationMs != null
                      ? clockLabel(cell.durationMs)
                      : "";
                  const online = result ? onlineResultNote(result) : "";
                  return (
                    <td key={id} className="py-1.5 pr-3">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Pill variant={cell.tone}>{cell.label}</Pill>
                        {detail && <span className="text-fg-3 tabular-nums">{detail}</span>}
                      </div>
                      {online && (
                        <div className="mt-0.5 text-[11.5px] text-fg-3" data-testid="scan-job-online">
                          {online}
                        </div>
                      )}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
