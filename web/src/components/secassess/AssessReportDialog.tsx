import { useEffect, useState } from "react";
import { Button, Modal, Skeleton } from "@/components/primitives";
import { TitleWithHelp } from "@/components/HelpInd";
import { assessReportError, assessReportPath, type AssessRun } from "@/lib/secAssess";
import { redactionNote } from "@/lib/secAssessModel";

// AssessReportDialog shows a run's report.md as plain text. The server reads
// it through its confined reader (a regular file inside the run folder, size
// capped) and serves it as text/plain, so what the agent wrote is displayed
// as characters and never interpreted as markup or followed as a link.

type ReportState = { kind: "loading" } | { kind: "text"; text: string; note: string } | { kind: "error"; words: string };

/** The response header that says secrets Observer recognised were hidden in the text, with how many places. */
export const REDACTED_HEADER = "X-Observer-Redacted";

/** reportRedactionNote is the line under the report text: hiding is on when the server sent the header (with a count of places hidden), and off when it did not. */
export function reportRedactionNote(header: string | null): string {
  if (header === null) return redactionNote({ on: false, hidden: 0 });
  const n = Number.parseInt(header, 10);
  return redactionNote({ on: true, hidden: Number.isFinite(n) && n > 0 ? n : 0 });
}

export function AssessReportDialog({ run, onClose }: { run: AssessRun | null; onClose: () => void }) {
  const [state, setState] = useState<ReportState>({ kind: "loading" });
  const id = run?.id ?? "";
  useEffect(() => {
    if (!id) return;
    const ctl = new AbortController();
    setState({ kind: "loading" });
    fetch(assessReportPath(id), { signal: ctl.signal, headers: { Accept: "text/plain" } })
      .then(async (res) => {
        if (!res.ok) {
          // Only a 409 (the run record cannot be used) carries a body worth reading.
          const body = res.status === 409 ? await res.text().catch(() => "") : "";
          setState({ kind: "error", words: assessReportError(res.status, body) });
          return;
        }
        setState({ kind: "text", text: await res.text(), note: reportRedactionNote(res.headers.get(REDACTED_HEADER)) });
      })
      .catch((e: unknown) => {
        if ((e as { name?: string })?.name === "AbortError") return;
        setState({ kind: "error", words: "The report could not be read." });
      });
    return () => ctl.abort();
  }, [id]);

  return (
    <Modal
      open={run != null}
      onClose={onClose}
      title={<TitleWithHelp text={run ? `${run.kind_title}: report` : "Report"} helpId="card.code_security_assess_runs" />}
      subtitle={run ? `${run.project_name || "Unknown project"} · .observer/assessments/${run.id}/report.md` : undefined}
      width={820}
      bodyClassName="px-5 py-4"
      footer={
        <div className="flex items-center justify-end">
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
      }
    >
      <div data-testid="assess-report">
        {state.kind === "loading" && (
          <div className="space-y-2" role="status" aria-label="Loading the report">
            <p className="m-0 text-[12.5px] text-fg-3">Loading the report</p>
            <Skeleton className="h-24 w-full" />
          </div>
        )}
        {state.kind === "error" && (
          <p role="alert" className="m-0 text-[12.5px] text-fg-2">
            {state.words}
          </p>
        )}
        {state.kind === "text" && (
          <div className="space-y-2">
            <pre
              className="m-0 max-h-[60vh] overflow-auto whitespace-pre-wrap break-words rounded-2 border border-line-2 bg-bg-2 p-3 font-mono text-[11.5px] leading-relaxed text-fg-1"
              data-testid="assess-report-text"
            >
              {state.text}
            </pre>
            {state.note && (
              <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-report-redaction">
                {state.note}
              </p>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}
