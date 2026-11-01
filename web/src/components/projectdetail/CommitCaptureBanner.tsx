import { useState } from "react";
import clsx from "clsx";
import { RefreshCw } from "lucide-react";
import { Button, InfoDisclosure } from "@/components/primitives";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import { fmtDateTime, fmtRelative } from "@/lib/format";
import type { CommitRescanResponse, ProjectCaptureInfo } from "@/lib/types";
import { COMMIT_CAPTURE, COMMIT_SCAN_FAILURE } from "@/lib/vocabTones";
import { VocabPill } from "@shared/lib/vocabPill";

// CommitCaptureBanner - the Project detail's commit-capture health
// (2026-10-15). It replaces the one generic "the last commit scan failed
// ... may be stale" line with: the specific cause (COMMIT_CAPTURE state,
// refined by COMMIT_SCAN_FAILURE for a plain "error"), what to do about it,
// git's own message behind a disclosure, when the last attempt and the
// last good scan were, and a "Rescan now" button (POST
// /api/project/{id}/commit-scan, the dashboard twin of `observer backfill
// --commits --commits-project <id>`).

type RescanState =
  | { phase: "idle" }
  | { phase: "running" }
  | { phase: "done"; ok: boolean; message: string };

export function CommitCaptureBanner({
  projectId,
  capture,
  onRescanned,
}: {
  projectId: number;
  capture: ProjectCaptureInfo;
  onRescanned?: () => void;
}) {
  const [rescan, setRescan] = useState<RescanState>({ phase: "idle" });
  const state = capture.commits;
  const entry = COMMIT_CAPTURE[state] ?? COMMIT_CAPTURE.error;
  const scan = capture.commit_scan;
  const failure = state === "error" ? COMMIT_SCAN_FAILURE[capture.commits_kind ?? "other"] ?? COMMIT_SCAN_FAILURE.other : null;
  const calm = state === "catching_up";
  const canRescan = Boolean(scan?.can_rescan) && entry.rescan;

  async function runRescan() {
    setRescan({ phase: "running" });
    try {
      const res = await fetchJSON<CommitRescanResponse>(`/api/project/${projectId}/commit-scan`, undefined, {
        method: "POST",
        headers: await localConfirmHeaders(),
        body: "{}",
      });
      if (!res.done) {
        setRescan({ phase: "done", ok: true, message: "Still scanning in the background. This panel refreshes when you reopen it." });
      } else if (res.error) {
        const next = COMMIT_CAPTURE[res.capture.commits];
        setRescan({ phase: "done", ok: false, message: next?.banner ? `${next.banner}.` : res.error });
      } else {
        setRescan({ phase: "done", ok: true, message: "Scan finished." });
      }
      onRescanned?.();
    } catch (e) {
      setRescan({ phase: "done", ok: false, message: e instanceof Error ? e.message : String(e) });
    }
  }

  const heading = failure ? `${entry.banner}: ${failure.what}` : entry.banner;
  const todo = failure ? failure.todo : entry.todo;

  return (
    <div
      role="status"
      className={clsx(
        "rounded-3 border px-3 py-2.5 text-[11.5px] text-fg-2",
        calm ? "border-info/30 bg-info-soft/50" : "border-warn/30 bg-warn-soft/60",
      )}
    >
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex min-w-0 flex-1 flex-col gap-1.5 sm:flex-row sm:items-start sm:gap-2">
          <span className="shrink-0 self-start whitespace-nowrap">
            <VocabPill vocab="commitCapture" table={COMMIT_CAPTURE} value={state} />
          </span>
          <div className="min-w-0">
            <div className="font-medium text-fg-1">{heading}</div>
            {todo && <p className="mt-0.5 text-fg-2">{todo}</p>}
          </div>
        </div>
        {canRescan && (
          <Button
            size="sm"
            variant="secondary"
            iconLeft={RefreshCw}
            loading={rescan.phase === "running"}
            onClick={() => void runRescan()}
            title="Read this project's git history now (the same scan the daemon runs every 2 minutes)"
          >
            Rescan now
          </Button>
        )}
      </div>

      {scan && (scan.last_scan_at || scan.last_success_at || scan.scan_root) && (
        <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[10.5px] text-fg-3">
          {scan.last_scan_at && (
            <span title={fmtDateTime(scan.last_scan_at)}>Last attempt {fmtRelative(scan.last_scan_at)}</span>
          )}
          <span title={scan.last_success_at ? fmtDateTime(scan.last_success_at) : undefined}>
            Last good scan {scan.last_success_at ? fmtRelative(scan.last_success_at) : "never"}
          </span>
          {state === "error" && scan.failures > 1 && <span>{scan.failures} failed attempts in a row; retrying with a growing delay</span>}
          {scan.scan_root && (
            <span>
              Scanned at <code className="font-mono text-fg-2">{scan.scan_root}</code>
            </span>
          )}
        </div>
      )}

      {rescan.phase === "done" && (
        <p className={clsx("mt-1.5 text-[11px]", rescan.ok ? "text-fg-2" : "text-danger")} aria-live="polite">
          {rescan.message}
        </p>
      )}

      {scan?.detail && (
        <InfoDisclosure summary="What git said" className="mt-1.5">
          <pre className="whitespace-pre-wrap break-all font-mono text-[10.5px] text-fg-2">{scan.detail}</pre>
        </InfoDisclosure>
      )}
    </div>
  );
}
