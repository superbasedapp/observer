import { ShieldAlert } from "lucide-react";
import { Button, Modal } from "@/components/primitives";
import type { LiveSandboxRun } from "@/lib/useDaemonRestart";

// LiveSandboxRunsDialog asks the owner what to do with live sandboxed runs
// before a daemon restart or a deferred update ends them (sandbox plan v2
// section 5.5, ledger SBX-UPD-1). Two answers, never a silent end: "End the
// N runs and ..." (each ends with a recorded reason; a tool with its own
// resume continues afterwards) or "... when they finish" (a pending
// restart or apply shown in the banner, cancellable there).

export type LiveRunsQuestionMode = "restart" | "update";

export type LiveSandboxRunsDialogViewProps = {
  runs: LiveSandboxRun[];
  mode: LiveRunsQuestionMode;
  busy?: boolean;
  error?: string | null;
  onEnd: () => void;
  onWhenFinished: () => void;
  onClose: () => void;
};

// ageLabel renders a run's age in whole minutes or hours.
export function ageLabel(seconds: number): string {
  if (seconds < 60) return "under a minute";
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  const rest = m % 60;
  return rest > 0 ? `${h} h ${rest} min` : `${h} h`;
}

// liveRunsCopy is the dialog's text for a mode and a run count.
export function liveRunsCopy(mode: LiveRunsQuestionMode, n: number) {
  const runs = n === 1 ? "1 sandboxed run" : `${n} sandboxed runs`;
  const endRuns = n === 1 ? "End the run" : `End the ${n} runs`;
  const finishes = n === 1 ? "when it finishes" : "when they finish";
  const title = n === 1 ? "A sandboxed run is live" : "Sandboxed runs are live";
  if (mode === "update") {
    return {
      title,
      body: `An update is waiting: applying it restarts the daemon, which ends ${runs}. Nothing ends until you choose.`,
      end: `${endRuns} and apply the update`,
      later: `Apply ${finishes}`,
    };
  }
  return {
    title,
    body: `Restarting the daemon ends ${runs}. Nothing ends until you choose.`,
    end: `${endRuns} and restart`,
    later: `Restart ${finishes}`,
  };
}

// LiveSandboxRunsDialogView is the pure view (render-tested).
export function LiveSandboxRunsDialogView({ runs, mode, busy, error, onEnd, onWhenFinished, onClose }: LiveSandboxRunsDialogViewProps) {
  const copy = liveRunsCopy(mode, runs.length);
  return (
    <Modal
      open
      onClose={onClose}
      dismissible={!busy}
      icon={ShieldAlert}
      title={copy.title}
      subtitle={copy.body}
      width={560}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy} data-testid="liveruns-cancel">
            Not now
          </Button>
          <Button variant="secondary" onClick={onWhenFinished} disabled={busy} data-testid="liveruns-later">
            {copy.later}
          </Button>
          <Button variant="danger" onClick={onEnd} disabled={busy} data-testid="liveruns-end">
            {copy.end}
          </Button>
        </>
      }
    >
      <ul className="space-y-1 text-[12px]" data-testid="liveruns-list">
        {runs.map((r) => (
          <li key={r.run_id} className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-mono text-fg-1">{r.tool}</span>
            <span className="text-fg-3">on</span>
            <span className="font-mono">{r.backend}</span>
            <span className="text-fg-3">running {ageLabel(r.age_seconds)}</span>
            {r.native_resume ? (
              <span className="text-fg-3">(continues with the tool's own resume afterwards)</span>
            ) : (
              <span className="text-fg-3">(no native resume: its conversation ends with it)</span>
            )}
          </li>
        ))}
      </ul>
      {error && <p className="mt-3 text-[12px] text-danger">{error}</p>}
    </Modal>
  );
}
