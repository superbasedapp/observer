// HeldLaunches: launches an agent asked for, which the daemon holds for a
// human (lane cli-2 fixes-1; the operator's decision is "ask on each
// launch"). Each hold is single use and expires; Confirm starts exactly the
// held request (recorded as the agent's launch), Reject drops it. An agent
// may not confirm: the daemon refuses a confirm from a caller it traces to
// an agent session, and guard rule R-165 asks the agent's own hook to stop
// it first. Renders nothing while nothing is held.
import { useState } from "react";
import { Link } from "react-router-dom";
import { Button, ChartShell, Pill, Tooltip } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import { fmtRelative, fmtShortId } from "@/lib/format";

// HeldLaunchDetail is one field the held request is bound to (lane cli-2
// fixes-2): the card shows every one, so what a confirm starts is visible
// whole; warn marks one to look at twice (unsandboxed, a sign-in copied
// into the box, a forwarded environment, a clone remote).
export type HeldLaunchDetail = { label: string; value: string; warn?: boolean };

export type HeldLaunch = {
  id: string;
  front: string;
  what: string;
  tool?: string;
  project?: string;
  sandbox?: string;
  details?: HeldLaunchDetail[];
  initiator: string;
  parent_session_id?: string;
  created_at: string;
  expires_at: string;
};

export function HeldLaunches({ onStarted }: { onStarted?: () => void }) {
  const pending = useApi<{ pending: HeldLaunch[]; enabled: boolean }>("/api/terminal/pending", undefined, [], {
    refreshMs: 5_000,
  });
  const [busy, setBusy] = useState("");
  const [note, setNote] = useState("");
  const held = pending.data?.pending ?? [];
  if (held.length === 0) return null;

  async function act(id: string, verb: "confirm" | "reject") {
    setBusy(id);
    setNote("");
    try {
      await fetchJSON(`/api/terminal/pending/${encodeURIComponent(id)}/${verb}`, undefined, {
        method: "POST",
        headers: await localConfirmHeaders(),
        body: "{}",
      });
      setNote(verb === "confirm" ? "Started. It runs as the agent's launch." : "Dropped. Nothing was started.");
      onStarted?.();
    } catch (err) {
      setNote(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy("");
      pending.reload();
    }
  }

  return (
    <ChartShell
      title="Launches waiting for you"
      sub="An agent asked to start these. Nothing runs until you confirm; each waits 10 minutes and works once."
      className="mb-4"
    >
      <div className="space-y-2 p-2 text-[12px]">
        {held.map((h) => (
          <div key={h.id} className="flex flex-wrap items-center gap-2 border-t border-line-1 pt-2 first:border-t-0 first:pt-0">
            <Pill variant="warn">agent</Pill>
            <span className="text-fg-1">{h.what}</span>
            {h.project ? <span className="font-mono text-fg-3">{h.project}</span> : null}
            {h.parent_session_id ? (
              <Tooltip content={`Asked for by session ${h.parent_session_id}`}>
                <Link
                  to={`/sessions?session=${encodeURIComponent(h.parent_session_id)}`}
                  className="font-mono text-accent underline decoration-dotted decoration-accent/50 underline-offset-[3px]"
                >
                  {fmtShortId(h.parent_session_id, 8)}
                </Link>
              </Tooltip>
            ) : null}
            <span className="text-fg-3">expires {fmtRelative(h.expires_at)}</span>
            {h.details && h.details.length > 0 ? (
              <dl className="basis-full grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 pl-1 text-[11px]">
                {h.details.map((d, i) => (
                  <HeldDetailRow key={`${h.id}-${i}`} d={d} />
                ))}
              </dl>
            ) : null}
            <span className="ml-auto flex gap-2">
              <Button size="sm" variant="primary" disabled={busy !== ""} onClick={() => void act(h.id, "confirm")}>
                Confirm
              </Button>
              <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => void act(h.id, "reject")}>
                Reject
              </Button>
            </span>
          </div>
        ))}
        {note ? <div className="text-fg-3">{note}</div> : null}
      </div>
    </ChartShell>
  );
}

// HeldDetailRow is one bound field; a flagged one is highlighted.
function HeldDetailRow({ d }: { d: HeldLaunchDetail }) {
  return (
    <>
      <dt className="text-fg-3">{d.label}</dt>
      <dd className={d.warn ? "break-all font-medium text-warn" : "break-all font-mono text-fg-2"}>
        {d.warn ? <Pill variant="warn">check</Pill> : null} {d.value}
      </dd>
    </>
  );
}
