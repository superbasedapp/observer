import { useState } from "react";
import { SquareTerminal, Trash2 } from "lucide-react";
import { Button, ConfirmButton } from "@/components/primitives";
import { ApiErrorNotice } from "@/components/NeedsSettingNotice";
import { ApiError, apiReason, fetchJSON, localConfirmHeaders } from "@/lib/api";
import { errorNote, type ErrorNote } from "@/lib/needsSetting";
import { installRecordView, uninstallErrorMessage } from "@/lib/toolUninstall";
import type { ToolInstallRecord, ToolUninstallStarted } from "@/lib/types";

// DashboardInstallRecord renders ONE dashboard-install record ("Installed from
// this dashboard on <date>") with its Uninstall / Forget actions. It is shared
// by the New terminal dialog and Settings > Connected tools so both say the
// same thing about the same record (copy owner: lib/toolUninstall.ts).
//
// The request carries only the tool NAME and the record id the operator saw:
// the server derives the uninstall command from its own record of what it
// installed, so the confirm note here names exactly what the server will run.
// Both actions are Local + confirm-token gated like the install route; the
// token comes from localConfirmHeaders exactly as installTool's does (never
// /api/remote/config, a Remote dashboard route that is off on most machines).

type Props = {
  record: ToolInstallRecord;
  /** The uninstall terminal was spawned: open it in the dock. */
  onUninstallStarted: (r: ToolUninstallStarted) => void;
  /** The record changed (forgotten): re-fetch whatever shows it. */
  onChanged: () => void;
  /** Open a live install / uninstall terminal in the dock (T-034j). When
   *  absent, the waiting-for-input note still tells the operator where to
   *  look. */
  onOpenTerminal?: (handle: string) => void;
};

async function postAction<T>(path: string, rec: ToolInstallRecord): Promise<T> {
  return fetchJSON<T>(path, undefined, {
    method: "POST",
    headers: await localConfirmHeaders(),
    body: JSON.stringify({ tool: rec.tool, record_id: rec.id }),
  });
}

function errorCopy(e: unknown): ErrorNote {
  return errorNote(e, (x) => (x instanceof ApiError ? uninstallErrorMessage(x.status, apiReason(x)) : null));
}

const TONE_CLASS = {
  ok: "border-ok/40 bg-ok/10 text-fg-2",
  info: "border-fg-3/30 bg-overlay-1 text-fg-3",
  warn: "border-warn/40 bg-warn/10 text-warn",
} as const;

export function DashboardInstallRecord({ record, onUninstallStarted, onChanged, onOpenTerminal }: Props) {
  const [busy, setBusy] = useState<"" | "uninstall" | "forget">("");
  const [err, setErr] = useState<ErrorNote | null>(null);
  const v = installRecordView(record);

  async function uninstall() {
    setBusy("uninstall");
    setErr(null);
    try {
      const r = await postAction<ToolUninstallStarted>("/api/terminal/uninstall", record);
      onUninstallStarted(r);
    } catch (e) {
      setErr(errorCopy(e));
    } finally {
      setBusy("");
    }
  }

  async function forget() {
    setBusy("forget");
    setErr(null);
    try {
      await postAction<unknown>("/api/terminal/installs/forget", record);
      onChanged();
    } catch (e) {
      setErr(errorCopy(e));
    } finally {
      setBusy("");
    }
  }

  return (
    <div
      className={`rounded-2 border px-2 py-1.5 text-[11px] leading-relaxed ${TONE_CLASS[v.tone]}`}
      data-testid="dashboard-install-record"
    >
      <div className="font-medium text-fg-1">{v.headline}</div>
      {v.detail && <div className="mt-0.5 break-all text-fg-3">{v.detail}</div>}
      {v.note && <div className="mt-1 text-fg-3">{v.note}</div>}
      {v.guidance && <div className="mt-1 text-fg-3">{v.guidance}</div>}
      {v.waitingForInput && record.terminal_handle && onOpenTerminal && (
        <div className="mt-1.5">
          <Button
            variant="secondary"
            size="sm"
            iconLeft={SquareTerminal}
            onClick={() => onOpenTerminal(record.terminal_handle as string)}
            data-testid="dashboard-install-open-terminal"
          >
            Open the install terminal
          </Button>
        </div>
      )}
      {(v.showUninstall || v.showForget) && (
        <div className="mt-1.5 flex flex-wrap items-center gap-2">
          {v.showUninstall && (
            <ConfirmButton
              variant="danger-outline"
              armedVariant="danger"
              size="sm"
              iconLeft={Trash2}
              confirmLabel="Uninstall?"
              armedNote={v.confirmNote}
              timeoutMs={8000}
              loading={busy === "uninstall"}
              disabled={busy !== ""}
              onConfirm={uninstall}
              ariaLabel={`Uninstall ${record.tool}`}
            >
              Uninstall
            </ConfirmButton>
          )}
          {v.showForget && (
            <ConfirmButton
              variant="ghost"
              armedVariant="secondary"
              size="sm"
              confirmLabel="Forget?"
              armedNote="Drops this record from the dashboard. Nothing is removed from this machine."
              loading={busy === "forget"}
              disabled={busy !== ""}
              onConfirm={forget}
              ariaLabel={`Forget the dashboard install record for ${record.tool}`}
            >
              Forget
            </ConfirmButton>
          )}
        </div>
      )}
      <ApiErrorNotice note={err} className="mt-1.5" plainClassName="mt-1.5 text-danger" />
    </div>
  );
}
