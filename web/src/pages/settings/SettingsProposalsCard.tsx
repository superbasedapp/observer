import { useState } from "react";
import { ShieldQuestion } from "lucide-react";
import { Card, confirmDialog } from "@/components/primitives";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import { putConfigKeys } from "@/lib/configKeysPut";
import { useApi } from "@/lib/useApi";
import {
  categoryLabel,
  pendingProposals,
  requesterLabel,
  type SettingsProposal,
  type SettingsProposalsResponse,
} from "@/lib/sdkDestination";
import type { ConfigResponse } from "@/lib/types";

// SettingsProposalsCard - Settings "Changes waiting for you" (Plane A
// build-out lane B6, W2-8 ruling D19). An AI agent changes an ordinary
// setting through MCP set_setting directly, but a security-sensitive one
// (the guard, what is captured or shared, where data or requests go,
// admission, budgets, an online SDK destination) only files a proposal that
// waits here. Approve writes the value through the normal checked save (PUT
// /api/config/keys: governance, the confirm token, validation), then marks
// the proposal approved; the server marks it only once the value is in
// force. Reject writes nothing. The CLI twin is `observer config proposals`.
// The card renders nothing when no change is waiting.

const LIST = "/api/config/proposals";
const BTN =
  "rounded-2 border border-line-2 bg-bg-3 px-3 py-1 text-small font-medium text-fg-1 hover:bg-bg-4 disabled:opacity-50";
const CODE = "rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1";

async function resolve(id: number, decision: "approved" | "rejected"): Promise<void> {
  const r = await fetch(`${LIST}/${id}/resolve`, {
    method: "POST",
    headers: await localConfirmHeaders(),
    body: JSON.stringify({ decision }),
  });
  if (!r.ok) {
    const body = (await r.json().catch(() => ({}))) as { message?: string };
    throw new Error(body.message || `HTTP ${r.status}`);
  }
}

export function SettingsProposalsCard({ readOnly = false, onSaved }: { readOnly?: boolean; onSaved: () => void }) {
  const res = useApi<SettingsProposalsResponse>(LIST);
  const rows = pendingProposals(res.data?.proposals);
  const [busy, setBusy] = useState<number | null>(null);
  const [err, setErr] = useState<string | null>(null);
  if (rows.length === 0) return null;

  const approve = async (p: SettingsProposal) => {
    const ok = await confirmDialog({
      title: `Set ${p.key} = ${p.value || '""'}?`,
      body: p.reason ? `An AI agent asked for this. It ${p.reason}.` : "An AI agent asked for this.",
      confirmLabel: "Approve and save",
    });
    if (!ok) return;
    setBusy(p.id);
    setErr(null);
    try {
      const base = await fetchJSON<ConfigResponse>("/api/config");
      await putConfigKeys(base, [{ key: p.key, value: p.value }], false);
      await resolve(p.id, "approved");
      onSaved();
      res.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Approve failed");
    } finally {
      setBusy(null);
    }
  };

  const reject = async (p: SettingsProposal) => {
    setBusy(p.id);
    setErr(null);
    try {
      await resolve(p.id, "rejected");
      res.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Reject failed");
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card id="settings-proposals" className="mb-4" title="Changes waiting for you" icon={ShieldQuestion}>
      <p className="text-[12px] text-fg-3">
        An AI agent asked to change these settings. They are not applied until you approve them.
      </p>
      <ul className="mt-3 space-y-3">
        {rows.map((p) => (
          <li key={p.id} className="rounded-2 border border-line-2 bg-bg-2 p-3">
            <div className="text-[12px] text-fg-1">
              <span className={CODE}>{p.key}</span> = <span className={CODE}>{p.value || '""'}</span>
              {p.prev_value !== "" && (
                <span className="text-fg-3">
                  {" "}
                  (now <span className={CODE}>{p.prev_value}</span>)
                </span>
              )}
            </div>
            <div className="mt-1 text-[11px] text-fg-3">
              {categoryLabel(p.category)}: {p.reason}. Asked by {requesterLabel(p.requested_by)}
              {p.note ? `: "${p.note}"` : ""}.
            </div>
            <div className="mt-2 flex gap-2">
              <button type="button" className={BTN} disabled={readOnly || busy !== null} onClick={() => void approve(p)}>
                Approve
              </button>
              <button type="button" className={BTN} disabled={readOnly || busy !== null} onClick={() => void reject(p)}>
                Reject
              </button>
            </div>
          </li>
        ))}
      </ul>
      {err && (
        <p role="alert" className="mt-2 text-[12px] text-danger">
          {err}
        </p>
      )}
    </Card>
  );
}
