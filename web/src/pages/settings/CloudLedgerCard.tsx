import { cloudEvidenceSettingsSummary } from "@/lib/cloud";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Button, JsonPreview, Pill, Table } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import { apiReason } from "@/lib/api";
import { fmtShortId } from "@/lib/format";
import {
  cloudFmtWhen,
  cloudOutputTail,
  cloudPreviewByReceipt,
  cloudStateMeta,
  CLOUD_PURPOSE_LABELS,
} from "@/lib/cloud";
import type { CloudLedgerEntry, CloudLedgerResponse } from "@/lib/cloud";
import type { CloudPreviewResponse } from "@/lib/types";

const LEDGER_LIMIT = 200;

// CloudLedgerCard is the "What we sent" ledger (plan of record W2, CI-P5
// follow-on): every consent receipt this device holds, what was queued
// under it, and what came back — read from GET /api/cloud/ledger
// (store.ListCloudLedger), which is CONTENT-FREE by construction (it never
// selects payload bytes, titles, or excerpts). "Show exact bytes" rebuilds
// and previews the actual bytes on demand via POST /api/cloud/preview
// {receipt_id} — the same local-only, no-network preview the session card
// (CloudRow.tsx) runs for a fresh purpose choice.
//
// Anchored `id="cloud-ledger"` so the "Turn on Cloud Intelligence" card's
// "What leaves this machine" link can scroll straight to it.
export function CloudLedgerCard({ actionsAvailable }: { actionsAvailable: boolean }) {
  const ledger = useApi<CloudLedgerResponse>(
    "/api/cloud/ledger",
    { limit: LEDGER_LIMIT },
    [],
    { refreshMs: 20000 },
  );
  const entries = ledger.data?.entries ?? [];

  return (
    <div id="cloud-ledger" className="rounded-3 border border-line-2 bg-bg-2 p-4">
      <div className="text-[13px] font-semibold text-fg-1">What we sent</div>
      <p className="mt-1 max-w-[66ch] text-[11.5px] leading-relaxed text-fg-3">
        Every consent recorded on this device, what was queued under it, and what came back.
        Content-free - the exact bytes are rebuilt on demand.
      </p>

      <ChartState loading={ledger.loading && !ledger.data} error={ledger.error} empty={false} height={80}>
        {entries.length === 0 ? (
          <p className="mt-3 text-[11.5px] text-fg-3">Nothing has been sent from this device yet.</p>
        ) : (
          <div className="mt-3">
            <Table
              minWidth={720}
              head={
                <tr className="border-b border-line-2">
                  <th className="py-1.5 pl-1 font-medium">When</th>
                  <th className="py-1.5 font-medium">Consent</th>
                  <th className="py-1.5 font-medium">Session</th>
                  <th className="py-1.5 font-medium">State</th>
                  <th className="py-1.5 font-medium">Result</th>
                  <th className="py-1.5 pr-1 font-medium">Action</th>
                </tr>
              }
            >
              {entries.map((entry) => (
                <LedgerRow key={entry.receipt.id} entry={entry} actionsAvailable={actionsAvailable} />
              ))}
            </Table>
          </div>
        )}
      </ChartState>
    </div>
  );
}

// LedgerRow renders one receipt row plus its own collapsible "exact bytes"
// preview (a second <tr> toggled open, so it can span every column).
function LedgerRow({
  entry,
  actionsAvailable,
}: {
  entry: CloudLedgerEntry;
  actionsAvailable: boolean;
}) {
  const { receipt, items, result } = entry;
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [preview, setPreview] = useState<CloudPreviewResponse | null>(null);

  // "the receipt has items" — the session pointer is whichever outbox item
  // was queued under it, regardless of kind.
  const sessionItem = items[0];
  // Standing grants have no single upload to preview; their daily snapshots
  // are what the ledger's own rows already list.
  const canShowBytes = receipt.grant_mode !== "standing";

  async function showBytes() {
    if (preview) {
      setPreviewOpen((v) => !v);
      return;
    }
    setPreviewBusy(true);
    setPreviewError(null);
    try {
      const data = await cloudPreviewByReceipt(receipt.id);
      setPreview(data);
      setPreviewOpen(true);
      if (!data.ok) {
        setPreviewError(data.exit_error || cloudOutputTail(data.output) || "Preview failed.");
      }
    } catch (e) {
      setPreviewError(apiReason(e));
    } finally {
      setPreviewBusy(false);
    }
  }

  return (
    <>
      <tr className="border-b border-line-1 last:border-b-0 align-top">
        <td className="py-2 pl-1 font-mono text-[10.5px] text-fg-2">
          {cloudFmtWhen(receipt.created_at)}
        </td>
        <td className="py-2 text-fg-1">
          <div className="flex flex-wrap items-center gap-1">
            <span>{CLOUD_PURPOSE_LABELS[receipt.purpose] ?? receipt.purpose}</span>
            <Pill variant="neutral">
              {receipt.grant_mode === "standing" ? "standing" : "per session"}
            </Pill>
            {!receipt.live && <Pill variant="warn">revoked</Pill>}
          </div>
        </td>
        <td className="py-2 font-mono text-[10.5px] text-fg-2">
          {sessionItem ? (
            <Link
              to={`/sessions?session=${encodeURIComponent(sessionItem.session_id)}`}
              className="text-accent hover:text-accent-strong"
              title={sessionItem.session_id}
            >
              {fmtShortId(sessionItem.session_id)}
            </Link>
          ) : (
            "-"
          )}
        </td>
        <td className="py-2">
          <div className="flex flex-wrap items-center gap-1">
            {items.length === 0 ? (
              <span className="text-fg-4">-</span>
            ) : (
              items.map((it) => {
                const meta = cloudStateMeta(it.state);
                return (
                  <span key={it.id} title={meta.meaning}>
                    <Pill variant={meta.variant}>{meta.label}</Pill>
                  </span>
                );
              })
            )}
          </div>
        </td>
        <td className="py-2 text-fg-2">
          {result ? `received ${cloudFmtWhen(result.received_at)}, ${result.tokens} tokens` : "-"}
        </td>
        <td className="py-2 pr-1">
          {canShowBytes ? (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => void showBytes()}
              disabled={previewBusy || !actionsAvailable}
              title={
                !actionsAvailable
                  ? "Available when the dashboard runs under `observer start`"
                  : undefined
              }
            >
              {previewBusy ? "Loading…" : previewOpen && preview ? "Hide" : "Show exact bytes"}
            </Button>
          ) : (
            <span className="text-[10.5px] text-fg-4">-</span>
          )}
        </td>
      </tr>
      {previewOpen && preview && (
        <tr className="border-b border-line-1 last:border-b-0">
          <td colSpan={6} className="py-2 pl-1">
            {receipt.evidence_settings_json && <p className="mb-2 break-words text-[11px] text-fg-3">Saved evidence limits: {cloudEvidenceSettingsSummary(receipt.evidence_settings_json)}</p>}
            <JsonPreview value={preview.output || "(no output)"} maxHeight={320} />
            {preview.truncated && (
              <div className="mt-1 text-[10px] text-fg-4">
                Output truncated - showing the first part.
              </div>
            )}
          </td>
        </tr>
      )}
      {previewError && (
        <tr className="border-b border-line-1 last:border-b-0">
          <td colSpan={6} className="pb-2 pl-1">
            <div className="rounded-2 border border-danger/30 bg-danger-soft px-2 py-1.5 text-[10.5px] text-danger">
              {previewError}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
