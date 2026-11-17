import { useState } from "react";
import { IntelResultCard, type IntelResultLike } from "@shared/components/sessiondetail";
import { Button, Pill } from "@/components/primitives";
import { apiReason, fetchJSON } from "@/lib/api";
import { fmtDateTime } from "@/lib/format";
import { apiCache, useApi } from "@/lib/useApi";
import {
  ORG_INTEL_TRIGGER_LABELS,
  orgIntelCardMode,
  orgIntelEnrichButton,
  orgIntelLevelLabel,
  orgIntelPreviewPath,
  orgIntelSessionPath,
  orgIntelSubmissionState,
  type OrgIntelEnrichResult,
  type OrgIntelPreview,
  type OrgIntelSessionResponse,
} from "@/lib/orgIntel";
import type { OrgIntelResultRow } from "@/lib/types";
import { orgDisplayLabel } from "@/lib/orgName";

// OrgIntelCard is the ORG-PLANE Cloud Intelligence row on the session Overview
// tab (parity phase 3, design 3.2). It reads GET /api/intel/session/{id}: the
// session's plane, what the developer may do, the latest submission from this
// machine and the cached org result, rendered through the SHARED
// IntelResultCard so the node and org drawers show the same card.
//
//   - Preview builds the exact org-plane evidence on this machine
//     (GET /api/intel/preview, nothing is sent) and shows the bytes and both
//     digests, the same transparency the personal plane gives.
//   - Enrich queues and sends one submission (POST /api/intel/enrich, the same
//     function as `observer intel enrich`). On an individual-tenancy machine
//     it needs a preview of the current bytes and sends exactly those; a
//     managed machine sends directly (a notice, no veto).
//
// Quiet by design: a session that is not the organization's and has no org
// result renders nothing; a 404 (the organization hid this section) or a 501
// (an older daemon) renders nothing either.

function intelError(e: unknown): string {
  const raw = apiReason(e);
  try {
    const parsed = JSON.parse(raw) as { message?: string };
    if (parsed.message) return parsed.message;
  } catch {
    // not JSON: show the reason as is
  }
  return raw;
}

function toResult(r: OrgIntelResultRow): IntelResultLike {
  return {
    title: r.title,
    description: r.description,
    confidence: r.confidence,
    taxonomyTags: r.taxonomy_tags,
    suggestedTags: r.suggested_tags,
    limitations: r.limitations,
    workDone: r.work_done,
    plansImplemented: r.plans_implemented,
    issuesFound: r.issues_found,
    failures: r.failures,
    nextSteps: r.next_steps,
    schemaVersion: r.schema_version,
    generatedAt: r.fetched_at,
  };
}

export function OrgIntelCard({ sessionId }: { sessionId: string }) {
  const path = orgIntelSessionPath(sessionId);
  const intel = useApi<OrgIntelSessionResponse>(path, undefined, [sessionId]);
  const [preview, setPreview] = useState<OrgIntelPreview | null>(null);
  const [busy, setBusy] = useState<"preview" | "enrich" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<OrgIntelEnrichResult | null>(null);

  const v = intel.data?.session;
  if (!v) return null;
  const mode = orgIntelCardMode(v);
  if (mode === "hidden") return null;
  const result = v.enriched && v.result ? toResult(v.result) : null;
  if (mode === "result_only") {
    return result ? <IntelResultCard result={result} emptyMessage="No enrichment for this session." generatedAtLabel="fetched" /> : null;
  }

  const org = orgDisplayLabel(v.org_name);
  const button = orgIntelEnrichButton(v, preview?.upload_digest ?? "");

  async function runPreview() {
    setBusy("preview");
    setErr(null);
    setOutcome(null);
    try {
      setPreview(await fetchJSON<OrgIntelPreview>(orgIntelPreviewPath(sessionId)));
    } catch (e) {
      setErr(intelError(e));
    } finally {
      setBusy(null);
    }
  }

  async function runEnrich() {
    setBusy("enrich");
    setErr(null);
    try {
      const res = await fetchJSON<OrgIntelEnrichResult>("/api/intel/enrich", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Observer-Confirm": intel.data?.confirm_token ?? "" },
        body: JSON.stringify({ session_id: sessionId, upload_digest: preview?.upload_digest ?? "" }),
      });
      setOutcome(res);
      setPreview(null);
      apiCache.invalidate(path);
      intel.reload();
    } catch (e) {
      setErr(intelError(e));
      // A changed session: the preview on screen is stale, ask for a new one.
      setPreview(null);
    } finally {
      setBusy(null);
    }
  }

  const latest = v.latest;
  const latestState = latest ? orgIntelSubmissionState(latest.state) : null;

  return (
    <div className="flex flex-col gap-2">
      <section className="rounded-2 border border-line-2 bg-bg-1 p-3" aria-label="Team AI summaries">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <h4 className="text-body font-medium text-fg-1">Team AI summaries</h4>
            {latestState && <Pill variant={latestState.tone} case="none">{latestState.label}</Pill>}
          </div>
          {mode === "actions" && (v.actions.preview || button.show) && (
            <div className="flex flex-wrap items-center gap-2">
              {v.actions.preview && (
                <Button size="sm" onClick={() => void runPreview()} disabled={busy != null} loading={busy === "preview"}>
                  {preview ? "Preview again" : "Preview evidence"}
                </Button>
              )}
              {button.show && (
                <Button size="sm" variant="primary" onClick={() => void runEnrich()} disabled={!button.enabled || busy != null}
                  loading={busy === "enrich"} title={button.hint}>
                  {button.label}
                </Button>
              )}
            </div>
          )}
        </div>
        <p className="mt-1 text-caption text-fg-3">
          {mode === "unavailable"
            ? v.actions.reason_text
            : `Run by ${org} on its own server and model. ${v.class === "managed" ? "Your organization decides what is sent; you can preview it." : "Only what you preview and confirm is sent."}`}
        </p>
        {mode === "actions" && v.actions.reason_text && (
          <p className="mt-1 text-caption text-fg-3">{v.actions.reason_text}</p>
        )}
        {button.show && button.hint && <p className="mt-1 text-caption text-fg-4">{button.hint}</p>}
        {latest && (
          <p className="mt-1 text-[11px] text-fg-3">
            Last submission: {ORG_INTEL_TRIGGER_LABELS[latest.trigger] ?? latest.trigger}, {orgIntelLevelLabel(latest.evidence_level)},{" "}
            {fmtDateTime(latest.updated_at)}
            {latest.reason ? ` (${latest.reason})` : ""}
          </p>
        )}
        {outcome && <p className="mt-2 rounded-2 border border-line-2 px-2 py-1 text-[11.5px] text-fg-2">{outcome.message}</p>}
        {err && <p className="mt-2 rounded-2 border border-danger/30 px-2 py-1 text-[11.5px] text-danger">{err}</p>}
        {preview && (
          <div className="mt-2 rounded-2 border border-line-2">
            <div className="flex flex-wrap gap-x-4 gap-y-1 border-b border-line-2 p-2 text-[11px] text-fg-3">
              <span>Level: {orgIntelLevelLabel(preview.evidence_level)}</span>
              <span>{preview.size_bytes} bytes, {preview.actions} actions, {preview.excerpts} excerpts</span>
              <span className="break-all font-mono">upload {preview.upload_digest}</span>
            </div>
            <pre className="max-h-[20rem] overflow-auto whitespace-pre-wrap break-all p-2 font-mono text-[10.5px] text-fg-2">{preview.bytes}</pre>
            <p className="border-t border-line-2 p-2 text-[10.5px] text-fg-4">
              {preview.notice_only
                ? "This is exactly what this machine sends to your organization for this session."
                : "Confirming sends exactly these bytes to your organization. Nothing has been sent yet."}
            </p>
          </div>
        )}
      </section>
      {result && <IntelResultCard result={result} emptyMessage="No enrichment for this session." generatedAtLabel="fetched" />}
    </div>
  );
}
