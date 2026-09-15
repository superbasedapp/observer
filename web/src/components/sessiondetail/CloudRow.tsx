import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Pill, SegmentedControl, Tooltip } from "@/components/primitives";
import { CopyOnClick } from "@/components/CopyOnClick";
import { useApi } from "@/lib/useApi";
import { fmtDateTime, fmtRelative, fmtShortId } from "@/lib/format";
import { fetchJSON, apiReason } from "@/lib/api";
import { cloudProgressMeta } from "@/lib/cloudProgress";
import {
  cloudAuthorityMeta, cloudOutputTail, cloudProviderNotAccepting,
  cloudPurposeForLevel, cloudStateMeta, CLOUD_ENRICH_LEVEL_LABELS,
  CLOUD_PURPOSE_LABELS, runCloudSync,
} from "@/lib/cloud";
import type { CloudStatusWithPolicy } from "@/lib/cloud";
import type { CloudConsentResponse, CloudPreviewResponse, CloudPurpose, CloudSessionResponse } from "@/lib/types";

const CLOUD_ID_TOOLTIP = "This is the pseudonym the cloud service knows this session by. Your local session id never leaves this machine.";
const BUTTON = "rounded-2 border border-line-2 bg-bg-1 px-2.5 py-1.5 text-[11px] font-medium text-fg-2 hover:bg-bg-3 disabled:cursor-not-allowed disabled:opacity-50";
const PRIMARY = `${BUTTON} border-accent/60 bg-accent text-white hover:bg-accent/90 disabled:border-line-2 disabled:bg-bg-1 disabled:text-fg-3`;

type Submit = (purpose: CloudPurpose, digest?: string) => Promise<void>;

// One operation owner covers quick consent, preview/confirm and retry. Durable
// node progress survives closing/reopening the panel and is shared with the list.
export function CloudRow({ sessionId, onChanged }: { sessionId: string; onChanged?: () => void }) {
  const cloud = useApi<CloudSessionResponse>(`/api/cloud/session/${encodeURIComponent(sessionId)}`, undefined, [sessionId], { refreshMs: 5000, retainErrorOnRefresh: true });
  const [reenrich, setReenrich] = useState(false);
  const [operation, setOperation] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [submittedAgainst, setSubmittedAgainst] = useState<CloudSessionResponse | null>(null);
  const [previewVersion, setPreviewVersion] = useState(0);
  const operationLock = useRef(false);
  const d = cloud.data;
  const progress = d?.progress;
  // Bridge the response/poll gap without interpreting the last result as the
  // result of the new submission. Unchanged useApi data retains its identity.
  const awaitingStatus = !!submittedAgainst && (d === submittedAgainst || !progress || ["idle", "unknown"].includes(progress.state));
  useEffect(() => {
    if (submittedAgainst && !awaitingStatus) setSubmittedAgainst(null);
  }, [submittedAgainst, awaitingStatus]);
  const meta = cloudProgressMeta(awaitingStatus ? { state: "pending" } : progress);
  const blocked = !!operation || awaitingStatus || meta.blocksEnrichment || !!cloud.error;
  const refresh = () => { cloud.reload(); onChanged?.(); };

  async function sync() {
    const st = await runCloudSync(sessionId);
    refresh();
    if (!st.ok) throw new Error(st.exit_error || cloudOutputTail(st.tail || "") || "Sync failed. Your saved request can be retried.");
    if (cloudProviderNotAccepting(st.tail || "")) setNotice("The enrichment provider is temporarily unavailable. Your request is saved; a later sync will try again.");
  }

  async function submit(purpose: CloudPurpose, digest?: string) {
    if (operationLock.current || blocked || !d) return;
    operationLock.current = true;
    setOperation("Saving enrichment request"); setError(null); setNotice(null);
    try {
      const res = await fetchJSON<CloudConsentResponse>("/api/cloud/consent", undefined, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: sessionId, purpose, ...(digest ? { expected_upload_digest: digest } : {}) }),
      });
      if (!res.ok) throw new Error(res.exit_error || cloudOutputTail(res.output) || "The request could not be saved. Please try again.");
      setSubmittedAgainst(d); setReenrich(false); setPreviewVersion((v) => v + 1);
      refresh(); setOperation("Uploading session");
      await sync();
    } catch (e) {
      setError(apiReason(e)); refresh();
    } finally {
      operationLock.current = false; setOperation(null);
    }
  }

  async function retryOrCheck() {
    if (operationLock.current) return;
    operationLock.current = true;
    setOperation(progress?.state === "sent" ? "Checking for result" : "Syncing saved request");
    setError(null); setNotice(null);
    try { await sync(); } catch (e) { setError(apiReason(e)); refresh(); }
    finally { operationLock.current = false; setOperation(null); }
  }

  if (!d) return <div className="space-y-2 p-4 text-[12px] text-fg-3" role="status">
    <p>{cloud.error ? "Could not load enrichment status." : "Loading enrichment status…"}</p>
    {cloud.error && <button type="button" className={BUTTON} onClick={refresh}>Retry status</button>}
  </div>;
  const auth = cloudAuthorityMeta(d.authority);
  const state = awaitingStatus ? "pending" : progress?.state;
  const showForm = !blocked && (!d.result || reenrich || state === "reconfirmation_required" || state === "failed_terminal" || state === "cancelled");
  const stage = state === "complete" ? 2 : state === "sent" ? 1 : 0;

  return <section className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3" aria-label="Session enrichment progress">
    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
      <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">Cloud Intelligence</span>
      <Pill variant={auth.variant}>{auth.label}</Pill>
    </div>
    {d.excluded ? <p className="text-[11.5px] text-fg-3">Excluded from personal cloud enrichment: {d.excluded_reason || "organization-owned or unknown data authority."}</p> : <div className="space-y-3">
      <div role="status" aria-live="polite" aria-atomic="true" className="space-y-2">
        <p className="text-[13px] font-semibold text-fg-1">{operation || meta.label}</p>
        <p className="text-[11.5px] leading-relaxed text-fg-3">{operation ? "This request is in progress. You do not need to click Enrich again." : meta.message}</p>
        {["pending", "sending", "sent", "complete"].includes(state || "") && <ol aria-label="Enrichment stages" className="grid grid-cols-3 gap-2 text-[10.5px]">
          {["Queued", "Uploaded", "Result ready"].map((label, i) => <li key={label} aria-current={i === stage ? "step" : undefined} className={`border-t-2 pt-1.5 ${i <= stage ? "border-accent text-fg-1" : "border-line-2 text-fg-4"}`}>{label}</li>)}
        </ol>}
      </div>
      {progress?.updated_at && <p className="text-[10px] text-fg-4" title={fmtDateTime(progress.updated_at)}>Updated {fmtRelative(progress.updated_at)}</p>}
      {blocked && <div className="flex flex-wrap items-center gap-2">
        <button type="button" disabled className={PRIMARY}>{operation || meta.label}</button>
        {!operation && !awaitingStatus && meta.syncLabel && <button type="button" onClick={() => void retryOrCheck()} className={BUTTON}>{meta.syncLabel}</button>}
        {!operation && (cloud.error || state === "unknown" || !state) && <button type="button" onClick={refresh} className={BUTTON}>Refresh status</button>}
      </div>}
      {cloud.error && <p role="alert" className="text-[11px] text-warn">Status could not be refreshed. The last known state is shown; check status before submitting again.</p>}
      {error && <p role="alert" className="rounded-2 border border-danger/30 bg-danger-soft p-2 text-[11px] text-danger">{error}</p>}
      {notice && state !== "complete" && <p className="text-[11px] text-fg-3">{notice}</p>}
      {d.result && <div className="space-y-2">
        {state !== "complete" && <p className="text-[11px] font-medium text-fg-3">Previous enrichment — the new request is shown above.</p>}
        <CloudResultBlock result={d.result} />
      </div>}
      {d.result && !blocked && state === "complete" && <button type="button" onClick={() => setReenrich((v) => !v)} className={BUTTON}>{reenrich ? "Cancel re-enrichment" : "Re-enrich this session"}</button>}
      {/* Keep preview controls mounted while consent/sync runs; hide the form
          once submitted so its enabled state can never imply another request. */}
      <div hidden={!showForm}>
        <CloudEnrichControls sessionId={sessionId} submit={submit} disabled={blocked} forcePreview={state === "reconfirmation_required"} previewVersion={previewVersion} />
      </div>
      <p className="text-[10px] text-fg-4">Status refreshes automatically while this panel is open. Uploads and result retrieval use cloud sync.</p>
      {d.outbox.length > 0 && <details className="border-t border-line-2 pt-2">
        <summary className="w-fit cursor-pointer text-[11px] text-fg-3">Request history</summary>
        <div className="mt-2 space-y-2">
          {d.outbox.map((o) => { const m = cloudStateMeta(o.state); return <div key={o.id} className="flex flex-wrap items-center gap-2"><Tooltip content={m.meaning}><span tabIndex={0}><Pill variant={m.variant}>{m.label}</Pill></span></Tooltip><span className="text-[10px] text-fg-4">{o.updated_at ? fmtDateTime(o.updated_at) : ""}</span></div>; })}
          {d.cloud_session_id && <CopyOnClick value={d.cloud_session_id} title={CLOUD_ID_TOOLTIP} className="text-[10px] text-fg-3">{fmtShortId(d.cloud_session_id)}</CopyOnClick>}
        </div>
      </details>}
    </div>}
  </section>;
}

function CloudEnrichControls({ sessionId, submit, disabled, forcePreview, previewVersion }: { sessionId: string; submit: Submit; disabled: boolean; forcePreview: boolean; previewVersion: number }) {
  const status = useApi<CloudStatusWithPolicy>("/api/cloud/status", undefined, [], { refreshMs: 15000 });
  const signedIn = !!status.data?.sign_in?.signed_in;
  const policy = status.data?.policy;
  const quick = !!policy && policy.level !== "off" && signedIn && !forcePreview;
  return <fieldset disabled={disabled} className="space-y-2">
    {quick ? <>
      <button type="button" onClick={() => void submit(cloudPurposeForLevel(policy.level) ?? "structural_activity_insights")} className={PRIMARY}>Enrich now</button>
      <p className="text-[10.5px] text-fg-4">Uses your setting: {CLOUD_ENRICH_LEVEL_LABELS[policy.level] ?? policy.level}. <Link to="/settings?section=cloud" className="text-accent">Change enrichment settings</Link></p>
      <details className="rounded-2 border border-line-2 p-2"><summary className="cursor-pointer text-[11px] text-fg-3">Preview or change data for this request</summary><ManualEnrichPanel sessionId={sessionId} submit={submit} signedIn={signedIn} previewVersion={previewVersion} /></details>
    </> : <ManualEnrichPanel sessionId={sessionId} submit={submit} signedIn={signedIn} previewVersion={previewVersion} />}
  </fieldset>;
}

function ManualEnrichPanel({ sessionId, submit, signedIn, previewVersion }: { sessionId: string; submit: Submit; signedIn: boolean; previewVersion: number }) {
  const [purpose, setPurpose] = useState<CloudPurpose>("structural_activity_insights");
  const [preview, setPreview] = useState<{ purpose: CloudPurpose; data: CloudPreviewResponse } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { setPreview(null); setError(null); }, [previewVersion]);
  async function runPreview() {
    setBusy(true); setError(null);
    try {
      const data = await fetchJSON<CloudPreviewResponse>("/api/cloud/preview", undefined, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ session_id: sessionId, purpose }) });
      setPreview({ purpose, data });
      if (!data.ok) setError(data.exit_error || cloudOutputTail(data.output) || "Preview failed.");
    } catch (e) { setError(apiReason(e)); }
    finally { setBusy(false); }
  }
  const shown = preview?.purpose === purpose;
  const ready = shown && preview?.data.ok && !preview.data.truncated && !!preview.data.upload_digest;
  return <div className="space-y-2 pt-1">
    <SegmentedControl<CloudPurpose> size="sm" value={purpose} onChange={(next) => { setPurpose(next); setPreview(null); setError(null); }} options={[
      { value: "structural_activity_insights", label: "Title only", disabled: busy },
      { value: "bounded_context_enrichment", label: "Title, tags and description", disabled: busy },
    ]} />
    <p className="text-[10.5px] text-fg-4">{purpose === "structural_activity_insights" ? "Sends a structural signal and your first prompt. No other content." : "Additionally sends bounded, post-scrub excerpts."}</p>
    <div className="flex flex-wrap items-center gap-2">
      <button type="button" onClick={() => void runPreview()} disabled={busy} className={BUTTON}>{busy ? "Previewing…" : "Preview session"}</button>
      <button type="button" onClick={() => void submit(purpose, preview?.data.upload_digest)} disabled={!signedIn || !ready || busy} title={!signedIn ? "Sign in to submit this request" : !ready ? "Preview the session before confirming" : undefined} className={PRIMARY}>Confirm and enrich</button>
    </div>
    {!signedIn && <Link to="/settings?section=cloud" className="text-[11px] text-accent">Sign in under Settings → Cloud Intelligence</Link>}
    {shown && <details open className="rounded-2 border border-line-2 bg-bg-1">
      <summary className="cursor-pointer px-2 py-1 text-[11px] text-fg-3">Exactly what would leave this machine</summary>
      <pre className="max-h-[20rem] overflow-auto whitespace-pre-wrap break-all border-t border-line-2 p-2 font-mono text-[10.5px] text-fg-2">{preview?.data.output || "(no output)"}</pre>
      {preview?.data.truncated && <p className="p-2 text-[11px] text-warn">Preview was truncated. Generate a complete preview before confirming.</p>}
    </details>}
    {ready && <p className="text-[10.5px] text-fg-4">Confirming uploads exactly the previewed data ({CLOUD_PURPOSE_LABELS[purpose] ?? purpose}). The consent receipt is available in Settings → Cloud Intelligence.</p>}
    {error && <p role="alert" className="text-[11px] text-danger">{error}</p>}
  </div>;
}

function CloudResultBlock({
  result,
}: {
  result: NonNullable<CloudSessionResponse["result"]>;
}) {
  const titleOverride = result.overrides?.title?.user_value;
  const aiTitle = result.result.title ?? "";
  const aiTags = [
    ...(result.result.taxonomy_tags ?? []),
    ...(result.result.suggested_tags ?? []),
  ];

  return (
    <div className="rounded-2 border border-line-1 bg-bg-3/40 px-3 py-2 text-[11.5px]">
      <div className="mb-1 flex items-center gap-1.5">
        <Pill variant="accent">AI</Pill>
        <span className="text-[10px] uppercase tracking-[0.05em] text-fg-3">
          suggested{result.model_route ? ` · ${result.model_route}` : ""}
        </span>
      </div>

      {/* Title — the user override wins visually; the AI suggestion is shown
          secondary so the source is still legible. */}
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
        {titleOverride ? (
          <>
            <span className="font-medium text-fg-1">{titleOverride}</span>
            <Pill variant="success">your edit</Pill>
            {aiTitle && (
              <span className="text-[10.5px] text-fg-4 line-through">
                AI: {aiTitle}
              </span>
            )}
          </>
        ) : (
          <span className="font-medium text-fg-1">{aiTitle || "(no title)"}</span>
        )}
      </div>

      {aiTags.length > 0 && (
        <div className="mt-1.5 flex flex-wrap items-center gap-1">
          {aiTags.slice(0, 12).map((t, i) => (
            <span
              key={`${t}-${i}`}
              className="rounded-pill border border-line-2 bg-bg-2 px-1.5 py-px text-[10px] text-fg-2"
            >
              {t}
            </span>
          ))}
        </div>
      )}

      <p className="mt-2 text-[10px] leading-snug text-fg-4">
        Edit the title and tags via the session controls - cloud suggestions
        never overwrite your edits.
      </p>
    </div>
  );
}
