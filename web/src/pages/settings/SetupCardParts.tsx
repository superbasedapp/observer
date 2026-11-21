import { useState } from "react";
import { Pill } from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { errorText, type SetupOutcome, type Tone } from "@/lib/setupExtras";

// Shared parts of the Settings setup cards (status line, start at login,
// browser capture; dashboard CLI parity, lane L2). Each card is a status GET
// that mints the confirm token, a PREVIEW (the same POST with dry_run) and an
// APPLY that only ever sends the body that was just previewed.

export const CODE = "rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1";
export const BTN =
  "rounded-2 border border-line-2 bg-bg-3 px-3 py-1 text-small font-medium text-fg-1 hover:bg-bg-4 disabled:opacity-50";
export const PRIMARY_BTN =
  "rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] font-medium text-accent hover:bg-accent/25 disabled:opacity-50";

/** The request a preview was made for; apply re-sends exactly this. */
export type SetupRequest = Record<string, unknown>;

export interface Previewed {
  label: string;
  request: SetupRequest;
  out: SetupOutcome;
}

/** The slice of useSetupFlow the button row needs. */
export interface SetupFlow {
  preview: Previewed | null;
  busy: boolean;
  err: string | null;
  doApply: () => Promise<void>;
  cancel: () => void;
}

interface StatusEnvelope<S> {
  confirm_token: string;
  status: S;
}

/**
 * useSetupFlow drives one setup route: status read, preview, apply. Apply is
 * offered only for the previewed request and only when the preview was not
 * refused.
 */
export function useSetupFlow<S>(path: string) {
  const res = useApi<StatusEnvelope<S>>(path);
  const token = res.data?.confirm_token ?? "";
  const [preview, setPreview] = useState<Previewed | null>(null);
  const [result, setResult] = useState<SetupOutcome | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function post(request: SetupRequest, dryRun: boolean): Promise<SetupOutcome> {
    return fetchJSON<SetupOutcome>(path, undefined, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Observer-Confirm": token },
      body: JSON.stringify({ ...request, dry_run: dryRun }),
    });
  }

  async function run(fn: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setErr(null);
    try {
      await fn();
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  const doPreview = (label: string, request: SetupRequest) =>
    run(async () => {
      const out = await post(request, true);
      setPreview({ label, request, out });
      setResult(null);
    });

  const doApply = () =>
    run(async () => {
      if (!preview || preview.out.refused) return;
      const out = await post(preview.request, false);
      setResult(out);
      setPreview(null);
      res.reload();
    });

  return {
    res,
    status: res.data?.status ?? null,
    preview,
    result,
    busy,
    err,
    doPreview,
    doApply,
    cancel: () => setPreview(null),
  };
}

/** SetupCardShell is the card chrome shared by the setup cards. */
export function SetupCardShell({
  title,
  badge,
  children,
}: {
  title: string;
  badge?: { text: string; tone: Tone };
  children: React.ReactNode;
}) {
  return (
    <section className="mt-6 space-y-3 rounded-3 border border-line-2 bg-bg-2 p-4">
      <header className="flex items-baseline justify-between gap-3">
        <h4 className="text-[13px] font-semibold text-fg-0">{title}</h4>
        {badge && <Pill variant={badge.tone}>{badge.text}</Pill>}
      </header>
      {children}
    </section>
  );
}

/** OutcomeView renders a preview or a result: the refusal, or the exact changes. */
export function OutcomeView({ out }: { out: SetupOutcome }) {
  return (
    <div className="space-y-2 rounded-2 border border-line-2 bg-bg-3/40 p-3 text-[11.5px]" role="status">
      <div className="font-semibold text-fg-1">
        {out.refused ? "Not applied" : out.dry_run ? "Preview - nothing written yet" : out.changed ? "Done" : "Nothing changed"}
      </div>
      {out.refused && out.reason && <p className="text-warn">{out.reason}</p>}
      {(out.lines ?? []).map((l, i) => (
        <p key={i} className="font-mono text-[11px] leading-relaxed text-fg-2">
          {l}
        </p>
      ))}
    </div>
  );
}

/**
 * PreviewActions is the button row under a card: one Preview button per
 * offered action, then Apply / Cancel for the previewed one.
 */
export function PreviewActions({
  buttons,
  flow,
  readOnly,
}: {
  buttons: { label: string; onClick: () => void }[];
  flow: SetupFlow;
  readOnly?: boolean;
}) {
  const { preview, busy, doApply, cancel, err } = flow;
  return (
    <div className="flex flex-wrap items-center gap-2">
      {!preview &&
        buttons.map((b) => (
          <button key={b.label} type="button" className={BTN} onClick={b.onClick} disabled={busy}>
            {busy ? "working..." : b.label}
          </button>
        ))}
      {preview && (
        <>
          <button
            type="button"
            className={PRIMARY_BTN}
            onClick={doApply}
            disabled={busy || preview.out.refused === true || readOnly === true}
            title={preview.out.refused ? "This change was refused; see the reason above." : undefined}
          >
            Confirm: {preview.label}
          </button>
          <button type="button" className={BTN} onClick={cancel} disabled={busy}>
            Cancel
          </button>
        </>
      )}
      {err && <span className="text-[11.5px] text-danger">{err}</span>}
      {readOnly && <span className="text-[11px] text-fg-3">Pinned by your organization.</span>}
    </div>
  );
}
