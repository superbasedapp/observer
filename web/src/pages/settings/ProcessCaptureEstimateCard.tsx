import { useEffect, useMemo, useState } from "react";
import { Card, InlineLoading, Meter, Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { fmtBytes, fmtInt } from "@/lib/format";
import {
  captureDraft,
  captureDraftQuery,
  estimateModel,
  fmtRowsPerDay,
  parseEstimate,
  type DeltaPill,
  type EstimateModel,
  type SettingImpact,
} from "@/lib/processCapture";
import type { ProcessCaptureEstimate } from "@/lib/types";

// ProcessCaptureEstimateCard - the data-volume indicator beside the process
// capture limits (process capture budget plan section 8 ruling 0 and 9.3). It
// asks GET /api/process/capture/estimate what the values being EDITED (the
// unsaved Settings draft, debounced) would store per day, replayed over the
// node's own recent capture, and shows current against projected rows and
// storage, the rollup and org push rows, and each setting's own effect with
// the biggest contributor first.
//
// Honest states: loading; "not enough history yet" when the node has no stored
// runs to replay; and a daemon without the endpoint (404, or a config with no
// capture keys) says it needs a newer daemon instead of showing an error.

/** DEBOUNCE_MS is how long the draft must sit still before the estimate is asked for. */
export const ESTIMATE_DEBOUNCE_MS = 400;

export type EstimateCardState =
  | { kind: "loading" }
  | { kind: "unavailable" }
  | { kind: "error"; message: string }
  | { kind: "ready"; estimate: ProcessCaptureEstimate; stale?: boolean };

const TITLE = "Data volume";

function PillFor({ pill }: { pill: DeltaPill }) {
  return <Pill variant={pill.tone}>{pill.text}</Pill>;
}

function Tile({ label, value, pill, hint }: { label: string; value: string; pill?: DeltaPill; hint?: string }) {
  return (
    <div className="rounded-2 border border-line-2 bg-bg-3/40 p-2.5">
      <div className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">{label}</div>
      <div className="mt-1 flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <span className="font-mono text-[13px] tabular-nums text-fg-0">{value}</span>
        {pill && <PillFor pill={pill} />}
      </div>
      {hint && <div className="mt-0.5 text-[10.5px] leading-snug text-fg-3">{hint}</div>}
    </div>
  );
}

function SettingRow({ s }: { s: SettingImpact }) {
  return (
    <li className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 sm:grid-cols-[minmax(0,14rem)_minmax(0,1fr)_auto_auto]">
      <span className="truncate text-[11.5px] text-fg-1" title={s.key}>
        {s.label}
      </span>
      <span className="col-span-2 order-last sm:order-none sm:col-span-1">
        <Meter ratio={s.barPct / 100} tone={s.pill.tone === "neutral" ? "info" : s.pill.tone} label={`${s.label}: ${fmtRowsPerDay(s.rowsPerDay)}`} />
      </span>
      <span className="text-right font-mono text-[11px] tabular-nums text-fg-2">{fmtRowsPerDay(s.rowsPerDay)}</span>
      <span className="justify-self-end">
        <PillFor pill={s.pill} />
      </span>
    </li>
  );
}

/** SETTINGS_SHOWN is how many per-setting rows show before "Show all". */
const SETTINGS_SHOWN = 6;

function Ready({ model }: { model: EstimateModel }) {
  const [all, setAll] = useState(false);
  const shown = all ? model.settings : model.settings.slice(0, SETTINGS_SHOWN);
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <Tile
          label="Rows / day"
          value={`${fmtInt(model.rows.current)} → ${fmtInt(model.rows.projected)}`}
          pill={model.rows.pill}
          hint="stored now → with these values"
        />
        <Tile
          label="Storage / day"
          value={`${fmtBytes(model.bytes.current)} → ${fmtBytes(model.bytes.projected)}`}
          pill={model.bytes.pill}
          hint="per day"
        />
        <Tile label="Rollup rows / day" value={fmtInt(model.rollupRowsPerDay)} hint="counted, not kept" />
        <Tile label="Org push rows / day" value={fmtInt(model.orgRowsPerDay)} hint="sent when this node shares" />
      </div>
      {model.settings.length > 0 && (
        <div>
          <div className="mb-1.5 flex flex-wrap items-baseline justify-between gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
              Each setting on its own · rows / day
            </span>
            <span className="text-[10.5px] text-fg-3">biggest change first</span>
          </div>
          <ul className="m-0 list-none space-y-1.5 p-0" data-testid="capture-by-setting">
            {shown.map((s) => (
              <SettingRow key={s.key} s={s} />
            ))}
          </ul>
          {model.settings.length > SETTINGS_SHOWN && (
            <button
              type="button"
              onClick={() => setAll((v) => !v)}
              className="mt-1.5 text-[10.5px] text-accent hover:underline"
            >
              {all ? "Show fewer" : `Show all ${fmtInt(model.settings.length)}`}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * ProcessCaptureEstimateView draws one state of the card. Pure of fetching so
 * the states render in a test.
 */
export function ProcessCaptureEstimateView({ state }: { state: EstimateCardState }) {
  const model = useMemo(() => (state.kind === "ready" ? estimateModel(state.estimate) : null), [state]);
  let sub: React.ReactNode = "What the capture limits above would store per day, replayed over this node's own recent capture.";
  let body: React.ReactNode;
  switch (state.kind) {
    case "loading":
      body = <InlineLoading size="sm" label="Estimating data volume" />;
      break;
    case "unavailable":
      body = <p className="text-[11.5px] text-fg-3">The estimate needs a newer daemon.</p>;
      break;
    case "error":
      body = <p className="text-[11.5px] text-danger">Could not estimate: {state.message}</p>;
      break;
    case "ready":
      if (model && !model.hasHistory) {
        body = (
          <p className="text-[11.5px] text-fg-3">
            Not enough history yet. The estimate replays stored process runs, and this node has none in the recent window.
          </p>
        );
      } else if (model) {
        sub = `Estimated ${model.basisText}.`;
        body = <Ready model={model} />;
      }
      break;
  }
  return (
    <Card title={TITLE} sub={sub} stale={state.kind === "ready" && Boolean(state.stale)} className="mt-6">
      {body}
    </Card>
  );
}

/**
 * ProcessCaptureEstimateCard is the card on the process section: `draft` is the
 * section's unsaved edit (StructuredConfigSection's onDraftChange), so the
 * numbers follow the form before anything is saved.
 */
export function ProcessCaptureEstimateCard({ draft }: { draft: Record<string, unknown> | null }) {
  const query = useMemo(() => captureDraftQuery(draft), [draft]);
  // Debounce: ask once the draft has sat still. The first value goes through
  // at once so the card does not open empty.
  const [settled, setSettled] = useState<string | null>(query);
  useEffect(() => {
    if (query == null) {
      setSettled(null);
      return;
    }
    const t = setTimeout(() => setSettled(query), ESTIMATE_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [query]);

  const api = useApi<unknown>(settled == null ? null : `/api/process/capture/estimate?${settled}`, undefined, []);
  const estimate = useMemo(() => (api.data == null ? null : parseEstimate(api.data)), [api.data]);

  let state: EstimateCardState;
  if (draft == null) state = { kind: "loading" };
  else if (captureDraft(draft) == null) state = { kind: "unavailable" };
  else if (api.status === 404 || api.notInstalled) state = { kind: "unavailable" };
  else if (estimate) state = { kind: "ready", estimate, stale: api.isStale || query !== settled };
  else if (api.error) state = { kind: "error", message: api.error.message };
  else state = { kind: "loading" };
  return <ProcessCaptureEstimateView state={state} />;
}
