import { useMemo, useState } from "react";
import { Button, Callout, Card, Modal, Pill, Toggle } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { ApiError, fetchJSON, localConfirmHeaders } from "@/lib/api";
import type { ApiState } from "@/lib/useApi";
import type { CatalogReport, ComponentsStateResponse } from "@/lib/componentState";
import {
  appliedNote,
  buildScannerRows,
  changeFor,
  classifyFailure,
  confirmModel,
  type ComponentChange,
  type ComponentPreview,
  type DriverFacts,
  type ScannerRow,
} from "@/lib/securityComponents";
import { NamedLoading } from "./NamedLoading";

// ScannerSwitches: one row per scanner component with an On/Off switch (Code
// security redesign plan section 4.6, request 6). It replaces the old
// "add security.scan.opengrep under [components]" sentence: a switch runs the
// existing owner-local components preview (POST /api/components/preview), a
// confirm dialog lists exactly what the preview says will happen, and the
// confirm sends POST /api/components/apply with the preview's fingerprint.
// Nothing is previewed or applied on page load, there is no shortcut around
// the confirm, and the server (guard rule R-165 and the components
// self-approval rules) refuses an agent that tries the same routes: these
// switches are for the person at the dashboard.
//
// Working surface: calm register, zero delight elements.

type Pending = {
  row: ScannerRow;
  turnOn: boolean;
  change: ComponentChange;
  preview: ComponentPreview;
};

async function post<T>(path: string, body: unknown): Promise<T> {
  return fetchJSON<T>(path, undefined, {
    method: "POST",
    headers: await localConfirmHeaders(),
    body: JSON.stringify(body),
  });
}

/** failureOf reads an ApiError's body into the page's failure shape. */
function failureOf(e: unknown) {
  if (e instanceof ApiError) return classifyFailure(e.body, e.message);
  return classifyFailure(null, e instanceof Error ? e.message : String(e));
}

export function ScannerSwitches({
  catalog,
  state,
  drivers,
  onChanged,
}: {
  catalog: ApiState<CatalogReport>;
  state: ApiState<ComponentsStateResponse>;
  drivers?: DriverFacts[];
  /** Called after a change was applied, so the page re-reads what depends on it. */
  onChanged: () => void;
}) {
  const [pending, setPending] = useState<Pending | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [dialogNote, setDialogNote] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [undoWrites, setUndoWrites] = useState(true);

  const rows = useMemo(
    () => buildScannerRows(catalog.data, state.data, drivers ?? []),
    [catalog.data, state.data, drivers],
  );
  const names = useMemo(() => new Map((catalog.data?.components ?? []).map((c) => [c.id, c.title])), [catalog.data]);
  const nameOf = (id: string) => names.get(id) ?? id;
  const view = state.data?.view;

  async function startToggle(row: ScannerRow, turnOn: boolean) {
    setBusy(true);
    setErr(null);
    setNotice(null);
    setDialogNote(null);
    setUndoWrites(true);
    const change = changeFor(row.id, turnOn);
    try {
      const preview = await post<ComponentPreview>("/api/components/preview", { change });
      setPending({ row, turnOn, change, preview });
    } catch (e) {
      setErr(failureOf(e).message);
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    if (!pending) return;
    setBusy(true);
    setDialogNote(null);
    try {
      const res = await post<{ preview?: ComponentPreview }>("/api/components/apply", {
        change: pending.change,
        fingerprint: pending.preview.fingerprint,
        skip_teardown: !undoWrites,
      });
      const restart = res.preview?.restart_required ?? pending.preview.restart_required;
      setNotice(appliedNote(pending.turnOn, pending.row.name, view?.restart_note, restart));
      setPending(null);
      state.reload();
      onChanged();
    } catch (e) {
      const f = failureOf(e);
      // A stale or managed refusal carries the server's own preview: show it
      // in place of the old one, never apply it unseen.
      if (f.preview) setPending({ ...pending, preview: f.preview });
      setDialogNote(f.message);
    } finally {
      setBusy(false);
    }
  }

  const loading = (catalog.loading && !catalog.data) || (state.loading && !state.data);
  const error = catalog.error ?? state.error;
  const model = pending ? confirmModel(pending.preview, { id: pending.row.id, name: pending.row.name, turnOn: pending.turnOn }, nameOf) : null;

  return (
    <Card title="Scanner switches" sub="Turn each scanner on or off. Each change is previewed first and only applied when you confirm.">
      <div className="space-y-3">
        {view?.org_managed ? (
          <Callout tone="info" title="Your organization manages this setting">
            {view.org_name ? `${view.org_name} decides which scanners run on this machine.` : "Your organization decides which scanners run on this machine."} A change is previewed, and anything the organization refuses is listed.
          </Callout>
        ) : null}
        {notice ? (
          <p className="m-0 text-[12.5px] text-success" role="status" data-testid="scanner-switch-notice">
            {notice}
          </p>
        ) : null}
        {err ? (
          <p className="m-0 text-[12.5px] text-danger" role="alert" data-testid="scanner-switch-error">
            {err}
          </p>
        ) : null}
        <NamedLoading active={loading} label="Loading scanner settings" slowLine="The component list is still loading." />
        <ChartState
            loading={loading}
            error={error}
            denied={catalog.denied || state.denied}
            deniedPermission={catalog.deniedPermission ?? state.deniedPermission}
            empty={!loading && !error && rows.length === 0}
            emptyHint="This build has no scanner components."
            kind="list"
            height={180}
            onRetry={() => {
              catalog.reload();
              state.reload();
            }}
          >
            <ul className="m-0 list-none divide-y divide-line-1 p-0" data-testid="scanner-switches">
              {rows.map((r) => (
                <SwitchRow key={r.id} row={r} busy={busy} onToggle={(next) => void startToggle(r, next)} />
              ))}
            </ul>
        </ChartState>
      </div>
      <Modal
        open={pending != null && model != null}
        onClose={() => (busy ? undefined : setPending(null))}
        dismissible={!busy}
        title={model?.title}
        width={520}
        footer={
          <div className="flex flex-wrap justify-end gap-2">
            <Button size="sm" disabled={busy} onClick={() => setPending(null)}>
              Cancel
            </Button>
            <Button
              size="sm"
              variant="primary"
              disabled={busy || !model?.canApply}
              onClick={() => void confirm()}
              data-testid="scanner-switch-apply"
            >
              {model?.applyLabel ?? "Apply"}
            </Button>
          </div>
        }
      >
        {model && pending ? (
          <div className="space-y-3 text-[13px]" data-testid="scanner-switch-confirm">
            {model.sections.length === 0 ? <p className="m-0 text-fg-2">Nothing changes.</p> : null}
            {model.sections.map((s) => (
              <div key={s.heading}>
                <div className={s.tone === "danger" ? "text-danger" : s.tone === "warn" ? "text-warn" : "text-fg-2"}>{s.heading}</div>
                <ul className="m-0 list-disc pl-5 text-fg-1">
                  {s.items.map((it, i) => (
                    <li key={`${i}-${it}`}>{it}</li>
                  ))}
                </ul>
              </div>
            ))}
            {pending.preview.teardown.length > 0 ? (
              <label className="flex items-center gap-2 text-fg-2">
                <input type="checkbox" checked={undoWrites} disabled={busy} onChange={(e) => setUndoWrites(e.target.checked)} />
                Undo those writes now (otherwise they stay until you run the teardown)
              </label>
            ) : null}
            {model.notes.map((n) => (
              <p key={n} className="m-0 text-fg-3">
                {n}
              </p>
            ))}
            {model.blockedReason ? (
              <p className="m-0 text-warn" role="status">
                {model.blockedReason}
              </p>
            ) : null}
            {dialogNote ? (
              <p className="m-0 text-danger" role="alert" data-testid="scanner-switch-dialog-note">
                {dialogNote}
              </p>
            ) : null}
          </div>
        ) : null}
      </Modal>
    </Card>
  );
}

/** SwitchRow is one scanner: name, one line, state pills and the switch. */
export function SwitchRow({ row, busy, onToggle }: { row: ScannerRow; busy: boolean; onToggle: (next: boolean) => void }) {
  return (
    <li className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 py-3" data-testid="scanner-switch-row" data-component={row.id}>
      <div className="min-w-[14rem] flex-1 space-y-1">
        <div className="text-[13.5px] font-medium text-fg-1">{row.name}</div>
        <p className="m-0 text-[12.5px] text-fg-3">{row.line}</p>
        <div className="flex flex-wrap items-center gap-1.5">
          {row.pills.map((p) => (
            <Pill key={p.text} variant={p.tone}>
              {p.text}
            </Pill>
          ))}
        </div>
        {row.whyNot ? <p className="m-0 text-[12px] text-fg-3">{row.whyNot}</p> : null}
      </div>
      {row.switchable ? (
        <Toggle on={row.on} onChange={onToggle} disabled={busy} label={row.on ? "On" : "Off"} ariaLabel={`${row.name}: ${row.on ? "on" : "off"}`} />
      ) : null}
    </li>
  );
}
