// FirstLaunchConsent: the launchpad's ONE first-launch step inside New
// terminal (door A, docs/plans/local-dashboard-first-run-options-2026-11-18.md
// section 8, step 3). Instead of sending the person to Terminals > Settings to
// allow the tool, it says what starting the tool here takes, shows the exact
// config change, and applies it on Allow:
//
//   To start Claude Code here, Observer will:
//   - allow Claude Code to launch from the dashboard
//   - allow fresh launches
//   - allow the folder ~/observer-playground (created now)
//   [Allow] [Cancel]
//
// Both requests go to POST /api/terminal/first-launch with the owner-local
// confirm token (localConfirmHeaders): a dry run renders the diff, and Allow
// saves at the previewed etag with the change list the person saw, which the
// server refuses (409) if the settings changed since. Which changes are asked
// is lib/launchpad.ts consentChanges; this component only renders them.

import { useEffect, useRef, useState } from "react";
import { apiReason, fetchJSON, localConfirmHeaders } from "@/lib/api";
import type { ConfigKeysDryRun } from "@/lib/configSchema";
import {
  consentHeading,
  consentLines,
  consentSettings,
  type ConsentChange,
} from "@/lib/launchpad";
import { ConfigSavePreview } from "@/components/ConfigSavePreview";
import { Button } from "@/components/primitives";
import { HelpTooltip } from "@shared/primitives/HelpTooltip";

/** The route's extra fields, on the dry run and on the save. */
type FirstLaunchFields = { tool: string; folder: string; changes: ConsentChange[]; folder_created?: boolean };

/** The dry run of the consent. */
export type FirstLaunchPreview = ConfigKeysDryRun & FirstLaunchFields;

/** The save's answer. */
export type FirstLaunchSaved = FirstLaunchFields & { saved: boolean; restart_required?: boolean };

async function postFirstLaunch<T>(params: Record<string, string>, body: unknown): Promise<T> {
  return fetchJSON<T>("/api/terminal/first-launch", params, {
    method: "POST",
    headers: await localConfirmHeaders(),
    body: JSON.stringify(body),
  });
}

/** previewFirstLaunch is the consent's dry run: the diff, nothing written. */
export function previewFirstLaunch(tool: string, folder: string, changes: readonly ConsentChange[]) {
  return postFirstLaunch<FirstLaunchPreview>({ dry_run: "1" }, { tool, folder, changes });
}

/** applyFirstLaunch saves the previewed consent at the previewed etag. */
export function applyFirstLaunch(preview: FirstLaunchPreview, folder: string) {
  return postFirstLaunch<FirstLaunchSaved>(
    { base_etag: preview.config_etag },
    { tool: preview.tool, folder, changes: preview.changes },
  );
}

type Props = {
  tool: string;
  toolLabel: string;
  /** The folder sent to the route ("" = the agent's default directory). */
  folder: string;
  /** The folder as the consent writes it ("~/observer-playground"); defaults to folder. */
  displayFolder?: string;
  /** The changes the dialog computed (lib/launchpad.ts consentChanges). */
  changes: ConsentChange[];
  /** Called after the save with the server's answer (the canonical folder). */
  onAllowed: (saved: FirstLaunchSaved) => void;
  onCancel: () => void;
  /** True while the step is previewing or saving (the dialog holds Start). */
  onBusy?: (busy: boolean) => void;
  /** Tests render a preview directly (no fetch answers under server rendering). */
  initialPreview?: FirstLaunchPreview;
};

export function FirstLaunchConsent({
  tool,
  toolLabel,
  folder,
  displayFolder,
  changes,
  onAllowed,
  onCancel,
  onBusy,
  initialPreview,
}: Props) {
  const [preview, setPreview] = useState<FirstLaunchPreview | null>(initialPreview ?? null);
  const [err, setErr] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const busyRef = useRef(onBusy);
  busyRef.current = onBusy;
  const key = `${tool}\u0000${folder}\u0000${changes.join(",")}`;

  useEffect(() => {
    if (initialPreview) return;
    let cancelled = false;
    setPreview(null);
    setErr(null);
    busyRef.current?.(true);
    previewFirstLaunch(tool, folder, changes)
      .then((p) => {
        if (!cancelled) setPreview(p);
      })
      .catch((e) => {
        if (!cancelled) setErr(apiReason(e));
      })
      .finally(() => {
        if (!cancelled) busyRef.current?.(false);
      });
    return () => {
      cancelled = true;
    };
    // key folds tool, folder and the change list.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, initialPreview]);

  useEffect(() => () => busyRef.current?.(false), []);

  async function allow() {
    if (!preview || saving) return;
    setSaving(true);
    setErr(null);
    busyRef.current?.(true);
    try {
      const saved = await applyFirstLaunch(preview, folder);
      onAllowed(saved);
    } catch (e) {
      setErr(apiReason(e));
    } finally {
      setSaving(false);
      busyRef.current?.(false);
    }
  }

  // The lines come from the server's own plan once the dry run answered (it
  // is what the save checks), else from the dialog's.
  const shown = preview?.changes ?? changes;
  const lines = consentLines(toolLabel, shown, displayFolder || folder);
  const settings = consentSettings(shown);
  return (
    <div
      className="-mt-1 mb-3 rounded-2 border border-accent/40 bg-accent/10 px-2.5 py-2 text-[11px] leading-relaxed text-fg-2"
      data-testid="first-launch-consent"
    >
      <p className="font-medium text-fg-1">{consentHeading(toolLabel)}</p>
      <ul className="mt-1 list-disc pl-4" data-testid="first-launch-consent-lines">
        {lines.map((l) => (
          <li key={l} className="break-all">
            {l}
          </li>
        ))}
      </ul>
      {settings.length > 0 && (
        <p className="mt-1 text-fg-3">
          This changes Terminals &gt; Settings &gt; Fresh-agent launch policy{" "}
          <HelpTooltip
            technical
            subject="the launch policy settings this changes"
            content={settings.map((k) => `[terminal.launch].${k}`).join(", ")}
            className="align-middle"
          />
          {preview ? (
            <>
              {" "}in <span className="break-all font-mono">{preview.config_path}</span>
            </>
          ) : null}
          . Nothing else changes, and you can undo it in Terminals &gt; Settings.
        </p>
      )}
      {preview ? (
        <details className="mt-1.5" open>
          <summary className="cursor-pointer text-fg-2">The exact change</summary>
          <div className="mt-1">
            <ConfigSavePreview data={preview} />
          </div>
        </details>
      ) : !err ? (
        <p className="mt-1.5 text-fg-3">Preparing the exact change…</p>
      ) : null}
      {err && <p className="mt-1.5 text-danger">{err}</p>}
      <div className="mt-1.5 flex gap-2">
        <Button
          variant="primary"
          size="sm"
          disabled={!preview || saving}
          onClick={() => void allow()}
          data-testid="first-launch-allow"
        >
          {saving ? "Allowing…" : "Allow"}
        </Button>
        <Button variant="ghost" size="sm" disabled={saving} onClick={onCancel} data-testid="first-launch-cancel">
          Cancel
        </Button>
      </div>
    </div>
  );
}
