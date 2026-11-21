import { useState } from "react";
import { Button, Card, Modal, Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import {
  IAC_INSTALL_ROUTE,
  iacEngineName,
  iacErrorText,
  iacInstallBody,
  iacMB,
  iacPinChanged,
  iacShownEngines,
  iacStage,
  iacStageLine,
  type IaCEngineRow,
  type IaCInstallResponse,
  type IaCStage,
} from "@/lib/codeSecurityIac";

// IaCInstallCard - the Code security page's IaC scanners card (components
// security.scan.trivy and security.scan.kics, lane GATES-SEC; dashboard CLI
// parity plan B-CS2): one row per selected engine with its install state,
// and for an engine that is not installed the guided install behind a
// confirm dialog that shows the consent text, the download size and the
// pin (sha256) before anything is downloaded. The accept sends the pin the
// dialog showed; the server refuses any other pin in force (409), so a
// consent is never given for a pin not seen. The same install is `observer
// security iac install --engine <id>`. The route is owner-local and an agent
// can never give the accept (guard rule R-165). An engine that is off is
// turned on with its switch at the top of the tab; the card then lists it.
//
// Working surface: calm register, zero delight elements.

const STAGE_PILL: Record<IaCStage, ["success" | "warn" | "neutral", string]> = {
  installed: ["success", "Installed"],
  waiting: ["warn", "Not installed"],
  blocked: ["warn", "Install blocked"],
  unavailable: ["neutral", "Not installed"],
};

/** IaCEngineInstall is one engine's row and its install dialog. */
export function IaCEngineInstall({ engine, onInstalled }: { engine: IaCEngineRow; onInstalled: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // The pin the dialog showed: the accept sends it.
  const [seenPin, setSeenPin] = useState("");
  const [current, setCurrent] = useState<IaCEngineRow | undefined>(undefined);
  const name = iacEngineName(engine.driver);
  const stage = iacStage(engine);
  const [variant, label] = STAGE_PILL[stage];

  async function install() {
    setBusy(true);
    setErr(null);
    try {
      // Re-read for the confirm token and the pin in force now.
      const got = await fetch(IAC_INSTALL_ROUTE);
      if (!got.ok) throw new Error(iacErrorText(await got.text(), got.status));
      const fresh = (await got.json()) as IaCInstallResponse;
      const now = (fresh.engines ?? []).find((e) => e.driver === engine.driver);
      setCurrent(now);
      if (iacPinChanged(now, seenPin)) throw new Error(`The ${name} pin changed since this dialog opened. Review the new pin below.`);
      const body = iacInstallBody(now ?? engine, seenPin);
      if (!body) throw new Error(`${name} has nothing to install now.`);
      const res = await fetch(IAC_INSTALL_ROUTE, {
        method: "POST",
        headers: { "content-type": "application/json", ...(fresh.confirm_token ? { "X-Observer-Confirm": fresh.confirm_token } : {}) },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(iacErrorText(await res.text(), res.status));
      setOpen(false);
      onInstalled();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const changed = iacPinChanged(current, seenPin);
  return (
    <div className="space-y-2 border-t border-line-1 pt-3 first:border-t-0 first:pt-0" data-testid={`iac-install-${engine.driver}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-fg-1">{name}</span>
        <Pill variant={variant}>{label}</Pill>
        {(engine.labels ?? []).map((l) => (
          <Pill key={l} variant="neutral">
            {l}
          </Pill>
        ))}
      </div>
      <p className="m-0 break-words text-fg-3">{iacStageLine(engine)}</p>
      {stage === "waiting" && (
        <Button
          variant="primary"
          size="sm"
          onClick={() => {
            setSeenPin(engine.install_pin ?? "");
            setCurrent(undefined);
            setErr(null);
            setOpen(true);
          }}
          disabled={busy}
          data-testid={`iac-install-open-${engine.driver}`}
        >
          {`Install ${name}...`}
        </Button>
      )}
      {err && !open && <p className="m-0 text-danger">{err}</p>}
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        dismissible={!busy}
        title={`Install ${name}?`}
        subtitle={`${name}: ${iacMB(engine.install_bytes)} download, the pinned, signature-checked release`}
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" onClick={() => void install()} disabled={busy || changed} loading={busy}>
              {`Accept and install ${name}`}
            </Button>
          </div>
        }
      >
        <div className="space-y-2 text-[12.5px]">
          {engine.install_consent && <p className="m-0 whitespace-pre-wrap text-fg-2">{engine.install_consent}</p>}
          {seenPin && <p className="m-0 break-all text-fg-3">{`sha256 ${seenPin}`}</p>}
          {changed && current?.install_pin && (
            <p className="m-0 break-all text-danger">{`The pin changed since this dialog opened (now sha256 ${current.install_pin}). Close it and review the new pin.`}</p>
          )}
          <p className="m-0 text-fg-3">
            Recorded once, on this machine, with the time; a new pin asks again. The same install is `observer security iac install --engine {engine.driver}`.
          </p>
          {err && <p className="m-0 text-danger">{err}</p>}
        </div>
      </Modal>
    </div>
  );
}

/** IaCInstallCardView is the card over an already-read answer (the
 *  component tests render it). It renders nothing when no engine is
 *  selected. */
export function IaCInstallCardView({ data, onInstalled }: { data: IaCInstallResponse | null | undefined; onInstalled: () => void }) {
  const engines = iacShownEngines(data);
  if (engines.length === 0) return null;
  return (
    <Card title="IaC scanners" sub="Terraform, Kubernetes and Docker checks, run by a pinned and verified Trivy or KICS (flag only)">
      <div className="space-y-3 text-[12.5px]" data-testid="iac-install-card">
        {engines.map((e) => (
          <IaCEngineInstall key={e.driver} engine={e} onInstalled={onInstalled} />
        ))}
      </div>
    </Card>
  );
}

/** IaCInstallCard reads the route and renders the card; a 404 (the module
 *  compiled out) or an error renders nothing, as the other setup cards do. */
export function IaCInstallCard({ onChanged }: { onChanged?: () => void }) {
  const api = useApi<IaCInstallResponse>(IAC_INSTALL_ROUTE);
  if (!api.data) return null;
  return (
    <IaCInstallCardView
      data={api.data}
      onInstalled={() => {
        api.reload();
        onChanged?.();
      }}
    />
  );
}
