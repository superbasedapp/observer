import { useState } from "react";
import { Button, Card, Modal, Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { securityPost } from "@/lib/codeSecurityExceptions";
import {
  OPENGREP_ROUTE,
  mb,
  opengrepAcceptLabel,
  opengrepInstallLine,
  opengrepRows,
  opengrepStage,
  type OpengrepResponse,
} from "@/lib/opengrepCard";

// The Code security page's Code rules card (component
// security.scan.opengrep, lane SEC-G2): Opengrep's guided install behind a
// confirm dialog that states the download and the unpacked sizes before
// anything is downloaded, then the engine, its verification, the rule pack
// and where it came from, the last run, the triggers and isolation. The
// route answers 404 unless the component is selected (opt-in), so an
// install that never chose it sees no card. The install route is
// owner-local; the dialog's accept is the developer's consent, never an
// agent's (guard rule R-165). The triggers are edited on the Settings card.
//
// Working surface: calm register, zero delight elements.

const STAGE_PILL = {
  waiting: ["warn", "Not installed"],
  installing: ["neutral", "Installing"],
  installed: ["success", "Installed"],
  managed: ["neutral", "Org mirror"],
  blocked: ["warn", "Install blocked"],
} as const;

export function OpengrepScannerCard() {
  const api = useApi<OpengrepResponse>(OPENGREP_ROUTE, undefined, [], { refreshMs: 5000 });
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // The pin the dialog showed: the accept sends it, and the server refuses
  // any other pin in force with 409 and the current one (lane SEC-G2 audit
  // finding 3), so a consent is never given for a pin not seen.
  const [seenSha, setSeenSha] = useState("");
  const st = api.data?.status;
  if (!st || !st.selected) return null;
  const stage = opengrepStage(st);
  const [variant, label] = STAGE_PILL[stage];
  async function install() {
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch(OPENGREP_ROUTE);
      if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
      const got = (await res.json()) as OpengrepResponse;
      await securityPost(OPENGREP_ROUTE, got.confirm_token ?? "", { install: true, sha256: seenSha });
      setOpen(false);
      api.reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
      api.reload();
    } finally {
      setBusy(false);
    }
  }
  const canInstall = stage === "waiting" || stage === "managed";
  return (
    <Card title="Code rules" sub="Observer's own code rules, run by a pinned and verified Opengrep (flag only until a rule has a measured precision figure)">
      <div className="space-y-3 text-[12.5px]" data-testid="opengrep-card">
        <div className="flex flex-wrap items-center gap-2">
          <Pill variant={variant}>{label}</Pill>
          <span className="text-fg-3">{opengrepInstallLine(st)}</span>
        </div>
        {st.last_error && stage !== "installing" && <p className="m-0 text-danger">Last install failed: {st.last_error}</p>}
        {canInstall && (
          <Button
            variant="primary"
            onClick={() => {
              setSeenSha(st.sha256 ?? "");
              setOpen(true);
            }}
            disabled={busy}
          >
            Install Opengrep...
          </Button>
        )}
        {err && !open && <p className="m-0 text-danger">{err}</p>}
        <table className="w-full text-[13px]" data-testid="opengrep-rows">
          <tbody>
            {opengrepRows(st).map(([k, v]) => (
              <tr key={k} className="border-t border-line-1">
                <td className="py-1.5 pr-3 text-fg-3">{k}</td>
                <td className="py-1.5 text-fg-2 break-all">{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {st.pack_note && <p className="m-0 text-fg-3">{st.pack_note}</p>}
        <Modal
          open={open}
          onClose={() => setOpen(false)}
          dismissible={!busy}
          title="Install Opengrep?"
          subtitle={
            st.managed
              ? `Opengrep ${st.version ?? ""} from your organization's mirror`
              : `Opengrep ${st.version ?? ""}: ${mb(st.download_bytes)} download, ${mb(st.tree_bytes)} unpacked on first run`
          }
          footer={
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setOpen(false)} disabled={busy}>
                Cancel
              </Button>
              <Button variant="primary" onClick={install} disabled={busy} loading={busy}>
                {opengrepAcceptLabel(st)}
              </Button>
            </div>
          }
        >
          <div className="space-y-2 text-[12.5px]">
            {st.consent_text && <p className="m-0 text-fg-2">{st.consent_text}</p>}
            {seenSha && <p className="m-0 text-fg-3 break-all">sha256 {seenSha}</p>}
            {seenSha && st.sha256 && st.sha256 !== seenSha && (
              <p className="m-0 text-danger">The pin changed since this dialog opened (now sha256 {st.sha256}). Close it and review the new pin.</p>
            )}
            <p className="m-0 text-fg-3">
              Recorded once, on this machine, with the time; a new pin asks again. The same install is `observer security code install`.
            </p>
            {err && <p className="m-0 text-danger">{err}</p>}
          </div>
        </Modal>
      </div>
    </Card>
  );
}
