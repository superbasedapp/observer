import { useState } from "react";
import { Power, Save } from "lucide-react";
import { Button, Callout, EmptyState } from "@/components/primitives";
import { RestartOverlay } from "@/components/RestartOverlay";
import { fetchJSON } from "@/lib/api";
import { ConfigSaveCancelled, saveConfigSection } from "@/lib/configSectionSave";
import { markRestartPending } from "@/lib/restartPending";
import { useDaemonRestart } from "@/lib/useDaemonRestart";
import { pushToast } from "@/components/Toast";
import { ADMISSION_STARTS_NEXT_TEXT } from "./applyRule";
import {
  type AdmissionPolicyGet,
  type ConfigResponse,
  applyAdmissionPolicy,
  policyErrorText,
} from "./types";

// AdmissionOff is the Policies call to action when admission checks are not
// running on this machine ([observability.admission] enabled = false; UI
// review U-13: the page could not turn them on and showed a raw API 404).
// Turning them on saves the setting through the usual config preview, then
// asks to restart the daemon (the service is built at start). A policy that
// was saved as off comes back in observe only, never straight to enforce.
export function AdmissionOff() {
  const { restarting, error, restart } = useDaemonRestart();
  const [busy, setBusy] = useState(false);

  async function turnOn() {
    setBusy(true);
    try {
      const cfg = await fetchJSON<ConfigResponse>("/api/config").catch(() => null);
      const saved = cfg?.config.Observability.Admission.Mode ?? "";
      const patch: { Enabled: boolean; Mode?: string } = { Enabled: true };
      if (saved === "" || saved === "off") patch.Mode = "observe";
      const res = await saveConfigSection("observability", { Admission: patch }, { title: "Turn on admission checks" });
      if (!res.saved) {
        pushToast("The setting was not saved. Try again.", "danger");
        return;
      }
      markRestartPending("observability", res.restart_required_keys);
      await restart({
        title: "Restart the daemon to turn on admission checks?",
        lead: "Admission checks start after the restart, in observe only unless a saved policy says otherwise.",
      });
    } catch (e) {
      if (e instanceof ConfigSaveCancelled) return;
      pushToast(policyErrorText(e), "danger");
    } finally {
      setBusy(false);
    }
  }

  if (restarting) {
    return (
      <RestartOverlay
        title="Restarting the daemon…"
        body="Turning on admission checks and reconnecting. This page reloads automatically when the new process is up."
      />
    );
  }
  return (
    <Callout
      tone="info"
      title="Admission checks are off"
      action={
        <Button size="sm" variant="primary" iconLeft={Power} loading={busy} disabled={busy} onClick={() => void turnOn()}>
          {busy ? "Turning on" : "Turn on"}
        </Button>
      }
    >
      Your app's requests are not checked. Turning checks on needs a daemon restart; they start in observe only, so
      nothing is blocked.
      {error && <span className="mt-1 block text-danger">{restartErrorText(error)}</span>}
    </Callout>
  );
}

// AdmissionStartsNext replaces the off card when admission is turned on but
// waits for the next daemon start (pending_next_start, FR-M01): there is
// nothing to turn on, so no button.
export function AdmissionStartsNext() {
  return (
    <Callout tone="info" title="Admission starts at the next daemon start">
      {ADMISSION_STARTS_NEXT_TEXT}
    </Callout>
  );
}

// AdmissionOffNote stands in for a tab's admission controls while checks are
// off; the page's AdmissionOff callout above carries the one Turn on button.
export function AdmissionOffNote({ what }: { what: string }) {
  return (
    <EmptyState
      variant="inline"
      title="Admission checks are off"
      body={`Use Turn on at the top of this page to ${what}.`}
    />
  );
}

// restartErrorText words a failed restart without its raw API text: a
// standalone dashboard cannot re-exec itself.
export function restartErrorText(error: string): string {
  return /501|not\s|unavailable/i.test(error)
    ? "Saved. This dashboard cannot restart the daemon; restart it from the command line to apply."
    : "Saved, but the restart did not start. Use Restart now in the banner at the top.";
}

// LiveUnsaved is the U-27 honesty state: the live admission policy did not
// reach config (the save failed or persistence is unavailable), so the next
// daemon restart drops it. Save retries the write of the live policy.
export function LiveUnsaved({ onSaved }: { onSaved: () => void }) {
  const [busy, setBusy] = useState(false);
  async function save() {
    setBusy(true);
    try {
      const cur = await fetchJSON<AdmissionPolicyGet>("/api/obs/admission/policy");
      const { data } = await applyAdmissionPolicy(cur.policy);
      if (data.persisted) {
        pushToast("Admission policy saved.", "success");
        onSaved();
      } else {
        pushToast("Still not saved. Check that the config file is writable.", "danger");
      }
    } catch (e) {
      pushToast(policyErrorText(e), "danger");
    } finally {
      setBusy(false);
    }
  }
  return (
    <Callout
      tone="warn"
      title="The live admission policy is not saved"
      action={
        <Button size="sm" iconLeft={Save} loading={busy} disabled={busy} onClick={() => void save()}>
          {busy ? "Saving" : "Save it"}
        </Button>
      }
    >
      It applies now, but a daemon restart drops it and brings back the saved policy.
    </Callout>
  );
}
