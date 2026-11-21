import { useEffect, useState } from "react";
import { Send } from "lucide-react";
import { HelpTooltip } from "@shared/primitives/HelpTooltip";
import { Button, Card, Input, Pill, SegmentedControl, confirmDialog } from "@/components/primitives";
import { localConfirmHeaders } from "@/lib/api";
import { putConfigKeys } from "@/lib/configKeysPut";
import { useApi } from "@/lib/useApi";
import { orgDisplayLabel } from "@/lib/orgName";
import {
  DESTINATION_CHOICES,
  destinationLabel,
  sdkKeyNudge,
  sendsOnline,
  sourceText,
  type SdkDestinationChoice,
  type SdkDiscovery,
} from "@/lib/sdkDestination";
import type { ConfigResponse, EnrolmentStatus } from "@/lib/types";

// SdkDestinationCard - Settings > Observability "SDK data destination"
// (Plane A build-out lane B6, W2-7 ruling D18). The superbased SDKs ask this
// machine where to send an app's data unless the app's init() or
// SUPERBASED_DESTINATION says; this card sets that default
// ([observability.sdk] destination and gateway_url, through PUT
// /api/config/keys like every schema setting) and signs this machine in for
// SDK data (your own SDK key, minted by your organization). The key is kept
// in a file only you can read; it is never shown here and no route returns
// it. Contract: docs/plans/plane-a-sdk-buildout/contracts/destination.md.

/** The field paths the schema-driven "More settings" card must not repeat. */
export const SDK_DESTINATION_FIELDS = ["Observability.SDK.Destination", "Observability.SDK.GatewayURL"];

const DISCOVERY = "/api/sdk/destination";

function savedChoice(config: ConfigResponse | null): { destination: SdkDestinationChoice; gateway: string } {
  const sdk = (config?.config as { Observability?: { SDK?: { Destination?: string; GatewayURL?: string } } } | undefined)
    ?.Observability?.SDK;
  const d = sdk?.Destination ?? "";
  return {
    destination: (["", "local", "online", "both"].includes(d) ? d : "") as SdkDestinationChoice,
    gateway: sdk?.GatewayURL ?? "",
  };
}

export function SdkDestinationCard({
  config,
  readOnly = false,
  onSaved,
}: {
  config: ConfigResponse | null;
  readOnly?: boolean;
  onSaved: () => void;
}) {
  const res = useApi<SdkDiscovery>(DISCOVERY);
  const d = res.data;
  // U-26: enrolment and the SDK key are separate; point from one to the other.
  const enrolment = useApi<EnrolmentStatus>("/api/enrolment/status", undefined, [], { refreshMs: 30000 });
  const nudge = sdkKeyNudge(
    d,
    !!enrolment.data?.enrolled,
    orgDisplayLabel(enrolment.data?.org_display, enrolment.data?.org_name),
  );
  const saved = savedChoice(config);
  const [choice, setChoice] = useState<SdkDestinationChoice>(saved.destination);
  const [gateway, setGateway] = useState(saved.gateway);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  useEffect(() => {
    setChoice(saved.destination);
    setGateway(saved.gateway);
  }, [saved.destination, saved.gateway]);

  const dirty = choice !== saved.destination || gateway.trim() !== saved.gateway;

  const save = async () => {
    setBusy(true);
    setErr(null);
    setNote(null);
    try {
      if (sendsOnline(choice) && choice !== saved.destination) {
        const ok = await confirmDialog({
          title: `Send your apps' data to your organization (${destinationLabel(choice)})?`,
          body: "An SDK on this machine will export an app's spans off this machine, to your organization's gateway.",
          confirmLabel: "Send online",
        });
        if (!ok) return;
      }
      const patches = [];
      if (choice !== saved.destination) patches.push({ key: "observability.sdk.destination", value: choice });
      if (gateway.trim() !== saved.gateway) patches.push({ key: "observability.sdk.gateway_url", value: gateway.trim() });
      await putConfigKeys(config ?? {}, patches, false);
      setNote("Saved. SDKs read it when they start, so restart your app to pick it up.");
      onSaved();
      res.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Save failed");
    } finally {
      setBusy(false);
    }
  };

  const signInOut = async (signIn: boolean) => {
    if (
      !signIn &&
      !(await confirmDialog({
        title: "Revoke your SDK key?",
        body: "It is revoked on your organization and removed from this machine; apps stop sending online.",
        confirmLabel: "Revoke",
        tone: "danger",
      }))
    )
      return;
    setBusy(true);
    setErr(null);
    setNote(null);
    try {
      const r = await fetch("/api/sdk/credential", {
        method: signIn ? "POST" : "DELETE",
        headers: await localConfirmHeaders(),
        body: "{}",
      });
      const body = (await r.json().catch(() => ({}))) as { message?: string; warning?: string };
      if (!r.ok) throw new Error(body.message || `HTTP ${r.status}`);
      setNote(signIn ? "Signed in: your SDK key is on this machine." : body.warning || "Signed out: your SDK key was revoked.");
      res.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card
      id="sdk-destination"
      className="mt-4"
      title="SDK data destination"
      icon={Send}
      sub="Where the superbased SDKs send an app's data when the app does not choose."
    >
      {d && (
        <p className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-[12px] text-fg-2">
          <span>
            An SDK on this machine sends to <strong>{destinationLabel(d.destination)}</strong> ({sourceText(d)}).
          </span>
          <Pill variant={d.signed_in ? "success" : "neutral"} case="none">
            {d.signed_in ? "Signed in for SDK data" : "Not signed in"}
          </Pill>
          <HelpTooltip
            technical
            subject="what wins over this choice"
            content="The app's init() destination, or SUPERBASED_DESTINATION in its environment."
          />
        </p>
      )}
      {nudge && (
        <div
          data-testid="sdk-key-nudge"
          className="mt-3 flex flex-wrap items-center gap-2 rounded-2 border border-accent/30 bg-accent-soft px-3 py-2 text-[12px] text-fg-1"
        >
          <span className="min-w-0 flex-1">{nudge}</span>
          <Button size="sm" variant="primary" disabled={readOnly || busy} onClick={() => void signInOut(true)}>
            Get my SDK key
          </Button>
        </div>
      )}
      <div className="mt-3">
        <SegmentedControl
          options={DESTINATION_CHOICES.map((c) => ({ value: c.value || "default", label: c.label }))}
          value={choice || "default"}
          onChange={(v) => setChoice((v === "default" ? "" : v) as SdkDestinationChoice)}
        />
        <p className="mt-1 text-[11px] text-fg-3">{DESTINATION_CHOICES.find((c) => c.value === choice)?.help}</p>
      </div>
      <div className="mt-3">
        <Input
          label="Gateway address (optional)"
          help="Empty uses the address your organization returned when you signed in."
          mono
          placeholder={d?.online.gateway_url_source === "org" ? d.online.gateway_url : "https://gw.example.com:4318"}
          value={gateway}
          disabled={readOnly || busy}
          onChange={(e) => setGateway(e.target.value)}
        />
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <Button size="sm" variant="primary" disabled={readOnly || busy || !dirty} title={dirty ? undefined : "Change the destination or the address to save."} onClick={() => void save()}>
          Save
        </Button>
        {d?.signed_in ? (
          <Button size="sm" variant="secondary" disabled={readOnly || busy} onClick={() => void signInOut(false)}>
            Sign out (revoke my SDK key)
          </Button>
        ) : nudge ? null : (
          <Button size="sm" variant="secondary" disabled={readOnly || busy} onClick={() => void signInOut(true)}>
            Get my SDK key
          </Button>
        )}
      </div>
      {d?.signed_in && (
        <p className="mt-2 flex flex-wrap items-center gap-1 text-[11px] text-fg-3">
          <span>
            Your SDK key ({d.online.scopes.join(", ")}) is kept in a file only you can read. It is never shown here.
          </span>
          <HelpTooltip technical subject="where the key is kept" content={`Key ${d.online.key_id}, in ${d.online.credential_file}`} />
        </p>
      )}
      {(d?.warnings ?? []).map((w) => (
        <p key={w} className="mt-2 text-[12px] text-warn">
          {w}
        </p>
      ))}
      {note && (
        <p role="status" className="mt-2 text-[12px] text-fg-2">
          {note}
        </p>
      )}
      {err && (
        <p role="alert" className="mt-2 text-[12px] text-danger">
          {err}
        </p>
      )}
      {/* U-25: the commands used to trail off as "and observer config set ."
          with the key only in a tooltip. They are help, so all three sit in
          one technical tooltip after the sentence. */}
      <p className="mt-3 flex flex-wrap items-center gap-1 text-[11px] text-fg-3">
        <span>An AI agent can only propose an online destination; you approve it under Changes waiting for you.</span>
        <HelpTooltip
          technical
          subject="the command-line twins"
          content="observer sdk status; observer sdk sign-in; observer config set observability.sdk.destination both --yes"
        />
      </p>
    </Card>
  );
}
