import { useEffect, useState } from "react";
import { KeyRound, Send } from "lucide-react";
import { HelpTooltip } from "@shared/primitives/HelpTooltip";
import { Button, Card, Input, Pill, SegmentedControl, confirmDialog } from "@/components/primitives";
import { localConfirmHeaders } from "@/lib/api";
import { putConfigKeys } from "@/lib/configKeysPut";
import { useApi } from "@/lib/useApi";
import { orgDisplayLabel } from "@/lib/orgName";
import {
  DESTINATION_CHOICES,
  adminIssued,
  destinationLabel,
  installKeyBody,
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
//
// "Use an SDK key from my admin" (lane sdk-use-key) is the form of `observer
// sdk use-key`: for an organization that issues no member keys, the member
// pastes the key an admin minted on Machine identities and the gateway
// address the admin's dialog showed. The key goes in the POST body of
// /api/sdk/credential/key (never a URL), the field is cleared as soon as the
// request is sent, and the answer never carries it. An admin-issued key is
// removed, never revoked, by sign-out.

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
  const [useKeyOpen, setUseKeyOpen] = useState(false);
  const fromAdmin = adminIssued(d);
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
      !(await confirmDialog(
        fromAdmin
          ? {
              title: "Remove this SDK key from this machine?",
              body: "Your admin issued it, so it is removed from this machine only and not revoked: it keeps working wherever else it is used until an admin revokes it on Machine identities. Apps on this machine stop sending online.",
              confirmLabel: "Remove",
              tone: "danger",
            }
          : {
              title: "Revoke your SDK key?",
              body: "It is revoked on your organization and removed from this machine; apps stop sending online.",
              confirmLabel: "Revoke",
              tone: "danger",
            },
      ))
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
      setNote(
        signIn
          ? "Signed in: your SDK key is on this machine."
          : body.warning || (fromAdmin ? "Removed: the SDK key is no longer on this machine." : "Signed out: your SDK key was revoked."),
      );
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
            {fromAdmin ? "Remove this SDK key" : "Sign out (revoke my SDK key)"}
          </Button>
        ) : (
          <>
            {!nudge && (
              <Button size="sm" variant="secondary" disabled={readOnly || busy} onClick={() => void signInOut(true)}>
                Get my SDK key
              </Button>
            )}
            <Button
              size="sm"
              variant="secondary"
              disabled={readOnly || busy}
              aria-expanded={useKeyOpen}
              onClick={() => setUseKeyOpen((o) => !o)}
            >
              Use an SDK key from my admin
            </Button>
          </>
        )}
      </div>
      {!d?.signed_in && useKeyOpen && (
        <UseAdminKeyForm
          defaultGateway={saved.gateway}
          disabled={readOnly || busy}
          onBusy={setBusy}
          onDone={(msg) => {
            setUseKeyOpen(false);
            setErr(null);
            setNote(msg);
            res.reload();
          }}
        />
      )}
      {d?.signed_in && (
        <p className="mt-2 flex flex-wrap items-center gap-1 text-[11px] text-fg-3">
          <span>
            {fromAdmin
              ? "An SDK key your admin issued is kept in a file only you can read. It is never shown here; its scopes are on Machine identities in your organization's dashboard."
              : `Your SDK key (${d.online.scopes.join(", ")}) is kept in a file only you can read. It is never shown here.`}
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
          content="observer sdk status; observer sdk sign-in; observer sdk use-key --gateway-url <address> (the key on stdin); observer config set observability.sdk.destination both --yes"
        />
      </p>
    </Card>
  );
}

/**
 * UseAdminKeyForm installs an SDK key an admin issued (POST
 * /api/sdk/credential/key, the form of `observer sdk use-key`). The key field
 * is a password field, cleared the moment the request is sent; the key never
 * goes in a URL and the answer never carries it.
 */
export function UseAdminKeyForm({
  defaultGateway,
  disabled,
  onBusy,
  onDone,
}: {
  defaultGateway: string;
  disabled: boolean;
  onBusy: (busy: boolean) => void;
  onDone: (note: string) => void;
}) {
  const [key, setKey] = useState("");
  const [gateway, setGateway] = useState(defaultGateway);
  const [err, setErr] = useState<string | null>(null);
  const install = async () => {
    const built = installKeyBody(key, gateway);
    if ("error" in built) {
      setErr(built.error);
      return;
    }
    setErr(null);
    // The key leaves the form state now; only the request carries it.
    setKey("");
    onBusy(true);
    try {
      const r = await fetch("/api/sdk/credential/key", {
        method: "POST",
        headers: await localConfirmHeaders(),
        body: JSON.stringify(built.body),
      });
      const body = (await r.json().catch(() => ({}))) as { message?: string };
      if (!r.ok) throw new Error(body.message || `HTTP ${r.status}`);
      onDone("Installed: the SDK key your admin issued is on this machine. Restart your apps to pick it up.");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Request failed");
    } finally {
      onBusy(false);
    }
  };
  return (
    <form
      data-testid="sdk-use-admin-key"
      className="mt-3 space-y-2 rounded-2 border border-line-2 bg-bg-2 px-3 py-3"
      onSubmit={(e) => {
        e.preventDefault();
        void install();
      }}
    >
      <p className="flex items-center gap-1.5 text-[12px] text-fg-1">
        <KeyRound className="h-3.5 w-3.5 text-fg-3" aria-hidden />
        Your admin mints the key on Machine identities and shows it once, with the gateway address.
      </p>
      <Input
        type="password"
        autoComplete="off"
        spellCheck={false}
        label="SDK key"
        help="It is kept in a file only you can read and is never shown again here."
        mono
        placeholder="Paste the key your admin gave you"
        value={key}
        disabled={disabled}
        onChange={(e) => setKey(e.target.value)}
      />
      <Input
        label="Gateway address"
        help="The address the admin's dialog shows beside the key (SUPERBASED_ORG_URL)."
        mono
        placeholder="https://your-org.superbased.app"
        value={gateway}
        disabled={disabled}
        onChange={(e) => setGateway(e.target.value)}
      />
      <p className="text-[11px] text-fg-3">
        After this, an SDK on this machine sends to this machine and your organization unless you chose another destination.
        Removing the key later does not revoke it; your admin does that.
      </p>
      <div className="flex gap-2">
        <Button size="sm" variant="primary" type="submit" disabled={disabled}>
          Install the key
        </Button>
      </div>
      {err && (
        <p role="alert" className="text-[12px] text-danger">
          {err}
        </p>
      )}
    </form>
  );
}
