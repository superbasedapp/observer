// sdkDestination - the pure half of Settings > Observability "SDK data
// destination" and "Changes waiting for you" (Plane A build-out lane B6,
// W2-7 ruling D18, W2-8 ruling D19). The contract is
// docs/plans/plane-a-sdk-buildout/contracts/destination.md.
//
// GET /api/sdk/destination answers the same body the superbased SDKs read:
// the machine default, where local and online data go and whether this
// machine holds an SDK key. It never carries the key.

/** The explicit destinations; "" is "the default". */
export type SdkDestination = "local" | "online" | "both";
export type SdkDestinationChoice = "" | SdkDestination;

/** GET /api/sdk/destination (api_version 1). */
export type SdkDiscovery = {
  api_version: number;
  destination: SdkDestination;
  source: "config" | "default_signed_in" | "default_not_signed_in";
  configured: SdkDestinationChoice;
  signed_in: boolean;
  local: {
    enabled: boolean;
    otlp_traces_url: string;
    otlp_logs_url: string;
    otlp_metrics_url: string;
    admission_url: string;
  };
  online: {
    gateway_url: string;
    gateway_url_source: "" | "config" | "org";
    credential_present: boolean;
    credential_file: string;
    cred_id: string;
    key_id: string;
    scopes: string[];
    signals: string[];
    workspace_id: string;
    environment_id: string;
    org_id: string;
    minted_at: string;
    expires_at: string;
  };
  warnings: string[];
};

/** One settings proposal an AI agent filed (GET /api/config/proposals). */
export type SettingsProposal = {
  id: number;
  key: string;
  value: string;
  prev_value: string;
  category: string;
  reason: string;
  requested_by: string;
  note: string;
  status: "pending" | "approved" | "rejected" | "superseded";
  created_at: string;
  decided_at?: string;
  decided_by?: string;
};

export type SettingsProposalsResponse = { proposals: SettingsProposal[]; confirm_token?: string };

/** The choices the card offers, in order, with their plain words. */
export const DESTINATION_CHOICES: { value: SdkDestinationChoice; label: string; help: string }[] = [
  { value: "", label: "Default", help: "This machine when you are not signed in; this machine and your organization when you are." },
  { value: "local", label: "This machine", help: "An app's data stays on this machine." },
  { value: "online", label: "Your organization", help: "An app's data goes to your organization's gateway only." },
  { value: "both", label: "Both", help: "An app's data goes to this machine and to your organization." },
];

/** destinationLabel is the plain name of a resolved destination. */
export function destinationLabel(d: SdkDestinationChoice): string {
  return DESTINATION_CHOICES.find((c) => c.value === d)?.label ?? d;
}

/** sendsOnline mirrors config.SDKDestinationSendsOnline: online and both
 * send an app's data off this machine, which is why saving them asks for
 * confirmation and an agent can only propose them. */
export function sendsOnline(d: SdkDestinationChoice): boolean {
  return d === "online" || d === "both";
}

/** sourceText says why the machine default is what it is. */
export function sourceText(d: SdkDiscovery): string {
  switch (d.source) {
    case "config":
      return "you chose it";
    case "default_signed_in":
      return "the default while you are signed in";
    default:
      return "the default while you are not signed in";
  }
}

/** CATEGORY_LABELS name a proposal's D19 category in plain words. */
const CATEGORY_LABELS: Record<string, string> = {
  guard: "Guard",
  capture_content: "What is captured",
  sharing: "What is shared",
  egress: "Where requests go",
  admission_mode: "Admission",
  budget: "Budgets",
  destination_online: "SDK destination",
  sensitive: "Sensitive setting",
};

export function categoryLabel(c: string): string {
  return CATEGORY_LABELS[c] ?? (c || "Setting");
}

/** pendingProposals keeps the rows still waiting, oldest first. */
export function pendingProposals(rows: SettingsProposal[] | undefined | null): SettingsProposal[] {
  return (rows ?? []).filter((p) => p.status === "pending").sort((a, b) => a.id - b.id);
}

/** requesterLabel is "an AI agent (claude-code)" for "mcp:claude-code". */
export function requesterLabel(who: string): string {
  if (who === "mcp") return "an AI agent";
  if (who.startsWith("mcp:")) return `an AI agent (${who.slice(4)})`;
  return who || "an AI agent";
}

/**
 * sdkKeyNudge is the line Settings > AI Apps shows next to "Get my SDK key"
 * when this machine is connected to an organization but holds no SDK key
 * (U-26): enrolment and the SDK key are separate steps, and nothing used to
 * point from one to the other. null when there is nothing to say (not
 * connected, already signed in, or the discovery has not answered).
 */
export function sdkKeyNudge(d: Pick<SdkDiscovery, "signed_in"> | null | undefined, enrolled: boolean, orgName: string): string | null {
  if (!d || d.signed_in || !enrolled) return null;
  const org = orgName.trim() || "your organization";
  return `This machine is connected to ${org}, but your SDK key is separate. Get it so your apps can send their data to ${org}.`;
}
