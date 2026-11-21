// planeaFirstRun - the pure half of the "Your apps" first-run card (Plane A
// lane B5, plan W2-5, D7, D17): what one click must do to turn app
// observability on, on this build and this machine's config.
//
// D7: obs is compiled into the developer and full builds and stays off
// until the user turns it on; it is out of minimal and managed. In a
// developer build obs is a component that is off, so `[observability]
// enabled` alone is forced off (the Batch A gate note): the one consent adds
// the component AND sets the key. In a build without obs the card refuses
// loudly, never offers a button that cannot work.
//
// Decision logic as data (CLAUDE.md #5): FIRST_RUN_RULES is walked top-down,
// one test per row (planeaFirstRun.test.ts). Pure: no React, no fetch, no
// app path aliases, so `node --test` loads it.

import { PRODUCT_NAMES } from "../../../shared/lib/productNames.ts";
import { SDK_CATALOG, type SdkEntry } from "../../../shared/lib/sdkCatalog.ts";
import type { FirstRunApps } from "./firstRun.ts";

/** The obs component's state on this machine (componentState
 *  ComponentStateName), or "unknown" while it is being read. */
export type ObsComponentState = "active" | "available" | "absent" | "blocked" | "unknown";

/** What the card knows. */
export type FirstRunFacts = {
  component: ObsComponentState;
  /** `[observability].enabled` in config.toml; null when unknown. */
  enabled: boolean | null;
  /** GET /api/obs/enabled answered (the routes are registered). */
  routesUp: boolean;
};

/** The card's shape. */
export type FirstRunPhase =
  | "on" // nothing to do: the pages work
  | "loading" // a fact is still unknown
  | "absent" // not in this build: refuse, name the builds that have it
  | "blocked" // the component is blocked here (an organization, a rule)
  | "add_component_and_key" // one consent: add obs, set the key
  | "set_key" // the component is on, the key is off
  | "restart"; // both are on in config, the routes wait for a restart

/** One row of the table. */
export type FirstRunRule = { name: string; when: (f: FirstRunFacts) => boolean; phase: FirstRunPhase };

/** FIRST_RUN_RULES: the ordered table, walked top-down. */
export const FIRST_RUN_RULES: readonly FirstRunRule[] = [
  { name: "the routes answer: it is on", when: (f) => f.routesUp, phase: "on" },
  { name: "not in this build", when: (f) => f.component === "absent", phase: "absent" },
  { name: "blocked on this machine", when: (f) => f.component === "blocked", phase: "blocked" },
  { name: "a fact is unknown", when: (f) => f.component === "unknown" || f.enabled === null, phase: "loading" },
  { name: "the component is off", when: (f) => f.component === "available", phase: "add_component_and_key" },
  { name: "the component is on, the key is off", when: (f) => f.enabled === false, phase: "set_key" },
  { name: "both on in config: restart", when: () => true, phase: "restart" },
];

/** firstRunPhase walks FIRST_RUN_RULES. */
export function firstRunPhase(f: FirstRunFacts): FirstRunPhase {
  return (FIRST_RUN_RULES.find((r) => r.when(f)) ?? FIRST_RUN_RULES[FIRST_RUN_RULES.length - 1]).phase;
}

/** The obs component id and its config key. */
export const OBS_COMPONENT = "obs";
export const OBS_ENABLED_KEY = "observability.enabled";

/** firstRunSteps lists what one click does, in order (the confirm note). */
export function firstRunSteps(phase: FirstRunPhase): string[] {
  switch (phase) {
    case "add_component_and_key":
      return [
        `adds the ${OBS_COMPONENT} component under [components] (the change Settings > Components makes)`,
        `sets ${OBS_ENABLED_KEY} = true in config.toml`,
      ];
    case "set_key":
      return [`sets ${OBS_ENABLED_KEY} = true in config.toml`];
    default:
      return [];
  }
}

/** firstRunNote is the confirm step's sentence (review FR-M02): what the one
 *  enable seam does, in order, with no restart, then the daemon's one consent
 *  sentence (apps.consent, P-05), the one the other AI Apps cards show;
 *  "Stays on this machine." only while the daemon has not said. */
export function firstRunNote(phase: FirstRunPhase, consentSentence?: string | null): string {
  const consent = consentSentence?.trim() || "Stays on this machine.";
  if (phase === "restart") {
    // Both are on in config already: the seam only starts it in place.
    return `Starts ${PRODUCT_NAMES.planea} in the running daemon: the trace receiver opens now, with no restart. ${consent}`;
  }
  const steps = firstRunSteps(phase);
  if (steps.length === 0) return "";
  return `Turns on ${PRODUCT_NAMES.planea} on this machine: ${steps.join(", then ")}. The daemon checks each change before it is written and opens the trace receiver now, with no restart. ${consent}`;
}

/** firstRunAction is what the "Your apps" card offers in a phase (review
 *  FR-M02): the one enable seam wherever a click can help (POST
 *  /api/apps/enable also retries a receiver that did not open, so "both on in
 *  config" turns on in place too), and the restart only where this process
 *  has no seam (hot_enable false: a dashboard the daemon does not serve). */
export type FirstRunAction = "turn_on" | "restart" | "none";

export function firstRunAction(phase: FirstRunPhase, hotEnable: boolean | null | undefined): FirstRunAction {
  switch (phase) {
    case "add_component_and_key":
    case "set_key":
      return "turn_on";
    case "restart":
      return hotEnable === false ? "restart" : "turn_on";
    default:
      return "none";
  }
}

/** One SDK tab of the card: the language, its install line and a minimal
 *  init that sends to this machine. */
export type SdkSnippet = { id: string; label: string; install: string; code: string };

/** sdkSnippets maps the SDK catalog (shared/lib/sdkCatalog.json, the one
 *  owner of every SDK's install line, published flag and init snippet,
 *  review P-11) to the card's tabs, in catalog order. The install line is
 *  the checkout line until the catalog marks the package published
 *  (scripts/sdk-install-strings.py flips it on the SDK release, E-66). */
export function sdkSnippets(catalog: readonly SdkEntry[]): SdkSnippet[] {
  return catalog.map((s) => ({ id: s.id, label: s.label, install: s.install, code: s.code }));
}

/** The SDK tabs the card shows: one per catalog row. */
export const SDK_SNIPPETS: readonly SdkSnippet[] = sdkSnippets(SDK_CATALOG);

/** The builds that include obs (D7), for the "not in this build" copy. */
export const OBS_BUILDS = ["developer", "full"] as const;

// ------------------------------------------------------------ dismissal

/** The per-viewer convenience key for hiding the Overview card. */
export const FIRST_RUN_DISMISS_KEY = "superbased.planea.firstRun.dismissed";

/** showOnOverview: the Overview card shows only where it can help (the
 *  component is in the build, not blocked, the pages are not up) and the
 *  viewer has not dismissed it. A Your apps page always shows its card. */
export function showOnOverview(phase: FirstRunPhase, dismissed: boolean): boolean {
  if (dismissed) return false;
  return phase === "add_component_and_key" || phase === "set_key" || phase === "restart";
}

// ------------------------------------------------------------ OTLP receiver

/** What GET /api/sdk/receiver answers: the daemon's record of its local
 *  OTLP receiver's bind (the record `observer doctor` reads). */
export type OTLPReceiverState = {
  state: string;
  grpc_addr?: string;
  http_addr?: string;
  error?: string;
  at?: string;
};

/** The callout the AI Apps pages show for the receiver, or null. */
export type ReceiverNotice = { tone: "danger"; title: string; body: string };

/** receiverNotice (review E-72): a taken OTLP port used to show only in
 *  `observer doctor`, so the AI Apps pages stayed empty and the SDK's
 *  exports failed with no word in the dashboard. Only a recorded bind
 *  failure speaks; listening, unknown or no answer says nothing. */
export function receiverNotice(r: OTLPReceiverState | null | undefined): ReceiverNotice | null {
  if (!r || r.state !== "bind_failed") return null;
  const addrs = [r.http_addr && `HTTP ${r.http_addr}`, r.grpc_addr && `gRPC ${r.grpc_addr}`].filter(Boolean).join(", ");
  return {
    tone: "danger",
    title: "This machine is not receiving your apps' traces",
    body:
      `The OTLP receiver could not open its port${addrs ? ` (${addrs})` : ""}, so every span an app sends here is lost.` +
      (r.error ? ` The error was: ${r.error}.` : "") +
      " Another program holds the port: stop it, or give the receiver other ports in Settings > OTel export (the OTLP receiver settings, under More settings), then restart the daemon.",
  };
}

// ------------------------------------------------------------ persistent nav

/** The persistent AI Apps nav item (review E-71): the way back to the
 *  first-run page after "Not now" hid the Overview card, and the place a
 *  build without app observability says so. Its route is /apps (a core
 *  route, App.tsx), which forwards to Traces once the pages are up. */
export const APPS_START_NAV_ID = "apps-start";
export const APPS_START_PATH = "/apps";
/** Where /apps forwards when the AI Apps pages answer. */
export const APPS_HOME_PATH = "/apps/traces";

/** appsStartNavShown: the item stands in for the AI Apps group while its
 *  pages are not in the nav (off, waiting for a restart, not in this build,
 *  or the probe has not answered), and never where the organization hides
 *  AI Apps on this machine. Once the pages answer, the group itself is the
 *  way in. */
export function appsStartNavShown(routesUp: boolean | null, orgHidesApps: boolean): boolean {
  return routesUp !== true && !orgHidesApps;
}

/** withAppsStart returns shown (the filtered nav groups) with standIn put
 *  where the group of the same id sits in full (the unfiltered order), so
 *  the item keeps the AI Apps group's place. A group of that id already in
 *  shown is left alone. */
export function withAppsStart<G extends { id: string }>(full: readonly G[], shown: readonly G[], standIn: G): G[] {
  if (shown.some((g) => g.id === standIn.id)) return [...shown];
  const at = full.findIndex((g) => g.id === standIn.id);
  if (at < 0) return [...shown, standIn];
  const before = new Set(full.slice(0, at).map((g) => g.id));
  let i = 0;
  while (i < shown.length && before.has(shown[i].id)) i++;
  return [...shown.slice(0, i), standIn, ...shown.slice(i)];
}

/** firstRunPageTitle is the first-run page's heading (review E-71): a build
 *  without AI Apps says the edition does not include it, every other phase
 *  that AI Apps is off. */
export function firstRunPageTitle(phase: FirstRunPhase): string {
  return phase === "absent" ? `This edition does not include ${PRODUCT_NAMES.planea}` : `${PRODUCT_NAMES.planea} is off`;
}

// ------------------------------------------------------------ the AI apps track
//
// First-run plan revision 2, sections 3.6 (c) to (e) and 7.1: the AI apps
// column of the one getting-started surface. The daemon reports the facts
// (/api/firstrun "apps", lane POLISH-F1); the tables below only pick which
// card shows. Whether this machine is on the AI apps track at all is the
// daemon's decision ("plane.track"), never made here.

/** The card the AI apps column shows. */
export type AppsTrackPhase =
  | "loading" // the first-run read has not answered
  | "legacy" // a daemon without the apps block: today's card (restart banner)
  | "glance" // the first trace was opened: the normal strip
  | "first_trace" // a trace arrived: show it once
  | "waiting" // on, no trace yet
  | "bind_failed" // turned on, but the receiver could not open its port
  | "unavailable" // not in this edition, or blocked here
  | "consent"; // off: the one consent

export type AppsTrackFacts = {
  loaded: boolean;
  apps: FirstRunApps | null | undefined;
  /** The trace id this browser already opened from the first-trace card. */
  openedTrace: string | null;
};

type AppsTrackRule = { name: string; when: (f: AppsTrackFacts) => boolean; phase: AppsTrackPhase };

/** APPS_TRACK_RULES: walked top-down, one test per row. */
export const APPS_TRACK_RULES: readonly AppsTrackRule[] = [
  { name: "the first-run read has not answered", when: (f) => !f.loaded, phase: "loading" },
  { name: "a daemon without the apps block", when: (f) => !f.apps, phase: "legacy" },
  {
    name: "a trace arrived and was opened here",
    when: (f) => !!f.apps?.on && !!f.apps.latest_trace && f.openedTrace != null,
    phase: "glance",
  },
  { name: "a trace arrived", when: (f) => !!f.apps?.on && !!f.apps.latest_trace, phase: "first_trace" },
  {
    // Only once AI Apps was turned on (on, or saved on): with it never
    // enabled, the consent card shows even when the receiver (bound for
    // [ingest.otel]) could not open its port (review FR-M12).
    name: "the receiver could not bind",
    when: (f) => f.apps?.receiver.state === "bind_failed" && (!!f.apps.on || !!f.apps.configured_on),
    phase: "bind_failed",
  },
  { name: "on, waiting for a trace", when: (f) => !!f.apps?.on, phase: "waiting" },
  { name: "not available here", when: (f) => f.apps?.available.available === false, phase: "unavailable" },
  { name: "this process cannot turn it on in place", when: (f) => f.apps?.hot_enable === false, phase: "legacy" },
  { name: "off: one consent", when: () => true, phase: "consent" },
];

/** appsTrackPhase walks APPS_TRACK_RULES. */
export function appsTrackPhase(f: AppsTrackFacts): AppsTrackPhase {
  return (APPS_TRACK_RULES.find((r) => r.when(f)) ?? APPS_TRACK_RULES[APPS_TRACK_RULES.length - 1]).phase;
}

/** The three steps of the AI apps track (plan 7.1) and which are done. */
export type AppsStep = { n: number; title: string; done: boolean };

export function appsSteps(phase: AppsTrackPhase): AppsStep[] {
  const on = phase === "waiting" || phase === "first_trace" || phase === "glance";
  const traced = phase === "first_trace" || phase === "glance";
  return [
    { n: 1, title: `Turn on ${PRODUCT_NAMES.planea}`, done: on },
    { n: 2, title: "Send your first trace", done: traced },
    { n: 3, title: "Look at it", done: phase === "glance" },
  ];
}

/** The per-viewer key of the trace opened from the first-trace card. */
export const FIRST_TRACE_OPENED_KEY = "superbased.planea.firstTraceOpened";

/** The OTLP HTTP receiver's default, used only while the daemon has not
 *  reported an address (the receiver is not running yet). */
export const DEFAULT_RECEIVER_HTTP = "127.0.0.1:4318";

/** receiverURL turns the daemon's receiver address ("127.0.0.1:4318",
 *  "0.0.0.0:4318", ":4318", "[::]:4318") into the URL an app on this
 *  machine sends to. A wildcard or empty host is reached on loopback. */
export function receiverURL(addr: string | null | undefined): string {
  const a = (addr || DEFAULT_RECEIVER_HTTP).trim().replace(/^https?:\/\//, "");
  const i = a.lastIndexOf(":");
  if (i < 0) return `http://${a}`;
  let host = a.slice(0, i);
  const port = a.slice(i + 1);
  if (host === "" || host === "0.0.0.0" || host === "[::]" || host === "::") host = "127.0.0.1";
  return `http://${host}:${port}`;
}

/** The address the consent card and the prompt name: the receiver's own
 *  report when it has one, else the configured address. */
export function receiverAddress(apps: FirstRunApps | null | undefined, configured: string | null | undefined): string {
  return apps?.receiver.http_addr || configured || DEFAULT_RECEIVER_HTTP;
}

/** The catalog fields the agent prompt needs from one SDK. */
export type PromptSdk = { label: string; install: string; published?: boolean; installPublished?: string };

/** The placeholder the prompt puts where a checkout path goes. */
export const CHECKOUT_PLACEHOLDER = "<path to your superbased checkout>";

/** promptInstall is one SDK's install instruction in the agent prompt
 *  (U-06). A published SDK is its registry line. An unpublished one is the
 *  registry line to use once it is published, then the checkout line with
 *  its path made explicit: the prompt runs in the app's folder, where a
 *  "./sdk/python" path does not exist. Install-line comments are dropped. */
export function promptInstall(s: PromptSdk): string {
  const strip = (line: string) => line.replace(/\s+(#|\/\/).*$/, "").trim();
  if (s.published || !s.installPublished) return `${s.label}: ${strip(s.install)}`;
  const checkout = strip(s.install)
    .replace(/(^|[\s=])\.\/sdk\//g, `$1${CHECKOUT_PLACEHOLDER}/sdk/`)
    .replace(/<checkout>/g, CHECKOUT_PLACEHOLDER);
  return `${s.label}: ${strip(s.installPublished)} once it is published; until then, from a superbased checkout: ${checkout}`;
}

/** snippetForReceiver points an SDK snippet at the daemon's live receiver
 *  (U-04): the catalog snippets name the default 127.0.0.1:4318, which is
 *  wrong on a machine whose receiver listens elsewhere. On the default the
 *  snippet is unchanged; otherwise the address is replaced and the
 *  environment variable that points the SDK there is named. */
export function snippetForReceiver(code: string, receiver: string | null | undefined): string {
  const url = receiverURL(receiver);
  const hostPort = url.replace(/^https?:\/\//, "");
  if (hostPort === DEFAULT_RECEIVER_HTTP) return code;
  return code.replaceAll(DEFAULT_RECEIVER_HTTP, `${hostPort} (set OTEL_EXPORTER_OTLP_ENDPOINT=${url})`);
}

/** agentPrompt is the "Let your coding agent do it" text (plan 3.6 d),
 *  generated from the running daemon's receiver and dashboard addresses and
 *  the SDK catalog's install lines; it never hard-codes a port. */
export function agentPrompt(i: {
  receiver: string;
  dashboard: string;
  sdks: readonly PromptSdk[];
}): string {
  const endpoint = receiverURL(i.receiver);
  const installs = i.sdks.map(promptInstall).join("; ");
  const dash = i.dashboard.replace(/\/+$/, "");
  return [
    "Add superbased tracing to this app.",
    `Install the superbased SDK for this project's language (${installs}).`,
    "Call init with the service name set to this project's name at startup.",
    "Wrap the main request handler as an agent span and each model call as an LLM span with its token usage.",
    "Call shutdown before the process exits.",
    `Traces go to ${endpoint} (set OTEL_EXPORTER_OTLP_ENDPOINT=${endpoint} if that is not the SDK's default).`,
    `Run the app once, then check ${dash}/api/obs/traces for the trace.`,
  ].join(" ");
}

/** The coding-agent tab leads only on a machine with coding history
 *  (decision 9, P-14); otherwise the code tab leads. */
export type SendTab = "agent" | "code";

export function sendTabs(codingHistory: boolean): SendTab[] {
  return codingHistory ? ["agent", "code"] : ["code", "agent"];
}

/** How long the waiting card waits before it offers the "not seeing it"
 *  help (plan 3.6 d). */
export const WAITING_HELP_MS = 2 * 60 * 1000;
/** The waiting card's poll, while the tab is visible. */
export const WAITING_POLL_MS = 3000;

/** showWaitingHelp: two minutes after the waiting card opened, or at once
 *  when the receiver reports it is not listening. The daemon cannot see an
 *  export that never arrived, so the help says what it can check. */
export function showWaitingHelp(openedAt: number, now: number, apps: FirstRunApps | null | undefined): boolean {
  const st = apps?.receiver.state;
  if (st === "bind_failed" || st === "no_answer" || st === "not_running") return true;
  return now - openedAt >= WAITING_HELP_MS;
}

/** One line of the "not seeing it" help. */
export type WaitingHelpLine = { tone: "danger" | "neutral"; text: string };

/** waitingHelp lists what the person can check, receiver facts first. */
export function waitingHelp(apps: FirstRunApps | null | undefined, receiver: string): WaitingHelpLine[] {
  const out: WaitingHelpLine[] = [];
  const r = apps?.receiver;
  if (r?.state === "bind_failed") {
    out.push({
      tone: "danger",
      text: `The receiver could not open ${r.http_addr || receiver}${r.error ? ` (${r.error})` : ""}. Another program holds the port: stop it, or give the receiver another port in Settings > ${PRODUCT_NAMES.planea}, then turn it on again.`,
    });
  } else if (r?.state === "not_running" || r?.state === "no_answer") {
    out.push({ tone: "danger", text: "The receiver is not running in this daemon. Turn it on again, or restart the daemon." });
  } else {
    out.push({ tone: "neutral", text: `The receiver is listening on ${r?.http_addr || receiver}.` });
  }
  out.push({ tone: "neutral", text: `Check that the app sends to ${receiverURL(r?.http_addr || receiver)}, with the path /v1/traces.` });
  out.push({ tone: "neutral", text: "Spans are sent in batches: let the app call shutdown, or wait a few seconds after a request." });
  out.push({ tone: "neutral", text: "An app in a container reaches this machine through the host's address, not 127.0.0.1." });
  return out;
}

/** consentLines is the consent card's text (plan 3.6 c): where it listens
 *  and the one consent sentence the daemon builds (P-05, P-18). */
export function consentLines(apps: FirstRunApps | null | undefined, receiver: string): string[] {
  const note = apps?.consent.receiver_note ? ` ${apps.consent.receiver_note}` : "";
  return [
    `Listens for your app's traces on ${receiver}${note}.`,
    apps?.consent.sentence || "Stays on this machine.",
    `Turn it off in Settings > ${PRODUCT_NAMES.planea} (takes effect at the next start).`,
  ];
}

/** What the one click changes, in plain words ("What changes", L-7). */
export function consentChanges(apps: FirstRunApps | null | undefined): string[] {
  const out: string[] = [];
  if (apps?.component !== "active") out.push(`Adds the ${PRODUCT_NAMES.planea} component to this machine's components.`);
  out.push(`Turns ${PRODUCT_NAMES.planea} on in your config file (a backup is kept).`);
  out.push("Opens the trace receiver now; no restart.");
  out.push(
    "Admission checks, egress routing, proxy turn traces, alerts and organization sharing start with the daemon: any you set up wait for its next start, and the card names them.",
  );
  return out;
}

/** pendingLine names the AI Apps features a hot enable could not start
 *  (the daemon's pending_next_start, review FR-M01): they are configured on
 *  and start with the daemon, so the card never says they took effect at
 *  once. null when nothing waits. */
export function pendingLine(pending: readonly string[] | null | undefined): string | null {
  const names = (pending ?? []).map((p) => p.trim()).filter(Boolean);
  if (names.length === 0) return null;
  return `These start at the next daemon start: ${names.join(", ")}.`;
}

/** enableResult is the line the card shows after the button: the report's
 *  message, with its fix when there is one, and what waits for the next
 *  start. */
export function enableResult(
  r: { ok: boolean; message?: string; fix?: string; pending_next_start?: string[] } | null,
): { tone: "success" | "danger"; text: string } | null {
  if (!r) return null;
  const text = [r.message, r.fix, r.ok ? pendingLine(r.pending_next_start) : null].filter((x) => x && x.trim()).join(" ");
  return { tone: r.ok ? "success" : "danger", text: text || (r.ok ? `${PRODUCT_NAMES.planea} is on.` : "It could not be turned on.") };
}

/** obsPendingOnlyForRestart reports whether a Settings > Components pending
 *  change is the AI Apps component's activation that a hot enable already
 *  made live (POLISH-F1 finding F1-4): the component set is recorded at
 *  start, so after a hot enable the page would still say obs waits for a
 *  restart. With AI Apps on in the daemon, that row is not pending. */
export function hotEnabledPending(p: { id: string; change: string }, appsOn: boolean): boolean {
  return appsOn && p.id === OBS_COMPONENT && p.change === "activate";
}

/** configuredReceiver reads the receiver's HTTP address from GET
 *  /api/config's `config` object (the saved setting), or null. */
export function configuredReceiver(config: unknown): string | null {
  let cur: unknown = config;
  for (const p of ["Ingest", "OTel", "HTTPAddr"]) {
    if (!cur || typeof cur !== "object") return null;
    cur = (cur as Record<string, unknown>)[p];
  }
  return typeof cur === "string" && cur.trim() !== "" ? cur.trim() : null;
}
