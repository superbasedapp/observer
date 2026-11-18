// getStarted - the pure half of the Overview "Get started" panel and the
// connect flow it shares with the top bar and Settings > Account (Getting
// started v2). No JSX, no fetch: pinned by getStarted.test.ts.
//
// The panel has three steps: (1) sign in to superbased and connect this
// machine (recommended, never required), (2) turn capture on for the AI
// tools found here, (3) use them as usual. Signing in and connecting is ONE
// action: the daemon runs `observer connect --json --no-browser`
// (POST /api/connect/start, internal/intelligence/dashboard/connect_flow.go),
// the page opens the approval page in a new tab and reads progress until
// the machine is connected, the person chose "Not now" (signed in only), or
// it failed. When the machine is connected the panel becomes a one-line
// strip with an Open online dashboard button.
//
// Put away, the panel comes back as a one-line strip a week later; the time
// is kept on the daemon (POST /api/firstrun/seen {"snooze": "get_started"},
// GET /api/firstrun "snoozed"), so another browser agrees.

import type { FirstRunTool } from "./firstRun.ts";
import { connectedChipLabel, dashboardRolesLine, onlineKindOf } from "./connectHandoff.ts";
import { onlineRole } from "../../../shared/lib/twoDashboards.ts";

// ---- the connect flow (GET /api/connect/progress) -------------------------

export const CONNECT_START_PATH = "/api/connect/start";
export const CONNECT_PROGRESS_PATH = "/api/connect/progress";
export const CONNECT_CANCEL_PATH = "/api/connect/cancel";
/** Poll cadence while a connect flow runs. */
export const CONNECT_POLL_MS = 2000;

export type ConnectState =
  | "idle"
  | "starting"
  | "waiting_approval"
  | "approved"
  | "attaching"
  | "connected"
  | "signed_in_only"
  | "error"
  | "canceled"
  | "expired";

/** Where an approved request connects this machine (contract A). */
export type ConnectTarget = {
  org_id?: string;
  slug?: string;
  kind?: "personal" | "team";
  display_name?: string;
  share_level?: "summary" | "full";
};

/** ConnectProgress mirrors dashboard.ConnectProgress. */
export type ConnectProgress = {
  state: ConnectState;
  running: boolean;
  team?: string;
  approve_url?: string;
  verify_url?: string;
  user_code?: string;
  expires_at?: string;
  target?: ConnectTarget | null;
  display_name?: string;
  kind?: "personal" | "team";
  online_url?: string;
  code?: string;
  message?: string;
  started_at?: string;
  finished_at?: string;
};

const TERMINAL: ReadonlySet<ConnectState> = new Set(["connected", "signed_in_only", "error", "canceled", "expired"]);

/** connectFinished: the flow reached an end state. */
export function connectFinished(p: ConnectProgress | null | undefined): boolean {
  return !!p && TERMINAL.has(p.state);
}

/** connectActive: a flow is in flight (the page keeps polling). */
export function connectActive(p: ConnectProgress | null | undefined): boolean {
  return !!p && p.running && !TERMINAL.has(p.state);
}

export type ConnectTone = "accent" | "success" | "warn" | "danger" | "neutral";

/** The one line the panel, the top bar and Settings show for a flow. */
export type ConnectLine = { text: string; tone: ConnectTone; showCode: boolean };

/** CONNECT_LINES says each state in plain words. */
const CONNECT_LINES: Record<ConnectState, (p: ConnectProgress) => ConnectLine> = {
  idle: () => ({ text: "", tone: "neutral", showCode: false }),
  starting: () => ({ text: "Starting...", tone: "accent", showCode: false }),
  waiting_approval: () => ({ text: "Waiting for approval in your browser...", tone: "accent", showCode: true }),
  approved: () => ({ text: "Approved. Connecting this machine...", tone: "accent", showCode: false }),
  attaching: () => ({ text: "Approved. Connecting this machine...", tone: "accent", showCode: false }),
  connected: (p) => ({ text: `Connected to ${connectedName(p)}.`, tone: "success", showCode: false }),
  signed_in_only: () => ({
    text: "Signed in. This machine is not connected, and nothing was sent.",
    tone: "neutral",
    showCode: false,
  }),
  error: (p) => ({ text: p.message || "Connecting did not finish.", tone: "danger", showCode: false }),
  canceled: () => ({ text: "Stopped. Nothing was connected.", tone: "neutral", showCode: false }),
  expired: (p) => ({
    text: p.message || "The request expired before it was approved. Start again for a new code.",
    tone: "warn",
    showCode: false,
  }),
};

export function connectLine(p: ConnectProgress | null | undefined): ConnectLine {
  if (!p) return CONNECT_LINES.idle({ state: "idle", running: false });
  return (CONNECT_LINES[p.state] ?? CONNECT_LINES.idle)(p);
}

/** connectedName is the target's display name, never its address. */
export function connectedName(p: Pick<ConnectProgress, "display_name" | "target" | "kind">): string {
  const name = p.display_name || p.target?.display_name;
  if (name) return name;
  return (p.kind ?? p.target?.kind) === "personal" ? "your personal dashboard" : "your team";
}

/** The start POST: JSON plus the owner-local confirm header. */
export function connectStartInit(team: string, confirmHeaders: Record<string, string>): RequestInit {
  return { method: "POST", headers: confirmHeaders, body: JSON.stringify({ team: team.trim() }) };
}

/** The cancel POST. */
export function connectCancelInit(confirmHeaders: Record<string, string>): RequestInit {
  return { method: "POST", headers: confirmHeaders, body: "{}" };
}

/**
 * safeOpenURL keeps an address a button may open: https, or http on a
 * loopback host. The daemon already drops anything else; this is the
 * page's own check before window.open.
 */
export function safeOpenURL(raw: string | null | undefined): string | null {
  if (!raw) return null;
  try {
    const u = new URL(raw);
    if (u.username || u.password) return null;
    if (u.protocol === "https:") return u.toString();
    if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]")) {
      return u.toString();
    }
  } catch {
    // Not a URL.
  }
  return null;
}

// ---- the account facts -----------------------------------------------------

/** The part of GET /api/connect/status the panel reads (lib/connect.ts). */
export type AccountStatusInput = {
  kind: "local" | "managed" | "individual";
  destination?: string;
  signed_in: boolean;
  identity_known: boolean;
  locked: boolean;
  /**
   * The connected dashboard's name and online address as the daemon keeps
   * them with the enrolment (recorded when the machine connected; they
   * survive a daemon restart and a connection the CLI or an installer made).
   */
  display_name?: string;
  online_url?: string;
};

/** The part of GET /api/enrolment/status the panel reads. */
export type AccountEnrolmentInput = {
  enrolled: boolean;
  org_display?: string;
  org_server_url?: string;
  user_email?: string;
  tenancy?: string;
  last_push?: { pushed_at: string } | null;
};

/** Account is what every account surface shows, in the five words. */
export type Account = {
  signedIn: boolean;
  /** This build can read the superbased sign-in at all. */
  identityKnown: boolean;
  connected: boolean;
  locked: boolean;
  /** Where this machine is connected, by name (never an address). */
  displayName: string;
  email?: string;
  lastSentAt?: string;
  /** The online dashboard, for buttons only (never printed). */
  onlineUrl: string | null;
  /** "personal" | "team" when known; managed machines read as team. */
  kind?: "personal" | "team";
};

/**
 * accountOf folds the status reads into one Account. The connected flow's
 * own report wins for the name, kind and online address (it is the newest
 * fact); after a daemon restart the status's recorded connection facts come
 * next, then the enrolment's org name and server address.
 */
export function accountOf(
  status: AccountStatusInput | null | undefined,
  enrolment: AccountEnrolmentInput | null | undefined,
  progress: ConnectProgress | null | undefined,
): Account | null {
  if (!status) return null;
  const connected = status.kind !== "local" || !!enrolment?.enrolled;
  const flow = progress?.state === "connected" ? progress : null;
  const flowSignedIn = flow != null || progress?.state === "signed_in_only";
  const kind: Account["kind"] =
    flow?.kind ?? flow?.target?.kind ?? (enrolment?.tenancy === "managed" || status.kind === "managed" ? "team" : undefined);
  return {
    signedIn: status.signed_in || flowSignedIn,
    identityKnown: status.identity_known,
    connected: connected || flow != null,
    locked: status.locked,
    displayName:
      (flow ? connectedName(flow) : "") ||
      status.display_name ||
      enrolment?.org_display ||
      status.destination ||
      "your dashboard",
    email: enrolment?.user_email || undefined,
    lastSentAt: enrolment?.last_push?.pushed_at || undefined,
    onlineUrl:
      safeOpenURL(flow?.online_url) ?? safeOpenURL(status.online_url) ?? safeOpenURL(enrolment?.org_server_url),
    kind,
  };
}

// ---- share levels ------------------------------------------------------

export type ShareLevel = "summary" | "full";

/** SHARE_LEVELS says each share level in plain words. */
export const SHARE_LEVELS: Record<ShareLevel, { label: string; detail: string }> = {
  summary: {
    label: "Summary only",
    detail: "Counts, costs and timings. No prompts, responses or file paths.",
  },
  full: {
    label: "Full detail",
    detail: "Prompts, responses and file paths. Team admins can read it.",
  },
};

/** The daemon's share-mode rules (cmd/observer shareModeRules) by level. */
const SHARE_MODE_LEVEL: Record<string, ShareLevel> = {
  metadata_only: "summary",
  full_content: "full",
  admin_managed: "full",
  enterprise_grant: "full",
};

/** shareLevelOf maps a share-mode rule (or a target's level) to the two words. */
export function shareLevelOf(rule: string | null | undefined): ShareLevel | null {
  if (!rule) return null;
  if (rule === "summary" || rule === "full") return rule;
  return SHARE_MODE_LEVEL[rule] ?? null;
}

// ---- the panel's mode --------------------------------------------------------

export const GET_STARTED_SNOOZE_KEY = "get_started";
/** Put away, the panel returns as a strip after this many days. */
export const GET_STARTED_RETURN_DAYS = 7;
const DAY_MS = 86_400_000;

export type GetStartedMode = "loading" | "panel" | "strip" | "connected" | "hidden";

export type GetStartedInput = {
  account: Account | null;
  /** When the panel was last put away (RFC3339), from the daemon. */
  snoozedAt?: string | null;
  /** A connect flow is in flight. */
  connecting: boolean;
  now: number;
};

type ModeRule = { name: string; when: (i: GetStartedInput) => boolean; mode: GetStartedMode };

/** The ordered rules; the first match decides. */
export const GET_STARTED_RULES: readonly ModeRule[] = [
  { name: "unknown", when: (i) => i.account == null, mode: "loading" },
  { name: "connected", when: (i) => !!i.account?.connected, mode: "connected" },
  // A flow started from the top bar or Settings shows its progress here too.
  { name: "connecting", when: (i) => i.connecting, mode: "panel" },
  { name: "never_put_away", when: (i) => snoozeAge(i) == null, mode: "panel" },
  { name: "put_away_this_week", when: (i) => (snoozeAge(i) ?? 0) < GET_STARTED_RETURN_DAYS * DAY_MS, mode: "hidden" },
  { name: "back_after_a_week", when: () => true, mode: "strip" },
];

function snoozeAge(i: GetStartedInput): number | null {
  if (!i.snoozedAt) return null;
  const t = Date.parse(i.snoozedAt);
  if (!Number.isFinite(t)) return null;
  return i.now - t;
}

export function getStartedMode(i: GetStartedInput): GetStartedMode {
  for (const r of GET_STARTED_RULES) {
    if (r.when(i)) return r.mode;
  }
  return "panel";
}

/** The snooze POST: JSON plus the owner-local confirm header. */
export function snoozeRequestInit(token: string): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Observer-Confirm": token },
    body: JSON.stringify({ snooze: GET_STARTED_SNOOZE_KEY }),
  };
}

// ---- step 1 ------------------------------------------------------------

export type SignInStep =
  | { kind: "sign_in" }
  | { kind: "connect" }
  | { kind: "skipped" }
  | { kind: "unavailable"; reason: string };

/**
 * signInStep decides step 1: sign in (and connect), connect only (already
 * signed in), skipped ("Continue without an account"), or unavailable (a
 * company lock, or a build that cannot sign in).
 */
export function signInStep(a: Account, skipped: boolean): SignInStep {
  if (a.locked) return { kind: "unavailable", reason: "Your company's settings choose where this machine sends data." };
  if (skipped) return { kind: "skipped" };
  if (!a.identityKnown) return { kind: "unavailable", reason: "This install cannot sign in to superbased." };
  return a.signedIn ? { kind: "connect" } : { kind: "sign_in" };
}

// ---- step 2: turn capture on for every tool found --------------------------

/** One write the bulk action makes, through the same routes the wizard uses. */
export type WiringAction = {
  tool: string;
  name: string;
  step: "hooks" | "route";
  endpoint: string;
  body: Record<string, unknown>;
};

export type WiringPlan = {
  /** Tools with at least one write to make. */
  tools: { tool: string; name: string; actions: WiringAction[] }[];
  /** Tools whose proxy route changes how the tool behaves: left to Settings. */
  routeLeftToSettings: string[];
  /** Detected tools with nothing left to turn on. */
  alreadyOn: number;
};

const HOOKS_ENDPOINT = "/api/setup/hooks";

/**
 * wiringPlan lists the writes "Turn on for all" makes: each found tool's
 * hooks and proxy route that the server offers (the wiring it computes
 * from the same rules `observer init` uses) and that are not on yet. A
 * route whose server note says the tool switches something off while it
 * is in force is never written in bulk; that one stays a per-tool choice in
 * Settings > Connected tools. MCP and telemetry stay per-tool too.
 */
export function wiringPlan(tools: readonly FirstRunTool[]): WiringPlan {
  const plan: WiringPlan = { tools: [], routeLeftToSettings: [], alreadyOn: 0 };
  for (const t of tools) {
    if (!t.detected) continue;
    const w = t.wiring;
    const actions: WiringAction[] = [];
    const hooks = t.hooks;
    if (w?.hooks.register && !(hooks && (hooks.registered || hooks.no_hooks))) {
      actions.push({ tool: t.tool, name: t.name, step: "hooks", endpoint: HOOKS_ENDPOINT, body: { tool: t.tool, force: false, dry_run: false } });
    }
    if (w?.route_endpoint && w.route.register && !t.proxy?.registered) {
      if (w.route.tradeoff) {
        plan.routeLeftToSettings.push(t.name);
      } else {
        actions.push({ tool: t.tool, name: t.name, step: "route", endpoint: w.route_endpoint, body: { force: false, dry_run: false } });
      }
    }
    if (actions.length > 0) plan.tools.push({ tool: t.tool, name: t.name, actions });
    else plan.alreadyOn++;
  }
  return plan;
}

/** One bulk write's outcome, from setupWizardPreview.classifyWizardReply. */
export type WiringOutcome = { tool: string; step: "hooks" | "route"; kind: "plan" | "conflict" | "error" };

/** wiringResultLine says what "Turn on for all" did, in one sentence. */
export function wiringResultLine(outcomes: readonly WiringOutcome[]): { text: string; tone: ConnectTone } {
  const failedTools = new Set(outcomes.filter((o) => o.kind !== "plan").map((o) => o.tool));
  const okTools = new Set(outcomes.filter((o) => o.kind === "plan" && !failedTools.has(o.tool)).map((o) => o.tool));
  const n = (k: number) => `${k} tool${k === 1 ? "" : "s"}`;
  if (failedTools.size === 0) return { text: `Turned on for ${n(okTools.size)}.`, tone: "success" };
  const look = `${n(failedTools.size)} need${failedTools.size === 1 ? "s" : ""} a look in Settings > Connected tools.`;
  if (okTools.size === 0) return { text: `Nothing changed. ${look}`, tone: "warn" };
  return { text: `Turned on for ${n(okTools.size)}. ${look}`, tone: "warn" };
}

/** A found tool's capture state for the step 2 list, in plain words. */
export function toolCaptureLabel(t: FirstRunTool): { text: string; tone: ConnectTone } {
  if (!t.watcher_active) return { text: "Not captured yet", tone: "neutral" };
  const hooksOn = !!t.hooks?.registered;
  const routed = !!t.proxy?.registered;
  if (hooksOn && routed) return { text: "Fully on", tone: "success" };
  if (hooksOn || routed) return { text: "On", tone: "success" };
  return { text: "Reading session files", tone: "accent" };
}

// ---- the top bar's account control ----------------------------------------

export type TopBarAccountView =
  | { kind: "hidden" }
  | { kind: "sign_in"; label: string; tooltip: string }
  | { kind: "connect"; label: string; tooltip: string }
  | { kind: "connecting"; label: string; tooltip: string }
  | {
      kind: "connected";
      label: string;
      /** Where this machine is connected, and what each dashboard holds. */
      tooltip: string;
      managed: boolean;
      onlineUrl: string | null;
      /** The Open online button's tooltip: what the online dashboard holds. */
      onlineTooltip: string;
    };

type TopBarInput = {
  account: Account | null;
  /** This view can start the flow (the owner's own browser). */
  available: boolean;
  progress: ConnectProgress | null | undefined;
  /** An organization manages this machine (enrolment tenancy). */
  managed: boolean;
  /** The installer's terminal is connecting this machine (?connecting=1,
   * lib/connectHandoff.ts): the terminal owns that flow, so nothing here
   * offers to start a second one. */
  handoffWaiting?: boolean;
};

type TopBarRule = { name: string; when: (i: TopBarInput) => boolean; view: (i: TopBarInput) => TopBarAccountView };

/**
 * TOP_BAR_RULES decides the top bar's account control, at every width: a
 * connected machine names where (and opens it online); a flow in flight,
 * here or in the installer's terminal, says it is waiting; otherwise Sign in
 * (or Connect, once signed in). A
 * remote view and a build that cannot sign in show nothing to start.
 */
export const TOP_BAR_RULES: readonly TopBarRule[] = [
  { name: "unknown", when: (i) => i.account == null, view: () => ({ kind: "hidden" }) },
  {
    name: "connected",
    when: (i) => !!i.account?.connected,
    view: (i) => {
      const a = i.account!;
      // A managed machine reads as a team (lib/connectHandoff onlineKindOf).
      const facts = { ...a, kind: i.managed ? ("team" as const) : a.kind };
      const where = i.managed ? `Managed by ${a.displayName}` : connectedChipLabel(facts);
      const who = a.email ? ` as ${a.email}` : "";
      const roles = dashboardRolesLine(facts);
      const tooltip = i.managed
        ? `This machine is connected to ${a.displayName}${who}, which manages it. ${roles} Details in Settings > Account.`
        : `This machine is connected to ${a.displayName}${who}. ${roles} Details in Settings > Account.`;
      return {
        kind: "connected",
        label: where,
        tooltip,
        managed: i.managed,
        onlineUrl: a.onlineUrl,
        onlineTooltip: `Open the online dashboard in a new tab: ${onlineRole(onlineKindOf(facts))}.`,
      };
    },
  },
  {
    name: "connecting",
    when: (i) => connectActive(i.progress),
    view: (i) => ({
      kind: "connecting",
      label: "Waiting for approval",
      tooltip: i.progress?.user_code
        ? `Approve this machine in your browser. Code ${i.progress.user_code}.`
        : "Approve this machine in your browser.",
    }),
  },
  {
    name: "terminal_connecting",
    when: (i) => !!i.handoffWaiting,
    view: () => ({
      kind: "connecting",
      label: "Waiting for approval",
      tooltip: "Approve this machine in the browser tab that just opened, or enter the code shown in your terminal.",
    }),
  },
  { name: "cannot_start_here", when: (i) => !i.available || !!i.account?.locked || !i.account?.identityKnown, view: () => ({ kind: "hidden" }) },
  {
    name: "signed_in",
    when: (i) => !!i.account?.signedIn,
    view: () => ({
      kind: "connect",
      label: "Connect",
      tooltip: "You are signed in. Connect this machine to see it in your online dashboard.",
    }),
  },
  {
    name: "signed_out",
    when: () => true,
    view: () => ({
      kind: "sign_in",
      label: "Sign in",
      tooltip: "Sign in and connect this machine: one online dashboard for all your machines and your team. Free, and optional.",
    }),
  },
];

export function topBarAccountView(i: TopBarInput): TopBarAccountView {
  for (const r of TOP_BAR_RULES) {
    if (r.when(i)) return r.view(i);
  }
  return { kind: "hidden" };
}
