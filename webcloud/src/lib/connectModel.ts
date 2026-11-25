// connectModel - the pure rules of the console's connect flow (Getting
// started v2, docs/plans/onboarding-v2-connect-flow.md): the install
// commands the account home offers per operating system and which tab a
// browser opens on, what the account home shows while it waits for a first
// machine, what the approval page shows per request status, and the small
// wordings (request age, operating system, network). No React, no fetch:
// the pages read these and connectModel.test.ts pins them.

import type { ConnectChoice, ConnectHome, ConnectPurpose, ConnectRequestView, PortalOrg } from "../api.ts";
import {
  DASHBOARD_ROLES,
  LOCAL_DASHBOARD_URL,
  asSentence,
  onlineDashboardLabel,
  onlineRole,
} from "../../../shared/lib/twoDashboards.ts";

// ---------------------------------------------------------------------------
// The install commands
// ---------------------------------------------------------------------------

/** InstallTab is one way to install and connect Observer. */
export type InstallTabId = "unix" | "windows" | "npm" | "pip";

/** INSTALL_TABS is one row per tab, in tab order. Each command installs
 * Observer, starts it in the background and opens the browser to approve
 * the machine (the website serves connect.sh and connect.ps1). */
export const INSTALL_TABS: readonly { id: InstallTabId; label: string; command: string }[] = [
  { id: "unix", label: "macOS / Linux", command: "curl -fsSL https://superbased.app/connect.sh | sh" },
  { id: "windows", label: "Windows", command: "irm https://superbased.app/connect.ps1 | iex" },
  { id: "npm", label: "npm", command: "npm install -g @superbased/observer && observer connect" },
  { id: "pip", label: "pip", command: "pip install superbased-observer && observer connect" },
];

/** installCommand returns the command of a tab. */
export function installCommand(id: InstallTabId): string {
  return INSTALL_TABS.find((t) => t.id === id)?.command ?? INSTALL_TABS[0].command;
}

/** tabForUserAgent picks the tab a browser opens on: Windows for a Windows
 * browser, else macOS / Linux. */
export function tabForUserAgent(ua: string): InstallTabId {
  return /windows|win32|win64/i.test(ua) ? "windows" : "unix";
}

/** CONNECT_FIRST says what the account home's first-machine card says. */
export const CONNECT_FIRST = {
  title: "Connect your first machine",
  lead: "Your numbers come from Observer running on your computer. Run this there:",
  after: "It installs Observer, starts it in the background and opens your browser to approve the machine. Nothing else to type.",
  waiting: "Waiting for a machine... this page updates by itself",
} as const;

// ---------------------------------------------------------------------------
// The account home's machine state
// ---------------------------------------------------------------------------

/** HomeMachineState is what the account home's machine card shows. */
export type HomeMachineState = "loading" | "waiting" | "connected" | "signed_in";

/** HomeMachineView is everything the machine card renders. */
export interface HomeMachineView {
  state: HomeMachineState;
  /** Show the install commands (the first-machine card). */
  showInstall: boolean;
  /** Poll the machines route (the page updates by itself). */
  poll: boolean;
  /** headline is the card's one line. */
  headline: string;
  /** openUrl opens the dashboard the newest machine connected to (a button). */
  openUrl: string | null;
}

interface HomeMachineRule {
  state: HomeMachineState;
  match: (home: ConnectHome | null) => boolean;
}

// Walked top-down, first match wins.
const HOME_MACHINE_RULES: HomeMachineRule[] = [
  { state: "loading", match: (h) => h === null },
  { state: "connected", match: (h) => (h?.recent.length ?? 0) > 0 },
  { state: "signed_in", match: (h) => (h?.devices ?? 0) > 0 },
  { state: "waiting", match: () => true },
];

/** homeMachineState walks HOME_MACHINE_RULES. */
export function homeMachineState(home: ConnectHome | null): HomeMachineState {
  for (const r of HOME_MACHINE_RULES) {
    if (r.match(home)) return r.state;
  }
  return "waiting";
}

/** machinesSignedInLabel words how many machines are signed in to the
 * account. */
export function machinesSignedInLabel(count: number): string {
  return count === 1 ? "1 machine is signed in." : `${count} machines are signed in.`;
}

/** homeMachineView decides the machine card. personalUrl is the personal
 * dashboard's Open target, used when the newest machine was signed in with
 * "Not now" (no dashboard of its own). */
export function homeMachineView(home: ConnectHome | null, personalUrl: string | null): HomeMachineView {
  const state = homeMachineState(home);
  switch (state) {
    case "loading":
      return { state, showInstall: false, poll: true, headline: "", openUrl: null };
    case "connected": {
      const newest = home!.recent[0];
      return {
        state,
        showInstall: false,
        poll: false,
        headline: `Connected: ${newest.machine_name}`,
        openUrl: newest.open_url ?? personalUrl,
      };
    }
    case "signed_in":
      return {
        state,
        showInstall: false,
        poll: false,
        headline: machinesSignedInLabel(home!.devices),
        openUrl: personalUrl,
      };
    case "waiting":
    default:
      return { state: "waiting", showInstall: true, poll: true, headline: CONNECT_FIRST.waiting, openUrl: null };
  }
}

// ---------------------------------------------------------------------------
// Team rows on the account home
// ---------------------------------------------------------------------------

/** teamMembersLabel words a team's member count (absent before the first
 * usage report). */
export function teamMembersLabel(org: Pick<PortalOrg, "members">): string {
  const memberCount = org.members;
  if (memberCount === undefined) return "Members appear after the first day";
  return memberCount === 1 ? "1 member" : `${memberCount} members`;
}

// ---------------------------------------------------------------------------
// The approval page
// ---------------------------------------------------------------------------

/** OS_LABEL names an operating system as Go's runtime.GOOS spells it. */
const OS_LABEL: Readonly<Record<string, string>> = {
  darwin: "macOS",
  linux: "Linux",
  windows: "Windows",
  // Node's process.platform and Python's sys.platform (an SDK's setup).
  win32: "Windows",
  freebsd: "FreeBSD",
};

/** osLabel names a machine's operating system. */
export function osLabel(os: string): string {
  return OS_LABEL[os] ?? os;
}

/** ageLabel words how long ago a request was made. */
export function ageLabel(seconds: number): string {
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return minutes === 1 ? "1 minute ago" : `${minutes} minutes ago`;
  const hours = Math.floor(minutes / 60);
  return hours === 1 ? "1 hour ago" : `${hours} hours ago`;
}

/** networkLine words where the request came from, against this browser. */
export function networkLine(net: ConnectRequestView["network"]): { text: string; warn: boolean } {
  if (!net.prefix) return { text: "Network unknown.", warn: true };
  if (net.same_as_you) return { text: `Same network as this browser (${net.prefix}).`, warn: false };
  return {
    text: `A different network from this browser (${net.prefix}). Approve only if you started this yourself.`,
    warn: true,
  };
}

/** ConnectPageState is what the approval page shows. */
export type ConnectPageState = "choose" | "connected" | "signed_in_only" | "declined" | "expired";

/** connectPageState reads the page state from a request view. */
export function connectPageState(v: Pick<ConnectRequestView, "status" | "target">): ConnectPageState {
  switch (v.status) {
    case "pending":
      return "choose";
    case "approved":
      return v.target ? "connected" : "signed_in_only";
    case "declined":
      return "declined";
    default:
      return "expired";
  }
}

/** CONNECT_PAGE_TEXT is the title and line of each finished state. */
export const CONNECT_PAGE_TEXT: Readonly<Record<Exclude<ConnectPageState, "choose">, { title: string; line: string }>> = {
  connected: {
    title: "Machine connected",
    line: "Observer on that machine finishes connecting by itself. Open either dashboard below, or close this page.",
  },
  signed_in_only: {
    title: "Signed in, nothing sent",
    line: "The machine is signed in to your account. It sends nothing until you connect it to a dashboard.",
  },
  declined: {
    title: "Request declined",
    line: "Nothing was connected and the machine is not signed in.",
  },
  expired: {
    title: "This request expired",
    line: "Run observer connect on the machine again to get a new one.",
  },
};

// ---------------------------------------------------------------------------
// The two dashboards, after approval
// ---------------------------------------------------------------------------

/** DashboardCard is one of the two dashboards the approved page shows side
 * by side: what it holds and the button that opens it. */
export interface DashboardCard {
  id: "local" | "online";
  title: string;
  /** role is what this dashboard holds (shared/lib/twoDashboards, the
   * terminal's words as a sentence). */
  role: string;
  button: string;
  href: string;
  /** "external" opens a new tab; "portal" is a path inside this portal
   * (the router's own, under /portal). */
  opens: "external" | "portal";
  /** note sits under the button. */
  note?: string;
}

/** PORTAL_HOME is the personal online dashboard's home in this portal. */
export const PORTAL_HOME = "/home";

/** httpsOnly keeps a server-built address a button may open: https only,
 * no credentials. */
function httpsOnly(raw: string | undefined): string | null {
  if (!raw) return null;
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:" || u.username || u.password) return null;
    return u.toString();
  } catch {
    return null;
  }
}

/** connectedDashboards is the approved page's two cards: the local dashboard
 * on the machine just connected (everything, in full, kept there) and the
 * online one (the personal or team dashboard's own address when the server
 * sent a usable one, else this portal's home). null before approval or
 * when nothing was connected. */
export function connectedDashboards(v: Pick<ConnectRequestView, "status" | "target" | "open_url">): DashboardCard[] | null {
  if (connectPageState(v) !== "connected" || !v.target) return null;
  const local: DashboardCard = {
    id: "local",
    title: "Local dashboard",
    role: asSentence(DASHBOARD_ROLES.local),
    button: "Open the local dashboard",
    href: LOCAL_DASHBOARD_URL,
    opens: "external",
    note: "On the computer you just connected.",
  };
  const kind = v.target.kind;
  // The dashboard's own address when the server sent a usable one (the
  // personal dashboard's, or the team's); else this portal's home.
  const onlineUrl = httpsOnly(v.open_url);
  const online: DashboardCard = {
    id: "online",
    title: kind === "team" ? `${onlineDashboardLabel(kind)}: ${v.target.display_name || v.target.slug}` : onlineDashboardLabel(kind),
    role: asSentence(onlineRole(kind)),
    button: kind === "team" ? "Open the team dashboard" : "Open your online dashboard",
    href: onlineUrl ?? PORTAL_HOME,
    opens: onlineUrl ? "external" : "portal",
  };
  return [local, online];
}

/** ChoicePosition is where a dashboard's name sits: a label of its own (the
 * chooser row) or mid-sentence ("... is connected to your personal
 * dashboard."). */
export type ChoicePosition = "label" | "inline";

/** PERSONAL_CHOICE_NAME is the personal dashboard's name per position (a
 * team's name is its own display name in either). */
const PERSONAL_CHOICE_NAME: Readonly<Record<ChoicePosition, string>> = {
  label: "Your personal dashboard",
  inline: "your personal dashboard",
};

/** choiceLabel names a dashboard: as a label by default, or mid-sentence. */
export function choiceLabel(c: { kind: "personal" | "team"; display_name: string }, at: ChoicePosition = "label"): string {
  return c.kind === "personal" ? PERSONAL_CHOICE_NAME[at] : c.display_name;
}

// ---------------------------------------------------------------------------
// An SDK key request (the AI Apps SDK quickstart, purpose "sdk_key")
// ---------------------------------------------------------------------------

/** connectPurpose reads a view's purpose; an older server sends none, which
 * is a machine. */
export function connectPurpose(v: Pick<ConnectRequestView, "purpose">): ConnectPurpose {
  return v.purpose ?? "machine";
}

/** PurposeText is everything the approval page words differently per
 * purpose. */
export interface PurposeText {
  /** The page title while the request waits. */
  title: string;
  /** The one line under the title. */
  intro: string;
  /** The chooser's legend. */
  legend: string;
  /** The approve button. */
  approve: string;
  /** Whether "Not now" is offered (a machine signs in without a
   * dashboard; an SDK key needs one). */
  notNow: boolean;
  /** The quiet decline link. */
  decline: string;
}

/** PURPOSE_TEXT is one row per purpose. */
export const PURPOSE_TEXT: Readonly<Record<ConnectPurpose, PurposeText>> = {
  machine: {
    title: "Connect this machine?",
    intro: "A machine running Observer asked to sign in to your account. Check it is yours.",
    legend: "Connect it to",
    approve: "Connect",
    notNow: true,
    decline: "This is not my machine",
  },
  sdk_key: {
    title: "Give this app an SDK key?",
    intro: "Setup for an AI Apps SDK asked for an SDK key so an app can send its traces. Check it is yours: the code should match what setup printed.",
    legend: "Make the key for",
    approve: "Approve",
    notNow: false,
    decline: "This is not my request",
  },
};

/** SDK_CLIENT_LABEL names the SDK packages whose setup may ask. */
const SDK_CLIENT_LABEL: Readonly<Record<string, string>> = {
  "superbased-sdk-python": "Python SDK",
  "superbased-sdk-typescript": "TypeScript SDK",
};

/** sdkClientLabel names the SDK that asks, with its version. */
export function sdkClientLabel(client: string | undefined, version: string | undefined): string {
  const name = (client && SDK_CLIENT_LABEL[client]) || client || "SDK";
  return version ? `${name} ${version}` : name;
}

/** choiceAvailable reads whether a dashboard may be chosen (an older server
 * sends no flag: every listed dashboard is). */
export function choiceAvailable(c: Pick<ConnectChoice, "available">): boolean {
  return c.available !== false;
}

/** pickChoice is the dashboard the page has selected: the one the person
 * picked if it may be chosen, else the server's preselected one, else the
 * first that may be chosen; undefined when none may. */
export function pickChoice(choices: readonly ConnectChoice[], picked: string | null): ConnectChoice | undefined {
  const ok = choices.filter(choiceAvailable);
  return ok.find((c) => c.org_id === picked) ?? ok.find((c) => c.preselected) ?? ok[0];
}

/** SdkKeyAfter is what the page does once an SDK key request is approved:
 * go to the dashboard's AI apps page, wait for a dashboard still being set
 * up, or nothing (not approved, or no usable address). */
export type SdkKeyAfter = { state: "go"; href: string } | { state: "wait" } | { state: "none" };

interface SdkKeyAfterRule {
  state: "go" | "wait" | "none";
  match: (v: Pick<ConnectRequestView, "status" | "target" | "target_ready">, href: string | null) => boolean;
}

// Walked top-down, first match wins.
const SDK_KEY_AFTER_RULES: SdkKeyAfterRule[] = [
  { state: "none", match: (v) => v.status !== "approved" || !v.target },
  { state: "wait", match: (v) => v.target_ready === false },
  { state: "go", match: (_v, href) => href !== null },
  { state: "none", match: () => true },
];

/** sdkKeyAfter walks SDK_KEY_AFTER_RULES. The address is the server's
 * open_url, kept only when it is https with no credentials. */
export function sdkKeyAfter(v: Pick<ConnectRequestView, "status" | "target" | "target_ready" | "open_url">): SdkKeyAfter {
  const href = httpsOnly(v.open_url);
  for (const r of SDK_KEY_AFTER_RULES) {
    if (!r.match(v, href)) continue;
    if (r.state === "go" && href) return { state: "go", href };
    return r.state === "wait" ? { state: "wait" } : { state: "none" };
  }
  return { state: "none" };
}

/** SDK_KEY_PAGE_TEXT is the title and line of each finished state of an SDK
 * key request. */
export const SDK_KEY_PAGE_TEXT: Readonly<Record<"approved" | "waiting" | "declined" | "expired", { title: string; line: string }>> = {
  approved: {
    title: "SDK key approved",
    line: "Setup on that computer receives the key by itself and sends a first trace. Taking you to the dashboard's AI apps page to watch it arrive.",
  },
  waiting: {
    title: "Setting up your dashboard",
    line: "Your dashboard is being set up. This page moves on by itself, and setup on that computer waits too.",
  },
  declined: {
    title: "Request declined",
    line: "No key was made. Setup on that computer stops.",
  },
  expired: {
    title: "This request expired",
    line: "Run setup on that computer again to get a new one.",
  },
};

// ---------------------------------------------------------------------------
// Signing in and coming back
// ---------------------------------------------------------------------------

/** CONNECT_CODE_KEY is the session storage key that keeps a code from a
 * ?code= link across the sign-in (the server refuses a return_to with a
 * query, so the code travels beside it). */
export const CONNECT_CODE_KEY = "sbo_connect_code";

/** safeReturnTo accepts a return path the sign-in may send the browser
 * back to: a path under /portal/ with no second slash, backslash, dot
 * segment or query. Anything else is null (the server checks it again). */
export function safeReturnTo(raw: string | null): string | null {
  if (!raw || !raw.startsWith("/portal/")) return null;
  if (raw.includes("//") || raw.includes("\\") || raw.includes("?") || raw.includes("#")) return null;
  if (raw.split("/").some((seg) => seg === "." || seg === "..")) return null;
  return raw;
}

/** routerPath turns a /portal/... return path into the router's own path
 * (the router's basename is /portal). */
export function routerPath(returnTo: string): string {
  const p = returnTo.slice("/portal".length);
  return p === "" ? "/" : p;
}
