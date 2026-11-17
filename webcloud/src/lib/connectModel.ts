// connectModel - the pure rules of the console's connect flow (Getting
// started v2, docs/plans/onboarding-v2-connect-flow.md): the install
// commands the account home offers per operating system and which tab a
// browser opens on, what the account home shows while it waits for a first
// machine, what the approval page shows per request status, and the small
// wordings (request age, operating system, network). No React, no fetch:
// the pages read these and connectModel.test.ts pins them.

import type { ConnectHome, ConnectRequestView, PortalOrg } from "../api.ts";

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
        openUrl: newest.online_url ?? personalUrl,
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
    line: "Observer on that machine finishes connecting by itself. You can close this page.",
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

/** choiceLabel names a dashboard in the chooser. */
export function choiceLabel(c: { kind: "personal" | "team"; display_name: string }): string {
  return c.kind === "personal" ? "Your personal dashboard" : c.display_name;
}

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
