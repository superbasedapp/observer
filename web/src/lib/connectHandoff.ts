// connectHandoff - the pure half of the installer's hand-off to the local
// dashboard. `curl -fsSL https://superbased.app/connect.sh | sh` (and
// connect.ps1) starts Observer, opens this dashboard at
// http://127.0.0.1:8081/?connecting=1 (plus &team=<slug> for a team), then
// runs `observer connect` in the terminal, which opens the online approval
// page in a new tab. This page cannot drive that flow (the terminal owns
// it): it says where to approve, reads GET /api/connect/status until the
// machine is connected, and then explains the two dashboards once.
//
// No JSX, no fetch: components/ConnectHandoff.tsx renders what this file
// decides, and connectHandoff.test.ts pins it.
//
// The installer restarts the daemon once right after the connect succeeds
// (the push loop starts at daemon start), so a few status reads fail around
// the moment the machine becomes connected. A failed read is never an
// error here: the phase stays "waiting" and the next answer decides.

import {
  DASHBOARD_ROLES,
  asSentence,
  onlineDashboardLabel,
  onlineRole,
  type OnlineDashboardKind,
} from "../../../shared/lib/twoDashboards.ts";
import type { Account, SurfaceLayout } from "./getStarted.ts";

/** The query the installer opens this dashboard with. */
export const HANDOFF_PARAM = "connecting";
export const HANDOFF_TEAM_PARAM = "team";
/** The installer's arrival intent (`--apps` adds &intent=apps). */
export const HANDOFF_INTENT_PARAM = "intent";

/** How often the page reads the status while it waits. */
export const HANDOFF_POLL_MS = 3000;
/** How long it waits: the connect request's own lifetime (15 minutes). */
export const HANDOFF_LIFETIME_MS = 15 * 60 * 1000;

/** The command that starts again after the wait ran out. */
export const HANDOFF_RETRY_COMMAND = "observer connect";

/** A team slug as `observer connect <team>` takes it. */
const TEAM_SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;

/** The arrival intents the hand-off carries (a closed value): the AI apps
 *  track, or none. */
export type HandoffIntent = "apps" | "";

/** Handoff is what the installer's query asked for. */
export type Handoff = {
  /** The team chosen on the approval page, "" for the personal dashboard. */
  team: string;
  /** The installer's arrival intent: "apps" for `--apps`; absent for none. */
  intent?: HandoffIntent;
};

/**
 * parseHandoff reads the installer's query: ?connecting=1, with an optional
 * team slug (anything that is not a slug is dropped, never shown) and an
 * optional arrival intent (review FR-M18: only "apps" is read, anything
 * else is none).
 */
export function parseHandoff(search: string): Handoff | null {
  const q = new URLSearchParams(search);
  if (q.get(HANDOFF_PARAM) !== "1") return null;
  const team = (q.get(HANDOFF_TEAM_PARAM) ?? "").trim().toLowerCase();
  const h: Handoff = { team: TEAM_SLUG.test(team) ? team : "" };
  if ((q.get(HANDOFF_INTENT_PARAM) ?? "").trim().toLowerCase() === "apps") h.intent = "apps";
  return h;
}

/**
 * withoutHandoff is the address with the installer's query removed (other
 * query keys and the hash kept), for history.replaceState once the machine
 * is connected.
 */
export function withoutHandoff(href: string): string {
  const u = new URL(href);
  u.searchParams.delete(HANDOFF_PARAM);
  u.searchParams.delete(HANDOFF_TEAM_PARAM);
  u.searchParams.delete(HANDOFF_INTENT_PARAM);
  const search = u.searchParams.toString();
  return u.pathname + (search ? `?${search}` : "") + u.hash;
}

/**
 * withArrivalIntent opens the AI apps track of the getting-started surface
 * for a hand-off that asked for it (the installer's `--apps`, review
 * FR-M18), where the daemon decided the coding track and AI Apps is
 * available here. It changes the view only, for this visit: it records
 * nothing and turns nothing on (the track's own consent does that). A
 * decision already on AI apps or Both, or AI Apps not available, keeps the
 * daemon's layout.
 */
export function withArrivalIntent(layout: SurfaceLayout, h: Handoff | null): SurfaceLayout {
  if (h?.intent !== "apps" || layout.track !== "coding" || layout.switchDisabled !== "") return layout;
  return { track: "apps", columns: ["apps"], showSwitch: false, offerApps: false, switchDisabled: "", switchBack: true };
}

// ---- the phase ---------------------------------------------------------------

export type HandoffPhase = "none" | "waiting" | "connected" | "expired";

export type HandoffInput = {
  handoff: Handoff | null;
  /** The account folded from the last status reads (null before the first
   * answer, and kept while the daemon restarts). */
  account: Account | null;
  /** When this page started waiting (epoch ms). */
  startedAt: number;
  now: number;
};

type PhaseRule = { name: string; when: (i: HandoffInput) => boolean; phase: HandoffPhase };

/**
 * HANDOFF_RULES decide the hand-off card, top-down. A failed or missing
 * status read matches no rule before "waiting": it only waits longer.
 */
export const HANDOFF_RULES: readonly PhaseRule[] = [
  { name: "no_handoff", when: (i) => i.handoff == null, phase: "none" },
  { name: "connected", when: (i) => !!i.account?.connected, phase: "connected" },
  { name: "ran_out", when: (i) => i.now - i.startedAt > HANDOFF_LIFETIME_MS, phase: "expired" },
  { name: "waiting", when: () => true, phase: "waiting" },
];

export function handoffPhase(i: HandoffInput): HandoffPhase {
  for (const r of HANDOFF_RULES) {
    if (r.when(i)) return r.phase;
  }
  return "waiting";
}

/** The card's words per phase ("none" shows nothing). */
export const HANDOFF_TEXT = {
  waiting: {
    title: "Connecting this machine",
    line: "Approve this machine in the browser tab that just opened (or enter the code shown in your terminal). This page updates when it is connected.",
  },
  expired: {
    title: "Not connected yet",
    line: "The approval was not finished in time. To try again, run this in a terminal:",
  },
} as const;

/** handoffTeamLine names the team the terminal asked for, when it did. */
export function handoffTeamLine(h: Handoff | null): string {
  return h?.team ? `Connecting to the team ${h.team}.` : "";
}

// ---- the two dashboards ------------------------------------------------------

/** Where the "Two dashboards" note was put away, in this browser. */
export const TWO_DASHBOARDS_NOTE_KEY = "sb_two_dashboards_note_dismissed";

/** onlineKindOf reads which online dashboard this machine shares with: a
 * team (a managed machine reads as one), else the personal dashboard. */
export function onlineKindOf(a: Pick<Account, "kind"> | null | undefined): OnlineDashboardKind {
  return a?.kind === "team" ? "team" : "personal";
}

/** TwoDashboardsNote is the short note shown once after connecting. */
export type TwoDashboardsNote = {
  title: string;
  local: { label: string; role: string };
  online: { label: string; role: string; url: string | null; button: string };
};

/** twoDashboardsNote words the note for a connected account. */
export function twoDashboardsNote(a: Pick<Account, "kind" | "displayName" | "onlineUrl">): TwoDashboardsNote {
  const kind = onlineKindOf(a);
  return {
    title: "Two dashboards",
    local: { label: "This local dashboard", role: asSentence(DASHBOARD_ROLES.local) },
    online: {
      label: kind === "team" ? `${onlineDashboardLabel(kind)}: ${a.displayName}` : "Your online dashboard",
      role: asSentence(onlineRole(kind)),
      url: a.onlineUrl,
      button: kind === "team" ? "Open the team dashboard" : "Open your online dashboard",
    },
  };
}

/**
 * showTwoDashboardsNote: the note shows once the machine is connected,
 * until it is put away in this browser.
 */
export function showTwoDashboardsNote(a: Pick<Account, "connected"> | null | undefined, dismissed: boolean): boolean {
  return !!a?.connected && !dismissed;
}

/** Storage seam: a Storage, or nothing where storage is unavailable. */
export type NoteStorage = Pick<Storage, "getItem" | "setItem"> | null | undefined;

/** readNoteDismissed reads the put-away flag; unreadable storage reads as
 * not put away (the note shows again on the next visit). */
export function readNoteDismissed(s: NoteStorage): boolean {
  try {
    return s?.getItem(TWO_DASHBOARDS_NOTE_KEY) === "1";
  } catch {
    return false;
  }
}

/** writeNoteDismissed keeps the put-away flag; a storage that refuses it
 * keeps the note away for this page view only. */
export function writeNoteDismissed(s: NoteStorage): void {
  try {
    s?.setItem(TWO_DASHBOARDS_NOTE_KEY, "1");
  } catch {
    // Storage unavailable: put away for this page view only.
  }
}

// ---- the top bar ---------------------------------------------------------------

/**
 * connectedChipLabel is the top bar's connected chip: "Connected · personal
 * dashboard", or the team's name. A managed machine keeps "Managed by
 * <name>" (topBarAccountView).
 */
export function connectedChipLabel(a: Pick<Account, "kind" | "displayName">): string {
  if (onlineKindOf(a) === "personal" && /^(your )?personal dashboard$/i.test(a.displayName.trim())) {
    return "Connected · personal dashboard";
  }
  return `Connected · ${a.displayName}`;
}

/** dashboardRolesLine is the tooltip's sentence about the two dashboards. */
export function dashboardRolesLine(a: Pick<Account, "kind">): string {
  const kind = onlineKindOf(a);
  return `${onlineDashboardLabel(kind)}: ${onlineRole(kind)}. This local dashboard: ${DASHBOARD_ROLES.local}.`;
}
