// twoDashboards - the one wording of Observer's two dashboards, shared by the
// local dashboard (web/) and the online approval page (webcloud/). The
// terminal (`observer connect`, cmd/observer/connect_request.go) and the
// installer print the same role lines; change all of them together.
//
// The local dashboard (served by the daemon on this computer) shows
// everything Observer records here, in full, and it stays here. The online
// dashboard receives what the machine shares: a summary for the personal
// dashboard, full detail for a team, whose admins can read it. Pure: no
// React, no fetch, no storage.

/** LOCAL_DASHBOARD_URL is the local dashboard's default address. */
export const LOCAL_DASHBOARD_URL = "http://127.0.0.1:8081";

/** OnlineDashboardKind is where a connected machine shares. */
export type OnlineDashboardKind = "personal" | "team";

/** DASHBOARD_ROLES is each dashboard's role line, lower-case as the
 * terminal prints it under the address. */
export const DASHBOARD_ROLES = {
  local: "everything Observer records on this computer, in full; it stays here",
  personal: "a summary from each machine you connect",
  team: "full detail (prompts, responses, file paths); the team's admins can read it",
} as const;

/** onlineRole is the online dashboard's role line for a kind. */
export function onlineRole(kind: OnlineDashboardKind): string {
  return kind === "team" ? DASHBOARD_ROLES.team : DASHBOARD_ROLES.personal;
}

/** onlineDashboardLabel names the online dashboard as the terminal does. */
export function onlineDashboardLabel(kind: OnlineDashboardKind): string {
  return kind === "team" ? "Team dashboard" : "Online dashboard";
}

/** asSentence turns a role line into a sentence for a page: a capital first
 * letter and a full stop (the words stay the terminal's). */
export function asSentence(line: string): string {
  const t = line.trim();
  if (!t) return "";
  const s = t[0].toUpperCase() + t.slice(1);
  return /[.!?]$/.test(s) ? s : s + ".";
}
