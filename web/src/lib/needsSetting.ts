// needsSetting: the ONE reading of an API error whose fix is "turn a setting
// or a component on" (the client half of internal/settingslink). The daemon
// adds a machine-readable deep link to every such refusal:
//
//   {"error": <code or sentence>, "message": <plain sentence>,
//    "settings": "/settings/components?component=remote",
//    "settings_label": "Settings > Components",
//    "command": "observer components add remote --yes"}   (when one exists)
//
// A component_not_installed body carries the same fields beside its
// "component" and "state". This module turns any thrown API error into an
// ErrorNote: the human text (never raw JSON, never an excerpt cut mid-word)
// and, when the server named one, the in-app link to the place that fixes it.
// The thin renderer is components/NeedsSettingNotice.tsx.
//
// The same reading covers a STATUS a route returns (not a refusal): any
// object carrying these fields (fixOf). When only the organization's admins
// can change the setting, the body names the TEAM dashboard place instead:
//
//   {"org_settings": "https://org.example/intelligence?tab=session-enrichment",
//    "org_settings_label": "Intelligence > Session enrichment"}
//
// (org_settings is omitted when the node knows no safe address; the label
// alone names the place in words). The node never offers a toggle for it.
//
// Pure (no React; its only import is the pure settingsPlaces.ts), so the node
// test runner covers it (needsSetting.test.ts). It reads the thrown value structurally (ApiError
// carries `status` and the full `body`) the way lib/apiFailure.ts does.

import { orgDashboardURL } from "./settingsPlaces.ts";

/** The deep link a refusal names. */
export type SettingsLink = {
  /** The in-app path, e.g. "/settings/components?component=remote". */
  href: string;
  /** The place's plain name, e.g. "Settings > Components". */
  label: string;
  /** The CLI command that makes the same change, or null. */
  command: string | null;
  /** The component a component_not_installed refusal names, or null. */
  component: string | null;
  /** That component's resolver state (available, absent, blocked), or null. */
  componentState: string | null;
};

/** A team-dashboard place only the organization's admins change. */
export type OrgSettingsLink = {
  /** The absolute team-dashboard URL, or null when the node knows no safe
   *  address (the label then names the place in words). */
  href: string | null;
  /** The place's plain name, e.g. "Intelligence > Session enrichment". */
  label: string;
  /** True on the person's own personal dashboard: they are its only admin,
   *  so the notice tells them to turn it on, not to ask anyone. */
  personal?: boolean;
};

/** What a surface shows for a failed request (or a status that is off). */
export type ErrorNote = {
  /** The full human sentence. */
  text: string;
  /** The place that fixes it, when the server named one. */
  settings: SettingsLink | null;
  /** The team-dashboard place, when only the organization's admins can. */
  org?: OrgSettingsLink | null;
};

type Body = Record<string, unknown>;

/** parseErrorBody reads a response body as a JSON object, or null. */
export function parseErrorBody(body: unknown): Body | null {
  if (typeof body !== "string") return null;
  const t = body.trim();
  if (!t.startsWith("{")) return null;
  try {
    const v = JSON.parse(t) as unknown;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Body) : null;
  } catch {
    return null;
  }
}

/** isInAppPath accepts only a same-origin path: one leading slash, no
 *  scheme, no protocol-relative "//", no backslash. Anything else is never
 *  navigated to. */
export function isInAppPath(href: unknown): href is string {
  return (
    typeof href === "string" &&
    href.startsWith("/") &&
    !href.startsWith("//") &&
    !href.includes("\\") &&
    !/^\/[^/?#]*:/.test(href)
  );
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

/** settingsLinkOfBody reads the deep link off a parsed body, or null. */
export function settingsLinkOfBody(b: Body | null): SettingsLink | null {
  if (!b) return null;
  const href = str(b.settings);
  if (!isInAppPath(href)) return null;
  return {
    href,
    label: str(b.settings_label) || "Settings",
    command: str(b.command) || null,
    component: str(b.component) || null,
    componentState: str(b.state) || null,
  };
}

/** orgSettingsLinkOfBody reads the "ask your organization" place off a
 *  parsed body, or null. The URL is kept only when it is one a button may
 *  open (https, or http on a loopback host, no credentials). */
export function orgSettingsLinkOfBody(b: Body | null): OrgSettingsLink | null {
  if (!b) return null;
  const label = str(b.org_settings_label);
  if (!label) return null;
  return { href: orgDashboardURL(str(b.org_settings)), label, personal: str(b.org_dashboard_kind) === "personal" };
}

/** The way forward a status or a body names: the local place and/or the
 *  team-dashboard place. Both null means no setting changes it. */
export type Fix = { settings: SettingsLink | null; org: OrgSettingsLink | null };

/** fixOf reads the fix fields off any object a route returns (a status
 *  view carries them beside its own fields, e.g. GET /api/intel/session's
 *  `actions`). */
export function fixOf(v: unknown): Fix {
  const b = v && typeof v === "object" && !Array.isArray(v) ? (v as Body) : null;
  return { settings: settingsLinkOfBody(b), org: orgSettingsLinkOfBody(b) };
}

/** The org form's sentence: who can change it, and where. On a personal
 *  dashboard that is the person; on a team, its admins (an admin uses the
 *  link, anyone else learns who to ask). */
export function orgAskText(org: OrgSettingsLink): string {
  return org.personal
    ? `Turn it on in your personal dashboard: ${org.label}.`
    : `The team's admins can turn it on in the team dashboard: ${org.label}.`;
}

/** The org form's button: "Open <the place's last part>", e.g. "Open
 *  session enrichment". */
export function orgActionLabel(org: OrgSettingsLink): string {
  const last = org.label.split(">").pop()?.trim() || "team dashboard";
  return `Open ${last.charAt(0).toLowerCase()}${last.slice(1)}`;
}

// A closed error code is one snake_case word ("not_enrolled"); a sentence
// has a space. Only a sentence is shown to a person.
const CODE_ONLY = /^[a-z0-9_.:-]+$/i;

/** bodyText is the sentence a body carries for a person: its "message",
 *  else an "error" that is a sentence, else null. */
export function bodyText(b: Body | null): string | null {
  if (!b) return null;
  const message = str(b.message);
  if (message) return message;
  const error = str(b.error);
  if (error && !CODE_ONLY.test(error)) return error;
  const detail = str(b.detail);
  if (detail) return detail;
  return null;
}

function bodyOf(e: unknown): unknown {
  return e && typeof e === "object" && "body" in e ? (e as { body: unknown }).body : undefined;
}

/** stripApiPrefix removes fetchJSON's "api <status> <path>: " prefix. */
export function stripApiPrefix(message: string): string {
  return message.replace(/^api \d{3} \S+: /, "");
}

/** errorText is the plain text of any thrown value: the server's sentence
 *  when the body is JSON, the whole non-JSON body otherwise, else the
 *  error's own message without fetchJSON's prefix. */
export function errorText(e: unknown): string {
  const raw = bodyOf(e);
  const text = bodyText(parseErrorBody(raw));
  if (text) return text;
  if (typeof raw === "string" && raw.trim() && !raw.trim().startsWith("{")) return raw.trim();
  if (e instanceof Error) return stripApiPrefix(e.message);
  return typeof e === "string" ? e : String(e ?? "");
}

/** needsSettingOf returns the deep link a thrown API error names, or null. */
export function needsSettingOf(e: unknown): SettingsLink | null {
  return settingsLinkOfBody(parseErrorBody(bodyOf(e)));
}

/**
 * errorNote turns a thrown value into what a surface shows. When the server
 * named a place to fix it, its own sentence wins (it says what is off and
 * where); otherwise the surface's own wording (`fallback`, e.g. a status
 * table) applies, then the server's sentence.
 */
export function errorNote(e: unknown, fallback?: (e: unknown) => string | null | undefined): ErrorNote {
  const body = parseErrorBody(bodyOf(e));
  const settings = settingsLinkOfBody(body);
  const org = orgSettingsLinkOfBody(body);
  if (settings || org) {
    const text = bodyText(body) || fallback?.(e) || errorText(e);
    return { text, settings, org };
  }
  return { text: fallback?.(e) || errorText(e), settings: null };
}

/** noteOf accepts the plain string a surface sets for its own messages. */
export function noteOf(v: ErrorNote | string | null | undefined): ErrorNote | null {
  if (v == null) return null;
  if (typeof v === "string") return v.trim() ? { text: v, settings: null } : null;
  return v.text.trim() || v.settings || v.org ? v : null;
}

/**
 * settingsActionLabel is the button's text: "Turn on <name>" for a
 * component this machine can turn on, else "Open <place>". `title` is the
 * component's catalog title when the caller knows it.
 */
export function settingsActionLabel(link: SettingsLink, title?: string | null): string {
  const canTurnOn =
    link.component && link.componentState !== "absent" && link.componentState !== "blocked";
  if (canTurnOn) return `Turn on ${title?.trim() || link.component}`;
  return `Open ${link.label}`;
}

/**
 * noteWithText keeps a surface's own sentence (a surface that owns a closed
 * code table, e.g. sandbox setup) and adds the deep link the server named.
 */
export function noteWithText(e: unknown, text: string): ErrorNote {
  return { text, settings: needsSettingOf(e) };
}
