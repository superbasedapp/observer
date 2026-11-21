// setupExtras.ts - pure models for the three Settings controls that used to
// exist only as CLI verbs (dashboard CLI parity, lane L2): the Claude Code
// status line, start at login and browser capture setup, plus the per-site
// browser toggles. No imports besides types, so it runs under plain node:test.

export type SetupAction = "install" | "remove";

/** The shared result of a preview or an apply (dashapi.SetupOutcome). */
export interface SetupOutcome {
  action: SetupAction;
  dry_run: boolean;
  changed: boolean;
  refused?: boolean;
  reason?: string;
  path?: string;
  lines: string[];
}

export type StatuslineState = "absent" | "installed" | "stale" | "foreign";

export interface StatuslineStatus {
  supported: boolean;
  reason?: string;
  config_path?: string;
  state: StatuslineState;
  command?: string;
}

export interface LoginStartStatus {
  supported: boolean;
  reason?: string;
  manager?: string;
  manager_label?: string;
  installed: boolean;
  enabled: boolean;
  running: boolean;
  path?: string;
  command?: string;
}

export interface BrowserExtensionCandidate {
  browser: string;
  profile: string;
  id: string;
}

export interface BrowserCaptureStatus {
  supported: boolean;
  reason?: string;
  host_files: string[];
  installed: boolean;
  candidates: BrowserExtensionCandidate[];
}

export interface BrowserSiteRow {
  site: string;
  label: string;
  enabled: boolean;
  explicit: boolean;
}

export type Tone = "success" | "warn" | "neutral" | "info";

/** One button a card offers: the action it previews, its label, and whether it forces. */
export interface SetupButton {
  action: SetupAction;
  label: string;
  force?: boolean;
}

/** statuslineBadge is the pill beside the card title. */
export function statuslineBadge(st: StatuslineStatus): { text: string; tone: Tone } {
  if (!st.supported) return { text: "unavailable", tone: "neutral" };
  switch (st.state) {
    case "installed":
      return { text: "on", tone: "success" };
    case "stale":
      return { text: "on - needs refresh", tone: "warn" };
    case "foreign":
      return { text: "your own status line", tone: "info" };
    default:
      return { text: "off", tone: "neutral" };
  }
}

/**
 * statuslineButtons lists what the card offers for a state. A status line the
 * user wrote is never removed, and replacing it is a separate, explicit button.
 */
export function statuslineButtons(st: StatuslineStatus): SetupButton[] {
  if (!st.supported) return [];
  switch (st.state) {
    case "installed":
      return [{ action: "remove", label: "Remove" }];
    case "stale":
      return [
        { action: "install", label: "Refresh" },
        { action: "remove", label: "Remove" },
      ];
    case "foreign":
      return [{ action: "install", label: "Replace it with Observer's", force: true }];
    default:
      return [{ action: "install", label: "Install" }];
  }
}

/** loginStartBadge is the pill beside the Start at login title. */
export function loginStartBadge(st: LoginStartStatus): { text: string; tone: Tone } {
  if (!st.supported) return { text: "unavailable", tone: "neutral" };
  if (!st.installed) return { text: "off", tone: "neutral" };
  return st.enabled ? { text: "on", tone: "success" } : { text: "installed, not enabled", tone: "warn" };
}

/** loginStartButtons: install when absent, remove when present; never both. */
export function loginStartButtons(st: LoginStartStatus): SetupButton[] {
  if (!st.supported) return [];
  return st.installed ? [{ action: "remove", label: "Remove" }] : [{ action: "install", label: "Install" }];
}

/**
 * loginStartNote is the line under the buttons that says honestly what the
 * control does not do: it never starts or stops the daemon, and a running
 * daemon keeps running when the entry is removed.
 */
export function loginStartNote(st: LoginStartStatus): string {
  if (!st.supported) return st.reason ?? "";
  if (st.installed && st.running) {
    return "The daemon is running under this entry now. Removing the entry does not stop it.";
  }
  return "Installing does not start the daemon now; it starts at your next login.";
}

const EXTENSION_ID = /^[a-p]{32}$/;

/** validExtensionId: a Chromium extension id is 32 lowercase letters a to p. */
export function validExtensionId(id: string): boolean {
  return EXTENSION_ID.test(id.trim());
}

/** browserBadge is the pill for the host-install row. */
export function browserBadge(st: BrowserCaptureStatus): { text: string; tone: Tone } {
  if (!st.supported) return { text: "unavailable", tone: "neutral" };
  return st.installed ? { text: "host installed", tone: "success" } : { text: "host not installed", tone: "neutral" };
}

/**
 * extensionIdProblem is the inline message for the id field, or "" when the
 * field is fine. Blank is allowed: the host is written with a placeholder.
 */
export function extensionIdProblem(id: string): string {
  const v = id.trim();
  if (v === "" || validExtensionId(v)) return "";
  return "An extension id is 32 lowercase letters a to p. Leave it blank to install now and add it later.";
}

/** siteDraft maps rows to their current on/off state keyed by site. */
export function siteDraft(rows: BrowserSiteRow[]): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const r of rows) out[r.site] = r.enabled;
  return out;
}

/**
 * changedSites is the request body for POST /api/browser/sites: only the sites
 * whose toggle differs from what the daemon reports, in row order.
 */
export function changedSites(rows: BrowserSiteRow[], draft: Record<string, boolean>): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const r of rows) {
    const want = draft[r.site];
    if (want !== undefined && want !== r.enabled) out[r.site] = want;
  }
  return out;
}

/** errorText pulls a readable message out of an ApiError-shaped failure. */
export function errorText(e: unknown): string {
  const body = (e as { body?: unknown } | null)?.body;
  if (typeof body === "string" && body.trim() !== "") {
    try {
      const j = JSON.parse(body) as { message?: unknown; error?: unknown };
      if (typeof j.message === "string" && j.message) return j.message;
      if (typeof j.error === "string" && j.error) return j.error;
    } catch {
      // A plain-text body (http.Error) is the message itself.
    }
    return body.trim();
  }
  return e instanceof Error ? e.message : String(e);
}

/** teardownLinkText is "Open <label>" for a teardown step's dashboard link. */
export function teardownLinkText(label: string | undefined): string {
  return label ? `Open ${label}` : "Open in the dashboard";
}

/** isInAppLink guards a server-supplied link: only same-origin app paths render. */
export function isInAppLink(link: string | undefined): link is string {
  return typeof link === "string" && link.startsWith("/") && !link.startsWith("//");
}
